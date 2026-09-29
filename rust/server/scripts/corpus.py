#!/usr/bin/env python3
"""Runs the corpus (1,179 rows plus 5,000 mutants) through aprv-server,
over HTTP and through the one-shot CLI, and compares every row with the
ABI v1 Node reference rows, as round 13 did for eight in-process hosts
(docs/evidence/2026-09-29-canonical-abi-final/py/classify.py).

    corpus.py --aprv PATH/TO/aprv --calls CALLS_DIR --node NODE_ROWS_DIR
              [--mode http|cli] [--lifecycle fresh|pool] [--out ROWS_DIR]

CALLS_DIR holds round 13's calls files (`<corpus>.jsonl`, written by that
round's py/calls_bytes.py from ABI v1's calls); NODE_ROWS_DIR holds ABI v1's
Node rows (`node-<corpus>.jsonl`). Both are the evidence rounds' scratch
artifacts, named by placeholders in their READMEs.

Each row's `config` becomes the server's roots (one server per distinct
config over HTTP; `--roots` per process for the CLI) and its `now` the
X-Aprv-Now-Ms header or `--now-ms`. Categories, first match wins:

  identical          byte-identical to Node (request_date* masked on endpoint rows
                     without a pinned clock, as abi_compare.py does)
  over-cap           the input is over 3,145,728 bytes and the server answered 413
                     (the CLI exit 3) before the module saw it; Node's module answered it
  init-refusal       the roots are not certificates: ABI v1 answered INVALID_TEST_ENVELOPE,
                     the server refuses to start with init's {"ok":false}
  clock-moves-chain  an endpoint row with a pinned clock: now-ms is also the chain
                     instant when the receipt states no date (the 0.7 rule)
  DIFFERENT          anything else: a finding

The expectation printed at the end: every row one of the first four, none
DIFFERENT, 2 clock-moves-chain and 1 init-refusal as round 13 found.

With --reference DIR instead of --node, the rows are compared exactly
with DIR/module-<corpus>.jsonl: the release module's own answers to the
same calls, every clock pinned (--suffix .pinned reads
CALLS_DIR/<corpus>.pinned.jsonl). Then the only categories are identical,
over-cap (413 / exit 3 where the module itself answered the cap refusal,
TOO_LARGE or status 21002) and DIFFERENT, and the expectation is none
DIFFERENT.
"""
import argparse
import base64
import collections
import http.client
import json
import os
import re
import subprocess
import sys
import tempfile

MAX_BODY = 3_145_728
CORPORA = ("cases", "hostile", "algorithms", "substrate", "fuzz")
MASK = re.compile(r'"(request_date(?:_ms|_pst)?)":"[^"]*"')
PATHS = {"verify-receipt": "/v1/receipt/verify", "verify-signed-data": "/v1/signed-data/verify"}
ENVS = {0: "production", 1: "sandbox"}


def roots_file_text(config):
    return "\n".join(json.loads(config)["roots"]) + "\n"


class Server:
    def __init__(self, aprv, roots_file, lifecycle):
        args = [aprv, "serve", "--listen", "127.0.0.1:0", "--lifecycle", lifecycle]
        if roots_file:
            args += ["--roots", roots_file]
        self.p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
        line = self.p.stdout.readline().decode()
        self.refusal = None
        if not line.startswith("APRV_LISTEN="):
            self.refusal = self.p.stderr.read().decode().strip()
            self.p.wait()
            return
        host, port = line.strip().split("=", 1)[1].rsplit(":", 1)
        self.conn = http.client.HTTPConnection(host, int(port), timeout=120)

    def call(self, row, body):
        path = PATHS.get(row["fn"]) or "/v1/verify-receipt/" + ENVS[row["env"]]
        headers = {"Content-Type": "application/octet-stream"}
        if row["now"] is not None:
            headers["X-Aprv-Now-Ms"] = str(row["now"])
        self.conn.request("POST", path, body=body, headers=headers)
        r = self.conn.getresponse()
        data = r.read()
        if r.status == 200:
            return {"out": data.decode("utf-8")}
        if r.status == 413:
            return {"over_cap": 413}
        return {"trap": f"HTTP {r.status} {data.decode(errors='replace')}"}

    def close(self):
        if self.refusal is None:
            self.p.terminate()
            self.p.wait()


def cli_call(aprv, row, body, roots_file):
    cmd = [aprv, row["fn"]] if row["fn"] in PATHS else [aprv, row["fn"], ENVS[row["env"]]]
    if row["now"] is not None:
        cmd += ["--now-ms", str(row["now"])]
    if roots_file:
        cmd += ["--roots", roots_file]
    p = subprocess.run(cmd, input=body, capture_output=True, timeout=120)
    if p.returncode == 0:
        return {"out": p.stdout.decode("utf-8")}
    if p.returncode == 3:
        return {"over_cap": 3}
    err = p.stderr.decode(errors="replace").strip()
    if p.returncode == 2 and "refused the roots configuration" in err:
        return {"out": err.split("configuration: ", 1)[1]}
    return {"trap": f"exit {p.returncode}: {err}"}


def classify(call, ref, got, body_len):
    a = ref.get("out", ref.get("trap", ref.get("map")))
    b = got.get("out", got.get("trap", got.get("map")))
    if isinstance(a, str) and isinstance(b, str) and call.get("fn") == "verify-receipt-endpoint" and call.get("now") is None:
        a, b = MASK.sub(r'"\1":"*"', a), MASK.sub(r'"\1":"*"', b)
    if a == b:
        return "identical"
    if "over_cap" in got and body_len > MAX_BODY:
        return "over-cap"
    if isinstance(a, str) and "INVALID_TEST_ENVELOPE" in a and isinstance(b, str) and '"ok":false' in b:
        return "init-refusal"
    if call.get("fn") == "verify-receipt-endpoint" and call.get("now") is not None:
        return "clock-moves-chain"
    return "DIFFERENT"


def classify_exact(ref, got, body_len):
    a = ref.get("out", ref.get("trap", ref.get("map")))
    b = got.get("out", got.get("trap", got.get("map")))
    if a == b and ("trap" in ref) == ("trap" in got):
        return "identical"
    refused = isinstance(a, str) and ('"reason":"TOO_LARGE"' in a or a == '{"status":21002}')
    if "over_cap" in got and body_len > MAX_BODY and refused:
        return "over-cap"
    return "DIFFERENT"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--aprv", required=True)
    ap.add_argument("--calls", required=True)
    ap.add_argument("--node", help="ABI v1 Node rows (node-<corpus>.jsonl): round 13's comparison")
    ap.add_argument("--reference", help="the module's rows (module-<corpus>.jsonl): exact comparison")
    ap.add_argument("--suffix", default="", help="calls file suffix, e.g. .pinned")
    ap.add_argument("--mode", choices=["http", "cli"], default="http")
    ap.add_argument("--lifecycle", choices=["fresh", "pool"], default="fresh")
    ap.add_argument("--out", help="write the host's rows here as <mode>-<corpus>.jsonl")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    if bool(a.node) == bool(a.reference):
        ap.error("give exactly one of --node and --reference")
    tmp = tempfile.mkdtemp(prefix="aprv-corpus-")
    roots_files, servers = {}, {}
    total = collections.Counter()
    examples = []
    label = f"{a.mode}" + (f"-{a.lifecycle}" if a.mode == "http" else "")
    try:
        for c in CORPORA:
            calls = [json.loads(l) for l in open(os.path.join(a.calls, f"{c}{a.suffix}.jsonl"), encoding="utf-8")]
            refpath = os.path.join(a.node, f"node-{c}.jsonl") if a.node else os.path.join(a.reference, f"module-{c}.jsonl")
            ref = {r["id"]: r for r in map(json.loads, open(refpath, encoding="utf-8"))}
            per = collections.Counter()
            rows_out = open(os.path.join(a.out, f"{label}-{c}.jsonl"), "w") if a.out else None
            for row in calls:
                if "map" in row:
                    got, body_len = {"map": row["map"]}, 0
                else:
                    body = base64.b64decode(row["b64"])
                    body_len = len(body)
                    rf = None
                    if row["config"]:
                        if row["config"] not in roots_files:
                            path = os.path.join(tmp, f"roots-{len(roots_files)}.txt")
                            open(path, "w").write(roots_file_text(row["config"]))
                            roots_files[row["config"]] = path
                        rf = roots_files[row["config"]]
                    if a.mode == "http":
                        if rf not in servers:
                            servers[rf] = Server(a.aprv, rf, a.lifecycle)
                        s = servers[rf]
                        if s.refusal is not None:
                            m = s.refusal.split("configuration: ", 1)
                            got = {"out": m[1]} if len(m) == 2 else {"trap": s.refusal}
                        else:
                            got = s.call(row, body)
                    else:
                        got = cli_call(a.aprv, row, body, rf)
                got["id"] = row["id"]
                if rows_out:
                    rows_out.write(json.dumps(got) + "\n")
                if a.node:
                    cat = classify(row, ref[row["id"]], got, body_len)
                else:
                    cat = classify_exact(ref[row["id"]], got, body_len)
                per[cat] += 1
                if cat != "identical" and (a.list or len(examples) < 12):
                    examples.append((c, cat, row["id"], str(got)[:160]))
            total.update(per)
            print(f"{label} {c}: " + ", ".join(f"{k} {v}" for k, v in sorted(per.items())), flush=True)
    finally:
        for s in servers.values():
            s.close()
    ok = total["DIFFERENT"] == 0 and sum(total.values()) == 6179
    if a.node:
        ok = ok and total["clock-moves-chain"] == 2 and total["init-refusal"] == 1
    print(f"{label} all: " + ", ".join(f"{k} {v}" for k, v in sorted(total.items()))
          + f" (rows {sum(total.values())}, server processes {len(servers)}) -> {'AS EXPECTED' if ok else 'NOT AS EXPECTED'}")
    for c, cat, i, g in examples:
        print(f"  [{cat}] {c} {i}: {g}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
