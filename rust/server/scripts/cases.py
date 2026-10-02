#!/usr/bin/env python3
"""Runs the 311 cases of fixtures/cases.json through aprv-server, over HTTP
and through the one-shot CLI, and evaluates each case's expectation the way
the file's comment defines it.

    cases.py --aprv PATH/TO/aprv [--mode http|cli|both] [--cases FILE] [--list]

Each case gets its roots and its clock through the server's own
configuration: `--roots FILE` (one base64 DER per line) for fixture roots,
nothing for the defaults, and `X-Aprv-Now-Ms` / `--now-ms` for clock.now.
Over HTTP one server runs per distinct root set, default lifecycle (pool).

A body over the cap never reaches the module: the server answers 413 and the
CLI exits 3. The runner maps that as a client of the server must (TOO_LARGE
for the verify operations, Apple's {"status":21002} at the endpoint) and
counts those cases separately. decodeBase64 cases test a port's decoders
directly; the server exposes none, so they are reported as not expressible.

Exit status: 0 when every expressible case passed in every mode, 1 otherwise.
Needs only the Python standard library.
"""
import argparse
import base64
import collections
import datetime
import hashlib
import http.client
import json
import os
import subprocess
import sys
import tempfile
import time

MAX_BODY = 3_145_728
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", "..", ".."))


# ---------------------------------------------------------------- fixtures

def logical_bytes(fixtures_dir, fx):
    raw = open(os.path.join(fixtures_dir, fx["path"]), "rb").read()
    codec = fx["codec"]
    if codec == "raw" or codec == "text":
        data = raw
    elif codec == "base64":
        data = base64.b64decode(b"".join(raw.split()), validate=True)
    elif codec == "utf8":
        data = raw.decode("utf-8").strip().encode("utf-8")
    else:
        raise ValueError(codec)
    if hashlib.sha256(data).hexdigest() != fx["contentSha256"]:
        raise SystemExit(f"fixture {fx['path']}: contentSha256 mismatch")
    return data


def receipt_string(fixtures, fid):
    """verifyReceipt's argument: a text fixture verbatim, DER as canonical base64."""
    fx, data = fixtures[fid]
    return data if fx["codec"] == "text" else base64.b64encode(data)


def case_input(case, fixtures):
    op, inp = case["operation"], case["input"]
    if op == "verifyReceipt":
        return receipt_string(fixtures, inp["fixture"])
    if op == "verifySignedData":
        return fixtures[inp["fixture"]][1]
    if op == "verifyReceiptEndpoint":
        if "requestBody" in inp:
            return fixtures[inp["requestBody"]][1]
        return b'{"receipt-data":"' + receipt_string(fixtures, inp["fixture"]) + b'"}'
    raise ValueError(op)


def roots_key(case, fixtures):
    tr = case["config"]["trustedRoots"]
    if tr["source"] == "defaults":
        return None
    return "\n".join(base64.b64encode(fixtures[f][1]).decode() for f in tr["fixtures"]) + "\n"


def now_ms(case):
    if "clock" not in case:
        return None
    t = datetime.datetime.strptime(case["clock"]["now"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    return int(t.timestamp()) * 1000


# ---------------------------------------------------------------- evaluation

def pointer(doc, ptr):
    """RFC 6901 plus the [key=value] token. Returns (found, value)."""
    cur = doc
    for tok in ptr.split("/")[1:]:
        tok = tok.replace("~1", "/").replace("~0", "~")
        if tok.startswith("[") and tok.endswith("]") and "=" in tok:
            k, v = tok[1:-1].split("=", 1)
            if not isinstance(cur, list):
                return False, None
            hits = [e for e in cur if isinstance(e, dict) and e.get(k) == v]
            if len(hits) != 1:
                raise AssertionError(f"{ptr}: {len(hits)} elements match [{k}={v}]")
            cur = hits[0]
        elif isinstance(cur, dict):
            if tok not in cur:
                return False, None
            cur = cur[tok]
        elif isinstance(cur, list):
            if not tok.isdigit() or int(tok) >= len(cur):
                return False, None
            cur = cur[int(tok)]
        else:
            return False, None
    return True, cur


def same(a, b):
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    return a == b


def check_fields(doc, exp):
    for ptr, want in exp.get("fields", {}).items():
        found, got = pointer(doc, ptr)
        if want is None:
            if found and got is not None:
                raise AssertionError(f"{ptr}: expected null or absent, got {json.dumps(got)[:80]}")
        elif not found or not same(got, want):
            raise AssertionError(f"{ptr}: expected {json.dumps(want)[:80]}, got {json.dumps(got)[:80] if found else 'absent'}")
    for ptr, n in exp.get("lengths", {}).items():
        found, got = pointer(doc, ptr)
        if not found or not isinstance(got, list) or len(got) != n:
            raise AssertionError(f"{ptr}: expected an array of {n}, got {json.dumps(got)[:80] if found else 'absent'}")
    if "toJson" in exp and json.loads(exp["toJson"]) != doc:
        raise AssertionError("toJson: the payload differs from the pinned value")


def outcome_of(result):
    """The 0.7 wire result: ('ok', payload) or (reason, message)."""
    if not isinstance(result, dict) or not isinstance(result.get("verified"), bool):
        raise AssertionError(f"not a verification result: {json.dumps(result)[:120]}")
    if result["verified"]:
        payload = result.get("payload")
        if isinstance(payload, str):  # verify-signed-data: the signed payload JSON, exactly
            payload = json.loads(payload)
        return "ok", payload
    return result.get("reason"), result.get("message", "")


def evaluate(case, answer):
    """answer: ('json', bytes) | ('too-large', None) | ('failure', text). Raises on a failed case."""
    exp, op = case["expected"], case["operation"]
    kind, body = answer
    if kind == "failure":
        raise AssertionError(f"no result: {body}")
    if op == "verifyReceiptEndpoint":
        doc = {"status": 21002} if kind == "too-large" else json.loads(body)
        if "oneOf" in exp:
            # Port-defined within a list: the response's /status must be
            # listed, and nothing else is pinned.
            if doc.get("status") not in exp["oneOf"]:
                raise AssertionError(f"status {doc.get('status')} not in {exp['oneOf']}")
            return
        check_fields(doc, exp)
        return
    if kind == "too-large":
        outcome, detail = "TOO_LARGE", ""
    else:
        outcome, detail = outcome_of(json.loads(body))
    if "oneOf" in exp:
        if outcome not in exp["oneOf"]:
            raise AssertionError(f"outcome {outcome} not in {exp['oneOf']}")
        return
    if exp.get("status") == "error" or ("reason" in exp):
        if outcome != exp["reason"]:
            raise AssertionError(f"expected {exp['reason']}, got {outcome}" + (f" ({str(detail)[:100]})" if outcome != "ok" else ""))
        for cp in exp.get("messageMustNotContain", []):
            if chr(cp) in (detail or ""):
                raise AssertionError(f"the message contains U+{cp:04X}")
        return
    if outcome != "ok":
        raise AssertionError(f"expected ok, got {outcome}: {str(detail)[:120]}")
    check_fields(detail, exp)


# ---------------------------------------------------------------- transports

class Server:
    def __init__(self, aprv, roots_file):
        args = [aprv, "serve", "--listen", "127.0.0.1:0"] + (["--roots", roots_file] if roots_file else [])
        self.p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
        line = self.p.stdout.readline().decode()
        if not line.startswith("APRV_LISTEN="):
            err = self.p.stderr.read().decode()
            self.p.wait()
            raise RuntimeError(f"server did not start: {err.strip()}")
        host, port = line.strip().split("=", 1)[1].rsplit(":", 1)
        self.conn = http.client.HTTPConnection(host, int(port), timeout=60)

    def call(self, path, body, now):
        headers = {"Content-Type": "application/octet-stream"}
        if now is not None:
            headers["X-Aprv-Now-Ms"] = str(now)
        self.conn.request("POST", path, body=body, headers=headers)
        r = self.conn.getresponse()
        data = r.read()
        if r.status == 200:
            return "json", data
        if r.status == 413:
            return "too-large", None
        return "failure", f"HTTP {r.status} {data[:200].decode(errors='replace')}"

    def close(self):
        self.p.terminate()
        self.p.wait()


ROUTE = {"verifyReceipt": "/v1/receipt/verify", "verifySignedData": "/v1/signed-data/verify"}
CLI = {"verifyReceipt": ["verify-receipt"], "verifySignedData": ["verify-signed-data"]}


def route(case):
    if case["operation"] == "verifyReceiptEndpoint":
        return "/v1/verify-receipt/" + case["config"]["environment"].lower()
    return ROUTE[case["operation"]]


def cli_call(aprv, case, body, now, roots_file):
    cmd = [aprv] + (CLI.get(case["operation"]) or ["verify-receipt-endpoint", case["config"]["environment"].lower()])
    if now is not None:
        cmd += ["--now-ms", str(now)]
    if roots_file:
        cmd += ["--roots", roots_file]
    p = subprocess.run(cmd, input=body, capture_output=True, timeout=120)
    if p.returncode == 0:
        return "json", p.stdout
    if p.returncode == 3:
        return "too-large", None
    return "failure", f"exit {p.returncode}: {p.stderr[:200].decode(errors='replace').strip()}"


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--aprv", required=True)
    ap.add_argument("--mode", choices=["http", "cli", "both"], default="both")
    ap.add_argument("--cases", default=os.path.join(REPO, "fixtures", "cases.json"))
    ap.add_argument("--list", action="store_true", help="print every failing case with its reason")
    a = ap.parse_args()
    doc = json.load(open(a.cases, encoding="utf-8"))
    fdir = os.path.dirname(os.path.abspath(a.cases))
    fixtures = {k: (fx, logical_bytes(fdir, fx)) for k, fx in doc["fixtures"].items()}
    cases = doc["cases"]
    tmp = tempfile.mkdtemp(prefix="aprv-cases-")
    roots_files = {}

    def roots_file(case):
        key = roots_key(case, fixtures)
        if key is None:
            return None
        if key not in roots_files:
            path = os.path.join(tmp, f"roots-{len(roots_files)}.txt")
            open(path, "w").write(key)
            roots_files[key] = path
        return roots_files[key]

    modes = ["http", "cli"] if a.mode == "both" else [a.mode]
    all_ok = True
    for mode in modes:
        results = collections.OrderedDict()
        transport_413 = []
        slow = []
        servers = {}
        try:
            for case in cases:
                cid = case["id"]
                if case["operation"] == "decodeBase64":
                    results[cid] = ("not-expressible", "decodeBase64 tests a port's decoders; the server exposes none")
                    continue
                body = case_input(case, fixtures)
                now = now_ms(case)
                rf = roots_file(case)
                if mode == "http":
                    if rf not in servers:
                        servers[rf] = Server(a.aprv, rf)
                    call = lambda: servers[rf].call(route(case), body, now)
                else:
                    call = lambda: cli_call(a.aprv, case, body, now, rf)
                if "maxMillis" in case:
                    call()  # the warm-up call the file's comment asks for
                t = time.monotonic()
                answer = call()
                ms = (time.monotonic() - t) * 1000
                if answer[0] == "too-large":
                    transport_413.append(cid)
                try:
                    evaluate(case, answer)
                    if "maxMillis" in case and ms > case["maxMillis"]:
                        raise AssertionError(f"took {ms:.0f} ms, over maxMillis {case['maxMillis']}")
                    results[cid] = ("pass", "")
                except (AssertionError, ValueError, KeyError, TypeError) as e:
                    results[cid] = ("FAIL", str(e))
                if "maxMillis" in case:
                    slow.append((cid, round(ms)))
        finally:
            for s in servers.values():
                s.close()
        counts = collections.Counter(v[0] for v in results.values())
        print(f"# {mode}: {len(cases)} cases: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
        print(f"# {mode}: answered by the transport's size cap (413 / exit 3): {len(transport_413)}: {', '.join(transport_413)}")
        print(f"# {mode}: maxMillis cases, slowest: {sorted(slow, key=lambda x: -x[1])[:3]}")
        if servers:
            print(f"# {mode}: {len(servers)} server processes (one per root set)")
        fails = [(k, v[1]) for k, v in results.items() if v[0] == "FAIL"]
        for k, why in fails if a.list else fails[:0]:
            print(f"FAIL {mode} {k}: {why}")
        if not a.list:
            print(f"# {mode}: failing ids: {' '.join(k for k, _ in fails)}")
        all_ok = all_ok and not fails
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
