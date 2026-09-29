#!/usr/bin/env python3
"""Spike only. Runs the ABI v1 calls files (the other round's
$SCRATCH/abi/calls/<corpus>.jsonl) through a running aprv server over HTTP
and compares each answer byte for byte with the Node reference row
($SCRATCH/abi/run/node-<corpus>.jsonl, same module run in Node).

    corpus_http.py HOST:PORT CALLS_DIR NODE_DIR [corpus ...]

Ops 1-4 go to the public routes; the test variants 257-260 (test trust
anchors, pinned clock) go to the spike route /spike/call/{op}.
"""
import base64
import collections
import http.client
import json
import re
import struct
import sys

ROUTES = {1: "/v1/receipt/verify", 2: "/v1/signed-data/verify",
          3: "/v1/verify-receipt/production", 4: "/v1/verify-receipt/sandbox"}
MAX = 3_145_728
# As the ABI round's abi_compare.py: request_date* is the wall clock on an
# endpoint answer whose clock is not pinned, so it is masked there only.
MASK = re.compile(rb'"(request_date(?:_ms|_pst)?)":"[^"]*"')
I64_MIN = -(2 ** 63)


def clock_pinned(op, body):
    """True when a spike envelope (op > 256) pins the clock."""
    if op < 256:
        return False
    n = struct.unpack_from("<I", body, 6)[0]
    i = 10
    for _ in range(n):
        i += 4 + struct.unpack_from("<I", body, i)[0]
    return struct.unpack_from("<q", body, i)[0] != I64_MIN


def post(conn, path, body):
    """Returns (status, bytes) or (None, error) when the server closed the
    connection while the body was still being sent (hyper answers 413 early)."""
    try:
        conn.request("POST", path, body=body, headers={"Content-Type": "application/octet-stream"})
        resp = conn.getresponse()
        return resp.status, resp.read()
    except (BrokenPipeError, ConnectionResetError) as e:
        return None, repr(e)


def main():
    host, port = sys.argv[1].rsplit(":", 1)
    calls_dir, node_dir = sys.argv[2], sys.argv[3]
    corpora = sys.argv[4:] or ["cases", "hostile", "algorithms", "substrate", "fuzz"]
    conn = http.client.HTTPConnection(host, int(port), timeout=60)
    total = collections.Counter()
    for c in corpora:
        node = {}
        for line in open(f"{node_dir}/node-{c}.jsonl", encoding="utf-8"):
            if line.strip():
                r = json.loads(line)
                node[r["id"]] = r
        tally = collections.Counter()
        for line in open(f"{calls_dir}/{c}.jsonl", encoding="utf-8"):
            if not line.strip():
                continue
            call = json.loads(line)
            ref = node[call["id"]]
            if "op" not in call:
                tally["no-call (not expressible in ABI v1, as in Node)"] += 1
                continue
            op = call["op"]
            kind = "public" if op in ROUTES else "spike"
            path = ROUTES.get(op, f"/spike/call/{op}")
            body = base64.b64decode(call["input"])
            status, got = post(conn, path, body)
            if status is None and len(body) > MAX:
                status = 413  # refused while the oversized body was in flight
            if status is None:
                tally[f"{kind}: connection error {got}"] += 1
                conn.close()
                conn = http.client.HTTPConnection(host, int(port), timeout=60)
                continue
            if status == 413:
                # The server refuses bodies over 3 MiB before the module sees them.
                verdict = "verified" if '"verified":true' in ref.get("out", "") else "a refusal"
                tally[f"{kind}: HTTP 413 (body over {MAX} bytes; Node answered {verdict})"] += 1
                conn.close()
                conn = http.client.HTTPConnection(host, int(port), timeout=60)
                continue
            if status != 200:
                tally[f"{kind}: HTTP {status} {got[:80]!r}; node {'trap' if 'trap' in ref else 'value'}"] += 1
                continue
            want = ref.get("out", "").encode("utf-8")
            if op in (3, 4, 259, 260) and not clock_pinned(op, body):
                got, want = MASK.sub(rb'"\1":"*"', got), MASK.sub(rb'"\1":"*"', want)
            if "out" in ref and got == want:
                tally[f"{kind}: identical"] += 1
            else:
                tally[f"{kind}: DIFFERENT"] += 1
                print(f"DIFF {c} {call['id']}: server {got[:120]!r} node {str(ref)[:120]}", file=sys.stderr)
        print(f"{c}: rows {sum(tally.values())}: " + ", ".join(f"{k} {v}" for k, v in sorted(tally.items())))
        total.update(tally)
    print(f"all: rows {sum(total.values())}: " + ", ".join(f"{k} {v}" for k, v in sorted(total.items())))


if __name__ == "__main__":
    main()
