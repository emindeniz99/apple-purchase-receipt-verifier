#!/usr/bin/env python3
"""Start-up and per-call cost of a built `aprv`, for the record (not a gate).

  start     `aprv serve` per run: wall time from spawn to the address line,
            and to the first verified answer over HTTP
  cli       one `aprv verify-receipt` / `verify-signed-data` process per call:
            wall time from spawn to exit, verdict checked
  http      N calls over one keep-alive connection to one server (fresh
            lifecycle, the default): wall time per call

The inputs are fixtures/cases.json's g5 sandbox receipt (the built-in Apple
roots) and its shared StoreKit 2 transaction JWS (its own test root).

    startup.py --aprv PATH/TO/aprv [--runs 7] [--calls 200]

Prints the medians as one JSON line. Standard library only.
"""
import argparse
import base64
import http.client
import json
import os
import statistics
import subprocess
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.normpath(os.path.join(HERE, "..", "..", "..", "fixtures"))


def fixture(doc, fid):
    fx = doc["fixtures"][fid]
    raw = open(os.path.join(FIXTURES, fx["path"]), "rb").read()
    if fx["codec"] == "base64":
        return base64.b64decode(b"".join(raw.split()))
    if fx["codec"] == "utf8":
        return raw.strip()
    return raw


def serve(aprv, roots):
    args = [aprv, "serve", "--listen", "127.0.0.1:0"] + (["--roots", roots] if roots else [])
    t = time.monotonic()
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    host, port = p.stdout.readline().decode().strip().split("=", 1)[1].rsplit(":", 1)
    return p, http.client.HTTPConnection(host, int(port)), (time.monotonic() - t) * 1000


def post(conn, path, body):
    conn.request("POST", path, body=body)
    out = conn.getresponse().read()
    assert b'"verified":true' in out, out[:200]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--aprv", required=True)
    ap.add_argument("--runs", type=int, default=7)
    ap.add_argument("--calls", type=int, default=200)
    a = ap.parse_args()
    doc = json.load(open(os.path.join(FIXTURES, "cases.json"), encoding="utf-8"))
    g5 = base64.b64encode(fixture(doc, "public-receipt-sandbox-g5"))
    jws = fixture(doc, "transaction")
    roots = os.path.join(tempfile.mkdtemp(prefix="aprv-timing-"), "jws-roots.txt")
    open(roots, "w").write(base64.b64encode(fixture(doc, "jws-root")).decode() + "\n")
    med = lambda xs: round(statistics.median(xs), 2)

    ready, first = [], []
    for _ in range(a.runs):
        p, c, ms = serve(a.aprv, None)
        ready.append(ms)
        t = time.monotonic()
        post(c, "/v1/receipt/verify", g5)
        first.append(ms + (time.monotonic() - t) * 1000)
        p.terminate()
        p.wait()

    cli = {}
    for name, cmd, body in (("g5", ["verify-receipt"], g5), ("jws", ["verify-signed-data", "--roots", roots], jws)):
        xs = []
        for _ in range(a.runs):
            t = time.monotonic()
            r = subprocess.run([a.aprv] + cmd, input=body, capture_output=True)
            xs.append((time.monotonic() - t) * 1000)
            assert r.returncode == 0 and b'"verified":true' in r.stdout, r.stdout[:200] + r.stderr[:200]
        cli[name] = med(xs)

    keep = {}
    for name, path, body, rf in (("g5", "/v1/receipt/verify", g5, None), ("jws", "/v1/signed-data/verify", jws, roots)):
        p, c, _ = serve(a.aprv, rf)
        for _ in range(10):
            post(c, path, body)
        xs = []
        for _ in range(a.calls):
            t = time.monotonic()
            post(c, path, body)
            xs.append((time.monotonic() - t) * 1000)
        keep[name] = med(xs)
        p.terminate()
        p.wait()

    print(json.dumps({
        "median_server_ready_ms": med(ready), "median_server_first_result_ms": med(first),
        "median_cli_process_ms": cli, "median_http_keepalive_call_ms": keep,
        "runs": a.runs, "calls": a.calls, "loadavg": open("/proc/loadavg").read().split()[:3],
    }))


if __name__ == "__main__":
    main()
