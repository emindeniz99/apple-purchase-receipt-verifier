#!/usr/bin/env python3
"""Start-up of a built `aprv`, for the record (not a gate):

  cli     one `aprv verify-receipt` process per run on the g5 sandbox
          receipt: wall time from spawn to exit, verdict checked
  server  `aprv serve` per run: wall time from spawn to the address line,
          and to the first verified answer over HTTP

    startup.py --aprv PATH/TO/aprv [--runs 7] [--receipt FILE.b64]

Prints each run and the medians as JSON lines. Standard library only.
"""
import argparse
import http.client
import json
import os
import statistics
import subprocess
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", "..", ".."))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--aprv", required=True)
    ap.add_argument("--runs", type=int, default=7)
    ap.add_argument("--receipt", default=os.path.join(REPO, "fixtures", "public-receipts", "receipt-sandbox-g5.b64"))
    a = ap.parse_args()
    receipt = b"".join(open(a.receipt, "rb").read().split())
    cli, ready, first = [], [], []
    for _ in range(a.runs):
        t = time.monotonic()
        p = subprocess.run([a.aprv, "verify-receipt"], input=receipt, capture_output=True)
        cli.append((time.monotonic() - t) * 1000)
        assert p.returncode == 0 and b'"verified":true' in p.stdout, p.stderr

        t = time.monotonic()
        s = subprocess.Popen([a.aprv, "serve", "--listen", "127.0.0.1:0"], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        line = s.stdout.readline().decode().strip()
        ready.append((time.monotonic() - t) * 1000)
        host, port = line.split("=", 1)[1].rsplit(":", 1)
        c = http.client.HTTPConnection(host, int(port))
        c.request("POST", "/v1/receipt/verify", body=receipt)
        body = c.getresponse().read()
        first.append((time.monotonic() - t) * 1000)
        assert b'"verified":true' in body, body[:200]
        s.terminate()
        s.wait()
    r = lambda xs: [round(x, 1) for x in xs]
    print(json.dumps({"cli_process_ms": r(cli), "server_ready_ms": r(ready), "server_first_result_ms": r(first)}))
    print(json.dumps({"median_cli_process_ms": round(statistics.median(cli), 1),
                      "median_server_ready_ms": round(statistics.median(ready), 1),
                      "median_server_first_result_ms": round(statistics.median(first), 1),
                      "runs": a.runs, "loadavg": open("/proc/loadavg").read().split()[:3]}))


if __name__ == "__main__":
    main()
