#!/usr/bin/env python3
"""Drives one `aprv serve --managed` session the way a Java 8 or PHP parent
does, and checks the contract of README.md ("Managed mode"):

  1. the child reads a 256-bit token as its first stdin line and the roots
     as its second, and reports its port as one stdout line;
  2. it listens on 127.0.0.1 only, on the port it reported;
  3. /v1/ routes refuse a request without the token (401 problem) and answer
     with it; the verdict is the module's JSON;
  4. closing stdin makes it exit, promptly, with status 0;
  5. a parent that is killed leaves no orphan: the child sees EOF and exits.

    managed-smoke.py --aprv PATH/TO/aprv [--receipt FILE.b64]

Needs only the Python standard library. Exit status 0 when every check passed.
"""
import argparse
import http.client
import json
import os
import secrets
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", "..", ".."))
failed = 0


def check(name, ok, detail=""):
    global failed
    failed += not ok
    print(f"{'PASS' if ok else 'FAIL'} {name}{': ' + detail if detail else ''}", flush=True)


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A zombie is dead for our purpose.
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().split(")")[-1].split()[0] != "Z"
    except OSError:
        return False


def start(aprv, token, roots_line="{}"):
    p = subprocess.Popen([aprv, "serve", "--managed"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.stdin.write(token + b"\n" + roots_line.encode() + b"\n")
    p.stdin.flush()
    t = time.monotonic()
    line = p.stdout.readline().decode().strip()
    return p, line, (time.monotonic() - t) * 1000


def post(port, path, body, headers):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    c.request("POST", path, body=body, headers=headers)
    r = c.getresponse()
    return r.status, r.getheader("Content-Type"), r.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--aprv", required=True)
    ap.add_argument("--receipt", default=os.path.join(REPO, "fixtures", "public-receipts", "receipt-sandbox-g5.b64"))
    a = ap.parse_args()
    receipt = b"".join(open(a.receipt, "rb").read().split())
    token = secrets.token_hex(32).encode()  # 256 bits

    # 1-4: a session.
    p, line, ms = start(a.aprv, token)
    check("the child reports its address on stdout", line.startswith("APRV_LISTEN=127.0.0.1:"), f"{line!r} after {ms:.0f} ms")
    port = int(line.rsplit(":", 1)[1])
    check("it chose a port (127.0.0.1:0)", port > 0, str(port))
    s, ct, body = post(port, "/v1/receipt/verify", receipt, {})
    check("no token: 401 problem", s == 401 and ct == "application/problem+json" and json.loads(body)["code"] == "UNAUTHORIZED", f"{s} {body[:80]!r}")
    s, ct, body = post(port, "/v1/receipt/verify", receipt, {"X-Aprv-Token": token.decode()})
    check("with the token: 200 and a verdict", s == 200 and b'"verified":true' in body, f"{s} {body[:60]!r}")
    s, _, body = post(port, "/v1/receipt/verify", receipt, {"X-Aprv-Token": token.decode()[:-1] + "x"})
    check("a wrong token: 401", s == 401, str(s))
    t = time.monotonic()
    p.stdin.close()
    try:
        code = p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()
        code = None
    check("stdin EOF: the child exits 0", code == 0, f"exit {code} after {(time.monotonic() - t) * 1000:.0f} ms")

    # The handshake is checked: a short token and bad roots are refused.
    p, line, _ = start(a.aprv, b"short")
    check("a token under 32 bytes is refused", line == "" and p.wait(timeout=10) == 2, p.stderr.read().decode().strip())
    p, line, _ = start(a.aprv, token, '{"roots":[]}')
    check("an empty root list is refused", line == "" and p.wait(timeout=10) == 2, p.stderr.read().decode().strip())

    # 5: the parent dies with kill -9; the child must not outlive it.
    parent = subprocess.Popen(
        [sys.executable, "-c",
         "import subprocess,sys,time\n"
         f"p=subprocess.Popen([{a.aprv!r},'serve','--managed'],stdin=subprocess.PIPE,stdout=subprocess.PIPE)\n"
         f"p.stdin.write({token!r}+b'\\n{{}}\\n'); p.stdin.flush()\n"
         "print(p.pid, p.stdout.readline().decode().strip(), flush=True)\n"
         "time.sleep(600)\n"],
        stdout=subprocess.PIPE)
    child_pid, addr = parent.stdout.readline().decode().split()
    child_pid = int(child_pid)
    check("the grandchild server is up", alive(child_pid) and addr.startswith("APRV_LISTEN="), addr)
    os.kill(parent.pid, signal.SIGKILL)
    parent.wait()
    t = time.monotonic()
    while alive(child_pid) and time.monotonic() - t < 10:
        time.sleep(0.02)
    check("kill -9 of the parent leaves no orphan", not alive(child_pid), f"gone after {(time.monotonic() - t) * 1000:.0f} ms")

    print(f"summary: {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
