#!/usr/bin/env python3
"""Spike only. Server start-up, first verification and memory, per binary:
spawn `BIN serve --listen 127.0.0.1:0`, time until the APRV_LISTEN line,
read VmRSS (idle), POST the g5 receipt once (first verification), read
VmRSS again, POST 20 more, read VmRSS and VmHWM, stop. Median of RUNS.

    startup.py BIN G5_FILE [RUNS] [extra env NAME=VALUE ...]
"""
import http.client
import os
import statistics
import subprocess
import sys
import time


def status(pid, key):
    for line in open(f"/proc/{pid}/status"):
        if line.startswith(key):
            return int(line.split()[1])
    return -1


def main():
    binary, g5 = sys.argv[1], open(sys.argv[2], "rb").read()
    runs = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    env = dict(os.environ)
    for kv in sys.argv[4:]:
        k, v = kv.split("=", 1)
        env[k] = v
    rows = []
    for _ in range(runs):
        t0 = time.perf_counter()
        p = subprocess.Popen([binary, "serve", "--listen", "127.0.0.1:0", "--lifecycle", "fresh"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        line = p.stdout.readline().decode()
        t_ready = time.perf_counter() - t0
        assert line.startswith("APRV_LISTEN="), (line, p.stderr.read())
        host, port = line.strip().split("=", 1)[1].rsplit(":", 1)
        idle = status(p.pid, "VmRSS:")
        c = http.client.HTTPConnection(host, int(port))
        t1 = time.perf_counter()
        c.request("POST", "/v1/receipt/verify", body=g5)
        r = c.getresponse().read()
        first = time.perf_counter() - t1
        assert b'"verified":true' in r, r[:200]
        after1 = status(p.pid, "VmRSS:")
        t2 = time.perf_counter()
        for _ in range(20):
            c.request("POST", "/v1/receipt/verify", body=g5)
            c.getresponse().read()
        warm = (time.perf_counter() - t2) / 20
        after = status(p.pid, "VmRSS:")
        hwm = status(p.pid, "VmHWM:")
        p.terminate()
        p.wait()
        rows.append((t_ready * 1e3, first * 1e3, warm * 1e3, idle, after1, after, hwm))
    med = [statistics.median(col) for col in zip(*rows)]
    print(f"{os.path.basename(binary)}: runs {runs}; start to listening {med[0]:.1f} ms; first verification "
          f"{med[1]:.1f} ms (then {med[2]:.2f} ms warm); RSS idle {med[3]/1024:.1f} MiB, after 1 call "
          f"{med[4]/1024:.1f} MiB, after 21 calls {med[5]/1024:.1f} MiB, peak {med[6]/1024:.1f} MiB")


if __name__ == "__main__":
    main()
