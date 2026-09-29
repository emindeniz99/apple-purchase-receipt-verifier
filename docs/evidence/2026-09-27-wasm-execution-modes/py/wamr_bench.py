#!/usr/bin/env python3
"""Spike only (2026-09-27, round 9). The native hosts' `bench` mode through
the ctypes facade (py/aprv_wamr): calls #1, #2, #5, #10 and #100 timed one
by one, then a steady-state loop of at least 20 calls and 2 seconds, for g5
and then the JWS; the same JSON lines, so py/procs.py runs it unchanged.

    APRV_LIBIWASM=... APRV_MODULE=... python wamr_bench.py G5 JWS
"""
import json
import os
import sys
import time

import aprv_wamr


def status(key):
    for line in open("/proc/self/status"):
        if line.startswith(key):
            return int(line.split()[1])
    return 0


g5, jws = open(sys.argv[1], "rb").read(), open(sys.argv[2], "rb").read()
t0 = time.perf_counter()
aprv_wamr._runtime()
v = aprv_wamr.Verifier()
print(json.dumps({"phase": "setup", "engine": "python-ctypes-wamr", "mode": os.path.basename(os.path.dirname(os.environ["APRV_LIBIWASM"])),
                  "running_mode": v._inst.running_mode, **aprv_wamr.LOAD_INFO,
                  "instantiate_ms": round((time.perf_counter() - t0) * 1000 - aprv_wamr.LOAD_INFO["init_ms"] - aprv_wamr.LOAD_INFO["load_ms"], 3),
                  "rss_kb": status("VmRSS:")}), flush=True)
for name, op, data in (("g5", 1, g5), ("jws", 258, jws)):
    marks, bad = {}, 0
    for n in range(1, 101):
        t = time.perf_counter()
        out = v.call(op, data)
        us = int((time.perf_counter() - t) * 1e6)
        bad += b'"verified":true' not in out
        if n in (1, 2, 5, 10, 100):
            marks[str(n)] = us
    t, calls = time.perf_counter(), 0
    while calls < 20 or time.perf_counter() - t < 2.0:
        bad += b'"verified":true' not in v.call(op, data)
        calls += 1
    secs = time.perf_counter() - t
    print(json.dumps({"op": name, "calls_us": marks, "steady_calls": calls, "steady_s": round(secs, 3), "per_s": round(calls / secs, 1),
                      "mean_us": round(secs * 1e6 / calls), "not_verified": bad}), flush=True)
print(json.dumps({"phase": "end", "rss_kb": status("VmRSS:"), "hwm_kb": status("VmHWM:")}), flush=True)
os._exit(0)
