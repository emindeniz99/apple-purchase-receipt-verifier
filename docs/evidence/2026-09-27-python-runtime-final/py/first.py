#!/usr/bin/env python3
"""Spike only (2026-09-27, round 11). Round 9's wamr_first.py for any facade
module (APRV_FACADE=aprv_wasmi_rs | aprv_wasmi_capi | ...): one cold Python
process to its first verified g5, with the same JSON keys, so round 9's
startup.py times it the same way.

    APRV_FACADE=... APRV_MODULE=... python first.py G5
"""
import importlib
import json
import os
import sys
import time

t0 = time.perf_counter()
m = importlib.import_module(os.environ["APRV_FACADE"])
t_import = time.perf_counter()
g5 = open(sys.argv[1], "rb").read()
m._runtime()
t_load = time.perf_counter()
v = m.Verifier()
t_inst = time.perf_counter()
r1 = v.call(1, g5)
t_first = time.perf_counter()
first_ns = time.monotonic_ns()
r2 = v.call(1, g5)
t_second = time.perf_counter()


def status(key):
    for line in open("/proc/self/status"):
        if line.startswith(key):
            return int(line.split()[1])
    return 0


print(json.dumps({
    "engine": os.environ["APRV_FACADE"], "mode": m.InProcHost().label(),
    "import_ms": round((t_import - t0) * 1000, 3), "init_ms": m.LOAD_INFO["init_ms"], "load_ms": m.LOAD_INFO["load_ms"],
    "instantiate_ms": round((t_inst - t_load) * 1000, 3), "first_call_ms": round((t_first - t_inst) * 1000, 3),
    "second_call_ms": round((t_second - t_first) * 1000, 3),
    "verified": b'"verified":true' in r1 and b'"verified":true' in r2, "first_result_mono_ns": first_ns,
    "rss_kb": status("VmRSS:"), "hwm_kb": status("VmHWM:"),
}))
sys.stdout.flush()
os._exit(0)
