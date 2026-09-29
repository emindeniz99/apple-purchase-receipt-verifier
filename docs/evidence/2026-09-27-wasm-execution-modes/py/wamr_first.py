#!/usr/bin/env python3
"""Spike only (2026-09-27, round 9). One cold Python process to its first
verified g5 through the ctypes facade (py/aprv_wamr), printing the same keys
as the native hosts' `first` mode, so py/startup.py times it the same way
(its CLOCK_MONOTONIC stamp is time.monotonic_ns(), the same clock).

    APRV_LIBIWASM=... APRV_MODULE=... python wamr_first.py G5
"""
import json
import os
import sys
import time

t0 = time.perf_counter()
import aprv_wamr  # noqa: E402

t_import = time.perf_counter()
g5 = open(sys.argv[1], "rb").read()
aprv_wamr._runtime()
t_load = time.perf_counter()
v = aprv_wamr.Verifier()
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
    "engine": "python-ctypes-wamr", "mode": os.path.basename(os.path.dirname(os.environ["APRV_LIBIWASM"])),
    "running_mode": v._inst.running_mode,
    "import_ms": round((t_import - t0) * 1000, 3), "init_ms": aprv_wamr.LOAD_INFO["init_ms"], "load_ms": aprv_wamr.LOAD_INFO["load_ms"],
    "instantiate_ms": round((t_inst - t_load) * 1000, 3), "first_call_ms": round((t_first - t_inst) * 1000, 3),
    "second_call_ms": round((t_second - t_first) * 1000, 3),
    "verified": b'"verified":true' in r1 and b'"verified":true' in r2, "first_result_mono_ns": first_ns,
    "rss_kb": status("VmRSS:"), "hwm_kb": status("VmHWM:"),
}))
sys.stdout.flush()
os._exit(0)  # as the native hosts: do not time the runtime's teardown
