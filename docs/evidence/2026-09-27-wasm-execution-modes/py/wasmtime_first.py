#!/usr/bin/env python3
"""Spike only (2026-09-27, round 9). Round 8's wasmtime-py measurement,
re-run on this machine so the Python rows compare on one CPU model: one
cold process imports round 8's selectable facade
(../../2026-09-27-python-runtime-options/py/aprv_wasm, on PYTHONPATH, with
its APRV_ENGINE / APRV_BASELINE / APRV_MODULE settings), verifies g5 twice,
and prints the keys of wamr_first.py, so py/startup.py times both the same
way (spawn to first result on CLOCK_MONOTONIC).

    PYTHONPATH=<round 8>/py APRV_ENGINE=... APRV_MODULE=... python wasmtime_first.py G5
"""
import json
import os
import sys
import time

t0 = time.perf_counter()
import aprv_wasm  # noqa: E402

t_import = time.perf_counter()
g5 = open(sys.argv[1], "rb").read()
aprv_wasm._runtime()
t_load = time.perf_counter()
v = aprv_wasm.Verifier()
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
    "engine": "python-wasmtime-py", "mode": os.environ.get("APRV_ENGINE", "cranelift") + (" " + os.path.basename(os.environ["APRV_MODULE"])),
    "import_ms": round((t_import - t0) * 1000, 3), "init_ms": 0.0, "load_ms": round((t_load - t_import) * 1000, 3),
    "instantiate_ms": round((t_inst - t_load) * 1000, 3), "first_call_ms": round((t_first - t_inst) * 1000, 3),
    "second_call_ms": round((t_second - t_first) * 1000, 3),
    "verified": b'"verified":true' in r1 and b'"verified":true' in r2, "first_result_mono_ns": first_ns,
    "rss_kb": status("VmRSS:"), "hwm_kb": status("VmHWM:"),
}))
sys.stdout.flush()
os._exit(0)  # as the other first-result scripts: do not time teardown
