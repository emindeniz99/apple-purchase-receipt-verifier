#!/usr/bin/env python3
"""Spike only (2026-09-27, round 11). The early-stop probe for pywasm 2.2.3:
one fresh process, timed step by step, printing a JSON line after every
step so a killed run still leaves its numbers.

    APRV_MODULE=aprv-abi1.wasm python pywasm_probe.py G5 JWS [G5_CALLS JWS_CALLS BUDGET_S]

Steps: import; parse the module; instantiate + _initialize + version;
g5 calls #1..#G5_CALLS; then JWS calls #1..#JWS_CALLS. Each op stops early
once its calls have used BUDGET_S seconds. The caller (scripts/pywasm.sh)
applies the stop rule to the output.
"""
import json
import os
import sys
import time


def status(key):
    for line in open("/proc/self/status"):
        if line.startswith(key):
            return int(line.split()[1])
    return 0


def out(**kw):
    kw.update(rss_kb=status("VmRSS:"), hwm_kb=status("VmHWM:"))
    print(json.dumps(kw), flush=True)


t0 = time.perf_counter()
import aprv_pywasm  # noqa: E402

out(step="import", ms=round((time.perf_counter() - t0) * 1000, 1))
g5, jws = open(sys.argv[1], "rb").read(), open(sys.argv[2], "rb").read()
g5_calls, jws_calls, budget = (int(sys.argv[3]), int(sys.argv[4]), float(sys.argv[5])) if len(sys.argv) > 5 else (10, 5, 300.0)
aprv_pywasm._module()
out(step="parse", ms=aprv_pywasm.LOAD_INFO["load_ms"])
t = time.perf_counter()
v = aprv_pywasm.Verifier()
out(step="instantiate", ms=round((time.perf_counter() - t) * 1000, 1))
for name, op, data, n in (("g5", 1, g5, g5_calls), ("jws", 258, jws, jws_calls)):
    spent = 0.0
    for i in range(1, n + 1):
        t = time.perf_counter()
        r = v.call(op, data)
        ms = (time.perf_counter() - t) * 1000
        spent += ms / 1000
        rec = {"step": f"{name} #{i}", "ms": round(ms, 1), "verified": b'"verified":true' in r}
        if name == "g5" and i == 1:
            rec["first_result_mono_ns"] = time.monotonic_ns()
            rec["since_start_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        out(**rec)
        if spent > budget:
            out(step=f"{name}: stopped after {i} calls, {spent:.0f} s spent (budget {budget:.0f} s)")
            break
