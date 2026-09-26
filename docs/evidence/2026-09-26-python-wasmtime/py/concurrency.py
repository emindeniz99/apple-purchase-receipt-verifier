#!/usr/bin/env python3
"""Spike only (2026-09-26). Warm speed, scaling and isolation for the facade.

    python concurrency.py calls-cases.jsonl bench            # one thread, 200 warm-up + 1,000 timed, g5 and JWS
    python concurrency.py calls-cases.jsonl threads          # 1/2/4 threads, one Verifier each
    python concurrency.py calls-cases.jsonl processes        # 1/2/4 processes, one Verifier each
    python concurrency.py calls-cases.jsonl isolation        # independent instances; traps under concurrency

Every timed result is checked to be verified=true. wasmtime-py calls the
C API through ctypes' CDLL, which releases the GIL for the duration of a
call, so threads can run Wasm in parallel; the two host functions take the
GIL back briefly.
"""
import base64
import json
import multiprocessing as mp
import os
import sys
import threading
import time

import aprv_wasm

G5_ID = "receipt/verify-genuine-sandbox-g5-against-apple-roots"
JWS_ID = "transaction/verify-shared-sandbox"
OK = b'{"verified":true'


def load(path):
    calls = {c["id"]: c for c in map(json.loads, open(path, encoding="utf-8"))}
    return {k: (calls[k]["op"], base64.b64decode(calls[k]["input"])) for k in (G5_ID, JWS_ID)}


def bench(rows):
    v = aprv_wasm.Verifier()
    for rid, (op, data) in rows.items():
        for _ in range(200):
            assert v.call(op, data).startswith(OK)
        t = time.perf_counter()
        for _ in range(1000):
            assert v.call(op, data).startswith(OK)
        us = (time.perf_counter() - t) / 1000 * 1e6
        print(json.dumps({"id": rid, "op": op, "warm": 200, "n": 1000, "mean_us": round(us), "per_s": round(1e6 / us, 1)}))
    # The bridge's own floor: an endpoint request "{}" does almost nothing in
    # Wasm (it answers 21002), so this is mostly the seven ctypes calls, the
    # copies and one clock callback.
    for _ in range(1000):
        v.call(4, b"{}")
    t = time.perf_counter()
    for _ in range(20000):
        v.call(4, b"{}")
    us = (time.perf_counter() - t) / 20000 * 1e6
    print(json.dumps({"id": "endpoint-sandbox body {} (bridge floor)", "op": 4, "warm": 1000, "n": 20000, "mean_us": round(us)}))


def worker(op, data, warm, n, start, bad, k):
    v = aprv_wasm.Verifier()
    for _ in range(warm):
        v.call(op, data)
    start.wait()
    for _ in range(n):
        if not v.call(op, data).startswith(OK):
            bad[k] += 1


def scale(rows, kind):
    for rid, (op, data) in rows.items():
        warm, n = (300, 600) if rid == G5_ID else (150, 300)
        for t in (1, 2, 4):
            if kind == "threads":
                start = threading.Barrier(t + 1)
                bad = [0] * t
                ws = [threading.Thread(target=worker, args=(op, data, warm, n, start, bad, k)) for k in range(t)]
            else:
                ctx = mp.get_context("spawn")
                start = ctx.Barrier(t + 1)
                bad = ctx.Array("l", t)
                ws = [ctx.Process(target=worker, args=(op, data, warm, n, start, bad, k)) for k in range(t)]
            for w in ws:
                w.start()
            start.wait()
            t0 = time.perf_counter()
            for w in ws:
                w.join()
            s = time.perf_counter() - t0
            print(json.dumps({"id": rid, "op": op, kind: t, "warm_each": warm, "n_each": n, "seconds": round(s, 2),
                              "total_per_s": round(t * n / s, 1), "not_verified": sum(bad)}))


def isolation(rows):
    op, g5 = rows[G5_ID]
    a, b = aprv_wasm.Verifier(), aprv_wasm.Verifier()
    ref = a.call(op, g5)
    try:
        a.call(99, b"")
    except aprv_wasm.WasmTrapError:
        pass
    same_b = b.call(op, g5) == ref
    same_a = a.call(op, g5) == ref
    print(json.dumps({"test": "independent instances: a trap in A leaves B untouched; A restarts fresh",
                      "b_unchanged": same_b, "a_after_trap": same_a, "a_traps": a.traps, "b_traps": b.traps,
                      "pass": same_b and same_a and a.traps == 1 and b.traps == 0}))
    # Four threads, each with its own Verifier; every 7th call is a deliberate
    # trap (unknown operation). All other calls must still verify, and each
    # thread's trap count must be its own.
    errors, traps, good = [], [0] * 4, [0] * 4

    def churn(k):
        v = aprv_wasm.Verifier()
        for i in range(210):
            if i % 7 == 6:
                try:
                    v.call(99, b"")
                    errors.append("no trap")
                except aprv_wasm.WasmTrapError:
                    pass
            else:
                out = v.call(op, g5)
                if out != ref:
                    errors.append(out[:80])
                else:
                    good[k] += 1
        traps[k] = v.traps

    ts = [threading.Thread(target=churn, args=(k,)) for k in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    print(json.dumps({"test": "4 threads, one Verifier each, a trap every 7th call", "good_calls": good,
                      "traps": traps, "errors": len(errors), "pass": not errors and traps == [30] * 4 and good == [180] * 4}))


if __name__ == "__main__":
    rows = load(sys.argv[1])
    mode = sys.argv[2]
    print(f"# python {sys.version.split()[0]}, {os.cpu_count()} cores, load average {os.getloadavg()}")
    {"bench": bench, "threads": lambda r: scale(r, "threads"), "processes": lambda r: scale(r, "processes"),
     "isolation": isolation}[mode](rows)
