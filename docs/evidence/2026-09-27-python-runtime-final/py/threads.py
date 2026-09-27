#!/usr/bin/env python3
"""Spike only (2026-09-27, round 11). Thread behaviour of a facade in one
Python process: N threads, each with its own Verifier (own store and
instance, one shared engine and module), run g5 then the JWS for SECONDS
each; prints aggregate calls/s per N. ctypes releases the GIL around every
foreign call, so the question is how much of each call still needs it.

    APRV_FACADE=... APRV_MODULE=... threads.py G5 JWS [SECONDS] [N...]
"""
import importlib
import json
import os
import sys
import threading
import time

m = importlib.import_module(os.environ["APRV_FACADE"])
g5, jws = open(sys.argv[1], "rb").read(), open(sys.argv[2], "rb").read()
secs = float(sys.argv[3]) if len(sys.argv) > 3 else 5.0
ns = [int(x) for x in sys.argv[4:]] or [1, 2, 4]
m._runtime()
res = {"facade": os.environ["APRV_FACADE"], "label": m.InProcHost().label(), "seconds": secs}
for name, op, data in (("g5", 1, g5), ("jws", 258, jws)):
    for n in ns:
        vs = [m.Verifier() for _ in range(n)]
        for v in vs:  # warm each instance (lazy translation happens per engine, once)
            v.call(op, data)
        counts, bad = [0] * n, [0] * n
        start = threading.Barrier(n + 1)

        def work(k):
            start.wait()
            end = time.perf_counter() + secs
            while time.perf_counter() < end:
                if b'"verified":true' not in vs[k].call(op, data):
                    bad[k] += 1
                counts[k] += 1

        ts = [threading.Thread(target=work, args=(k,)) for k in range(n)]
        for t in ts:
            t.start()
        t0 = time.perf_counter()
        start.wait()
        for t in ts:
            t.join()
        wall = time.perf_counter() - t0
        res[f"{name}_threads_{n}"] = {"per_s": round(sum(counts) / wall, 1), "each": counts, "not_verified": sum(bad)}
        print(json.dumps({"op": name, "threads": n, "per_s": round(sum(counts) / wall, 1), "each": counts, "not_verified": sum(bad)}), flush=True)
print(json.dumps(res), flush=True)
os._exit(0)
