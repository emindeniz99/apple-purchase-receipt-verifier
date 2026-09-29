#!/usr/bin/env python3
"""Spike only (2026-09-29, round 13). What list<u8> costs through
wasmtime-py 49.0.0: its ListType.convert_to_c lowers bytes one element at
a time in Python. Times verify-signed-data on inputs the guest rejects at
once (no '.'), so the time is the lowering, per input size.

    bytes_cost.py COMPONENT
"""
import sys
import time

from wasmtime import Engine
from wasmtime.component import Component

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from run_calls import Aprv, make_linker  # noqa: E402

engine = Engine()
component = Component.from_file(engine, sys.argv[1])
g = Aprv(engine, component, make_linker(engine))
g.call("init", b"")
print("# wasmtime-py 49.0.0: verify-signed-data on n bytes of 'A' (rejected by the guest at once), median of 5")
for n in (0, 1_000, 10_000, 100_000, 1_000_000):
    data = b"A" * n
    ts = []
    for _ in range(5):
        t = time.perf_counter()
        out = g.call("verify-signed-data", 0, data)
        ts.append((time.perf_counter() - t) * 1000)
    ts.sort()
    print(f"n={n:>9,} bytes: {ts[2]:9.2f} ms per call  ({out[:60]})")
