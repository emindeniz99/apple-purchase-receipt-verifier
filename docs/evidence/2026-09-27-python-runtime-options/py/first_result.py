#!/usr/bin/env python3
"""Spike only (2026-09-27). One cold process to its first result: import the
facade, load the module (per APRV_* settings), create a Verifier, verify
g5, verify it again. Prints the breakdown in ms. startup.py runs it.

    python first_result.py g5.b64
"""
import time

t0 = time.perf_counter()
import base64  # noqa: E402
import json  # noqa: E402
import sys  # noqa: E402

import aprv_wasm  # noqa: E402

t1 = time.perf_counter()
aprv_wasm._runtime()
t2 = time.perf_counter()
v = aprv_wasm.Verifier()
t3 = time.perf_counter()
g5 = base64.b64decode(open(sys.argv[1]).read())
t4 = time.perf_counter()
first = v.call(1, g5)
t5 = time.perf_counter()
v.call(1, g5)
t6 = time.perf_counter()
ms = lambda a, b: round((b - a) * 1000, 1)  # noqa: E731
print(json.dumps({"import_ms": ms(t0, t1), "load_ms": ms(t1, t2), "instance_ms": ms(t2, t3), "first_call_ms": ms(t4, t5),
                  "second_call_ms": ms(t5, t6), "verified": first.startswith(b'{"verified":true'), **aprv_wasm.LOAD_INFO}))
