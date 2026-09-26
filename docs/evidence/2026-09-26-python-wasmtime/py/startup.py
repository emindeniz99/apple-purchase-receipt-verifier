#!/usr/bin/env python3
"""Spike only (2026-09-26). Start-up in a fresh process: import, the first
Verifier (Engine + Cranelift compile of the module + Linker + instantiate +
_initialize), a second Verifier (instantiate only), the first call and the
second call. Milliseconds. Then the size of the module precompiled with
Module.serialize and the time Module.deserialize takes to load it.

    python startup.py calls-cases.jsonl
"""
import base64
import json
import sys
import time

t0 = time.perf_counter()
import aprv_wasm  # noqa: E402
import wasmtime  # noqa: E402

t1 = time.perf_counter()
v = aprv_wasm.Verifier()
t2 = time.perf_counter()
aprv_wasm.Verifier()
t3 = time.perf_counter()
calls = {c["id"]: c for c in map(json.loads, open(sys.argv[1], encoding="utf-8"))}
g5 = base64.b64decode(calls["receipt/verify-genuine-sandbox-g5-against-apple-roots"]["input"])
t4 = time.perf_counter()
assert v.call(1, g5).startswith(b'{"verified":true')
t5 = time.perf_counter()
assert v.call(1, g5).startswith(b'{"verified":true')
t6 = time.perf_counter()
# The alternative to compiling at start-up: a module precompiled by the same
# wasmtime version for the same CPU, loaded with Module.deserialize.
engine, module, _ = aprv_wasm._runtime()
blob = module.serialize()
t7 = time.perf_counter()
wasmtime.Module.deserialize(engine, blob)
t8 = time.perf_counter()
ms = lambda a, b: round((b - a) * 1000, 1)  # noqa: E731
print(json.dumps({"import_ms": ms(t0, t1), "first_verifier_ms": ms(t1, t2), "second_verifier_ms": ms(t2, t3),
                  "first_call_ms": ms(t4, t5), "second_call_ms": ms(t5, t6),
                  "precompiled_bytes": len(blob), "deserialize_ms": ms(t7, t8)}))
