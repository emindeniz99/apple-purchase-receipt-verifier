#!/usr/bin/env python3
"""Spike only (2026-09-27, round 11). pywasm implements traps as Python
`assert` statements (`unreachable` is `assert 0`, bounds checks are asserts).
This runs three cheap trap cases with and without `python -O`, which strips
asserts, to see whether the sandbox's traps survive it.

    APRV_MODULE=... python    pywasm_asserts.py
    APRV_MODULE=... python -O pywasm_asserts.py
"""
import json
import sys

import aprv_pywasm

cases = [
    ("aprv_call with ABI version 3 (the module's first instruction traps: unreachable)", "aprv_call", (3, 1, 0, 0)),
    ("aprv_result_ptr(0): invalid handle (the module traps: unreachable)", "aprv_result_ptr", (0,)),
    ("aprv_call(1, VERIFY_RECEIPT, ptr = memory size - 4, len 16): out-of-range input", "aprv_call", None),
]
for label, name, args in cases:
    i = aprv_pywasm._Instance()
    if args is None:
        args = (1, 1, i.mem_len() - 4, 16)
    try:
        r = i.raw(name, *args)
        res = f"NO TRAP: returned {r}; memory now {i.mem_len()} bytes"
    except Exception as e:  # noqa: BLE001
        res = f"trap: {str(e)[:120]}"
    print(json.dumps({"python_optimize": sys.flags.optimize, "case": label, "result": res}), flush=True)
