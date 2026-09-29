#!/usr/bin/env python3
"""Spike only (2026-09-27, round 11). The heaviest corpus rows (by fuel,
from fuel.py), timed through py/aprv_wasmi_rs with metering on: fuel used,
median of 5 warm calls, fuel per second, and the margin a 5e9 budget leaves.

    APRV_LIBAPRVWASMI=... APRV_MODULE=... APRV_WASMI_FUEL=5000000000 fuel_heaviest.py CASES.jsonl
"""
import base64
import json
import sys
import time

import aprv_wasmi_rs as m

rows = {c["id"]: c for c in map(json.loads, open(sys.argv[1])) if "op" in c}
for rid in ("endpoint/verify-at-the-byte-floor", "receipt/verify-at-the-byte-floor", "receipt/accept-der-at-the-size-cap"):
    c = rows[rid]
    data = base64.b64decode(c["input"])
    i = m._Instance()
    i.invoke(c["op"], data)  # warm (lazy translation)
    ts = []
    for _ in range(5):
        t = time.perf_counter()
        out = i.invoke(c["op"], data)
        ts.append(time.perf_counter() - t)
    ts.sort()
    f = i.fuel_used()
    print(json.dumps({"id": rid, "input_bytes": len(data), "fuel": f, "median_ms": round(ts[2] * 1000, 1),
                      "fuel_per_s": round(f / ts[2]), "budget_5e9_margin": round(5e9 / f, 2),
                      "answer_head": out[:40].decode("utf-8", "replace")}))
    i.close()
