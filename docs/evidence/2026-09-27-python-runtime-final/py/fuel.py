#!/usr/bin/env python3
"""Spike only (2026-09-27, round 11). Fuel and memory envelope of the
corpus: every row of the five call files through py/aprv_wasmi_rs with
metering on and a budget no row can reach (APRV_WASMI_FUEL=2**62), recording
the fuel each aprv_call consumed and the linear-memory size after it.

    APRV_FACADE=aprv_wasmi_rs APRV_WASMI_FUEL=4611686018427387904 fuel.py CALLS_DIR
Prints one JSON line per corpus and one for all of them.
"""
import base64
import json
import os
import sys

import aprv_wasmi_rs as m

calls_dir = sys.argv[1]
tot = {"rows": 0, "traps": 0, "fuel_max": 0, "fuel_max_id": None, "mem_max": 0, "fuel_sum": 0}
named = {}
for c in ("cases", "hostile", "algorithms", "substrate", "fuzz"):
    s = {"corpus": c, "rows": 0, "traps": 0, "fuel_max": 0, "fuel_max_id": None, "mem_max": 0, "fuel_sum": 0}
    inst = m._Instance()
    for line in open(os.path.join(calls_dir, c + ".jsonl"), encoding="utf-8"):
        if not line.strip():
            continue
        row = json.loads(line)
        if "op" not in row:
            continue
        s["rows"] += 1
        try:
            inst.invoke(row["op"], base64.b64decode(row["input"]))
        except Exception:  # noqa: BLE001  (a trap: the fuel of the trapping call still counts)
            s["traps"] += 1
            used, mem = inst.fuel_used(), inst.mem_len()
            inst.close()
            inst = m._Instance()
        else:
            used, mem = inst.fuel_used(), inst.mem_len()
        s["fuel_sum"] += used
        if used > s["fuel_max"]:
            s["fuel_max"], s["fuel_max_id"] = used, row["id"]
        s["mem_max"] = max(s["mem_max"], mem)
        if row["id"] in ("receipt/verify-genuine-sandbox-g5-against-apple-roots", "transaction/verify-shared-sandbox"):
            named[row["id"]] = used
    inst.close()
    s["fuel_mean"] = round(s["fuel_sum"] / max(s["rows"], 1))
    print(json.dumps(s), flush=True)
    tot["rows"] += s["rows"]
    tot["traps"] += s["traps"]
    tot["fuel_sum"] += s["fuel_sum"]
    tot["mem_max"] = max(tot["mem_max"], s["mem_max"])
    if s["fuel_max"] > tot["fuel_max"]:
        tot["fuel_max"], tot["fuel_max_id"] = s["fuel_max"], s["fuel_max_id"]
tot["corpus"] = "all"
tot["named"] = named
print(json.dumps(tot), flush=True)
