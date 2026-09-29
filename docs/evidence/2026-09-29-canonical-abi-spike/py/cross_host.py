#!/usr/bin/env python3
"""Spike only (2026-09-29, round 12). Compares every host's rows with
wazero's, row by row (request_date* masked on endpoint rows whose clock is
the wall clock). Appended to results/classify.txt.

    cross_host.py CABI_CALLS_DIR RUN_DIR
"""
import json
import re
import sys

M = re.compile(r'"(request_date(?:_ms|_pst)?)":"[^"]*"')
calls, run = sys.argv[1:3]


def norm(r, pinned):
    r = dict(r)
    if not pinned and isinstance(r.get("out"), str):
        r["out"] = M.sub(r'"\1":"*"', r["out"])
    return json.dumps(r, sort_keys=True)


print("# cross-host: each host's rows against wazero's (request_date* masked on unpinned endpoint rows)")
for h in ("wazero-unchecked", "endive", "jco", "wasmtime-py"):
    same = diff = 0
    for c in ("cases", "hostile", "algorithms", "substrate", "fuzz"):
        k = {r["id"]: r for r in map(json.loads, open(f"{calls}/{c}.jsonl"))}
        a = {r["id"]: r for r in map(json.loads, open(f"{run}/wazero-{c}.jsonl"))}
        for r in map(json.loads, open(f"{run}/{h}-{c}.jsonl")):
            p = k[r["id"]].get("now") is not None
            ok = norm(a[r["id"]], p) == norm(r, p)
            same, diff = same + ok, diff + (not ok)
            if not ok:
                print("  differs:", r["id"])
    print(f"{h} vs wazero: {same} identical, {diff} different")
