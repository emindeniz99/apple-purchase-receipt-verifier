#!/usr/bin/env python3
"""Spike only (2026-09-29, round 13). Compares every host's rows with the
first host's, row by row (request_date* masked on endpoint rows whose
clock is the wall clock).

    cross_host.py CALLS_DIR RUN_DIR FIRST OTHER...
"""
import json
import re
import sys

M = re.compile(r'"(request_date(?:_ms|_pst)?)":"[^"]*"')
calls, run, first, others = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]


def norm(r, pinned):
    r = dict(r)
    if not pinned and isinstance(r.get("out"), str):
        r["out"] = M.sub(r'"\1":"*"', r["out"])
    return json.dumps(r, sort_keys=True)


print(f"# cross-host: each host's rows against {first}'s (request_date* masked on unpinned endpoint rows)")
for h in others:
    same = diff = 0
    for c in ("cases", "hostile", "algorithms", "substrate", "fuzz"):
        k = {r["id"]: r for r in map(json.loads, open(f"{calls}/{c}.jsonl"))}
        a = {r["id"]: r for r in map(json.loads, open(f"{run}/{first}-{c}.jsonl"))}
        for r in map(json.loads, open(f"{run}/{h}-{c}.jsonl")):
            p = k[r["id"]].get("now") is not None
            ok = norm(a[r["id"]], p) == norm(r, p)
            same, diff = same + ok, diff + (not ok)
            if not ok:
                print("  differs:", r["id"])
    print(f"{h} vs {first}: {same} identical, {diff} different")
