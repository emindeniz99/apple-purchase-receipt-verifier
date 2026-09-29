#!/usr/bin/env python3
"""Are the pure-Rust wasm32-unknown-unknown traps only the missing clock seam?

    python3 clock_traps.py <requests.jsonl>... -- <noseam-rows.jsonl>... -- <seam-rows.jsonl>...

noseam rows: the core as it is (no clock seam), run with js/run.mjs.
seam rows: the core + core-patch/clock-seam.patch, same runner; each row
carries "imports" = the host imports it called (aprv.clock_now_ms).
Prints the trap set, the clock-reading set, their difference (both must
be empty for "only the clock"), and a breakdown by request kind.
"""
import json
import sys
from collections import Counter

args = sys.argv[1:]
i = args.index("--"); j = args.index("--", i + 1)
reqs = {}
for p in args[:i]:
    for l in open(p):
        if l.strip():
            r = json.loads(l); reqs[r["id"]] = r
trap, clock, calls = set(), {}, 0
for p in args[i + 1:j]:
    for l in open(p):
        r = json.loads(l)
        if r["code"] == "TRAP":
            trap.add(r["id"])
for p in args[j + 1:]:
    for l in open(p):
        r = json.loads(l)
        if r["code"] == "TRAP":
            print("seam build trapped:", r["id"])
        n = (r.get("imports") or {}).get("aprv.clock_now_ms", 0)
        if n:
            clock[r["id"]] = n; calls += n
print(f"rows: {len(reqs)}")
print(f"trapped without the seam: {len(trap)}")
print(f"rows that read the host clock with the seam: {len(clock)} ({calls} reads)")
print(f"trapped but never read the clock: {sorted(trap - set(clock))}")
print(f"read the clock but did not trap: {sorted(set(clock) - trap)}")
by = Counter()
for rid in clock:
    r = reqs[rid]; opts = json.loads(r["options"])
    k = r["kind"]
    if k == "endpoint":
        k += " (no pinned clock)" if opts.get("nowMillis") is None else " (pinned clock)"
    by[(k, clock[rid])] += 1
for (k, n), c in sorted(by.items()):
    print(f"  {k}: {c} rows, {n} clock read(s) each")
