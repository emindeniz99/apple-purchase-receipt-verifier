#!/usr/bin/env python3
"""Evidence only (2026-09-29). Medians of the runs node-init-cost.mjs and
init-cost-wasmtime print, and the R23 rule: does init exceed 10% of a call?

    summarize.py <rows.jsonl>...
"""
import collections
import json
import statistics
import sys

PHASES = ["instantiate_us", "init_us", "fresh_call_us", "pool_call_us"]
groups = collections.defaultdict(list)
for path in sys.argv[1:]:
    for line in open(path, encoding="utf-8"):
        row = json.loads(line)
        groups[(row["host"], row["input"])].append(row)

print("| Host | Input | Runs x calls | Instantiate | init | First call | Pooled call | init / pooled call | Fresh request / pooled call |")
print("|---|---|---|---|---|---|---|---|---|")
for (host, name), rows in groups.items():
    med = {p: statistics.median(r[p] for r in rows) for p in PHASES}
    spread = {p: (min(r[p] for r in rows), max(r[p] for r in rows)) for p in PHASES}
    cell = lambda p: f"{med[p] / 1000:.2f} ms ({spread[p][0] / 1000:.2f}-{spread[p][1] / 1000:.2f})"
    fresh = med["instantiate_us"] + med["init_us"] + med["fresh_call_us"]
    print(
        f"| {host} | {name} | {len(rows)} x {rows[0]['calls']} | {cell('instantiate_us')} | {cell('init_us')} | "
        f"{cell('fresh_call_us')} | {cell('pool_call_us')} | {100 * med['init_us'] / med['pool_call_us']:.0f}% | "
        f"{fresh / med['pool_call_us']:.2f}x |"
    )
