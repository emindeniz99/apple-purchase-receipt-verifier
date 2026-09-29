#!/usr/bin/env python3
"""Spike only. Summarises bench.sh output lines ("<name> node {json}" and
"<name> endive jdk<V> memory=<m> {json}") into one table: per candidate and
runtime, the median of the runs' mean latency (microseconds), per row kind,
and the change against the candidate named 'base'.

    python3 summary.py bench-raw.txt
"""
import collections
import json
import statistics
import sys

runs = collections.defaultdict(list)
order = []
for line in open(sys.argv[1], encoding="utf-8"):
    head, _, js = line.partition("{")
    if not js:
        continue
    d = json.loads("{" + js)
    parts = head.split()
    name, host = parts[0], " ".join(parts[1:])
    kind = "receipt" if d["id"].startswith("receipt") else "jws"
    runs[(name, host, kind)].append(d["mean_us"])
    if name not in order:
        order.append(name)
hosts = []
for (_, h, _) in runs:
    if h not in hosts:
        hosts.append(h)
print("# median of runs' mean latency, microseconds (runs); change vs base in brackets")
for h in hosts:
    print(f"## {h}")
    print(f"{'candidate':<14} {'receipt (g5)':>26} {'JWS (shared-sandbox)':>26}")
    for n in order:
        cells = []
        for k in ("receipt", "jws"):
            v = runs.get((n, h, k))
            if not v:
                cells.append(f"{'-':>26}")
                continue
            m = statistics.median(v)
            b = runs.get(("base", h, k))
            ch = f" [{100 * (m / statistics.median(b) - 1):+.0f}%]" if b and n != "base" else ""
            cells.append(f"{f'{m:,.0f} ({len(v)}){ch}':>26}")
        print(f"{n:<14} {cells[0]} {cells[1]}")
