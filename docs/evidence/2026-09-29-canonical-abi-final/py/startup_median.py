#!/usr/bin/env python3
"""Spike only (2026-09-29, round 13). Medians of the start-up runs: one
JSON line per run in each results/startup-*.txt (and bench-wazero.txt's
per-module lines), grouped by module (and binary, when given). Prints a
table per file and the canonical-ABI delta of every field against ABI v1.

    startup_median.py results/startup-*.txt > results/startup-summary.txt
"""
import collections
import json
import statistics
import sys

for path in sys.argv[1:]:
    groups = collections.OrderedDict()
    for line in open(path):
        if not line.startswith("{"):
            continue
        r = json.loads(line)
        key = r["module"] + (f" [{r['binary']}]" if "binary" in r else "")
        groups.setdefault(key, []).append(r)
    print(f"## {path.rsplit('/', 1)[-1]}")
    med = {}
    for key, runs in groups.items():
        fields = [k for k, v in runs[0].items() if isinstance(v, (int, float))]
        med[key] = {k: statistics.median(r[k] for r in runs) for k in fields}
        print(f"  {key} (n={len(runs)}): " + ", ".join(f"{k} {v:g}" for k, v in med[key].items()))
    base = next((k for k in med if k.startswith("ABI v1")), None)
    for key in med:
        if key.startswith("ABI v1") or base is None:
            continue
        d = ", ".join(f"{k} {med[key][k] - med[base][k]:+.1f} ({(med[key][k] - med[base][k]) / med[base][k] * 100:+.1f}%)"
                      for k in med[key] if k in med[base] and med[base][k])
        print(f"  delta {key} vs {base}: {d}")
