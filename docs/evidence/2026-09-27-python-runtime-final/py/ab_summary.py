#!/usr/bin/env python3
"""Spike only (2026-09-27, round 11). Medians per variant from ab.sh's
output, and each Python row's cost against the native row (same rounds).

    ab_summary.py results/ab.txt
"""
import json
import statistics
import sys

runs = {}
for line in open(sys.argv[1]):
    if line.startswith("{"):
        r = json.loads(line)
        runs.setdefault(r["label"], []).append(r)
med = {}
for label, rs in runs.items():
    g5 = [r["g5"]["per_s_mean"] for r in rs]
    jws = [r["jws"]["per_s_mean"] for r in rs]
    g5_us = [r["g5"]["calls_us"]["100"] for r in rs]
    jws_us = [r["jws"]["calls_us"]["100"] for r in rs]
    med[label] = (statistics.median(g5), statistics.median(jws))
    print(f"{label:<26} runs {len(rs)}  g5/s median {med[label][0]:6.1f} (min {min(g5)}, max {max(g5)})  "
          f"JWS/s median {med[label][1]:5.1f} (min {min(jws)}, max {max(jws)})  call #100 g5 {statistics.median(g5_us)} us, JWS {statistics.median(jws_us)} us  "
          f"peak RSS {max(r['hwm_kb_max'] for r in rs)} KB")
base = med.get("native-wasmi2-lazytr")
if base:
    for label, (g, j) in med.items():
        if label != "native-wasmi2-lazytr":
            print(f"{label:<26} vs native: g5 {100 * (g / base[0] - 1):+.1f}%, JWS {100 * (j / base[1] - 1):+.1f}%")
if "py-wasmi-rs-lazytr" in med and "py-wasmi-rs-lazytr-fuel" in med:
    a, b = med["py-wasmi-rs-lazytr"], med["py-wasmi-rs-lazytr-fuel"]
    print(f"fuel metering on vs off (py-wasmi-rs): g5 {100 * (b[0] / a[0] - 1):+.1f}%, JWS {100 * (b[1] / a[1] - 1):+.1f}%")
