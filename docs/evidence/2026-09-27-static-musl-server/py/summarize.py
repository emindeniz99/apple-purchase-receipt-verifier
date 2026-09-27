#!/usr/bin/env python3
"""Spike only (2026-09-27, round 10). The note's comparison tables from
results/: startup.txt (median of the round medians, min-max of those),
bench.txt and http.txt (median over rounds, min-max), rss.txt, build.txt.

    summarize.py RESULTS_DIR > results/summary.txt
"""
import json
import os
import re
import statistics
import sys

R = sys.argv[1]
ROWS = ["gnu", "musl", "musl-mimalloc"]
med = statistics.median


def rng(v):
    return f"{med(v):.1f} ({min(v):.1f}-{max(v):.1f})"


print("## CLI start-up (verify-receipt, g5): median of the per-round medians of 7 runs (range of the round medians)")
print("## first result = the verdict's bytes have arrived; exit = the process has exited")
st = {}
for line in open(os.path.join(R, "startup.txt")):
    if line.startswith("{"):
        r = json.loads(line)
        st.setdefault((r["label"], r["cpus"]), []).append(r)
for row in ROWS + ["gnu-fastexit", "musl-fastexit", "musl-mimalloc-fastexit"]:
    cells = []
    for c, name in (("all", "4 CPUs"), ("0", "taskset -c 0")):
        v = st[(row, c)]
        cells.append(f"{name}: first {rng([x['first_result_ms_median'] for x in v])}, exit {rng([x['exit_ms_median'] for x in v])} ms")
    allv = st[(row, "all")] + st[(row, "0")]
    print(f"{row:<23} " + " | ".join(cells) + f" | peak RSS {med([x['maxrss_kb_median'] for x in allv]) / 1024:.1f} MiB, minor faults {med([x['minflt_median'] for x in allv]):.0f}")

print("\n## in-process `aprv bench` on CPU 0, 1 thread: calls/s, median over rounds (min-max)")
b = {}
for line in open(os.path.join(R, "bench.txt")):
    if line.startswith("{"):
        r = json.loads(line)
        k = (r["row"], r["bench"]["op"], r["bench"]["lifecycle"])
        b.setdefault(k, []).append(r["bench"]["per_s"])
for op, name in ((1, "receipt"), (258, "JWS")):
    for lc in ("fresh", "pool"):
        base = med(b[("gnu", op, lc)])
        cells = [f"{row} {rng(b[(row, op, lc)])} ({100 * (med(b[(row, op, lc)]) / base - 1):+.1f}%)" for row in ROWS]
        print(f"{name:<7} {lc:<5} " + " | ".join(cells))

print("\n## HTTP: server on CPU 0 (1 worker, lifecycle fresh), aprv-load on CPUs 1-3, 1 connection, 8 s: requests per server CPU-second, median over rounds (min-max); p50 latency; server peak RSS")
h = {}
for line in open(os.path.join(R, "http.txt")):
    m = re.match(r"(\S+) round (\d+) (receipt|jws)\s+(\{.*\})", line)
    if m:
        h.setdefault((m.group(1), m.group(3)), []).append(json.loads(m.group(4)))
for op in ("receipt", "jws"):
    base = med([x["per_server_cpu_s"] for x in h[("gnu", op)]])
    for row in ROWS:
        v = h[(row, op)]
        pc = [x["per_server_cpu_s"] for x in v]
        print(f"{op:<7} {row:<14} {rng(pc)} per server CPU-s ({100 * (med(pc) / base - 1):+.1f}%) | {med([x['req_per_s'] for x in v]):.1f} req/s |"
              f" p50 {med([x['p50_us'] for x in v]) / 1000:.2f} ms | peak RSS {max(x['server_rss_peak_kb'] for x in v) / 1024:.1f} MiB")

print("\n## sizes (features server,embed; stripped with llvm-strip), from build.txt")
for line in open(os.path.join(R, "build.txt")):
    m = re.match(r"(\S+-min) \| (\S+) \| .* \| raw (\d+) \| stripped (\d+) \| gzip -9 (\d+) \| xz -9 (\d+)", line)
    if m:
        print(f"{m.group(1):<22} {m.group(2):<27} raw {int(m.group(3)):>10,} | stripped {int(m.group(4)):>10,} | gzip -9 {int(m.group(5)):>9,} | xz -9 {int(m.group(6)):>9,}")
