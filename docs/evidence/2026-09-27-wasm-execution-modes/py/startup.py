#!/usr/bin/env python3
"""Spike only (2026-09-27, round 9). Cold start of a native host, measured
from the parent: read CLOCK_MONOTONIC, spawn `HOST first MODULE G5 ...`
(optionally under taskset), and take the child's own CLOCK_MONOTONIC stamp
at the moment its first verified g5 came back. The difference is fresh
process to first result (exec, dynamic loading, runtime init, module load,
instantiate, first call). Wall to exit is reported too.

    startup.py LABEL RUNS [--cpus 0] -- HOST ARGV...

Prints one JSON line: median/min/max of spawn-to-first-result, and the
child's breakdown (init, load, instantiate, first and second call, RSS) for
the median run. A row whose cold run takes longer than SLOW seconds is not
repeated: "runs" then says how many ran.
"""
import json
import statistics
import subprocess
import sys
import time

sep = sys.argv.index("--")
label, runs = sys.argv[1], int(sys.argv[2])
cpus = sys.argv[sys.argv.index("--cpus") + 1] if "--cpus" in sys.argv[:sep] else None
cmd = sys.argv[sep + 1:]
if cpus is not None:
    cmd = ["taskset", "-c", cpus] + cmd
SLOW = 60.0
rows = []
for _ in range(runs):
    t0 = time.monotonic_ns()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)  # a timeout kills the host
    except subprocess.TimeoutExpired:
        print(json.dumps({"label": label, "cpus": cpus or "all", "hang": "no result in 1800 s; host killed; not repeated"}))
        sys.exit(3)
    t_exit = time.monotonic_ns()
    if p.returncode != 0:
        print(json.dumps({"label": label, "cpus": cpus or "all", "error": p.stderr.strip()[-400:]}))
        sys.exit(1)
    child = json.loads(p.stdout)
    rows.append(((child["first_result_mono_ns"] - t0) / 1e6, (t_exit - t0) / 1e6, child))
    if (t_exit - t0) / 1e9 > SLOW:
        break
rows.sort(key=lambda r: r[0])
firsts = [r[0] for r in rows]
med = rows[len(rows) // 2]
b = med[2]
print(json.dumps({
    "label": label, "cpus": cpus or "all", "runs": len(rows),
    "first_result_ms_median": round(statistics.median(firsts), 1),
    "first_result_ms_min": round(firsts[0], 1), "first_result_ms_max": round(firsts[-1], 1),
    "exit_ms_median": round(statistics.median(r[1] for r in rows), 1),
    "median_run": {k: b[k] for k in ("engine", "mode", "running_mode", "init_ms", "load_ms", "instantiate_ms", "first_call_ms",
                                     "second_call_ms", "verified", "rss_kb", "hwm_kb") if k in b},
}))
