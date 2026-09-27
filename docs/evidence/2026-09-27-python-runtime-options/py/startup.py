#!/usr/bin/env python3
"""Spike only (2026-09-27). Cold start to first result, measured from the
parent: spawn `python first_result.py` (interpreter start included), wait
for it to exit, repeat. Reports the median wall time and the child's own
breakdown for the median run. APRV_* settings pass through the environment.

    python startup.py g5.b64 runs [--cpus 0]      # --cpus: taskset CPU list (e.g. 0 = one core)
"""
import json
import os
import statistics
import subprocess
import sys
import time

here = os.path.dirname(os.path.abspath(__file__))
g5, runs = sys.argv[1], int(sys.argv[2])
cpus = sys.argv[sys.argv.index("--cpus") + 1] if "--cpus" in sys.argv else None
cmd = [sys.executable, os.path.join(here, "first_result.py"), g5]
if cpus is not None:
    cmd = ["taskset", "-c", cpus] + cmd
rows = []
for _ in range(runs):
    t = time.perf_counter()
    out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    wall = (time.perf_counter() - t) * 1000
    rows.append((wall, json.loads(out)))
rows.sort(key=lambda r: r[0])
walls = [r[0] for r in rows]
med = rows[len(rows) // 2]
print(json.dumps({"engine": os.environ.get("APRV_ENGINE", "cranelift"), "module": os.path.basename(os.environ["APRV_MODULE"]),
                  "cpus": cpus or "all", "runs": runs, "wall_ms_median": round(statistics.median(walls), 1),
                  "wall_ms_min": round(walls[0], 1), "wall_ms_max": round(walls[-1], 1), "median_run": med[1]}))
