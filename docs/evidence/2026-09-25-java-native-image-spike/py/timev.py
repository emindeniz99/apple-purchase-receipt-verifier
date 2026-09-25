#!/usr/bin/env python3
"""Minimal /usr/bin/time -v stand-in (the container has none):
    timev.py <report-file> <command...>
Writes wall time and the peak RSS of the largest waited-for descendant."""
import resource, subprocess, sys, time
report, cmd = sys.argv[1], sys.argv[2:]
start = time.monotonic()
rc = subprocess.call(cmd)
wall = time.monotonic() - start
peak_kb = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
with open(report, "w") as f:
    f.write(f"Elapsed (wall clock) seconds: {wall:.1f}\nMaximum resident set size (kbytes): {peak_kb}\nExit status: {rc}\n")
sys.exit(rc)
