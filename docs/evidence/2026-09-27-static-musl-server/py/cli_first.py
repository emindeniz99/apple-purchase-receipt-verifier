#!/usr/bin/env python3
"""Spike only (2026-09-27, round 10). One-shot CLI start-up to first
result: spawn `[taskset -c CPUS] BIN verify-receipt`, write the g5 receipt
to its stdin, and time from just before spawn to
  - first_result: the moment the bytes read so far parse as the complete
    JSON verdict (the CLI writes it in one write), and
  - exit: the process has exited (what a caller that waits for the exit
    status, e.g. subprocess.run, sees).
Peak RSS and minor page faults from wait4. One untimed run first (page
cache), then RUNS timed runs; prints one JSON line with medians.

    cli_first.py LABEL RUNS INPUT [--cpus 0] -- BIN ARGS...
"""
import json
import os
import statistics
import subprocess
import sys
import time

sep = sys.argv.index("--")
label, runs, inp = sys.argv[1], int(sys.argv[2]), open(sys.argv[3], "rb").read()
cpus = sys.argv[sys.argv.index("--cpus") + 1] if "--cpus" in sys.argv[:sep] else None
cmd = sys.argv[sep + 1:]
if cpus is not None:
    cmd = ["taskset", "-c", cpus] + cmd


def once():
    t0 = time.perf_counter()
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    p.stdin.write(inp)
    p.stdin.close()
    out, t_out, fd = b"", None, p.stdout.fileno()
    while True:
        chunk = os.read(fd, 1 << 20)
        if not chunk:
            break
        out += chunk
        if t_out is None:
            try:
                json.loads(out)
                t_out = time.perf_counter()
            except ValueError:
                pass
    _, status, ru = os.wait4(p.pid, 0)
    t_exit = time.perf_counter()
    err = p.stderr.read()
    ok = os.waitstatus_to_exitcode(status) == 0 and (b'"verified":true' in out or b'"status":0' in out)
    if not ok:
        raise SystemExit(json.dumps({"label": label, "error": (out[:200] + err[-300:]).decode("utf-8", "replace")}))
    return (t_out - t0) * 1e3, (t_exit - t0) * 1e3, ru.ru_maxrss, ru.ru_minflt


once()
rows = [once() for _ in range(runs)]
print(json.dumps({
    "label": label, "cpus": cpus or "all", "runs": runs,
    "first_result_ms_median": round(statistics.median(r[0] for r in rows), 2),
    "first_result_ms_min": round(min(r[0] for r in rows), 2), "first_result_ms_max": round(max(r[0] for r in rows), 2),
    "exit_ms_median": round(statistics.median(r[1] for r in rows), 2),
    "exit_ms_min": round(min(r[1] for r in rows), 2), "exit_ms_max": round(max(r[1] for r in rows), 2),
    "maxrss_kb_median": int(statistics.median(r[2] for r in rows)),
    "minflt_median": int(statistics.median(r[3] for r in rows)),
}))
