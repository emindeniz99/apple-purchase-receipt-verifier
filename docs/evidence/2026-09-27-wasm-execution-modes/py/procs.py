#!/usr/bin/env python3
"""Spike only (2026-09-27, round 9). Throughput of a native host's `bench`
mode on 1 CPU or on 4 CPUs at once: K copies of `HOST bench MODULE G5 JWS
...` run concurrently, copy i pinned to CPU i with taskset, each with its
own engine, module and instance. Each copy times calls #1, #2, #5, #10 and
#100, then a steady-state loop (>= 20 calls and >= 2 s) for g5 and then the
JWS. A copy that runs past TIMEOUT seconds has its process group killed.

    procs.py LABEL K -- HOST ARGV...

Prints one JSON line: per-copy steady g5/s and JWS/s, their mean (the per-core
figure), copy 0's warm-up marks and setup, and the peak RSS.
"""
import json
import os
import signal
import subprocess
import sys
import time

TIMEOUT = float(os.environ.get("APRV_BENCH_TIMEOUT", "900"))
sep = sys.argv.index("--")
label, k = sys.argv[1], int(sys.argv[2])
cmd = sys.argv[sep + 1:]
procs = [subprocess.Popen(["taskset", "-c", str(i)] + cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                          start_new_session=True) for i in range(k)]
deadline = time.monotonic() + TIMEOUT
outs = []
for p in procs:
    try:
        out, err = p.communicate(timeout=max(1, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        for q in procs:
            try:
                os.killpg(q.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        print(json.dumps({"label": label, "cpus": k, "hang": f"no result in {TIMEOUT:.0f} s; process groups killed"}))
        sys.exit(3)
    if p.returncode != 0:
        print(json.dumps({"label": label, "cpus": k, "error": err.strip()[-400:]}))
        sys.exit(1)
    outs.append([json.loads(l) for l in out.splitlines() if l.strip()])


def op(rows, name):
    return next(r for r in rows if r.get("op") == name)


res = {"label": label, "cpus": k}
for name in ("g5", "jws"):
    per = [op(rows, name)["per_s"] for rows in outs]
    res[name] = {"per_s_each": per, "per_s_mean": round(sum(per) / len(per), 1),
                 "calls_us": op(outs[0], name)["calls_us"], "not_verified": sum(op(rows, name)["not_verified"] for rows in outs)}
res["setup"] = {k2: v for k2, v in outs[0][0].items() if k2 not in ("phase",)}
res["hwm_kb_max"] = max(next(r for r in rows if r.get("phase") == "end")["hwm_kb"] for rows in outs)
print(json.dumps(res))
