#!/usr/bin/env python3
"""Spike only. One-shot CLI: one process per verification.
Sequential latency (median, p90 of N runs) and throughput with 4 parallel
callers, plus calls per child CPU-second (getrusage of the children).

    cli_bench.py LABEL N_SEQ N_PAR INPUT_FILE CMD... [-- NAME=VALUE ...]
"""
import concurrent.futures
import os
import resource
import statistics
import subprocess
import sys
import time


def main():
    label, n_seq, n_par, inp = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
    rest = sys.argv[5:]
    cmd, env = rest, dict(os.environ)
    if "--" in rest:
        i = rest.index("--")
        cmd = rest[:i]
        for kv in rest[i + 1:]:
            k, v = kv.split("=", 1)
            env[k] = v
    data = open(inp, "rb").read()

    def once():
        r = subprocess.run(cmd, input=data, capture_output=True, env=env)
        assert r.returncode == 0 and (b'"verified":true' in r.stdout or b'"status":0' in r.stdout), (r.returncode, r.stdout[:200], r.stderr[:300])

    once()  # page cache
    lat = []
    for _ in range(n_seq):
        t = time.perf_counter()
        once()
        lat.append((time.perf_counter() - t) * 1e3)
    lat.sort()
    ru0 = resource.getrusage(resource.RUSAGE_CHILDREN)
    t = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(4) as ex:
        list(ex.map(lambda _: once(), range(n_par)))
    wall = time.perf_counter() - t
    ru1 = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu = (ru1.ru_utime - ru0.ru_utime) + (ru1.ru_stime - ru0.ru_stime)
    print(f"{label}: sequential n={n_seq} median {statistics.median(lat):.1f} ms, p90 {lat[int(len(lat)*0.9)]:.1f} ms; "
          f"4 parallel callers n={n_par}: {n_par/wall:.1f} calls/s, {n_par/cpu:.1f} calls per child CPU-second")


if __name__ == "__main__":
    main()
