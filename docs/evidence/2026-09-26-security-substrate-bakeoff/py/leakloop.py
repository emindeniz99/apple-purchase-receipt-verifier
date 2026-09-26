#!/usr/bin/env python3
"""Resident set after the first and after the last of n calls in one
process (`run1 loop <n> ...`, which prints VmRSS to stderr). A per-call
leak shows as growth that scales with n.

    python3 leakloop.py <run1> <n> receipt|jws <input> <bundle> <root.der>...
"""

import subprocess
import sys


def main():
    run1, n, rest = sys.argv[1], sys.argv[2], sys.argv[3:]
    p = subprocess.run([run1, "loop", n] + rest, capture_output=True, text=True, check=True)
    v = dict(line.split()[:2] for line in p.stderr.splitlines() if line.startswith("rss_"))
    first, last = int(v["rss_after_first_kb"]), int(v["rss_after_last_kb"])
    print(f"{rest[0]}: {n} calls, VmRSS after call 1 {first} KB, after call {n} {last} KB, growth {last - first} KB")


if __name__ == "__main__":
    main()
