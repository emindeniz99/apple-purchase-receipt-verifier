#!/usr/bin/env python3
"""results/parity.txt -> artifact x host table of rows identical to the
reference (sum over the four corpora), for the lines of scripts/matrix.sh.
    python3 matrix.py results/parity.txt > results/matrix.txt
"""
import re
import sys
from collections import OrderedDict

cells = OrderedDict()
for line in open(sys.argv[1], encoding="utf-8"):
    m = re.match(r"^(\S+) (\S+) (cases|hostile|algorithms|substrate) vs (\S+): (\d+) same, (\d+) differ, (\d+) trapped", line)
    if not m:
        continue
    key = (m[1], m[2], m[4])
    s, d, t = cells.get(key, (0, 0, 0))
    cells[key] = (s + int(m[5]), d + int(m[6]), t + int(m[7]))
print(f"{'artifact':<14} {'host':<28} {'reference':<14} same/total  differ  trapped")
for (a, h, r), (s, d, t) in cells.items():
    print(f"{a:<14} {h:<28} {r:<14} {s:>5}/{s + d + t:<5} {d:>6} {t:>8}")
