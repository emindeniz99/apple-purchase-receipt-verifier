#!/usr/bin/env python3
"""Condenses results/parity.txt: for each (artifact, host), the LAST run of
each corpus, summed. A host passes when all four corpora ran and every one
of the 1,179 rows gave the native verdict of the same backend.

    python3 parity_matrix.py results/parity.txt
"""
import re
import sys
from collections import defaultdict

last = {}
pat = re.compile(r"^(\S+) (\S+) host=(\S+) (cases|hostile|algorithms|substrate) vs native-(\S+): (\d+) same, (\d+) differ, (\d+) trapped")
bpat = re.compile(r"^(\S+) (chromium|firefox|webkit) (cases|hostile|algorithms|substrate) vs native-(\S+): (\d+) same, (\d+) differ, (\d+) trapped")
for line in open(sys.argv[1], encoding="utf-8"):
    m = pat.match(line)
    if m:
        art, rt, host, corpus, nat, s, d, t = m.groups()
        last[(art, f"{rt}/{host}", nat, corpus)] = (int(s), int(d), int(t))
        continue
    m = bpat.match(line)
    if m:
        art, br, corpus, nat, s, d, t = m.groups()
        last[(art, br, nat, corpus)] = (int(s), int(d), int(t))
agg = defaultdict(lambda: [0, 0, 0, 0])
for (art, host, nat, corpus), (s, d, t) in last.items():
    a = agg[(art, host, nat)]
    a[0] += s; a[1] += d; a[2] += t; a[3] += 1
print(f"{'artifact':22} {'host':28} {'native':12} {'same':>5} {'differ':>6} {'trap':>5} corpora  verdict")
for (art, host, nat), (s, d, t, n) in sorted(agg.items()):
    ok = "PASS 1,179/1,179" if n == 4 and s == 1179 and d == 0 and t == 0 else ("partial run" if n < 4 else "DIFFERS")
    print(f"{art:22} {host:28} {nat:12} {s:5} {d:6} {t:5} {n:7}  {ok}")
