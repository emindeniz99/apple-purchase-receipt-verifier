#!/usr/bin/env python3
"""Spike only. Aggregates `jfr print --stack-depth 64 --events
jdk.ExecutionSample` output: the innermost frame of each sample, and the
innermost frame that is a compiled Wasm function (the generated methods
are named <wasm name>_<function index> by NameSectionMethodPrefixer).

    python3 jfr_top.py samples.txt [n]
"""
import collections
import re
import sys

FRAME = re.compile(r"^\s+([\w.$]+)\(")
WASM = re.compile(r"AprvModuleMachineFuncGroup_\d+\.(.+_\d+)$")
top = collections.Counter()
wasm = collections.Counter()
incl = collections.Counter()
n = 0
cur = []


def flush():
    global n
    if not cur:
        return
    n += 1
    top[cur[0].split(".")[-1]] += 1
    names = [m.group(1) for m in (WASM.search(f) for f in cur) if m]
    if names:
        wasm[names[0]] += 1
    for f in set(names):
        incl[f] += 1


for line in open(sys.argv[1], encoding="utf-8"):
    if line.startswith("jdk.ExecutionSample"):
        flush()
        cur = []
        continue
    m = FRAME.match(line)
    if m and "stackTrace" not in line:
        cur.append(m.group(1))
flush()
k = int(sys.argv[2]) if len(sys.argv) > 2 else 10
print(f"samples: {n}")
print("## innermost frame (any code)")
for f, v in top.most_common(k):
    print(f"{v:6} {100 * v / n:5.1f}%  {f}")
print("## innermost compiled-Wasm function (self time, attributed to the Wasm function that made the call)")
for f, v in wasm.most_common(k):
    print(f"{v:6} {100 * v / n:5.1f}%  {f}")
print("## inclusive, compiled-Wasm functions")
for f, v in incl.most_common(k):
    print(f"{v:6} {100 * v / n:5.1f}%  {f[:110]}")
