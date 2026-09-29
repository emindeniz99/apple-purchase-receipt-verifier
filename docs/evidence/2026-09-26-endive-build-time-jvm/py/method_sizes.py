#!/usr/bin/env python3
"""Spike only. Bytecode size of every method in a `javap -c -p` listing
(offset of its last instruction), against the JVM's limits: 65,535 bytes
per method (hard; Endive falls back to its interpreter above it) and
HotSpot's HugeMethodLimit, 8,000 bytes (methods above it are never
JIT-compiled unless -XX:-DontCompileHugeMethods).

    python3 method_sizes.py listing.javap
"""
import re
import sys

sizes = []
name = None
last = 0
for line in open(sys.argv[1], encoding="utf-8"):
    m = re.match(r"  (public|private|static|protected).*? ([\w$]+)\(", line)
    if m:
        if name is not None:
            sizes.append((last, name))
        name, last = m.group(2), 0
        continue
    m = re.match(r"\s+(\d+): ", line)
    if m:
        last = int(m.group(1))
if name is not None:
    sizes.append((last, name))
sizes.sort(reverse=True)
print(f"methods: {len(sizes)}")
for lim in (8000, 32000, 65535):
    print(f"above {lim} bytes: {sum(1 for s, _ in sizes if s > lim)}")
print("## largest")
for s, n in sizes[:8]:
    print(s, n[:100])
