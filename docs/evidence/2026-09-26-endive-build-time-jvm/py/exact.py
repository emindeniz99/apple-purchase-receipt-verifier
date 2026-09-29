#!/usr/bin/env python3
"""Spike only. Stricter than py/same.py: are two row files byte-identical,
field by field ("id", "code", "json" as strings), after masking the
endpoint's request_date* values (wall-clock time of the request)?

    python3 exact.py a.jsonl b.jsonl [--list]

Prints "<n> identical, <m> differ". Extra fields ("imports", "trap") are
ignored.
"""
import json
import re
import sys

MASK = re.compile(r'"(request_date(?:_ms|_pst)?)":"[^"]*"')


def rows(path):
    out = []
    for line in open(path, encoding="utf-8"):
        if line.strip():
            r = json.loads(line)
            j = r.get("json")
            if isinstance(j, str):
                j = MASK.sub(r'"\1":"*"', j)
            out.append((r["id"], r["code"], j))
    return out


a, b = rows(sys.argv[1]), rows(sys.argv[2])
assert len(a) == len(b), (len(a), len(b))
same = differ = 0
for x, y in zip(a, b):
    assert x[0] == y[0], (x[0], y[0])
    if x == y:
        same += 1
    else:
        differ += 1
        if "--list" in sys.argv:
            print("  differ", x[0], x[1], y[1])
print(f"{same} identical, {differ} differ")
