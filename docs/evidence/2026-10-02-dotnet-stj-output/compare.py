#!/usr/bin/env python3
"""Compares two dump files (dump/, endpoint lines removed) line by line.

    python3 compare.py old.noep new.noep

A line is `id <TAB> ok <TAB> hex` (the text as UTF-16 code units) or
`id <TAB> reason`. For every line whose text differs it parses both texts
as JSON and says whether the values are equal, and it names the escape
sequences only one side holds. Exit 1 when a verdict differs or a value
differs outside the lone-surrogate rows.
"""

import json
import re
import sys
from collections import Counter


def text(hexed):
    return bytes.fromhex(hexed).decode("utf-16-be", "surrogatepass")


def rows(path):
    out = []
    for line in open(path, encoding="utf-8"):
        parts = line.rstrip("\n").split("\t")
        out.append((parts[0], parts[1], text(parts[2]) if parts[1] == "ok" else None))
    return out


def escapes(s):
    return Counter(re.findall(r"\\u[0-9A-Fa-f]{4}|\\[^u]", s))


def show(c):
    return " ".join(f"{k}x{n}" for k, n in sorted(c.items())) or "-"


old, new = rows(sys.argv[1]), rows(sys.argv[2])
assert [r[0] for r in old] == [r[0] for r in new]
same = differ = value_equal = 0
bad = []
for (rid, a_status, a), (_, b_status, b) in zip(old, new):
    if a_status != b_status:
        bad.append(f"{rid}: verdict {a_status} -> {b_status}")
        continue
    if a == b:
        same += 1
        continue
    differ += 1
    equal = json.loads(a) == json.loads(b)
    value_equal += equal
    only_old, only_new = escapes(a) - escapes(b), escapes(b) - escapes(a)
    print(f"{rid}\tvalues {'equal' if equal else 'DIFFER'}\told only: {show(only_old)}\tnew only: {show(only_new)}")
    if not equal and not rid.startswith("lone-surrogate-"):
        bad.append(f"{rid}: value differs")
print(f"{len(old)} lines: {same} identical, {differ} differ, {value_equal} of those with equal values")
for line in bad:
    print("FAIL", line)
sys.exit(1 if bad else 0)
