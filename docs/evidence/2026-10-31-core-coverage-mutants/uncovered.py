#!/usr/bin/env python3
"""Lists every uncovered code region and every branch side never taken in
an llvm-cov JSON export (cargo llvm-cov report --json), per file.

    python3 -I uncovered.py <coverage.json> [path-prefix-to-strip]

The same source span can appear several times: once per monomorphised
copy and once per build of a crate (aprv-openssl is built twice, with and
without its test-seams feature). Counts are summed per span first, so a
span is reported only when no copy of it ever ran.

A region prints as file:line:col-line:col; a branch as
file:line:col-line:col true=<n> false=<n> when one side is zero.
"""
import json
import sys
from collections import defaultdict

data = json.load(open(sys.argv[1]))
strip = sys.argv[2] if len(sys.argv) > 2 else ""

regions = defaultdict(int)
branches = defaultdict(lambda: [0, 0])
for export in data["data"]:
    for fn in export.get("functions", []):
        names = [n.replace(strip, "") for n in fn["filenames"]]
        for r in fn["regions"]:
            # [line_start, col_start, line_end, col_end, count, file_id,
            #  expanded_file_id, kind]; kind 0 is a code region.
            ls, cs, le, ce, count, file_id, _exp, kind = r[:8]
            if kind == 0:
                regions[(names[file_id], ls, cs, le, ce)] += count
        for b in fn.get("branches", []):
            # [line_start, col_start, line_end, col_end, true, false,
            #  file_id, expanded_file_id, kind]
            ls, cs, le, ce, t, f, file_id = b[:7]
            side = branches[(names[file_id], ls, cs, le, ce)]
            side[0] += t
            side[1] += f

by_file = defaultdict(list)
for (name, ls, cs, le, ce), count in regions.items():
    if count == 0:
        by_file[name].append((ls, cs, f"region {ls}:{cs}-{le}:{ce}"))
for (name, ls, cs, le, ce), (t, f) in branches.items():
    if t == 0 or f == 0:
        by_file[name].append((ls, cs, f"branch {ls}:{cs}-{le}:{ce} true={t} false={f}"))

for export in data["data"]:
    for f in export["files"]:
        name = f["filename"].replace(strip, "")
        s = f["summary"]
        print(
            "== {}  lines {}/{}  regions {}/{}  branches {}/{}".format(
                name,
                s["lines"]["covered"], s["lines"]["count"],
                s["regions"]["covered"], s["regions"]["count"],
                s["branches"]["covered"], s["branches"]["count"],
            )
        )
        for _ls, _cs, text in sorted(by_file.get(name, [])):
            print("   " + text)
