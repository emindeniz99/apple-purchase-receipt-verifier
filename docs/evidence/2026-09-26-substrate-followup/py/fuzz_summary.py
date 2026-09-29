#!/usr/bin/env python3
"""Summarises tri-<variant>-fuzz.txt files ($SPIKE/py/tri.py --list output):
the total line, rows where the candidate accepts (0) while Java and Rust
both reject, and rows it rejects while both accept.
    python3 fuzz_summary.py results/tri-<v>-fuzz.txt ...
"""
import re
import sys

for path in sys.argv[1:]:
    lines = open(path, encoding="utf-8").read().splitlines()
    total = next((l for l in lines if l.startswith("total")), "")
    accepts, rejects = [], []
    i = 0
    while i < len(lines):
        m = re.match(r"^(cand-own)\s+(\S+)", lines[i])
        if m and i + 3 < len(lines):
            java, rust, cand = (lines[i + k].split(":", 1)[1].strip().split(" ")[0] for k in (1, 2, 3))
            if cand == "0" and java != "0" and rust != "0":
                accepts.append(m.group(2))
            if java == "0" and rust == "0" and cand != "0":
                rejects.append(m.group(2))
            i += 4
            continue
        i += 1
    name = path.rsplit("/", 1)[-1].removeprefix("tri-").removesuffix("-fuzz.txt")
    print(f"{name}: {' '.join(total.split())} | accepts what Java and Rust reject: {len(accepts)} {accepts} | rejects what both accept: {len(rejects)} {rejects}")
