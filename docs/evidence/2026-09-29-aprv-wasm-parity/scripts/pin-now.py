#!/usr/bin/env python3
"""Evidence only (2026-09-29). Pins every round-13 call row whose `now` is
null (the host's wall clock) to one instant, so aprv.wasm and its native
twin judge dateless inputs at the same instant and their rows can be
compared byte for byte.

    pin-now.py <ms> < calls.jsonl > pinned.jsonl
"""
import json
import sys

ms = int(sys.argv[1])
for line in sys.stdin:
    if not line.strip():
        continue
    row = json.loads(line)
    if "map" not in row and row.get("now") is None:
        row["now"] = ms
    sys.stdout.write(json.dumps(row) + "\n")
