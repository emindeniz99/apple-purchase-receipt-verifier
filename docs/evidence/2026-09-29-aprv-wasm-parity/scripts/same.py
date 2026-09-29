#!/usr/bin/env python3
"""Evidence only (2026-09-29). Are two row sets of the same calls
identical: aprv.wasm through the trap host against its native twin?
Compares each row's `out` string (or `trap`, or `map`) exactly.

    same.py a.jsonl b.jsonl [--list]
"""
import json
import sys

args = [a for a in sys.argv[1:] if not a.startswith("--")]
a = [json.loads(l) for l in open(args[0], encoding="utf-8") if l.strip()]
b = [json.loads(l) for l in open(args[1], encoding="utf-8") if l.strip()]
assert len(a) == len(b), (len(a), len(b))
differ, traps = [], 0
for x, y in zip(a, b):
    assert x["id"] == y["id"], (x["id"], y["id"])
    traps += ("trap" in x) + ("trap" in y)
    if (x.get("out"), x.get("trap"), x.get("map")) != (y.get("out"), y.get("trap"), y.get("map")):
        differ.append((x, y))
print(f"{len(a)} rows: {len(a) - len(differ)} identical, {len(differ)} differ, {traps} traps")
if "--list" in sys.argv:
    for x, y in differ:
        print(f"  {x['id']}\n    a: {json.dumps(x)[:300]}\n    b: {json.dumps(y)[:300]}")
sys.exit(1 if differ or traps else 0)
