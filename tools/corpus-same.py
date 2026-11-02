#!/usr/bin/env python3
"""Are two row sets of the same calls identical? Compares each row's
`out` string (or `trap`, or `map`) exactly, and exits 1 on a difference
or a trap.

    same.py a.jsonl b.jsonl [--list]

Every host's corpus script calls it as same.py in the G1 directory, to
compare the host's rows with the module's own (tools/corpus.sh g1 copies
it there). It is docs/evidence/2026-09-29-aprv-wasm-parity/scripts/same.py,
the copy the corpus archive carried before the nightly began deriving
its rows from main (2026-11-02, DECISIONS.md R35).
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
