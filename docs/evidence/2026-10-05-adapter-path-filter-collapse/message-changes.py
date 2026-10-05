#!/usr/bin/env python3
"""Evidence only (2026-10-05). Counts the message changes between two row
sets of the same calls, over the five corpora, as `'old' -> 'new'` pairs
(an ES256 length in a message is folded to `got N`), most frequent first.
The rows that differ in verdict, reason or payload are counted too, by
the same pairs, so the total is every row that differs.

    message-changes.py <rows dir a> <rows dir b>
"""
import collections
import json
import re
import sys

pairs = collections.Counter()
for corpus in ("cases", "hostile", "algorithms", "substrate", "fuzz"):
    a = [json.loads(l) for l in open(f"{sys.argv[1]}/{corpus}.jsonl", encoding="utf-8") if l.strip()]
    b = [json.loads(l) for l in open(f"{sys.argv[2]}/{corpus}.jsonl", encoding="utf-8") if l.strip()]
    assert len(a) == len(b), (corpus, len(a), len(b))
    for x, y in zip(a, b):
        assert x["id"] == y["id"], (x["id"], y["id"])
        if x == y:
            continue
        old = json.loads(x["out"]).get("message", "")
        new = json.loads(y["out"]).get("message", "")
        pairs[(re.sub(r"got \d+", "got N", old), new)] += 1
for (old, new), count in pairs.most_common():
    print(f"{count:4}  {old!r} -> {new!r}")
print(f"{sum(pairs.values()):4}  rows differ in all")
