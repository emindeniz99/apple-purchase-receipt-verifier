#!/usr/bin/env python3
"""Evidence only (2026-10-05). Classifies the differences between two row
sets of the same calls: verdict (one verifies, the other refuses, or an
endpoint status differs), reason (both refuse, for different reasons),
payload (both verify, different payloads or bodies), message (same verdict
and reason, other text).

    classify.py a.jsonl b.jsonl [--list]
"""
import collections
import json
import sys

def answer(row):
    if "out" not in row:
        return ("other", json.dumps(row, sort_keys=True))
    out = json.loads(row["out"])
    if "status" in out:  # an endpoint body
        return ("endpoint", out["status"])
    if out.get("verified"):
        return ("ok", None)
    return ("refused", out.get("reason"))

args = [a for a in sys.argv[1:] if not a.startswith("--")]
a = [json.loads(l) for l in open(args[0], encoding="utf-8") if l.strip()]
b = [json.loads(l) for l in open(args[1], encoding="utf-8") if l.strip()]
assert len(a) == len(b), (len(a), len(b))
classes = collections.Counter()
listed = []
for x, y in zip(a, b):
    assert x["id"] == y["id"], (x["id"], y["id"])
    if x == y:
        classes["same"] += 1
        continue
    ax, ay = answer(x), answer(y)
    if ax == ay:
        kind = "payload" if ax[0] in ("ok", "endpoint") else "message"
    elif ax[0] == ay[0] == "refused":
        kind = "reason"
    else:
        kind = "verdict"
    classes[kind] += 1
    listed.append((kind, x, y))
print(f"{len(a)} rows: " + ", ".join(f"{k} {v}" for k, v in sorted(classes.items())))
if "--list" in sys.argv:
    for kind, x, y in listed:
        if kind == "message" and "--all" not in sys.argv:
            continue
        print(f"  {kind} {x['id']}\n    a: {x.get('out', x)[:260]}\n    b: {y.get('out', y)[:260]}")
sys.exit(1 if any(k in classes for k in ("verdict", "reason", "payload")) else 0)
