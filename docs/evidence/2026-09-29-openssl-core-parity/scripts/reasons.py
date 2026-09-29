#!/usr/bin/env python3
"""Evidence only (2026-09-29). Lists how two runner row sets differ where
it matters: every row whose verdict flips (verified on one side only), and
every change of refusal reason, grouped by (old reason, old message, new
reason, new message) with a count and one example id.

    reasons.py <calls dir> <old rows prefix> <new rows prefix>
"""
import collections
import json
import sys

calls_dir, old_prefix, new_prefix = sys.argv[1:4]
flips, groups, example = [], collections.Counter(), {}
for c in ["cases", "hostile", "algorithms", "substrate", "fuzz"]:
    calls = [json.loads(l) for l in open(f"{calls_dir}/{c}.jsonl") if l.strip()]
    old = [json.loads(l) for l in open(f"{old_prefix}-{c}.jsonl") if l.strip()]
    new = [json.loads(l) for l in open(f"{new_prefix}-{c}.jsonl") if l.strip()]
    for call, o, n in zip(calls, old, new):
        oo, nn = o["out"], n["out"]
        if oo == nn:
            continue
        if bool(oo.get("verified")) != bool(nn.get("verified")):
            flips.append(f"{c}: {call['id']}: old {oo.get('reason')} ({oo.get('message')}), new "
                         + ("verified" if nn.get("verified") else f"{nn.get('reason')} ({nn.get('message')})"))
        elif "reason" in oo and "reason" in nn and oo["reason"] != nn["reason"]:
            key = (oo["reason"], oo["message"][:70], nn["reason"], nn["message"][:70])
            groups[key] += 1
            example.setdefault(key, f"{c}:{call['id']}")
print(f"verdict flips: {len(flips)}")
for f in flips:
    print("  " + f)
print(f"reason changes: {sum(groups.values())} rows in {len(groups)} groups")
for key, n in sorted(groups.items(), key=lambda kv: -kv[1]):
    print(f"  {n:4} {key[0]}: {key[1]}\n       -> {key[2]}: {key[3]}\n       e.g. {example[key]}")
