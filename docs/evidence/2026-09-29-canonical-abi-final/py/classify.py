#!/usr/bin/env python3
"""Spike only (2026-09-29, round 13). Attributes every row where a host's
answer is not byte-identical to ABI v1's Node answer (request_date* masked
where the clock is the wall clock, as abi_compare.py does). The round-13
expectation: 6,176 identical, plus exactly these two intended categories.
First match wins:

  identical            byte-identical (after the mask)
  init-refusal         the test envelope's anchor is not a certificate: ABI v1 answered
                       INVALID_TEST_ENVELOPE, the new interface answers init's {"ok":false}
  clock-moves-chain    a pinned clock on an endpoint row: ABI v1 used it for request_date
                       only (0.6: the chain check ran on the wall clock); now-ms is also
                       the chain instant when the receipt states no date (the 0.7 rule)
  DIFFERENT            anything else: a finding

    classify.py LABEL CALLS_DIR NODE_ROWS_DIR HOST_ROWS_PREFIX [--list]
"""
import collections
import json
import re
import sys

MASK = re.compile(r'"(request_date(?:_ms|_pst)?)":"[^"]*"')
label, calls_dir, node_dir, prefix = sys.argv[1:5]
listing = "--list" in sys.argv
total = collections.Counter()
examples = collections.defaultdict(list)
for c in ("cases", "hostile", "algorithms", "substrate", "fuzz"):
    calls = {r["id"]: r for r in map(json.loads, open(f"{calls_dir}/{c}.jsonl"))}
    node = {r["id"]: r for r in map(json.loads, open(f"{node_dir}/node-{c}.jsonl"))}
    per = collections.Counter()
    for r in map(json.loads, open(f"{prefix}-{c}.jsonl")):
        call, ref = calls[r["id"]], node[r["id"]]
        a, b = ref.get("out", ref.get("trap", ref.get("map"))), r.get("out", r.get("trap", r.get("map")))
        if isinstance(a, str) and isinstance(b, str) and call.get("fn") == "verify-receipt-endpoint" and call.get("now") is None:
            a, b = MASK.sub(r'"\1":"*"', a), MASK.sub(r'"\1":"*"', b)
        if a == b:
            cat = "identical"
        elif isinstance(a, str) and "INVALID_TEST_ENVELOPE" in a and isinstance(b, str) and '"ok":false' in b:
            cat = "init-refusal"
        elif call.get("fn") == "verify-receipt-endpoint" and call.get("now") is not None:
            cat = "clock-moves-chain (endpoint, pinned clock)"
        else:
            cat = "DIFFERENT"
        per[cat] += 1
        if cat != "identical" and len(examples[cat]) < (1000 if listing else 3):
            examples[cat].append((r["id"], str(a)[:150], str(b)[:150]))
    total.update(per)
    print(f"{label} {c}: " + ", ".join(f"{k} {v}" for k, v in sorted(per.items())))
ok = total["identical"] == 6176 and total["clock-moves-chain (endpoint, pinned clock)"] == 2 and total["init-refusal"] == 1 and sum(total.values()) == 6179
print(f"{label} all: " + ", ".join(f"{k} {v}" for k, v in sorted(total.items())) + f" (rows {sum(total.values())}) -> {'AS EXPECTED' if ok else 'NOT AS EXPECTED'}")
for cat, ex in examples.items():
    for i, a, b in ex:
        print(f"  [{cat}] {i}\n      ABI v1 : {a}\n      new    : {b}")
