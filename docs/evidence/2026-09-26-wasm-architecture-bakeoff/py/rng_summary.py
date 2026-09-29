#!/usr/bin/env python3
"""Broken-RNG runs of the OpenSSL WASI module against native OpenSSL.

    python3 rng_summary.py <run-dir> <wasm-run-dir>

<run-dir>/ossl402-<corpus>.jsonl: native rows; <wasm-run-dir>/ossl-w1h-rng<mode>-<corpus>.jsonl:
rows from js/run.mjs with APRV_RANDOM=<mode> (fail: random_get answers EIO;
zero: random_get writes zeros).
"""
import json
import sys

run, wrun = sys.argv[1], sys.argv[2]
print("# OpenSSL 4.0.2 wasm32-wasip1 (ossl-w1h) with a broken host RNG, all 1,179 rows,")
print("# compared with native OpenSSL 4.0.2 (js/hosts.mjs APRV_RANDOM=fail|zero).")
for mode in ["fail", "zero"]:
    tot = same = rej = rej2 = asked = 0
    flipped = []
    for c in ["cases", "hostile", "algorithms", "substrate"]:
        nat = [json.loads(l) for l in open(f"{run}/ossl402-{c}.jsonl")]
        w = [json.loads(l) for l in open(f"{wrun}/ossl-w1h-rng{mode}-{c}.jsonl")]
        for a, b in zip(nat, w):
            tot += 1
            asked += 1 if (b.get("imports") or {}).get("wasi_snapshot_preview1.random_get") else 0
            if a["code"] == b["code"]:
                same += 1
            elif b["code"] == 0:
                flipped.append(a["id"])
            elif a["code"] == 0:
                rej += 1
            else:
                rej2 += 1
    print(f"random_get={mode}: {tot} rows, {same} same code as native, {rej} accepted natively but rejected here, {rej2} rejected with another reason, "
          f"{len(flipped)} turned into an acceptance {flipped}; rows that called random_get: {asked}")
