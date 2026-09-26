#!/usr/bin/env python3
"""Three-way differential: Java oracle vs current Rust vs a candidate.

    python3 tri.py requests.jsonl java.jsonl rust.jsonl candidate.jsonl [--list]

Rows come from the previous spike's runners: OracleCli (Java) and
run_rust.py (Rust C ABI, used unchanged for every candidate, since each
candidate is the same rust/ffi C ABI over a patched core).

A row's verdict is its code, plus the full response for the endpoint
(request_date* masked when the request pins no clock) and the fields
both sides carry on a success. Classes:
  agree            java == rust == candidate
  cand=java        candidate agrees with Java, Rust differs
  cand=rust        candidate agrees with Rust, Java differs
  cand-own         candidate differs from both
  abi              the C ABI cannot express the input (NUL in a C
                   string) or refuses it before the core runs
                   (101 INVALID_UTF8): not a substrate question
"""

from __future__ import annotations

import json
import sys
from collections import Counter

ABI_CODES = {"NUL_IN_BODY", "NUL_IN_INPUT", 101}


def load(path):
    return [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]


def common_diff(a, b):
    if isinstance(a, dict) and isinstance(b, dict):
        return any(common_diff(a[k], b[k]) for k in a.keys() & b.keys())
    if isinstance(a, list) and isinstance(b, list):
        return len(a) != len(b) or any(common_diff(x, y) for x, y in zip(a, b))
    if isinstance(a, (int, float)) and isinstance(b, str) or isinstance(b, (int, float)) and isinstance(a, str):
        return str(a) != str(b)
    return a != b


def verdict(req, row):
    code = row["code"]
    if code in ("CTOR_REFUSED", -1, -2, -3):
        return ("ctor",)
    doc = json.loads(row["json"]) if row.get("json") else None
    if req["kind"] == "endpoint":
        if json.loads(req["options"]).get("nowMillis") is None and isinstance(doc, dict):
            if isinstance(doc.get("receipt"), dict):
                for k in ("request_date", "request_date_ms", "request_date_pst"):
                    doc["receipt"].pop(k, None)
        return ("endpoint", json.dumps(doc, sort_keys=True))
    return (req["kind"], code, doc)


def same(a, b):
    if a[0] != b[0]:
        return False
    if a[0] in ("ctor",):
        return True
    if a[0] == "endpoint":
        return a[1] == b[1]
    if a[1] != b[1]:
        return False
    if a[1] == 0:
        return not common_diff(a[2], b[2])
    return True


def brief(v):
    if v[0] == "endpoint":
        d = json.loads(v[1]) if v[1] != "null" else None
        return f"status {d.get('status') if isinstance(d, dict) else d}"
    if v[0] == "ctor":
        return "ctor refused"
    msg = (v[2] or {}).get("message", "") if isinstance(v[2], dict) else ""
    return f"{v[1]} {msg[:110]}"


def main():
    reqs = {r["id"]: r for r in load(sys.argv[1])}
    java = {r["id"]: r for r in load(sys.argv[2])}
    rust = {r["id"]: r for r in load(sys.argv[3])}
    cand = load(sys.argv[4])
    listing = "--list" in sys.argv
    tally = Counter()
    rows = []
    for c in cand:
        rid = c["id"]
        req = reqs[rid]
        if rust[rid]["code"] in ABI_CODES or c["code"] in ABI_CODES:
            tally[(req["kind"], "abi")] += 1
            continue
        vj, vr, vc = verdict(req, java[rid]), verdict(req, rust[rid]), verdict(req, c)
        cj, cr = same(vc, vj), same(vc, vr)
        rj = same(vr, vj)
        if cj and cr:
            cls = "agree"
        elif cj:
            cls = "cand=java"
        elif cr:
            cls = "cand=rust"
        else:
            cls = "cand-own"
        tally[(req["kind"], cls)] += 1
        if cls != "agree":
            rows.append((cls, rid, brief(vj), brief(vr), brief(vc)))
    kinds = sorted({k for k, _ in tally})
    classes = ["agree", "cand=java", "cand=rust", "cand-own", "abi"]
    print("kind      " + "".join(f"{c:>11}" for c in classes))
    for k in kinds:
        print(f"{k:10}" + "".join(f"{tally[(k, c)]:>11}" for c in classes))
    total = Counter()
    for (k, c), n in tally.items():
        total[c] += n
    print(f"{'total':10}" + "".join(f"{total[c]:>11}" for c in classes))
    if listing:
        for cls, rid, j, r, c in sorted(rows):
            print(f"{cls:9} {rid}\n    java: {j}\n    rust: {r}\n    cand: {c}")


if __name__ == "__main__":
    main()
