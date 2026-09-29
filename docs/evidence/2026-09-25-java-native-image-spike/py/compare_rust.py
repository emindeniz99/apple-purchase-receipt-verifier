#!/usr/bin/env python3
"""Compares native-image rows with Rust C ABI rows for the same requests.

    python3 compare_rust.py requests.jsonl native.jsonl rust.jsonl

Receipt and JWS: the reason code must match (both ABIs number the shared
reasons 1-10 and 12 identically) and, on success, every field both JSON
documents carry must be equal. Endpoint: Apple's response JSON must be
equal (request_date* masked when the request pins no clock). Constructor
refusals match when both sides refuse. Rows the Rust ABI cannot express
(a NUL byte inside a NUL-terminated string) are counted separately.
"""

from __future__ import annotations

import json
import sys
from collections import Counter


def load(path):
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]


def common_diff(a, b, path=""):
    """Paths where two JSON values differ, over keys both objects carry."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for k in a.keys() & b.keys():
            out += common_diff(a[k], b[k], f"{path}.{k}")
        return out
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return [f"{path}.length {len(a)} vs {len(b)}"]
        out = []
        for i, (x, y) in enumerate(zip(a, b)):
            out += common_diff(x, y, f"{path}[{i}]")
        return out
    if isinstance(a, (int, float)) and isinstance(b, str) or isinstance(b, (int, float)) and isinstance(a, str):
        return [] if str(a) == str(b) else [f"{path}: {a!r} vs {b!r}"]
    return [] if a == b else [f"{path}: {a!r} vs {b!r}"]


def main():
    reqs = {r["id"]: r for r in load(sys.argv[1])}
    ni = load(sys.argv[2])
    ru = {r["id"]: r for r in load(sys.argv[3])}
    tally = Counter()
    report = []
    for row in ni:
        r = reqs[row["id"]]
        other = ru[row["id"]]
        if other["code"] in ("NUL_IN_BODY", "NUL_IN_INPUT"):
            tally["not expressible in the Rust ABI (NUL in a C string)"] += 1
            continue
        if other["code"] == "CTOR_REFUSED" or row["code"] in (-1, -2, -3):
            ok = other["code"] == "CTOR_REFUSED" and row["code"] in (-1, -2, -3)
            tally["constructor refused: both" if ok else "constructor refused: one side only"] += 1
            if not ok:
                report.append((row["id"], row["code"], other["code"], row["json"], other["json"]))
            continue
        a = json.loads(row["json"]) if row["json"] else None
        b = json.loads(other["json"]) if other["json"] else None
        if r["kind"] == "endpoint":
            if json.loads(r["options"]).get("nowMillis") is None:
                for doc in (a, b):
                    if isinstance(doc, dict) and isinstance(doc.get("receipt"), dict):
                        for k in ("request_date", "request_date_ms", "request_date_pst"):
                            doc["receipt"].pop(k, None)
            if a == b:
                tally["endpoint: identical response"] += 1
            else:
                tally["endpoint: DIFFERENT response"] += 1
                report.append((row["id"], row["code"], other["code"], a, b))
            continue
        if row["code"] != other["code"]:
            tally[f"{r['kind']}: DIFFERENT code"] += 1
            report.append((row["id"], row["code"], other["code"], a, b))
            continue
        if row["code"] == 0:
            d = common_diff(a, b)
            if d:
                tally[f"{r['kind']}: same code, DIFFERENT fields"] += 1
                report.append((row["id"], 0, 0, d[:5], None))
            else:
                tally[f"{r['kind']}: success, common fields equal"] += 1
        else:
            tally[f"{r['kind']}: same failure code"] += 1
    for id_, ca, cb, a, b in report:
        print(f"DIVERGE {id_}: native/java {ca} vs rust {cb}\n  java: {json.dumps(a)[:400]}\n  rust: {json.dumps(b)[:400]}")
    for k, v in sorted(tally.items()):
        print(f"{v:5d}  {k}")
    return 1 if report else 0


if __name__ == "__main__":
    sys.exit(main())
