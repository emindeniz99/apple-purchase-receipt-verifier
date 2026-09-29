#!/usr/bin/env python3
"""Checks results against fixtures/cases.json, or two result files against each other.

    python3 check.py expect cases.jsonl native.jsonl     # every case's expected verdict and fields
    python3 check.py diff   a.jsonl b.jsonl              # code and JSON identical, line by line

`expect` asserts what ConformanceCasesTest asserts: the reason of an error
case; the listed fields of a success (subset semantics, nested paths); and an
endpoint case's failureReason, which this ABI returns as the call's code.

`diff` compares code and the parsed JSON. The only field masked is the
endpoint's request_date* triple when the case pins no clock (it is the
system clock at call time in both runs).
"""

from __future__ import annotations

import json
import sys

REASONS = {
    "INVALID_JWS_FORMAT": 1, "INVALID_CERTIFICATE": 2, "INVALID_CERTIFICATE_PURPOSE": 3, "INVALID_CHAIN": 4,
    "INVALID_SIGNATURE": 5, "WRONG_BUNDLE_ID": 6, "WRONG_ENVIRONMENT": 7, "WRONG_APP_APPLE_ID": 8,
    "INVALID_RECEIPT_FORMAT": 9, "DEVICE_HASH_MISMATCH": 10, "MALFORMED_REQUEST": 11, "INTERNAL_ERROR": 12,
    "REQUEST_TOO_LARGE": 13,
}
MISSING = object()

# Cases this ABI cannot express as written, each with the reason. Reported as
# EXPLAINED, never as passed.
EXPLAINED = {
    "endpoint/receipt-data-over-the-receipt-cap-answers-21002":
        "ConformanceCasesTest hands the endpoint a Map, skipping the 3,145,728-byte body cap; "
        "through a request-body ABI a receipt-data over the receipt cap always makes the body "
        "exceed the body cap, so failureReason is REQUEST_TOO_LARGE (13). The wire status is 21002 either way.",
}


def load(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def steps(path):
    out, cur, i = [], "", 0
    while i < len(path):
        c = path[i]
        if c == ".":
            if cur:
                out.append(("name", cur)); cur = ""
        elif c == "[":
            if cur:
                out.append(("name", cur)); cur = ""
            j = path.index("]", i)
            out.append(("bracket", path[i + 1 : j])); i = j
        else:
            cur += c
        i += 1
    if cur:
        out.append(("name", cur))
    return out


def resolve(root, path):
    cur = root
    for kind, step in steps(path):
        if cur is None:
            return None
        if kind == "name":
            if step == "length" and isinstance(cur, (list, dict)):
                return len(cur)
            if not isinstance(cur, dict) or step not in cur:
                return MISSING
            cur = cur[step]
        elif "=" in step:
            key, _, want = step.partition("=")
            hits = [e for e in cur if isinstance(e, dict) and str(e.get(key)) == want]
            if len(hits) != 1:
                return MISSING
            cur = hits[0]
        elif isinstance(cur, list):
            k = int(step)
            if k >= len(cur):
                return MISSING
            cur = cur[k]
        else:
            if not isinstance(cur, dict) or step not in cur:
                return MISSING
            cur = cur[step]
    return cur


def same(want, got):
    if isinstance(want, bool) or isinstance(got, bool):
        return want == got
    if isinstance(want, (int, float)) and isinstance(got, (int, float)):
        return want == got
    return want == got


def expect(requests_path, results_path):
    requests = {r["id"]: r for r in load(requests_path)}
    results = load(results_path)
    passed = failed = fields = explained = 0
    for row in results:
        case = requests[row["id"]]["case"]
        exp = case["expected"]
        payload = json.loads(row["json"]) if row["json"] else None
        problem = ""
        if case["operation"] == "verifyReceiptEndpoint":
            if "failureReason" in exp:
                want = REASONS[exp["failureReason"]] if exp["failureReason"] else 0
                if row["code"] != want:
                    problem = f"failureReason: want {exp['failureReason']} ({want}), got code {row['code']}"
            elif row["code"] < 0:
                problem = f"ABI error code {row['code']}: {payload}"
        elif exp["status"] == "error":
            want = REASONS[exp["reason"]]
            if row["code"] != want or (payload or {}).get("reason") != exp["reason"]:
                problem = f"want {exp['reason']} ({want}), got {row['code']} {payload}"
        elif row["code"] != 0:
            problem = f"want success, got {row['code']} {payload}"
        if not problem and (exp["status"] == "ok" or case["operation"] == "verifyReceiptEndpoint"):
            for path, want in (exp.get("fields") or {}).items():
                fields += 1
                got = resolve(payload, path)
                if want is None:
                    if got not in (None, MISSING):
                        problem = f"{path}: want absent, got {got!r}"; break
                elif got is MISSING or not same(want, got):
                    problem = f"{path}: want {want!r}, got {'nothing' if got is MISSING else repr(got)}"; break
        if problem and row["id"] in EXPLAINED:
            explained += 1
            print(f"EXPLAINED {row['id']}: {problem}. {EXPLAINED[row['id']]}")
        elif problem:
            failed += 1
            print(f"FAIL {row['id']}: {problem}")
        else:
            passed += 1
    ran = {r["id"] for r in results}
    missing = [i for i in requests if i not in ran]
    print(f"expect: {passed} passed, {failed} failed, {explained} explained, {len(missing)} not run, "
          f"{fields} expected fields checked")
    return 1 if failed or missing else 0


def masked(row, request_by_id):
    payload = json.loads(row["json"]) if row["json"] else None
    req = request_by_id.get(row["id"]) if request_by_id else None
    if isinstance(payload, dict) and isinstance(payload.get("receipt"), dict):
        opts = json.loads(req["options"]) if req else {}
        if opts.get("nowMillis") is None:
            for k in ("request_date", "request_date_ms", "request_date_pst"):
                payload["receipt"].pop(k, None)
    return row["code"], payload


def diff(a_path, b_path, requests_path=None):
    a, b = load(a_path), load(b_path)
    reqs = {r["id"]: r for r in load(requests_path)} if requests_path else None
    if [r["id"] for r in a] != [r["id"] for r in b]:
        print("the two files do not hold the same ids in the same order")
        return 1
    same_rows = code_only = 0
    diffs = []
    for x, y in zip(a, b):
        cx, px = masked(x, reqs)
        cy, py = masked(y, reqs)
        if cx == cy and px == py:
            same_rows += 1
        else:
            if cx == cy:
                code_only += 1
            diffs.append((x["id"], cx, cy, px, py))
    for id_, cx, cy, px, py in diffs[:40]:
        print(f"DIFF {id_}: code {cx} vs {cy}\n  a: {json.dumps(px)[:300]}\n  b: {json.dumps(py)[:300]}")
    print(f"diff: {same_rows} identical, {len(diffs)} different ({code_only} with the same code), of {len(a)}")
    return 1 if diffs else 0


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "expect":
        sys.exit(expect(sys.argv[2], sys.argv[3]))
    sys.exit(diff(sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else None))
