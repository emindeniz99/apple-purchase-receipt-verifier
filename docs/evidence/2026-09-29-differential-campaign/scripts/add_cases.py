#!/usr/bin/env python3
"""Evidence only (2026-09-29). Adds the differential campaign's cases to
fixtures/cases.json, each after the case it varies, and leaves every other
byte of the file as it was (the file is json.dumps(indent=2,
ensure_ascii=False) plus a newline).

    python3 add_cases.py <repo>
"""
import json
import sys

repo = sys.argv[1]
path = f"{repo}/fixtures/cases.json"
text = open(path, encoding="utf-8").read()
doc = json.loads(text)
assert json.dumps(doc, indent=2, ensure_ascii=False) + "\n" == text, "cases.json is not in canonical form"


def stranger(order, roots):
    return {
        "id": f"receipt/verify-with-a-stranger-vouched-by-a-same-named-root-listed-{order}",
        "description": (
            "The receipt of receipt/verify-with-a-stranger-whose-key-is-unreadable with both roots pinned, "
            f"the stranger's root {order}. The two roots share a subject name and each vouches for "
            "certificates in the unsigned bag: the genuine chain, and the stranger's intermediate and "
            "signer (a key on an unimplemented curve). The receipt verifies whatever the order of the "
            "roots. The core answered UNTRUSTED_CHAIN with the stranger's root first, because OpenSSL's "
            "issuer lookup takes the first root whose name matches (the differential campaign of "
            "2026-09-29). Apple's three roots have distinct names."
        ),
        "operation": "verifyReceipt",
        "input": {"fixture": "review-receipt-stranger-unreadable-key"},
        "config": {"trustedRoots": {"source": "fixtures", "fixtures": roots}},
        "expected": {"status": "ok", "fields": {"/bundle_id": "com.example.app"}},
        "tags": ["receipt", "pkcs7", "chain", "pinning", "positive", "differential", "new-in-0-7"],
    }


NEW = {
    "receipt/verify-with-a-stranger-whose-key-is-unreadable": [
        stranger("first", ["receipt-signer-root", "review-receipt-root"]),
        stranger("second", ["review-receipt-root", "receipt-signer-root"]),
    ],
}

ids = {c["id"] for c in doc["cases"]}
out = []
added = 0
for case in doc["cases"]:
    out.append(case)
    for new in NEW.get(case["id"], []):
        if new["id"] not in ids:
            out.append(new)
            added += 1
doc["cases"] = out
open(path, "w", encoding="utf-8").write(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
print(f"add_cases: {added} added, {len(out)} cases")
