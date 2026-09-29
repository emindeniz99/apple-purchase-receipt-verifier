#!/usr/bin/env python3
"""Evidence only (2026-09-29). Adds the differential campaign's cases and
the test inventory's (docs/rust-core/TEST-INVENTORY.md) to
fixtures/cases.json, and their fixtures to fixtures/generated-0.7/, and
leaves every other byte of the file as it was (the file is
json.dumps(indent=2, ensure_ascii=False) plus a newline). The differential
cases go after the case they vary; the inventory's at the end. Every new
fixture is cut from generated fixtures already in the repository: request
bodies, a truncated receipt, and the shared transaction with its header,
payload or signature segment replaced. Nothing is signed, so a rerun writes
the same bytes.

    python3 add_cases.py <repo>
"""
import base64
import hashlib
import json
import os
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

# --- the test inventory's cases -------------------------------------------

REGISTRY = doc["fixtures"]


def fixture_bytes(fid):
    entry = REGISTRY[fid]
    raw = open(f"{repo}/fixtures/{entry['path']}", "rb").read()
    if entry["codec"] == "base64":
        return base64.b64decode(b"".join(raw.split()))
    if entry["codec"] == "utf8":
        return raw.decode("utf-8").strip().encode("utf-8")
    return raw


def register(fid, name, data, codec):
    """Writes fixtures/generated-0.7/<name> and registers it (role input)."""
    path = f"generated-0.7/{name}"
    open(f"{repo}/fixtures/{path}", "wb").write(data)
    logical = data.decode("utf-8").strip().encode("utf-8") if codec == "utf8" else data
    REGISTRY[fid] = {"path": path, "role": "input", "codec": codec,
                     "contentSha256": hashlib.sha256(logical).hexdigest()}
    return fid


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def roots(*fixtures):
    return {"trustedRoots": {"source": "fixtures", "fixtures": list(fixtures)} if fixtures else {"source": "defaults"}}


TAGS = ["test-inventory", "new-in-0-7"]


def endpoint(cid, description, body_fid, status, root="receipt-root", tags=(), clock=None, fault=None):
    case = {"id": cid, "description": description, "operation": "verifyReceiptEndpoint",
            "input": {"requestBody": body_fid},
            "config": {**roots(root), "environment": "SANDBOX"}}
    if clock:
        case["clock"] = {"now": clock}
    case["expected"] = {"fields": {"/status": status}}
    if fault:
        case["fault"] = fault
    case["tags"] = ["endpoint", *tags, *TAGS]
    return case


def refusal(cid, operation, description, fid, reason, fault, config, tags, clock=None):
    case = {"id": cid, "description": description, "operation": operation,
            "input": {"fixture": fid}, "config": config}
    if clock:
        case["clock"] = {"now": clock}
    case["expected"] = {"status": "error", "reason": reason}
    case["fault"] = fault
    case["tags"] = [*tags, *TAGS]
    return case


def inventory():
    receipt = fixture_bytes("receipt")
    jws = fixture_bytes("transaction").decode("ascii")
    header, payload, signature = jws.split(".")
    x5c = json.loads(unb64url(header))["x5c"]
    sig = unb64url(signature)

    def jws_with(fid, name, head=None, body=None, sign=None):
        text = ".".join([head if head is not None else header, body if body is not None else payload,
                         sign if sign is not None else signature])
        return register(fid, name, (text + "\n").encode("ascii"), "utf8")

    def head(obj):
        return b64url(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))

    cases = []
    body = lambda fid, name, text: register(fid, name, text.encode("utf-8"), "text")
    cases.append(endpoint(
        "endpoint/empty-body-answers-21002",
        "A request body of no bytes at all is not a verifyReceipt request: 21002, as Apple's endpoint answers a body it cannot read.",
        body("inventory-body-empty", "inventory-body-empty.json", ""), 21002, tags=["negative", "format"]))
    cases.append(endpoint(
        "endpoint/body-that-is-not-json-answers-21002",
        "A request body that is not JSON at all: 21002.",
        body("inventory-body-not-json", "inventory-body-not-json.json", "not json at all"), 21002,
        tags=["negative", "format"]))
    cases.append(endpoint(
        "endpoint/truncated-object-answers-21002",
        "A request body cut off inside the receipt-data string, so the object never closes: 21002, whatever the base64 before the cut would have read as.",
        body("inventory-body-truncated", "inventory-body-truncated.json", '{"receipt-data":"MIAGCSqGSIb3DQEHAqCAMIACAQ'),
        21002, tags=["negative", "format"]))
    cases.append(endpoint(
        "endpoint/literal-status-body-answers-21002",
        "A request body that is itself a verifyReceipt response, {\"status\":21002}: no receipt-data member, so 21002, and nothing of the body is echoed.",
        body("inventory-body-status", "inventory-body-status.json", '{"status":21002}'), 21002,
        tags=["negative", "format"]))
    brackets = json.dumps({"receipt-data": base64.b64encode(receipt).decode("ascii"),
                           "password": "[" * 100 + "{" * 100}, separators=(",", ":"))
    cases.append(endpoint(
        "endpoint/brackets-inside-a-string-are-not-nesting-answers-0",
        "The shared receipt with a password of a hundred [ and a hundred { characters: brackets inside a JSON string are text, not nesting, so the 64-level depth bound does not apply and the receipt verifies: 0.",
        body("inventory-body-brackets-in-a-string", "inventory-body-brackets-in-a-string.json", brackets), 0,
        tags=["positive", "limits"]))
    cases.append(endpoint(
        "endpoint/pinned-clock-does-not-rescue-a-fresh-creation-date-answers-21003",
        "The expired chain (valid 2020 to 2021) over a receipt created 2024-08-06, with the clock pinned inside the chain's window: the receipt's own creation date is the chain instant and the clock never replaces it, so the chain fails: 21003.",
        body("inventory-body-expired-fresh", "inventory-body-expired-fresh.json",
             json.dumps({"receipt-data": base64.b64encode(fixture_bytes("receipt-expired-fresh")).decode("ascii")},
                        separators=(",", ":"))),
        21003, root="receipt-expired-root", tags=["negative", "clock", "validity-window"],
        clock="2020-06-01T00:00:00Z"))
    cases.append(refusal(
        "receipt/pinned-clock-does-not-rescue-a-fresh-creation-date", "verifyReceipt",
        "The expired chain (valid 2020 to 2021) over a receipt created 2024-08-06, with the clock pinned inside the chain's window: the creation date is the chain instant whatever the clock says, so INVALID_CERTIFICATE.",
        "receipt-expired-fresh", "INVALID_CERTIFICATE", "creation-date-outside-certificate-validity-window",
        roots("receipt-expired-root"), ["receipt", "pkcs7", "negative", "clock", "validity-window"],
        clock="2020-06-01T00:00:00Z"))
    cases.append(refusal(
        "receipt/reject-receipt-truncated-to-200-bytes", "verifyReceipt",
        "The first 200 bytes of the shared receipt: the ContentInfo's length runs past the end, so MALFORMED before anything is verified.",
        register("inventory-receipt-truncated-200", "inventory-receipt-truncated-200.der", receipt[:200], "raw"),
        "MALFORMED", "truncated-envelope", roots("receipt-root"), ["receipt", "pkcs7", "negative", "der"]))
    for length, fault in ((63, "signature-one-byte-short"), (65, "signature-one-byte-long")):
        sign = b64url(sig[:63]) if length == 63 else b64url(sig + b"\x00")
        cases.append(refusal(
            f"transaction/reject-signature-of-{length}-bytes", "verifySignedData",
            f"The shared transaction with its 64-byte ES256 signature {'cut to 63 bytes' if length == 63 else 'followed by one zero byte'}: an ES256 signature is exactly 64 bytes (R || S), so INVALID_SIGNATURE before any curve arithmetic.",
            jws_with(f"inventory-transaction-signature-{length}", f"inventory-transaction-signature-{length}.jws", sign=sign),
            "INVALID_SIGNATURE", fault, roots("jws-root"), ["jws", "negative", "signature"]))
    cases.append(refusal(
        "transaction/reject-an-all-zero-signature", "verifySignedData",
        "The shared transaction with 64 zero bytes as its signature: R and S of zero are outside the group, so INVALID_SIGNATURE, never a crash in the curve code.",
        jws_with("inventory-transaction-signature-zero", "inventory-transaction-signature-zero.jws", sign=b64url(bytes(64))),
        "INVALID_SIGNATURE", "signature-scalars-zero", roots("jws-root"), ["jws", "negative", "signature"]))
    cases.append(refusal(
        "transaction/reject-a-payload-swapped-for-an-array", "verifySignedData",
        "The shared transaction's payload segment replaced with the JSON array [], its signature kept: the signature covers the header and payload segments, so INVALID_SIGNATURE, and the payload is never read as claims.",
        jws_with("inventory-transaction-payload-array", "inventory-transaction-payload-array.jws", body=b64url(b"[]")),
        "INVALID_SIGNATURE", "payload-segment-replaced", roots("jws-root"), ["jws", "negative", "verification-order"]))
    cases.append(refusal(
        "transaction/reject-broken-signature-segment-under-a-foreign-chain", "verifySignedData",
        "The shared transaction with four characters outside base64url after its signature, under Apple's roots, which did not issue its chain: the segments are decoded before the chain is looked at, so MALFORMED rather than UNTRUSTED_CHAIN.",
        jws_with("inventory-transaction-signature-junk", "inventory-transaction-signature-junk.jws", sign=signature + "!!!!"),
        "MALFORMED", "signature-segment-not-base64url", roots(), ["jws", "negative", "verification-order"]))
    header_cases = [
        ("signed-data/reject-x5c-that-is-an-object", {"alg": "ES256", "x5c": {"0": x5c[0]}}, "MALFORMED", "x5c-not-an-array",
         "The header's x5c is an object holding the leaf, not an array: MALFORMED, as for any x5c that is not three certificates."),
        ("signed-data/reject-x5c-of-numbers", {"alg": "ES256", "x5c": [1, 2, 3]}, "MALFORMED", "x5c-entries-not-strings",
         "The header's x5c holds three numbers: MALFORMED."),
        ("signed-data/reject-x5c-with-null-and-a-list", {"alg": "ES256", "x5c": [x5c[0], None, []]}, "MALFORMED", "x5c-entries-not-strings",
         "The header's x5c holds the leaf, a null and an empty list: MALFORMED."),
        ("signed-data/reject-a-four-certificate-x5c", {"alg": "ES256", "x5c": x5c + [x5c[2]]}, "MALFORMED", "x5c-four-certificates",
         "The genuine x5c with its root repeated as a fourth entry: the chain is exactly leaf, intermediate and root, so MALFORMED."),
        ("signed-data/reject-alg-in-lower-case", {"alg": "es256", "x5c": x5c}, "MALFORMED", "alg-lower-case",
         "The header's alg is es256: algorithm names are case-sensitive (RFC 7518 section 3.1), so MALFORMED."),
        ("signed-data/reject-x5c-leaf-behind-a-byte-order-mark", {"alg": "ES256", "x5c": ["\ufeff" + x5c[0], x5c[1], x5c[2]]},
         "INVALID_CERTIFICATE", "x5c-entry-byte-order-mark",
         "The leaf's x5c entry starts with U+FEFF: an x5c entry is strict standard base64, so the leaf does not decode: INVALID_CERTIFICATE."),
    ]
    for cid, obj, reason, fault, description in header_cases:
        name = "inventory-" + cid.split("/", 1)[1].replace("reject-", "") + ".jws"
        fid = name[:-4]
        cases.append(refusal(cid, "verifySignedData", description, jws_with(fid, name, head=head(obj)), reason, fault,
                             roots("jws-root"), ["jws", "negative", "format"]))
    return cases


ids = {c["id"] for c in doc["cases"]}
out = []
added = 0
for case in doc["cases"]:
    out.append(case)
    for new in NEW.get(case["id"], []):
        if new["id"] not in ids:
            out.append(new)
            added += 1
for new in inventory():
    if new["id"] not in ids:
        out.append(new)
        added += 1
doc["cases"] = out
open(path, "w", encoding="utf-8").write(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
print(f"add_cases: {added} added, {len(out)} cases")
