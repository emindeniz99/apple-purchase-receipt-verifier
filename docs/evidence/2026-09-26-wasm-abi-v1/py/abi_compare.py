#!/usr/bin/env python3
"""Spike only (ABI v1). Classifies every ABI v1 answer against the answer
the C ABI gave for the same corpus row (round 4's native rows of the same
source), and checks that other hosts' answers are byte-identical.

    python3 abi_compare.py corpus.jsonl old.jsonl calls.jsonl new.jsonl [other-host.jsonl ...] [--list]

Categories (a row falls into the first that applies):
  same-verified          both verified; the payload objects are equal
  same-failure           both refused with the same reason token (and message)
  endpoint-same          the endpoint answer is byte-identical (request_date* masked when no clock is pinned)
  old-policy-verdict     the C ABI refused on caller policy (WRONG_BUNDLE_ID, WRONG_ENVIRONMENT,
                         WRONG_APP_APPLE_ID); ABI v1 verified, and its payload carries the claim
  old-device-binding     the C ABI refused DEVICE_HASH_MISMATCH; ABI v1 takes no GUID and verified
  old-typed-model        the C ABI's typed transaction/app-transaction model refused a claim's
                         JSON type (INTERNAL_ERROR); ABI v1 returns the claims untyped
  old-config-refusal     the C ABI refused to build a verifier (no bundleId, empty roots, ...)
  old-abi-inexpressible  the C ABI could not take the input: a NUL inside a C string, or a
                         string that is not UTF-8 (its status 101 INVALID_UTF8, an argument error)
  old-der-only           the C ABI took raw DER; ABI v1 takes the receipt-data string, and this
                         DER has no acceptable one (empty, or its base64 is over MAX_RECEIPT_BYTES):
                         ABI v1 refuses it exactly as the C ABI's own base64 entry refuses that string
  transport              no ABI v1 call: an endpoint environment other than Production/Sandbox
                         (the endpoint ops are per environment; the server picks one)
  DIFFERENT              anything else: a real difference (must be 0)
"""
import base64
import collections
import json
import re
import sys

POLICY = {"WRONG_BUNDLE_ID", "WRONG_ENVIRONMENT", "WRONG_APP_APPLE_ID"}
MAX_RECEIPT_BYTES = 3_145_728
BASE64_REFUSALS = {
    "receipt-data is not valid base64",
    f"receipt exceeds the maximum accepted size of {MAX_RECEIPT_BYTES} bytes of base64",
}
MASK = re.compile(r'"(request_date(?:_ms|_pst)?)":"[^"]*"')


def load(path):
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    corpus, old, calls, new, others = load(args[0]), load(args[1]), load(args[2]), load(args[3]), [load(p) for p in args[4:]]
    listing = "--list" in sys.argv
    cats = collections.Counter()
    ident = collections.Counter()
    samples = collections.defaultdict(list)
    different = []
    for i, (req, o, c, n) in enumerate(zip(corpus, old, calls, new)):
        assert req["id"] == o["id"] == c["id"] == n["id"], (req["id"], o["id"], c["id"], n["id"])
        for k, other in enumerate(others):
            ident[k] += masked(req, other[i]) == masked(req, n)
        cat = classify(req, o, c, n)
        cats[cat] += 1
        if len(samples[cat]) < 3:
            samples[cat].append(req["id"])
        if cat == "DIFFERENT":
            different.append(f"  DIFFERENT {req['id']} {o.get('code')} {(o.get('json') or '')[:120]} || {(n.get('out') or n.get('trap') or '')[:160]}")
    total = len(corpus)
    assert total == len(old) == len(calls) == len(new)
    print(f"rows {total}: " + ", ".join(f"{k} {v}" for k, v in sorted(cats.items())))
    if listing:
        print("\n".join(different))
    for k in range(len(others)):
        print(f"other host {k + 1}: {ident[k]} of {total} rows byte-identical to the first host"
              " (request_date* masked on endpoint rows with no pinned clock: the wall clock)")
    if listing:
        for k, v in sorted(samples.items()):
            print(f"  e.g. {k}: {', '.join(v)}")


def masked(req, row):
    if req["kind"] == "endpoint" and json.loads(req["options"]).get("nowMillis") is None and "out" in row:
        return {**row, "out": MASK.sub(r'"\1":"*"', row["out"])}
    return row


def classify(req, o, c, n):
    code = o.get("code")
    if (isinstance(code, str) and code.startswith("NUL_IN")) or code == 101:
        return "old-abi-inexpressible"
    if code == "CTOR_REFUSED":
        return "old-config-refusal"
    if "op" not in c:
        return "transport"
    if "trap" in n:
        return "DIFFERENT"
    if req["kind"] == "endpoint":
        if code is not None:
            return "DIFFERENT"
        pinned = json.loads(req["options"]).get("nowMillis") is not None
        a, b = o["json"], n["out"]
        if not pinned:
            a, b = MASK.sub(r'"\1":"*"', a), MASK.sub(r'"\1":"*"', b)
        return "endpoint-same" if a == b else "DIFFERENT"
    out = json.loads(n["out"])
    old_doc = json.loads(o["json"]) if o.get("json") else None
    if "der-encoded" in c.get("map", "") and out.get("verified") is False and out.get("message") in BASE64_REFUSALS:
        der_len = len(base64.b64decode(req["input"]))
        if der_len == 0 or 4 * ((der_len + 2) // 3) > MAX_RECEIPT_BYTES:
            return "old-der-only"
    if code == 0:
        if out.get("verified") is True and out["payload"] == old_doc:
            return "same-verified"
        return "DIFFERENT"
    reason = (old_doc or {}).get("reason")
    if out.get("verified") is False:
        if out.get("reason") == reason:
            return "same-failure" if out.get("message") == old_doc.get("message") else "same-failure-message-differs"
        return "DIFFERENT"
    if out.get("verified") is True:
        if reason in POLICY:
            return "old-policy-verdict"
        if reason == "DEVICE_HASH_MISMATCH":
            return "old-device-binding"
        if reason == "INTERNAL_ERROR" and req["kind"] == "jws" and req.get("op") in (0, 1):
            return "old-typed-model"
    return "DIFFERENT"


if __name__ == "__main__":
    main()
