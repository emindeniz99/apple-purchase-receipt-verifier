#!/usr/bin/env python3
"""Writes the spike's request corpus as JSON lines, one request per line.

    python3 requests_gen.py $REPO/fixtures cases   > cases.jsonl
    python3 requests_gen.py $REPO/fixtures hostile > hostile.jsonl

`cases`: every fixtures/cases.json case except the 33 decodeBase64 groups
(the ABI exposes no bare decoder), built the way ConformanceCasesTest builds
them: same roots, bundle id, accept set, app Apple id, device GUID, clock.

`hostile`: a deterministic (seeded) corpus of malformed and mutated inputs
for the three calls: bit flips, truncations, appended bytes, random bytes,
deep nesting, oversize inputs, non-UTF-8, JSON oddities. No expectations:
it exists for the differential (native image vs JVM vs Rust) and the crash
check.

Request: {"id", "kind": receipt|jws|endpoint, "options": "<json>",
"input": "<base64 bytes>", "base64": bool, "guidHex": str|null, "op": int,
"case": <cases.json case, cases corpus only>}
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
import re
import sys
from pathlib import Path

JWS_OPS = {"verifyTransaction": 0, "verifyAppTransaction": 1, "verifyRaw": 2}
ALL_ENVIRONMENTS = ["Production", "Sandbox", "Xcode", "LocalTesting"]


def fixture_bytes(directory: Path, registry: dict, name: str) -> bytes:
    entry = registry[name]
    raw = (directory / entry["path"]).read_bytes()
    codec = entry["codec"]
    if codec in ("raw", "text"):
        data = raw
    elif codec == "utf8":
        data = raw.decode("utf-8").strip().encode("utf-8")
    elif codec == "base64":
        data = base64.b64decode(re.sub(rb"\s+", b"", raw))
    else:
        raise SystemExit(f"unknown codec {codec}")
    if hashlib.sha256(data).hexdigest() != entry["contentSha256"]:
        raise SystemExit(f"fixture {name} drifted from cases.json")
    return data


def roots_option(directory, registry, spec):
    if spec["source"] == "builtin":
        return None
    return [base64.b64encode(fixture_bytes(directory, registry, n)).decode() for n in spec["fixtures"]]


def millis(iso: str) -> int:
    from datetime import datetime
    return round(datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp() * 1000)


def request(id_, kind, options, data: bytes, **extra):
    row = {"id": id_, "kind": kind, "options": json.dumps(options, separators=(",", ":")),
           "input": base64.b64encode(data).decode(), "base64": False, "guidHex": None, "op": 0}
    row.update(extra)
    return row


def case_requests(directory: Path):
    file = json.loads((directory / "cases.json").read_text(encoding="utf-8"))
    registry = file["fixtures"]
    for case in file["cases"]:
        op = case["operation"]
        if op == "decodeBase64":
            continue
        config = case["config"]
        roots = roots_option(directory, registry, config["trustedRoots"])
        spec = case["input"]
        fixture = spec.get("requestBody") or spec["fixture"]
        data = fixture_bytes(directory, registry, fixture)
        if op in JWS_OPS:
            options = {"bundleId": config.get("bundleId", ""),
                       "acceptedEnvironments": config.get("acceptedEnvironments", ALL_ENVIRONMENTS),
                       "appAppleId": config.get("appAppleId"), "roots": roots}
            yield request(case["id"], "jws", options, data, op=JWS_OPS[op], case=case)
        elif op in ("verifyReceipt", "verifyReceiptBase64"):
            options = {"bundleId": config["bundleId"], "roots": roots}
            yield request(case["id"], "receipt", options, data, base64=(op == "verifyReceiptBase64"),
                          guidHex=config.get("deviceGuidHex"), case=case)
        elif op == "verifyReceiptEndpoint":
            options = {"environment": config["environment"], "roots": roots,
                       "nowMillis": millis(case["clock"]["now"]) if case.get("clock") else None}
            if "requestBody" in spec:
                body = data
            else:
                codec = registry[spec["fixture"]]["codec"]
                receipt_data = data.decode("utf-8") if codec == "text" else base64.b64encode(data).decode()
                body = json.dumps({"receipt-data": receipt_data}).encode()
            yield request(case["id"], "endpoint", options, body, case=case)
        else:
            raise SystemExit(f"no adapter for {op}")


def mutations(rng: random.Random, data: bytes, count: int):
    """Bit flips, byte overwrites, truncations, extensions and splices."""
    n = len(data)
    for i in range(count):
        kind = i % 6
        b = bytearray(data)
        if kind == 0:  # one bit flip
            p = rng.randrange(n); b[p] ^= 1 << rng.randrange(8)
        elif kind == 1:  # up to 8 random bytes overwritten
            for _ in range(rng.randrange(1, 9)):
                b[rng.randrange(n)] = rng.randrange(256)
        elif kind == 2:  # truncation
            b = b[: rng.randrange(n)]
        elif kind == 3:  # appended garbage
            b += bytes(rng.randrange(256) for _ in range(rng.randrange(1, 64)))
        elif kind == 4:  # chunk duplicated in place
            p = rng.randrange(n); q = min(n, p + rng.randrange(1, 200)); b[p:p] = b[p:q]
        else:  # chunk deleted
            p = rng.randrange(n); del b[p : p + rng.randrange(1, 200)]
        yield f"m{kind}", bytes(b)


def hostile_requests(directory: Path):
    file = json.loads((directory / "cases.json").read_text(encoding="utf-8"))
    registry = file["fixtures"]
    rng = random.Random(20260925)
    g5 = fixture_bytes(directory, registry, "public-receipt-sandbox-g5")
    gen_receipt = fixture_bytes(directory, registry, "receipt")
    receipt_root = [base64.b64encode(fixture_bytes(directory, registry, "receipt-root")).decode()]
    jws = fixture_bytes(directory, registry, "transaction")
    jws_root = [base64.b64encode(fixture_bytes(directory, registry, "jws-root")).decode()]

    apple_receipt = {"bundleId": "dev.bonzer.weeka.app", "roots": None}
    gen_receipt_opts = {"bundleId": "com.example.app", "roots": receipt_root}
    jws_opts = {"bundleId": "com.example.app", "acceptedEnvironments": ALL_ENVIRONMENTS, "appAppleId": None,
                "roots": jws_root}
    endpoint_apple = {"environment": "Sandbox", "roots": None, "nowMillis": 1767225600000}

    # --- receipts: DER
    fixed = {
        "empty": b"",
        "zero": b"\x00",
        "seq-only": b"\x30\x00",
        "indef-nest-10k": b"\x30\x80" * 10000,
        "definite-nest-2k": b"".join(b"\x30\x84" + (4 * (2000 - i)).to_bytes(4, "big") for i in range(2000)),
        "huge-length": b"\x30\x84\xff\xff\xff\xff",
        "oid-overflow": b"\x06\x10" + b"\xff" * 16,
        "random-4k": bytes(rng.randrange(256) for _ in range(4096)),
        "over-cap": b"\x30" + b"\x00" * 3145728,
    }
    for name, data in fixed.items():
        yield request(f"hostile/receipt-der/{name}", "receipt", apple_receipt, data)
    for tag, data in mutations(rng, g5, 240):
        yield request(f"hostile/receipt-der/g5-{tag}-{rng.randrange(1 << 30)}", "receipt", apple_receipt, data)
    for tag, data in mutations(rng, gen_receipt, 120):
        yield request(f"hostile/receipt-der/gen-{tag}-{rng.randrange(1 << 30)}", "receipt", gen_receipt_opts, data)
    # device GUID edge cases on a genuine receipt
    for name, guid in {"guid-empty": "", "guid-1": "00", "guid-16": "00" * 16, "guid-4k": "ab" * 4096}.items():
        yield request(f"hostile/receipt-der/g5-{name}", "receipt", apple_receipt, g5, guidHex=guid)

    # --- receipts: base64 text
    b64 = base64.b64encode(g5)
    texts = {
        "empty": b"", "spaces": b"   ", "not-base64": b"!!!!", "unicode": "é𝄞".encode(),
        "invalid-utf8": b"\xff\xfe\xfd", "nul-inside": b64[:100] + b"\x00" + b64[100:],
        "crlf-wrapped": b"\r\n".join(b64[i:i + 76] for i in range(0, len(b64), 76)),
        "url-alphabet": b64.replace(b"+", b"-").replace(b"/", b"_"),
        "no-padding": b64.rstrip(b"="), "double-padding": b64 + b"==",
    }
    for name, data in texts.items():
        yield request(f"hostile/receipt-b64/{name}", "receipt", apple_receipt, data, base64=True)
    for tag, data in mutations(rng, b64, 60):
        yield request(f"hostile/receipt-b64/{tag}-{rng.randrange(1 << 30)}", "receipt", apple_receipt, data, base64=True)

    # --- JWS
    header, payload, signature = jws.split(b".")
    jws_fixed = {
        "empty": b"", "dots": b"..", "four-segments": jws + b".x", "no-dots": header,
        "not-json-header": base64.urlsafe_b64encode(b"not json").rstrip(b"=") + b"." + payload + b"." + signature,
        "alg-none": base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=") + b"." + payload + b".",
        "deep-header": base64.urlsafe_b64encode(b"[" * 5000 + b"]" * 5000).rstrip(b"=") + b"." + payload + b"." + signature,
        "x5c-numbers": base64.urlsafe_b64encode(b'{"alg":"ES256","x5c":[1,2,3]}').rstrip(b"=") + b"." + payload + b"." + signature,
        "x5c-garbage": base64.urlsafe_b64encode(b'{"alg":"ES256","x5c":["AAAA","AAAA","AAAA"]}').rstrip(b"=") + b"." + payload + b"." + signature,
        "sig-empty": header + b"." + payload + b".",
        "sig-65": header + b"." + payload + b"." + base64.urlsafe_b64encode(b"\x01" * 65).rstrip(b"="),
        "invalid-utf8": b"\xff\xfe." + payload + b"." + signature,
        "over-cap": b"a" * 262145,
    }
    for name, data in jws_fixed.items():
        for op in (0, 2):
            yield request(f"hostile/jws/{name}/op{op}", "jws", jws_opts, data, op=op)
    for tag, data in mutations(rng, jws, 200):
        yield request(f"hostile/jws/{tag}-{rng.randrange(1 << 30)}", "jws", jws_opts, data, op=rng.choice((0, 1, 2)))

    # --- endpoint bodies
    good = json.dumps({"receipt-data": b64.decode()}).encode()
    bodies = {
        "empty": b"", "null": b"null", "array": b"[]", "number": b"1", "string": b'"x"', "not-json": b"not json",
        "receipt-data-number": b'{"receipt-data":1}', "receipt-data-null": b'{"receipt-data":null}',
        "receipt-data-empty": b'{"receipt-data":""}', "receipt-data-object": b'{"receipt-data":{}}',
        "duplicate-key": b'{"receipt-data":"AAAA","receipt-data":' + json.dumps(b64.decode()).encode() + b"}",
        "nested-1000": b'{"a":' + b"[" * 1000 + b"]" * 1000 + b"}",
        "invalid-utf8": b'{"receipt-data":"\xff"}',
        "trailing-garbage": good + b"xyz",
        "bom": b"\xef\xbb\xbf" + good,
        "over-cap": b'{"receipt-data":"' + b"A" * 3145728 + b'"}',
        "genuine": good,
    }
    for name, data in bodies.items():
        yield request(f"hostile/endpoint/{name}", "endpoint", endpoint_apple, data)
    for tag, data in mutations(rng, good, 120):
        yield request(f"hostile/endpoint/{tag}-{rng.randrange(1 << 30)}", "endpoint", endpoint_apple, data)

    # --- constructor-level oddities (handled as constructor failures)
    yield request("hostile/ctor/receipt-empty-roots", "receipt", {"bundleId": "x", "roots": []}, g5)
    yield request("hostile/ctor/receipt-null-bundle", "receipt", {"roots": None}, g5)
    yield request("hostile/ctor/jws-no-environments", "jws", dict(jws_opts, acceptedEnvironments=[]), jws)
    yield request("hostile/ctor/endpoint-xcode", "endpoint", dict(endpoint_apple, environment="Xcode"), good)
    yield request("hostile/ctor/root-not-a-cert", "receipt", {"bundleId": "x", "roots": ["AAAA"]}, g5)


def main():
    directory = Path(sys.argv[1])
    which = sys.argv[2]
    rows = case_requests(directory) if which == "cases" else hostile_requests(directory)
    for row in rows:
        print(json.dumps(row, separators=(",", ":")))


if __name__ == "__main__":
    main()
