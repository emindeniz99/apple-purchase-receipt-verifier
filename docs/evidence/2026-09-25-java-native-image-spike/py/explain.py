#!/usr/bin/env python3
"""Explains each native-image vs Rust verdict divergence on the hostile corpus.

    python3 explain.py $REPO/fixtures hostile.jsonl native.jsonl rust.jsonl

For a mutated receipt or JWS it prints what was changed (offset, old and new
byte) and where that byte sits: the DER path (tag chain) for a receipt, the
segment and decoded position for a JWS. Then both sides' messages. Rows that
differ only because the Rust ABI refuses non-UTF-8 input (APRV_REASON_INVALID_UTF8,
101) before verification are summarised, not listed.
"""

from __future__ import annotations

import base64
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from requests_gen import fixture_bytes  # noqa: E402

TAGS = {0x30: "SEQ", 0x31: "SET", 0x02: "INT", 0x04: "OCTETS", 0x06: "OID", 0x05: "NULL", 0x03: "BITS",
        0xA0: "[0]", 0xA1: "[1]", 0xA3: "[3]", 0x17: "UTCTime", 0x18: "GenTime", 0x0C: "UTF8", 0x13: "PrintStr",
        0x16: "IA5", 0x01: "BOOL"}


def der_path(data: bytes, target: int):
    """Tag chain from the root to the TLV holding byte `target` (best effort, definite lengths)."""
    path = []

    def walk(start, end, depth):
        i = start
        while i < end and depth < 40:
            tag = data[i]
            if i + 1 >= len(data):
                return
            first = data[i + 1]
            if first < 0x80:
                length, hdr = first, 2
            else:
                n = first & 0x7F
                if n == 0 or n > 4:
                    return
                length, hdr = int.from_bytes(data[i + 2 : i + 2 + n], "big"), 2 + n
            body = i + hdr
            if i <= target < body + length:
                idx = sum(1 for _ in [])
                path.append(f"{TAGS.get(tag, hex(tag))}@{i}" + ("(header)" if target < body else ""))
                if target >= body and (tag & 0x20 or tag in (0x04,)):
                    if tag == 0x04:  # OCTET STRING: the receipt payload is DER inside one
                        walk(body, body + length, depth + 1)
                    else:
                        walk(body, body + length, depth + 1)
                return
            i = body + length

    walk(0, len(data), 0)
    return " > ".join(path)


def first_diff(a: bytes, b: bytes):
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i, x, y
    return min(len(a), len(b)), None, None


def main():
    fixtures, reqs, ni, ru = Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
    file = json.loads((fixtures / "cases.json").read_text())
    reg = file["fixtures"]
    originals = {
        "g5": fixture_bytes(fixtures, reg, "public-receipt-sandbox-g5"),
        "gen": fixture_bytes(fixtures, reg, "receipt"),
        "jws": fixture_bytes(fixtures, reg, "transaction"),
    }
    req = {json.loads(l)["id"]: json.loads(l) for l in open(reqs)}
    a = {json.loads(l)["id"]: json.loads(l) for l in open(ni)}
    b = {json.loads(l)["id"]: json.loads(l) for l in open(ru)}
    utf8 = Counter()
    for id_, r in req.items():
        x, y = a[id_], b[id_]
        if r["kind"] == "endpoint" or y["code"] in ("NUL_IN_BODY", "NUL_IN_INPUT", "CTOR_REFUSED") or x["code"] < 0:
            continue
        if x["code"] == y["code"]:
            continue
        if y["code"] == 101:
            utf8[(r["kind"], x["code"])] += 1
            continue
        data = base64.b64decode(r["input"])
        print(f"== {id_}: java {x['code']} vs rust {y['code']}")
        if r["kind"] == "receipt" and not r.get("base64"):
            orig = originals["g5" if "/g5-" in id_ else "gen"]
            off, old, new = first_diff(orig, data)
            print(f"   len {len(orig)} -> {len(data)}, first change at byte {off}: {old} -> {new}")
            print(f"   DER path: {der_path(orig, off)}")
        elif r["kind"] == "jws":
            orig = originals["jws"]
            off, old, new = first_diff(orig, data)
            seg = orig[:off].count(b".")
            print(f"   first change at char {off} (segment {seg}): {chr(old) if old else None!r} -> {chr(new) if new is not None and new < 128 else new!r}")
        print(f"   java: {json.loads(x['json']).get('message', x['json'])[:260]}")
        print(f"   rust: {(y['json'] or '')[:260]}")
    for k, v in sorted(utf8.items()):
        print(f"{v:4d} rows: Rust ABI refused non-UTF-8 input (101) before verifying; Java decoded it with U+FFFD and answered {k[1]} ({k[0]})")


if __name__ == "__main__":
    main()
