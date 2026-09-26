#!/usr/bin/env python3
"""Spike only (ABI v1). Maps request-corpus rows (the C ABI's row format:
kind, options, input, base64, guidHex, op) onto ABI v1 calls:

    python3 abi_calls.py corpus.jsonl > calls.jsonl

Each output line: {"id", "op", "input" (base64 of the exact input bytes),
"map"} where "map" names the mapping:
  direct            the row's bytes, as they were (a base64 receipt row's
                    string goes in untouched: the module decodes it)
  der-encoded       a DER receipt row, encoded here as canonical base64
                    (VERIFY_RECEIPT takes the receipt-data string)
  guid-dropped      a device-hash row: the GUID is not an ABI v1 input
                    (der-encoded+guid-dropped: both)
  no-call:<why>     rows ABI v1 cannot express at all (no "op")

Trust anchors and pinned clocks (the corpus's generated chains) go through
the spike-only test variants (op + 256) and their envelope:
"APRVT1" | u32le count | (u32le len | DER)* | i64le now (i64 min = none) | body.
"""
import base64
import json
import struct
import sys

VERIFY_RECEIPT, VERIFY_SIGNED_DATA, ENDPOINT_PRODUCTION, ENDPOINT_SANDBOX = 1, 2, 3, 4
TEST = 256
I64_MIN = -(2 ** 63)


def envelope(roots, now, body: bytes) -> bytes:
    out = bytearray(b"APRVT1")
    out += struct.pack("<I", len(roots))
    for der in roots:
        out += struct.pack("<I", len(der)) + der
    out += struct.pack("<q", I64_MIN if now is None else now)
    return bytes(out) + body


def main():
    for line in open(sys.argv[1], encoding="utf-8"):
        if not line.strip():
            continue
        r = json.loads(line)
        opts = json.loads(r["options"])
        data = base64.b64decode(r["input"])
        roots = opts.get("roots")
        now = opts.get("nowMillis")
        mapping = "direct"
        kind = r["kind"]
        if kind == "receipt":
            op = VERIFY_RECEIPT
            if not r.get("base64"):
                data, mapping = base64.b64encode(data), "der-encoded"
            if r.get("guidHex") is not None:
                mapping = "guid-dropped" if mapping == "direct" else mapping + "+guid-dropped"
        elif kind == "jws":
            op = VERIFY_SIGNED_DATA
        else:
            env = opts.get("environment")
            if env not in ("Production", "Sandbox"):
                print(json.dumps({"id": r["id"], "map": f"no-call:endpoint-environment-{env}"}))
                continue
            op = ENDPOINT_PRODUCTION if env == "Production" else ENDPOINT_SANDBOX
        if roots is not None or now is not None:
            ders = [base64.b64decode(x) for x in (roots or [])]
            data = envelope(ders, now, data)
            op += TEST
        print(json.dumps({"id": r["id"], "op": op, "input": base64.b64encode(data).decode(), "map": mapping}))


if __name__ == "__main__":
    main()
