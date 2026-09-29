#!/usr/bin/env python3
"""Evidence only (2026-09-29). aprv.wasm's rows against the OpenSSL core's
own rows from docs/evidence/2026-09-29-openssl-core-parity (its runner
calls the 0.7 public API: `verify_receipt(&str)` and friends).

Converts each module row into that runner's shape (a receipt's payload
object, a JWS's `payloadJson`, an endpoint answer under `endpoint` with
`request_date*` masked where the call had no pinned clock) and compares.
The rows the text API could not take are counted apart: `NOT_UTF8` (the
bytes API answers them as values now), an endpoint body that is not UTF-8
(that runner read it lossily, as the ABI v1 shim did, where the bytes API
answers 21002: JSON text is UTF-8), and `CONFIGURATION` (a root that is
not a certificate: the module's init refuses it, and both sides say so).
Every other difference is listed.

    against_a1.py <round-13 calls.jsonl, unpinned> <a1 rows.jsonl> <module rows.jsonl> [converted.jsonl]

With a fourth argument it also writes the converted module rows there,
for that note's compare.py (`ref` against the ABI v1 Node rows).
"""
import base64
import collections
import json
import sys

calls = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
a1 = [json.loads(l) for l in open(sys.argv[2], encoding="utf-8") if l.strip()]
mod = [json.loads(l) for l in open(sys.argv[3], encoding="utf-8") if l.strip()]
assert len(calls) == len(a1) == len(mod)


def convert(call, row):
    if "map" in row:
        return {"skip": row["map"]}
    if "trap" in row:
        return {"trap": row["trap"]}
    out = json.loads(row["out"])
    if "ok" in out:
        return {"error": "CONFIGURATION"}
    if call["fn"] == "verify-receipt-endpoint":
        if call.get("now") is None and isinstance(out.get("receipt"), dict):
            for key in ("request_date", "request_date_ms", "request_date_pst"):
                out["receipt"].pop(key, None)
        return {"endpoint": out}
    if out["verified"] and call["fn"] == "verify-signed-data":
        return {"verified": True, "payloadJson": out["payload"]}
    return out


def utf8(call):
    try:
        base64.b64decode(call["b64"]).decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


counts, groups, other = collections.Counter(), collections.Counter(), []
converted = open(sys.argv[4], "w", encoding="utf-8") if len(sys.argv) > 4 else None
for call, x, y in zip(calls, a1, mod):
    assert call["id"] == x["id"] == y["id"]
    theirs, ours = x["out"], convert(call, y)
    if converted:
        converted.write(json.dumps({"id": y["id"], "out": ours}) + "\n")
    if theirs.get("error") == "CONFIGURATION":
        theirs = {"error": "CONFIGURATION"}
    if theirs == ours:
        counts["identical"] += 1
    elif theirs.get("error") == "NOT_UTF8":
        counts["NOT_UTF8 in the text API, a value through the bytes"] += 1
        groups[(call["fn"], "verified" if ours.get("verified") else ours.get("reason"))] += 1
    elif call["fn"] == "verify-receipt-endpoint" and not utf8(call):
        counts["endpoint body not UTF-8: read lossily there, 21002 through the bytes"] += 1
        groups[(call["fn"], f"{theirs['endpoint'].get('status')} -> {ours['endpoint'].get('status')}")] += 1
    else:
        counts["DIFFERENT"] += 1
        other.append((call["id"], theirs, ours))
for k, v in sorted(counts.items()):
    print(f"  {v:5} {k}")
for (fn, verdict), n in sorted(groups.items()):
    print(f"        {n:5} {fn}: {verdict}")
for i, t, o in other:
    print(f"  DIFFERENT {i}\n    openssl core: {json.dumps(t)[:300]}\n    aprv.wasm:    {json.dumps(o)[:300]}")
sys.exit(1 if other else 0)
