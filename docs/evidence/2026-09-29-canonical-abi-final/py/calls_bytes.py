#!/usr/bin/env python3
"""Spike only (2026-09-29, round 13). Maps one ABI v1 calls file
($SCRATCH/abi/calls/<corpus>.jsonl) onto the round-13 interface, whose
inputs are bytes, so every host runs the same rows with no ABI v1
knowledge:

  {"id", "fn": "verify-receipt" | "verify-signed-data" | "verify-receipt-endpoint",
   "env": 0 (production) | 1 (sandbox)          (endpoint only; a u32)
   "config": "" | "{\"roots\":[...]}"           init's argument (ASCII; the host passes its bytes); the instance key
   "now": null | ms                             null: the host passes its wall clock
   "b64": "..."                                 the input bytes, base64 (standard, padded)}

ABI v1 ops 1-4 use the built-in roots and the wall clock. The test variants
257-260 carry an envelope ("APRVT1" | u32 count | (u32 len | DER)* | i64 now
| body): its anchors become init's roots, a pinned now becomes now-ms. The
input bytes pass through unchanged (round 12 had to replace non-UTF-8
input, because its inputs were strings). Rows without an op (no-call
mappings) pass through as {"id", "map"}.

    calls_bytes.py IN.jsonl > OUT.jsonl      (summary on stderr)
"""
import base64
import collections
import json
import struct
import sys

FN = {1: "verify-receipt", 2: "verify-signed-data", 3: "verify-receipt-endpoint", 4: "verify-receipt-endpoint"}
I64_MIN = -(2 ** 63)
stats = collections.Counter()
out = sys.stdout
for line in open(sys.argv[1], encoding="utf-8"):
    if not line.strip():
        continue
    c = json.loads(line)
    if "op" not in c:
        out.write(json.dumps({"id": c["id"], "map": c["map"]}) + "\n")
        stats["no-call"] += 1
        continue
    op, body = c["op"], base64.b64decode(c["input"])
    config, now = "", None
    if op > 256:
        op -= 256
        assert body.startswith(b"APRVT1"), c["id"]
        n = struct.unpack_from("<I", body, 6)[0]
        i, roots = 10, []
        for _ in range(n):
            ln = struct.unpack_from("<I", body, i)[0]
            roots.append(base64.b64encode(body[i + 4:i + 4 + ln]).decode())
            i += 4 + ln
        pinned = struct.unpack_from("<q", body, i)[0]
        body = body[i + 8:]
        if roots:
            config = json.dumps({"roots": roots}, separators=(",", ":"))
        if pinned != I64_MIN:
            now = pinned
            stats["pinned clock"] += 1
    row = {"id": c["id"], "fn": FN[op], "config": config, "now": now}
    if op in (3, 4):
        row["env"] = op - 3
    row["b64"] = base64.b64encode(body).decode()
    try:
        body.decode("utf-8")
    except UnicodeDecodeError:
        stats[f"not UTF-8 ({FN[op]})"] += 1
    stats[FN[op]] += 1
    out.write(json.dumps(row) + "\n")
print(json.dumps({"file": sys.argv[1].rsplit("/", 1)[-1], **stats}), file=sys.stderr)
