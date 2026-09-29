#!/usr/bin/env python3
"""Spike only (2026-09-29, round 12). Maps one ABI v1 calls file
($SCRATCH/abi/calls/<corpus>.jsonl) onto the canonical-ABI interface, so
every host runs the same rows with no ABI v1 knowledge:

  {"id", "fn": "verify-receipt" | "verify-signed-data" | "verify-receipt-endpoint",
   "env": 0 (production) | 1 (sandbox)          (endpoint only)
   "config": "" | "{\"roots\":[...]}"           init's argument: the instance key
   "now": null | ms                             null: the host passes its wall clock
   "text": "..."                                the string argument
   "lossy": true                                (only when the ABI v1 input was not UTF-8)}

ABI v1 ops 1-4 use the built-in roots and the wall clock. The test variants
257-260 carry an envelope ("APRVT1" | u32 count | (u32 len | DER)* | i64 now
| body): its anchors become init's roots, a pinned now becomes now-ms.
A WIT string must be UTF-8: an input that is not is decoded here with
U+FFFD replacement (errors="replace"), and marked lossy. Rows without an
op (no-call mappings) pass through as {"id", "map"}.

    calls_cabi.py IN.jsonl > OUT.jsonl      (summary on stderr)
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
    try:
        row["text"] = body.decode("utf-8")
    except UnicodeDecodeError:
        row["text"] = body.decode("utf-8", errors="replace")
        row["lossy"] = True
        stats[f"lossy ({FN[op]})"] += 1
    stats[FN[op]] += 1
    out.write(json.dumps(row, ensure_ascii=False) + "\n")
print(json.dumps({"file": sys.argv[1].rsplit("/", 1)[-1], **stats}), file=sys.stderr)
