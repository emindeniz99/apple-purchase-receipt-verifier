#!/usr/bin/env python3
"""Evidence only (2026-09-29). Splits module rows by the wire shape of
their answer, one answer per line, for tools/validate-wire.mjs: the
answers of verify-receipt, of verify-signed-data, and of an init that
refused the row's configuration (the row's answer then). Endpoint answers
are Apple's format and have no schema of ours.

    split.py <round-13 calls.jsonl> <module rows.jsonl> <out prefix>
"""
import json
import sys

calls = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
rows = [json.loads(l) for l in open(sys.argv[2], encoding="utf-8") if l.strip()]
files = {k: open(f"{sys.argv[3]}{k}.jsonl", "a", encoding="utf-8") for k in ("verify-receipt", "verify-signed-data", "init")}
for call, row in zip(calls, rows):
    assert call["id"] == row["id"]
    if "out" not in row:
        continue
    if "ok" in json.loads(row["out"]):
        files["init"].write(row["out"] + "\n")
    elif call["fn"] in ("verify-receipt", "verify-signed-data"):
        files[call["fn"]].write(row["out"] + "\n")
