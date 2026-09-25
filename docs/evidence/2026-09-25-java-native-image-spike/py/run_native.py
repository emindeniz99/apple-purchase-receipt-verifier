#!/usr/bin/env python3
"""Runs a request corpus (requests_gen.py) through the native image's C ABI.

    python3 run_native.py <path to .so> requests.jsonl > native.jsonl

Prints one line per request: {"id", "code", "json"}, the same shape as
OracleCli on the JVM. Verifiers are built once per distinct (kind, options)
pair and freed at the end, then the runtime is torn down.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from aprvj import Library  # noqa: E402


def main():
    lib = Library(sys.argv[1])
    handles = {}
    out = sys.stdout
    with open(sys.argv[2], encoding="utf-8") as requests:
        for line in requests:
            if not line.strip():
                continue
            r = json.loads(line)
            kind = r["kind"]
            if kind == "selfcheck":
                code, text = lib.self_check()
            else:
                key = (kind, r["options"])
                if key not in handles:
                    handles[key] = lib.new(kind, r["options"])
                handle, error = handles[key]
                data = base64.b64decode(r["input"])
                if not handle:
                    # The constructor refused the options: report its error,
                    # parsed the way the JVM oracle reports a constructor failure.
                    code, text = constructor_code(error), error
                elif kind == "receipt":
                    guid = bytes.fromhex(r["guidHex"]) if r.get("guidHex") is not None else None
                    code, text = lib.receipt(handle, data, r.get("base64", False), guid)
                elif kind == "jws":
                    code, text = lib.jws(handle, data, r.get("op", 0))
                else:
                    code, text = lib.endpoint(handle, data)
            out.write(json.dumps({"id": r["id"], "code": code, "json": text}) + "\n")
    for handle, _ in handles.values():
        if handle:
            lib.free(handle)
    rc = lib.close()
    print(f"runtime_free returned {rc}", file=sys.stderr)


CONSTRUCTOR_CODES = {"ABI_INVALID_ARGUMENT": -1, "ABI_INTERNAL": -2, "ABI_CONFIGURATION": -3}


def constructor_code(error: str | None) -> int:
    """The constructor's error JSON names its reason; map it back to the code."""
    if not error:
        return -2
    reason = json.loads(error).get("reason")
    return CONSTRUCTOR_CODES.get(reason, -2)


if __name__ == "__main__":
    main()
