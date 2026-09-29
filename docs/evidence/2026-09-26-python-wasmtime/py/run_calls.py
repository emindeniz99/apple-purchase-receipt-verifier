#!/usr/bin/env python3
"""Spike only (2026-09-26). The Python twin of the ABI v1 round's
js/run-calls.mjs: runs a calls file (that round's py/abi_calls.py) through
the facade, one Verifier (a trap discards its instance), and prints rows in
the Node runner's exact format: {"id","out"}, {"id","trap"} or {"id","map"}.

    python run_calls.py calls.jsonl > out.jsonl
"""
import base64
import json
import sys
from importlib import metadata

import aprv_wasm


def dump(obj):
    # JSON.stringify's spelling: no spaces, non-ASCII kept, the same escapes.
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def main():
    v = aprv_wasm.Verifier()
    rows = traps = 0
    out = sys.stdout
    for line in open(sys.argv[1], encoding="utf-8"):
        if not line.strip():
            continue
        c = json.loads(line)
        rows += 1
        if "op" not in c:
            out.write(dump({"id": c["id"], "map": c["map"]}) + "\n")
            continue
        try:
            res = v.call(c["op"], base64.b64decode(c["input"]))
            out.write(dump({"id": c["id"], "out": res.decode("utf-8")}) + "\n")
        except (aprv_wasm.WasmTrapError, aprv_wasm.AbiMismatchError) as e:
            traps += 1
            out.write(dump({"id": c["id"], "trap": str(e)}) + "\n")
    print(json.dumps({"host": "python-wasmtime", "python": sys.version.split()[0],
                      "wasmtime": metadata.version("wasmtime"), "rows": rows, "traps": traps}), file=sys.stderr)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
