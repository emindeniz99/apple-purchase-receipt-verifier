#!/usr/bin/env python3
"""Two-way check: does a wasm run give the same verdict as the native run of
the same variant, row by row? Uses tri.py's verdict (code, plus the payload
on a success, request_date* masked when no clock is pinned).

    python3 same.py requests.jsonl native.jsonl wasm.jsonl [--list]

Prints "<same> same, <diff> differ, <trap> trapped" and, with --list, each
differing row.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tri import load, same, verdict  # noqa: E402


def main():
    reqs, native, wasm = (load(p) for p in sys.argv[1:4])
    counts = {"same": 0, "differ": 0, "trapped": 0}
    for req, a, b in zip(reqs, native, wasm):
        assert req["id"] == a["id"] == b["id"], (req["id"], a["id"], b["id"])
        if b["code"] == "TRAP":
            counts["trapped"] += 1
            if "--list" in sys.argv:
                print("  trap", req["id"], a["code"], b.get("trap", ""))
        elif same(verdict(req, a), verdict(req, b)):
            counts["same"] += 1
        else:
            counts["differ"] += 1
            if "--list" in sys.argv:
                print("  differ", req["id"], a["code"], b["code"])
    assert len(reqs) == len(native) == len(wasm), (len(reqs), len(native), len(wasm))
    print(f"{counts['same']} same, {counts['differ']} differ, {counts['trapped']} trapped")


if __name__ == "__main__":
    main()
