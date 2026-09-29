#!/usr/bin/env python3
"""Where a hostile mutation landed: every changed byte of a mutated receipt
or JWS, with its DER path (receipt) or segment (JWS).

    python3 where.py $REPO/fixtures hostile.jsonl <id> [<id> ...]

Reuses the previous spike's der_path and fixture loader.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

PREV = Path(__file__).resolve().parents[2] / "2026-09-25-java-native-image-spike" / "py"
sys.path.insert(0, str(PREV))
from explain import der_path  # noqa: E402
from requests_gen import fixture_bytes  # noqa: E402


def main():
    fixtures = Path(sys.argv[1])
    reg = json.loads((fixtures / "cases.json").read_text())["fixtures"]
    orig = {
        "g5": fixture_bytes(fixtures, reg, "public-receipt-sandbox-g5"),
        "gen": fixture_bytes(fixtures, reg, "receipt"),
        "jws": fixture_bytes(fixtures, reg, "transaction"),
    }
    reqs = {json.loads(l)["id"]: json.loads(l) for l in open(sys.argv[2], encoding="utf-8")}
    for rid in sys.argv[3:]:
        r = reqs[rid]
        data = base64.b64decode(r["input"])
        key = "jws" if r["kind"] == "jws" else ("g5" if "/g5-" in rid else "gen")
        base = orig[key]
        print(f"== {rid}: len {len(base)} -> {len(data)}")
        if len(base) == len(data):
            for i, (x, y) in enumerate(zip(base, data)):
                if x != y:
                    where = der_path(base, i) if key != "jws" else f"segment {base[:i].count(b'.')}"
                    print(f"   byte {i}: {x:#04x} -> {y:#04x}  {where}")
        else:
            i = next((k for k, (x, y) in enumerate(zip(base, data)) if x != y), min(len(base), len(data)))
            where = der_path(base, i) if key != "jws" else f"segment {base[:i].count(b'.')}"
            print(f"   first change at byte {i}: {where}")


if __name__ == "__main__":
    main()
