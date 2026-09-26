#!/usr/bin/env python3
"""Runs corpus rows one per process through c/run1.c under a checker
(valgrind memcheck by default) and counts processes the checker flagged.

    python3 memcheck.py <run1 binary> <REPO> <out dir> <corpus.jsonl>[:step] ... [--checker valgrind|plain]

Only receipt (DER) and JWS rows run, since run1 drives those two calls. A
row without roots gets the three bundled Apple roots from $REPO/certs, and
every JWS row gets run1's fixed Sandbox environment and no app id: the
verdict may differ from the corpus row, the memory behavior is the question.
":step" keeps every step-th row. Prints one line per corpus:
"<corpus>: <n> runs, <flagged> flagged, <crashed> crashed", and one line
per flagged or crashed row.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

VALGRIND = ["valgrind", "-q", "--error-exitcode=99", "--leak-check=full",
            "--show-leak-kinds=definite", "--errors-for-leak-kinds=definite"]


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    checker = sys.argv[sys.argv.index("--checker") + 1] if "--checker" in sys.argv else "valgrind"
    if checker != "valgrind":
        args = [a for a in args if a != checker]
    run1, repo, out = args[0], Path(args[1]), Path(args[2])
    out.mkdir(parents=True, exist_ok=True)
    apple = [str(p) for p in sorted((repo / "certs").glob("*.cer"))]
    prefix = VALGRIND if checker == "valgrind" else []
    for spec in args[3:]:
        path, _, step = spec.partition(":")
        step = int(step or 1)
        rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()][::step]
        runs = flagged = crashed = 0
        for i, r in enumerate(rows):
            if r["kind"] not in ("receipt", "jws") or r.get("base64") or r.get("guidHex"):
                continue
            opts = json.loads(r["options"])
            data = base64.b64decode(r["input"])
            if r["kind"] == "jws" and b"\0" in data:
                continue
            inp = out / f"in-{i}"
            inp.write_bytes(data)
            roots = apple
            if opts.get("roots") is not None:
                roots = []
                for j, b in enumerate(opts["roots"]):
                    p = out / f"root-{i}-{j}.der"
                    p.write_bytes(base64.b64decode(b))
                    roots.append(str(p))
            if not roots:
                continue
            bundle = opts.get("bundleId") or "conformance.unset.bundle.id"
            cmd = prefix + [run1, r["kind"], str(inp), bundle] + roots
            p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=600)
            runs += 1
            if p.returncode == 99:
                flagged += 1
                print(f"  flagged {r['id']}: {p.stderr.strip().splitlines()[:3]}")
            elif p.returncode != 0:
                crashed += 1
                print(f"  exit {p.returncode} {r['id']}: {p.stderr.strip()[:200]}")
        print(f"{Path(path).name}:{step}: {runs} runs, {flagged} flagged, {crashed} crashed", flush=True)


if __name__ == "__main__":
    main()
