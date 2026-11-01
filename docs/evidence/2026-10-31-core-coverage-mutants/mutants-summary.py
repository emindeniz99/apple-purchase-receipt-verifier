#!/usr/bin/env python3
"""Per-file outcome counts and every missed or timed-out mutant from a
cargo-mutants outcomes.json.

    python3 -I mutants-summary.py <mutants.out/outcomes.json>
"""
import json
import sys
from collections import Counter, defaultdict

data = json.load(open(sys.argv[1]))
NAMES = {
    "CaughtMutant": "caught",
    "MissedMutant": "missed",
    "Timeout": "timeout",
    "Unviable": "unviable",
}

counts = defaultdict(Counter)
interesting = []
for outcome in data["outcomes"]:
    scenario = outcome["scenario"]
    if not isinstance(scenario, dict) or "Mutant" not in scenario:
        continue
    mutant = scenario["Mutant"]
    kind = NAMES.get(outcome["summary"], outcome["summary"])
    counts[mutant["file"]][kind] += 1
    if kind in ("missed", "timeout"):
        span = mutant.get("span", {})
        line = span.get("start", {}).get("line", "?")
        function = (mutant.get("function") or {}).get("function_name", "")
        interesting.append(
            (mutant["file"], line, kind, function, mutant.get("genre", ""),
             mutant.get("replacement", ""), mutant.get("name", ""))
        )

kinds = ["caught", "missed", "timeout", "unviable"]
print(f"{'file':32} " + " ".join(f"{k:>8}" for k in kinds) + "    total")
total = Counter()
for name in sorted(counts):
    c = counts[name]
    total.update(c)
    print(f"{name:32} " + " ".join(f"{c[k]:8}" for k in kinds) + f" {sum(c.values()):8}")
print(f"{'TOTAL':32} " + " ".join(f"{total[k]:8}" for k in kinds) + f" {sum(total.values()):8}")
print()
for file, line, kind, function, genre, replacement, name in sorted(
    interesting, key=lambda row: (row[0], int(row[1]) if str(row[1]).isdigit() else 0)
):
    # cargo-mutants' own name carries the span and the replacement.
    print(f"{kind.upper():8} {name}")
