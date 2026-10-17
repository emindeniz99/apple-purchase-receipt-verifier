"""Compares a new corpus's rows with the previous archive's.

    python3 -I tools/corpus-compare.py <previous-rows> <new-rows> <summary.txt> <corpus>...

The archive's own same.py counts rows and exits 1 on any difference,
which a new module's richer payload legitimately causes. This tells a
payload change from a changed verdict instead: a row whose `verified`
(verify-receipt, verify-signed-data) or `status` (verify-receipt-endpoint)
differs from the previous archive's fails the run, and the counts go into
<summary.txt> for the archive's README. tools/build-corpus.sh runs it.
"""

import json
import sys

previous_dir, new_dir, summary_path = sys.argv[1:4]
corpora = sys.argv[4:]


def load(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def verdict(row):
    out = row.get("out")
    if not isinstance(out, str):
        return (None, None)
    try:
        answer = json.loads(out)
    except ValueError:
        return (None, None)
    if not isinstance(answer, dict):
        return (None, None)
    return (answer.get("verified"), answer.get("status"))


def same(a, b):
    return (a.get("out"), a.get("trap"), a.get("map")) == (b.get("out"), b.get("trap"), b.get("map"))


lines = []
totals = [0, 0, 0, 0]
flipped = []
for corpus in corpora:
    old = load(f"{previous_dir}/module-{corpus}.jsonl")
    new = load(f"{new_dir}/module-{corpus}.jsonl")
    if [r["id"] for r in old] != [r["id"] for r in new]:
        print(f"::error::{corpus}: the rows are not the previous archive's calls in the same order")
        sys.exit(1)
    identical = differing = flips = 0
    for a, b in zip(old, new):
        if verdict(a) != verdict(b):
            flips += 1
            flipped.append(f"{corpus} {a['id']}: {verdict(a)} -> {verdict(b)}")
        elif same(a, b):
            identical += 1
        else:
            differing += 1
    lines.append(f"{corpus}: {len(new)} rows: {identical} identical, {differing} differ, {flips} flipped")
    for i, n in enumerate((len(new), identical, differing, flips)):
        totals[i] += n
lines.append(f"all: {totals[0]} rows: {totals[1]} identical, {totals[2]} differ, {totals[3]} flipped")
text = "\n".join(lines)
print(text)
with open(summary_path, "w", encoding="utf-8") as f:
    f.write(text + "\n")
if flipped:
    print("rows whose verified or status changed (first 20):")
    for entry in flipped[:20]:
        print(f"  {entry}")
    print("::error::a row's verified or status differs from the previous archive: this is a behavior change, not a refresh")
    sys.exit(1)
