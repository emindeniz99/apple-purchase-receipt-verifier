"""Compares one module's corpus rows with an earlier module's.

    python3 -I tools/corpus-compare.py [--warn] <previous-rows> <new-rows> <summary.txt> <corpus>...

same.py counts rows and exits 1 on any difference, which a new module's
richer payload legitimately causes. This tells a payload change from a
changed verdict instead: a row whose `verified` (verify-receipt,
verify-signed-data) or `status` (verify-receipt-endpoint) differs from
the previous rows' fails the run, and the counts go into <summary.txt>.
With --warn a flipped row is a ::warning:: with the counts and the run
passes: the nightly compares main with the last release, and main may
change a verdict on purpose. release-please.yml's release-branch-corpus
runs it without --warn; tools/corpus.sh makes both row sets.
"""

import json
import sys

args = sys.argv[1:]
warn = args[:1] == ["--warn"]
if warn:
    args = args[1:]
previous_dir, new_dir, summary_path = args[:3]
corpora = args[3:]


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
flips_by_corpus = []
for corpus in corpora:
    old = load(f"{previous_dir}/module-{corpus}.jsonl")
    new = load(f"{new_dir}/module-{corpus}.jsonl")
    if [r["id"] for r in old] != [r["id"] for r in new]:
        print(f"::error::{corpus}: the rows are not the previous rows' calls in the same order")
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
    if flips:
        flips_by_corpus.append(f"{corpus} {flips}")
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
    if warn:
        print(f"::warning::{len(flipped)} row(s) changed verified or status against the previous rows ({', '.join(flips_by_corpus)}): a behavior change since then, intended or not")
        sys.exit(0)
    print("::error::a row's verified or status differs from the previous rows: this is a behavior change")
    sys.exit(1)
