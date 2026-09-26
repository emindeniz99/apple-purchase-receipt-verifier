#!/bin/sh
# Spike only (2026-09-26, ABI v1). Node: maps the five corpora onto ABI v1
# calls, runs them through $MOD, classifies every answer against round 4's
# native C ABI rows, then runs the ABI tests and the base64-rule check.
#   node.sh > results/node.txt
set -eu
. "$(dirname "$0")/env.sh"
: "${CORPORA:?}"
echo "# node $(node --version), module sha256 $(sha256sum "$MOD" | cut -c1-64)"
for c in cases hostile algorithms substrate fuzz; do
  python3 "$AB/py/abi_calls.py" "$CORPORA/$c.jsonl" > "$S/calls/$c.jsonl"
  node "$AB/js/run-calls.mjs" "$MOD" "$S/calls/$c.jsonl" > "$S/run/node-$c.jsonl" 2> "$S/run/node-$c.err"
  echo "$c: $(python3 "$AB/py/abi_compare.py" "$CORPORA/$c.jsonl" "$NATIVENEW-$c.jsonl" "$S/calls/$c.jsonl" "$S/run/node-$c.jsonl" --list | tee "$S/cmp-$c.txt" | head -1)"
  echo "    $(cat "$S/run/node-$c.err")"
done
echo "# mappings over all rows"
cat "$S"/calls/*.jsonl | python3 -c 'import json,sys,collections; c=collections.Counter(json.loads(l)["map"] for l in sys.stdin); print("   ", dict(sorted(c.items())))'
echo "# ABI tests"
node "$AB/js/abi-tests.mjs" "$MOD" "$S/calls/cases.jsonl"
echo "# base64 rule"
node "$AB/js/base64-rule.mjs" "$MOD" "$REPO/fixtures/cases.json"
