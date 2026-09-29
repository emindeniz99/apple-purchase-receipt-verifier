#!/bin/sh
# Runs every request corpus through one built variant's C ABI and writes
# $SCRATCH/run/<name>-<corpus>.jsonl, then the three-way tally against the
# Java oracle and the current Rust core.
#
#   REPO=... SCRATCH=... CORPORA=$SCRATCH/corpora scripts/run-corpora.sh <name> [corpus ...]
#
# CORPORA holds <corpus>.jsonl (requests), jvm25-<corpus>.jsonl (Java
# oracle rows) and, once the baseline ran, $SCRATCH/run/rust-<corpus>.jsonl.
# The full three-way listing goes to results/tri-<name>-<corpus>.txt.
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${CORPORA:?}"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
PREV="$REPO/docs/evidence/2026-09-25-java-native-image-spike/py"
NAME="$1"; shift
[ $# -gt 0 ] || set -- cases hostile algorithms
mkdir -p "$SCRATCH/run" "$SPIKE/results"
for c in "$@"; do
  python3 "$PREV/run_rust.py" "$REPO" "$SCRATCH/target-$NAME/release" "$CORPORA/$c.jsonl" \
    > "$SCRATCH/run/$NAME-$c.jsonl"
  if [ "$NAME" != rust ]; then
    echo "== $NAME $c"
    python3 "$SPIKE/py/tri.py" "$CORPORA/$c.jsonl" "$CORPORA/jvm25-$c.jsonl" \
      "$SCRATCH/run/rust-$c.jsonl" "$SCRATCH/run/$NAME-$c.jsonl" --list \
      > "$SPIKE/results/tri-$NAME-$c.txt"
    sed '/^cand\|^agree\|^    /d' "$SPIKE/results/tri-$NAME-$c.txt"
  fi
done
