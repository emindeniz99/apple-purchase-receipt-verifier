#!/bin/sh
# Task 3: runs the four corpora through a native build and classifies every
# row three ways against Java and current Rust ($SPIKE/py/tri.py), and
# row by row against the PKCS7-path build of the same library.
#   scripts/cms-tri.sh <name> <pkcs7-reference-variant>
# Output: $SCRATCH/fu/run/<name>-<corpus>.jsonl, results/tri-<name>-<corpus>.txt,
#         results/cms-vs-pkcs7-<name>.txt
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${CORPORA:?}"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
FU="$REPO/docs/evidence/2026-09-26-substrate-followup"
PREVPY="$REPO/docs/evidence/2026-09-25-java-native-image-spike/py"
NAME="$1"; REF="$2"; R="$SCRATCH/fu/run"; mkdir -p "$R"
: > "$FU/results/cms-vs-pkcs7-$NAME.txt"
for c in cases substrate hostile algorithms; do
  python3 "$PREVPY/run_rust.py" "$REPO" "$SCRATCH/target-$NAME/release" "$CORPORA/$c.jsonl" > "$R/$NAME-$c.jsonl"
  python3 "$SPIKE/py/tri.py" "$CORPORA/$c.jsonl" "$CORPORA/jvm25-$c.jsonl" "$SCRATCH/run/rust-$c.jsonl" "$R/$NAME-$c.jsonl" --list > "$FU/results/tri-$NAME-$c.txt"
  REFF="$SCRATCH/run/$REF-$c.jsonl"; [ -f "$REFF" ] || REFF="$R/$REF-$c.jsonl"
  echo "# $c: $NAME vs $REF" >> "$FU/results/cms-vs-pkcs7-$NAME.txt"
  python3 "$SPIKE/py/same.py" "$CORPORA/$c.jsonl" "$REFF" "$R/$NAME-$c.jsonl" --list >> "$FU/results/cms-vs-pkcs7-$NAME.txt"
done
