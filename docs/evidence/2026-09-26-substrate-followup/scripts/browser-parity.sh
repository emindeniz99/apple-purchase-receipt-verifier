#!/bin/sh
# One artifact, one browser (chromium|firefox|webkit), 1,179 rows, through
# the wasm bake-off's browser page and runner, unchanged; compared with the
# native build of the same backend. Appends to THIS folder's parity.txt.
#   scripts/browser-parity.sh <name> <browser> <ref> <artifact-dir> '<query>'
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${CORPORA:?}"
PREV="$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
FU="$REPO/docs/evidence/2026-09-26-substrate-followup"
NAME="$1"; BR="$2"; REF="$3"; ART="$4"; Q="$5"
LIST="${CORPORA_LIST:-cases hostile algorithms substrate}"
W="$SCRATCH/fu/wrun"; mkdir -p "$W"
rep=$(node "$PREV/browser/run-browser.mjs" "$BR" "$ART" "$W/$NAME-$BR" "$Q&corpora=$(echo $LIST | tr ' ' ,)" 2>"$W/$NAME-$BR.err")
echo "$NAME $BR report: $rep" | cut -c1-600 | tee -a "$FU/results/parity.txt"
for c in $LIST; do
  res=$(python3 "$SPIKE/py/same.py" "$CORPORA/$c.jsonl" "$SCRATCH/run/$REF-$c.jsonl" "$W/$NAME-$BR-$c.jsonl" 2>&1 | tail -1)
  echo "$NAME $BR $c vs $REF: $res" | tee -a "$FU/results/parity.txt"
done
