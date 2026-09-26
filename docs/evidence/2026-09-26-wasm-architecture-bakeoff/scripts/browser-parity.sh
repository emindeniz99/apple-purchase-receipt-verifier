#!/bin/sh
# One artifact, one browser, the full 1,179-row corpus, compared with the
# native build of the same backend. Appends to results/parity.txt.
#
#   scripts/browser-parity.sh <name> <chromium|firefox> <native> <artifact-dir> '<query>'
#   e.g. '... core awslc $SCRATCH/target-awslc-c/wasm32-wasip1/release kind=core&mod=aprv_wasm_shim.wasm&policy=strict'
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${CORPORA:?}"
EV="$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
NAME="$1"; BR="$2"; NATIVE="$3"; ART="$4"; Q="$5"
LIST="${CORPORA_LIST:-cases hostile algorithms substrate}"
mkdir -p "$SCRATCH/wrun"
rep=$(node "$EV/browser/run-browser.mjs" "$BR" "$ART" "$SCRATCH/wrun/$NAME-$BR" "$Q&corpora=$(echo $LIST | tr ' ' ,)" 2>"$SCRATCH/wrun/$NAME-$BR.err")
echo "$NAME $BR report: $rep" | cut -c1-600 | tee -a "$EV/results/parity.txt"
for c in $LIST; do
  res=$(python3 "$SPIKE/py/same.py" "$CORPORA/$c.jsonl" "$SCRATCH/run/$NATIVE-$c.jsonl" "$SCRATCH/wrun/$NAME-$BR-$c.jsonl" 2>&1 | tail -1)
  echo "$NAME $BR $c vs native-$NATIVE: $res" | tee -a "$EV/results/parity.txt"
done
