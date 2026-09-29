#!/bin/sh
# One wasm artifact on one runtime, 1,179 rows, compared row by row with a
# reference row set (default: the native build of the same backend from the
# wasm bake-off, $SCRATCH/run/<ref>-<corpus>.jsonl). Uses the wasm
# bake-off's runners unchanged ($PREV/js, $PREV/py, $PREV/wazero); appends
# to THIS folder's results/parity.txt; rows go to $SCRATCH/fu/wrun.
#   scripts/parity.sh <name> <ref> <node|bun|deno|wazero|wasmtime> <host> <module>
# <host>: trap | strict | emscripten (js/run.mjs), '-' for wazero/wasmtime.
# REFDIR overrides the reference directory (e.g. $SCRATCH/fu/run).
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${CORPORA:?}"
PREV="$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
FU="$REPO/docs/evidence/2026-09-26-substrate-followup"
NAME="$1"; REF="$2"; RT="$3"; HOST="$4"; MOD="$5"; REFDIR="${REFDIR:-$SCRATCH/run}"
W="$SCRATCH/fu/wrun"; mkdir -p "$W"
for c in ${CORPORA_LIST:-cases hostile algorithms substrate}; do
  out="$W/$NAME-$RT-$HOST-$c.jsonl"
  case "$RT" in
    node) node "$PREV/js/run.mjs" --host "$HOST" "$MOD" "$CORPORA/$c.jsonl" > "$out" 2> "$out.err" || true ;;
    bun) bun "$PREV/js/run.mjs" --host "$HOST" "$MOD" "$CORPORA/$c.jsonl" > "$out" 2> "$out.err" || true ;;
    deno) deno run --allow-read --allow-env "$PREV/js/run.mjs" --host "$HOST" "$MOD" "$CORPORA/$c.jsonl" > "$out" 2> "$out.err" || true ;;
    wazero) "$SCRATCH/wazero-run" "$MOD" "$CORPORA/$c.jsonl" > "$out" 2> "$out.err" || true ;;
    wasmtime) "$SCRATCH/pyvenv/bin/python" "$PREV/py/run_wasmtime.py" "$MOD" "$CORPORA/$c.jsonl" > "$out" 2> "$out.err" || true ;;
  esac
  res=$(python3 "$SPIKE/py/same.py" "$CORPORA/$c.jsonl" "$REFDIR/$REF-$c.jsonl" "$out" 2>&1 | tail -1)
  echo "$NAME $RT host=$HOST $c vs $REF: $res | $(tail -1 "$out.err")" | tee -a "$FU/results/parity.txt"
done
