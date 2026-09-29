#!/bin/sh
# Runs the four request corpora (1,179 rows) through one wasm artifact on one
# JS runtime and compares every row with the native build of the SAME
# backend (py/same.py from the previous bake-off). Appends one line per
# corpus to results/parity.txt and keeps the rows in $SCRATCH/wrun.
#
#   scripts/run-parity.sh <artifact-name> <native-variant> <node|bun|deno|wazero|wasmtime> <host> <module>
#
# <native-variant>: rust | ossl402 | libressl432 | awslc ($SCRATCH/run/<v>-<corpus>.jsonl,
# from scripts/native-baseline.sh). <host>: see js/run.mjs.
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${CORPORA:?}"
EV="$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
NAME="$1"; NATIVE="$2"; RT="$3"; HOST="$4"; MOD="$5"
mkdir -p "$SCRATCH/wrun"
case "$RT" in
  node) RUN="node" ;;
  bun) RUN="bun" ;;
  deno) RUN="deno run --allow-read --allow-env" ;;
  wazero) RUN="" ;;
  wasmtime) RUN="" ;; # $SCRATCH/pyvenv with wasmtime==49.0.0 (py/run_wasmtime.py)   # $SCRATCH/wazero-run, built from wazero/ (go build -o $SCRATCH/wazero-run)
esac
tot_same=0; tot=0
for c in ${CORPORA_LIST:-cases hostile algorithms substrate}; do
  out="$SCRATCH/wrun/$NAME-$RT-$HOST-$c.jsonl"
  if [ "$RT" = wasmtime ] && [ "$HOST" = component ]; then
    "$SCRATCH/pyvenv/bin/python" "$EV/py/run_wasmtime_component.py" "$MOD" "$CORPORA/$c.jsonl" > "$out" 2> "$out.err" || true
  elif [ "$RT" = wasmtime ] && [ "$HOST" = component-wasi ]; then
    "$SCRATCH/pyvenv/bin/python" "$EV/py/run_wasmtime_component.py" "$MOD" "$CORPORA/$c.jsonl" --wasi > "$out" 2> "$out.err" || true
  elif [ "$RT" = wasmtime ]; then
    "$SCRATCH/pyvenv/bin/python" "$EV/py/run_wasmtime.py" "$MOD" "$CORPORA/$c.jsonl" > "$out" 2> "$out.err" || true
  elif [ "$RT" = wazero ]; then
    "$SCRATCH/wazero-run" "$MOD" "$CORPORA/$c.jsonl" > "$out" 2> "$out.err" || true
  elif [ "$HOST" = jco ] || [ "$HOST" = jco-p2min ] || [ "$HOST" = jco-p2shim ] || [ "$HOST" = jco-trapstubs ]; then
    [ "$HOST" = jco-trapstubs ] && export APRV_WASI_P2=trapstubs
    [ "$HOST" = jco-p2min ] && export APRV_WASI_P2=min
    [ "$HOST" = jco-p2shim ] && export APRV_WASI_P2=shim   # run from a dir whose node_modules has preview2-shim
    $RUN "$EV/js/run-jco.mjs" "$MOD" "$CORPORA/$c.jsonl" > "$out" 2> "$out.err" || true
  else
    $RUN "$EV/js/run.mjs" --host "$HOST" "$MOD" "$CORPORA/$c.jsonl" > "$out" 2> "$out.err" || true
  fi
  res=$(python3 "$SPIKE/py/same.py" "$CORPORA/$c.jsonl" "$SCRATCH/run/$NATIVE-$c.jsonl" "$out" 2>&1 | tail -1)
  calls=$(tail -1 "$out.err")
  echo "$NAME $RT host=$HOST $c vs native-$NATIVE: $res | $calls" | tee -a "$EV/results/parity.txt"
done
