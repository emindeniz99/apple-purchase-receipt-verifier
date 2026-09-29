#!/bin/sh
# Runs every request corpus through one wasm module under Node (node:wasi)
# and wazero, then compares each run with the native run of the same
# variant (py/same.py) and with Java and current Rust (py/tri.py).
#
#   REPO=... SCRATCH=... CORPORA=... scripts/run-wasm-corpora.sh <label> <module.wasm> <native name>
#
# Needs node on PATH and $SCRATCH/wazero-run, built from wasm/wazero with
#   go build -C "$SPIKE/wasm/wazero" -o "$SCRATCH/wazero-run" .
# Rows go to $SCRATCH/runw/<label>-<runtime>-<corpus>.jsonl. One line per
# runtime and corpus is appended to results/wasm-corpora.txt.
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${CORPORA:?}"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
LABEL="$1"; WASM="$2"; NATIVE="$3"
mkdir -p "$SCRATCH/runw"
for rt in node wazero; do
  for c in cases hostile algorithms substrate; do
    out="$SCRATCH/runw/$LABEL-$rt-$c.jsonl"
    if [ "$rt" = node ]; then
      node --no-warnings "$SPIKE/wasm/run.mjs" "$WASM" "$CORPORA/$c.jsonl" > "$out"
    else
      "$SCRATCH/wazero-run" "$WASM" "$CORPORA/$c.jsonl" > "$out"
    fi
    s=$(python3 "$SPIKE/py/same.py" "$CORPORA/$c.jsonl" "$SCRATCH/run/$NATIVE-$c.jsonl" "$out")
    t=$(python3 "$SPIKE/py/tri.py" "$CORPORA/$c.jsonl" "$CORPORA/jvm25-$c.jsonl" \
      "$SCRATCH/run/rust-$c.jsonl" "$out" | tail -1 | tr -s ' ')
    echo "$LABEL $rt $c: vs native $NATIVE: $s | vs java/rust (agree cand=java cand=rust cand-own abi):${t#total}" \
      | tee -a "$SPIKE/results/wasm-corpora.txt"
  done
done
