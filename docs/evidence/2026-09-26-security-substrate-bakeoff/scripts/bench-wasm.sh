#!/bin/sh
# Single-thread mean latency of one wasm module under Node and wazero:
# 200 warm-up calls on a fresh instance, then n timed calls of the same
# row. Rows: the genuine g5 sandbox receipt against the bundled Apple roots
# and the generated transaction (both from the cases corpus).
#
#   REPO=... SCRATCH=... CORPORA=... scripts/bench-wasm.sh <label> <module.wasm> [n]
#
# Appends one JSON line per runtime and row to results/wasm-bench.jsonl.
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${CORPORA:?}"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
LABEL="$1"; WASM="$2"; N="${3:-2000}"
for id in receipt/verify-genuine-sandbox-g5-against-apple-roots transaction/verify-shared-sandbox; do
  for rt in node wazero; do
    if [ "$rt" = node ]; then
      line=$(node --no-warnings "$SPIKE/wasm/run.mjs" "$WASM" "$CORPORA/cases.jsonl" --bench "$id" "$N")
    else
      line=$("$SCRATCH/wazero-run" "$WASM" "$CORPORA/cases.jsonl" --bench "$id" "$N")
    fi
    echo "{\"module\":\"$LABEL\",\"runtime\":\"$rt\",${line#\{}" | tee -a "$SPIKE/results/wasm-bench.jsonl"
  done
done
