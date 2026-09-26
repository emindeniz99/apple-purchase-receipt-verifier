#!/bin/sh
# Informational latency: one thread, one instance, N calls after 200 warm-up
# calls, on the given runtimes. Writes results/bench.jsonl.
#   scripts/bench.sh [N]
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${CORPORA:?}"
EV="$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff"
N="${1:-1000}"
OUT="$EV/results/bench.jsonl"; : > "$OUT"
b() { # label runtime script args...
  label="$1"; rt="$2"; shift 2
  for id in receipt/verify-genuine-sandbox-g5-against-apple-roots transaction/verify-shared-sandbox; do
    case "$rt" in node) R="node --no-warnings" ;; bun) R="bun" ;; deno) R="deno run --allow-read --allow-env" ;; esac
    line=$($R "$@" "$CORPORA/cases.jsonl" --bench "$id" "$N" 2>/dev/null | tail -1)
    echo "{\"artifact\":\"$label\",\"runtime\":\"$rt\",${line#\{}" | tee -a "$OUT"
  done
}
for rt in node bun; do
  b rust-uu $rt "$EV/js/run.mjs" --host strict "$SCRATCH/art/rust-uu.wasm"
  b awslc-c $rt "$EV/js/run.mjs" --host strict "$SCRATCH/art/awslc-c.wasm"
  b ossl-c $rt "$EV/js/run.mjs" --host trap "$SCRATCH/art/ossl-c.wasm"
  b awslc-w1-minimal $rt "$EV/js/run.mjs" --host trap "$SCRATCH/art/awslc-w1.wasm"
  b awslc-em $rt "$EV/js/run.mjs" --host emscripten "$SCRATCH/em/awslc-em/aprv-em.mjs"
  b ossl-em $rt "$EV/js/run.mjs" --host emscripten "$SCRATCH/em/ossl-em/aprv-em.mjs"
  b libressl-em $rt "$EV/js/run.mjs" --host emscripten "$SCRATCH/em/libressl-em/aprv-em.mjs"
  b awslc-comp-jco $rt "$EV/js/run-jco.mjs" "$SCRATCH/comp/awslc-min-jco/aprv.js"
  APRV_WASI_P2=min b ossl-comp-jco $rt "$EV/js/run-jco.mjs" "$SCRATCH/comp/ossl-wasi-jco/aprv.js"
done
