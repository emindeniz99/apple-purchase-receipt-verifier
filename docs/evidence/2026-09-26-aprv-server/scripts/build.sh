#!/bin/sh
# Spike only. Builds every variant into $SV/bin (one cargo target dir):
#   aprv-spike     full engine + spike routes/bench + pooling + crash (benchmarks, corpus)
#   aprv-full      A: full engine (Cranelift), embedded .wasm compiled at start
#   aprv-min       B: runtime-only Wasmtime, embedded .cwasm (precompiled by aprv-full)
#   aprv-min-side  B: runtime-only, .cwasm as a side file, SHA-256 pinned at build time
#   aprv-min-spike B + the spike routes and the crash route (JWS benchmark, Java crash test)
#   aprv-cli       B without the HTTP server: the one-shot CLI only
#   aprv-full-pin  A with the .cwasm hash pinned (CLI timing: same binary, both loads)
set -eu
. "$(dirname "$0")/env.sh"
M="$EV/server/Cargo.toml"
R="$CARGO_TARGET_DIR/release/aprv"
b() { name=$1; shift; cargo build -q --release --locked --manifest-path "$M" "$@"; cp "$R" "$SV/bin/$name"; echo "built $name ($(stat -c %s "$SV/bin/$name") bytes)"; }
[ "$(sha256sum "$WASM" | cut -c1-64)" = "$WASM_SHA256" ] || { echo "module hash mismatch" >&2; exit 1; }
export APRV_WASM="$WASM"
b aprv-spike --features spike,pooling,crash,pulley
b aprv-full
"$SV/bin/aprv-full" precompile "$SV/art/aprv-abi1.cwasm"
export APRV_CWASM="$SV/art/aprv-abi1.cwasm" APRV_CWASM_SHA256="$(sha256sum "$SV/art/aprv-abi1.cwasm" | cut -c1-64)"
b aprv-full-pin
b aprv-min --no-default-features --features server,embed
b aprv-min-side --no-default-features --features server
b aprv-min-spike --no-default-features --features server,embed,spike,crash
b aprv-cli --no-default-features --features embed
cargo build -q --release --manifest-path "$EV/loadtest/Cargo.toml"
