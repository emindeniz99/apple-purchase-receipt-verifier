#!/bin/sh
# Evidence only (2026-09-29): the init-cost runs of ../2026-09-29-init-cost.md.
#
#   REPO=<repository> OUT=<rust/bindings/abi/build.sh output> WORK=<scratch dir> sh run.sh
#
# Builds the Wasmtime bench against the ABI tests' hosts (the pinned
# Wasmtime of rust/bindings/abi/tests, same lockfile), then runs both
# benches pinned to one CPU and prints the summary table. Needs the pinned
# Rust toolchain (rust/rust-toolchain.toml), Node 20+ and taskset.
set -eu
: "${REPO:?}" "${OUT:?}" "${WORK:?}"
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$WORK/wasmtime/src" "$WORK/results"
sed "s|@REPO@|$REPO|" "$here/wasmtime/Cargo.toml.in" > "$WORK/wasmtime/Cargo.toml"
cp "$here/wasmtime/src/main.rs" "$WORK/wasmtime/src/main.rs"
cp "$REPO/rust/bindings/abi/tests/Cargo.lock" "$WORK/wasmtime/Cargo.lock"
CARGO_TARGET_DIR="$WORK/target" cargo build --release --manifest-path "$WORK/wasmtime/Cargo.toml"
uptime > "$WORK/results/load.txt"
APRV_WASM="$OUT/aprv.wasm" APRV_COMPONENT="$OUT/aprv.component.wasm" \
  taskset -c 0 "$WORK/target/release/init-cost-wasmtime" "$REPO/fixtures" 7 20 > "$WORK/results/wasmtime.jsonl"
taskset -c 0 node "$here/node-init-cost.mjs" "$OUT/aprv.wasm" "$REPO/fixtures" 7 20 > "$WORK/results/node.jsonl"
uptime >> "$WORK/results/load.txt"
python3 "$here/summarize.py" "$WORK/results/wasmtime.jsonl" "$WORK/results/node.jsonl"
