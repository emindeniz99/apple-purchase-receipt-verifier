#!/bin/sh
# Evidence only (2026-09-29). aprv.wasm against its native twin and the
# OpenSSL core, over the five corpora.
#
#   parity.sh
#
# Needs: REPO (the repository), SCRATCH (outputs), MODULE (the aprv.wasm
# rust/bindings/abi/build.sh wrote), TRAPHOST (tools/wasm-trap-host.mjs,
# from rust-core), CALLS_V1 (ABI v1's call files), A1ROWS (the OpenSSL core
# note's rows, $A1ROWS/openssl-dir-<corpus>.jsonl and old-<corpus>.jsonl),
# NODEROWS (ABI v1's Node rows, node-<corpus>.jsonl), and the cargo of
# rust/rust-toolchain.toml with OPENSSL_DIR (a native OpenSSL 4.0.2).
# With VALIDATOR (tools/validate-wire.mjs, from rust-core, after `npm ci
# --prefix tools`) it also validates every answer against the wire schemas.
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${MODULE:?}" "${TRAPHOST:?}" "${CALLS_V1:?}" "${A1ROWS:?}" "${NODEROWS:?}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
A1="$REPO/docs/evidence/2026-09-29-openssl-core-parity/scripts"
R13="$REPO/docs/evidence/2026-09-29-canonical-abi-final/py"
PIN=1790640000000   # 2026-09-29T00:00:00Z, for every call without a pinned clock
W="$SCRATCH/parity"
mkdir -p "$W/calls" "$W/rows" "$W/runner"
rm -f "$W"/answers-*.jsonl
status=0

# The native twin, built against this tree.
cp -r "$HERE/runner/src" "$W/runner/"
sed "s#@RUST@#$REPO/rust#g" "$HERE/runner/Cargo.toml.in" > "$W/runner/Cargo.toml"
cp "$REPO/rust/Cargo.lock" "$W/runner/Cargo.lock"
cargo build --quiet --manifest-path "$W/runner/Cargo.toml"
NATIVE="${CARGO_TARGET_DIR:-$W/runner/target}/debug/aprv-native-calls"

echo "module: $(wc -c < "$MODULE") bytes, sha256 $(sha256sum "$MODULE" | cut -c1-64)"
for c in cases hostile algorithms substrate fuzz; do
  python3 "$R13/calls_bytes.py" "$CALLS_V1/$c.jsonl" > "$W/calls/$c.jsonl" 2> /dev/null
  python3 "$HERE/scripts/pin-now.py" "$PIN" < "$W/calls/$c.jsonl" > "$W/calls/$c.pinned.jsonl"
  node "$TRAPHOST" calls "$MODULE" "$W/calls/$c.pinned.jsonl" > "$W/rows/module-$c.jsonl" 2> "$W/rows/module-$c.err" \
    || { echo "trap host failed on $c:"; cat "$W/rows/module-$c.err"; exit 1; }
  "$NATIVE" < "$W/calls/$c.pinned.jsonl" > "$W/rows/native-$c.jsonl"
  echo "== $c"
  echo "trap host: $(cat "$W/rows/module-$c.err")"
  echo "aprv.wasm against its native twin:"
  python3 "$HERE/scripts/same.py" "$W/rows/module-$c.jsonl" "$W/rows/native-$c.jsonl" > "$W/same-$c.txt" || status=1
  sed 's/^/  /' "$W/same-$c.txt"
  echo "aprv.wasm against the OpenSSL core's 0.7 API rows:"
  python3 "$HERE/scripts/against_a1.py" "$W/calls/$c.jsonl" "$A1ROWS/openssl-dir-$c.jsonl" \
    "$W/rows/module-$c.jsonl" "$W/rows/module-a1-$c.jsonl" || status=1
  echo "aprv.wasm against the ABI v1 Node rows, on the verdict (old = the pre-migration 0.7 core):"
  python3 "$A1/compare.py" ref "$CALLS_V1/$c.jsonl" "$NODEROWS/node-$c.jsonl" \
    "$A1ROWS/old-$c.jsonl" "$W/rows/module-a1-$c.jsonl"
  if [ -n "${VALIDATOR:-}" ]; then
    python3 "$HERE/scripts/split.py" "$W/calls/$c.jsonl" "$W/rows/module-$c.jsonl" "$W/answers-"
  fi
done
# Every answer of every corpus against the wire schemas (Ajv 2020, strict).
if [ -n "${VALIDATOR:-}" ]; then
  S="$REPO/rust/bindings/wire/schema"
  node "$VALIDATOR" "$S/verify-receipt-result.schema.json" "$W/answers-verify-receipt.jsonl" || status=1
  node "$VALIDATOR" "$S/verify-signed-data-result.schema.json" "$W/answers-verify-signed-data.jsonl" || status=1
  node "$VALIDATOR" "$S/init-result.schema.json" "$W/answers-init.jsonl" || status=1
fi
exit "$status"
