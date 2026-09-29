#!/bin/sh
# Evidence only (2026-09-29). Builds ../runner against one core tree and
# runs every ABI v1 call file through it.
#
#   parity.sh <name> <core tree: a rust/ directory>
#
# Writes $OUT/<name>-<corpus>.jsonl for cases, hostile, algorithms,
# substrate and fuzz. Needs CALLS (the directory of ABI v1 call files,
# made by docs/evidence/2026-09-26-wasm-abi-v1/py/abi_calls.py from the
# request corpora), OUT and WORK (a scratch build directory). Which
# OpenSSL the migrated core links is openssl-sys's choice, as for any
# build: the vendored default, or OPENSSL_NO_VENDOR=1 OPENSSL_DIR=...
set -eu
: "${CALLS:?}" "${OUT:?}" "${WORK:?}"
NAME="$1"
CORE="$(cd "$2" && pwd)"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
R="$WORK/runner-$NAME"
rm -rf "$R"
mkdir -p "$R" "$OUT"
cp -r "$HERE/runner/src" "$R/"
if [ -d "$CORE/vendor/openssl-sys" ]; then
  sed "s#@CORE@#$CORE#g" "$HERE/runner/Cargo.toml.in" > "$R/Cargo.toml"
else
  # The pre-migration core has no OpenSSL to patch.
  sed "s#@CORE@#$CORE#g; /^\[patch/,\$d" "$HERE/runner/Cargo.toml.in" > "$R/Cargo.toml"
fi
cp "$CORE/Cargo.lock" "$R/Cargo.lock"
cargo build --release --quiet --manifest-path "$R/Cargo.toml" --target-dir "$WORK/target-$NAME"
for c in cases hostile algorithms substrate fuzz; do
  "$WORK/target-$NAME/release/aprv-parity-runner" < "$CALLS/$c.jsonl" > "$OUT/$NAME-$c.jsonl"
  echo "$NAME $c: $(wc -l < "$OUT/$NAME-$c.jsonl") rows"
done
