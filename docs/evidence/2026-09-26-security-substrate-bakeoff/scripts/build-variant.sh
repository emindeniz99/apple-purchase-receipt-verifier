#!/bin/sh
# Builds the unchanged C ABI (rust/ffi) against a patched scratch copy of
# the core crate, with the security substrate selected by cargo features
# and openssl-sys environment variables.
#
#   REPO=... SCRATCH=... scripts/build-variant.sh <name> "<core features>"
#
# Examples (see README.md for the full list):
#   rust (baseline, no patch):  scripts/build-variant.sh rust ""
#   OpenSSL 4.0.2 static:       OPENSSL_DIR=$SCRATCH/inst/openssl-4.0.2 OPENSSL_STATIC=1 \
#                               scripts/build-variant.sh ossl402 substrate
#   LibreSSL 4.3.2 static:      OPENSSL_DIR=$SCRATCH/inst/libressl-4.3.2 OPENSSL_STATIC=1 \
#                               scripts/build-variant.sh libressl432 substrate
#   AWS-LC via aws-lc-sys:      scripts/build-variant.sh awslc substrate-aws-lc
#   OpenSSL 3.6 via openssl-src: scripts/build-variant.sh ossl36v substrate-vendored
#
# Output: $SCRATCH/target-<name>/release/libapple_purchase_receipt_verifier_ffi.so
set -eu
: "${REPO:?set REPO to the repository root}"
: "${SCRATCH:?set SCRATCH to a scratch directory outside the repository}"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
NAME="$1"
FEATURES="${2:-}"
TREE="$SCRATCH/tree-$NAME"

rm -rf "$TREE"
mkdir -p "$TREE/rust"
tar -C "$REPO/rust" --exclude=./target --exclude=./ffi/target --exclude=./fuzz/target -cf - . \
  | tar -C "$TREE/rust" -xf -
cp "$REPO/version.txt" "$TREE/"
if [ -n "$FEATURES" ]; then
  cp "$SPIKE/core-patch/substrate.rs" "$TREE/rust/src/substrate.rs"
  sed "s#@SPIKE@#$SPIKE#" "$SPIKE/core-patch/core.patch" | patch -s -d "$TREE/rust" -p1
  set -- --features "apple-purchase-receipt-verifier/$(echo "$FEATURES" | sed 's#,#,apple-purchase-receipt-verifier/#g')"
else
  set -- --locked
fi
cargo build --release --manifest-path "$TREE/rust/ffi/Cargo.toml" \
  --target-dir "$SCRATCH/target-$NAME" "$@"
cp "$TREE/rust/ffi/Cargo.lock" "$SCRATCH/target-$NAME/Cargo.lock.used"
