#!/bin/sh
# Task 3: the native C ABI over the substrate policy, with the adapter's
# SignedData on OpenSSL's CMS API instead of the PKCS7 API. Everything else
# is the substrate bake-off's build-variant.sh, unchanged: same core copy,
# same substrate.rs, same core.patch, same C ABI, same Cargo.lock.
#
#   OPENSSL_DIR=<static install> OPENSSL_STATIC=1 scripts/build-cms.sh <name>
#   PRESCAN=1 also turns on the substrate bake-off's `substrate-prescan`
#   (the Rust asn1.rs reader walks the whole input first).
#
# The adapter is the substrate bake-off's security-openssl/, copied to
# $SCRATCH/fu/spike-cms and patched with adapter-cms/ (the `cms` feature:
# src/cms_path.rs plus an 8-line cfg gate in lib.rs). Output:
# $SCRATCH/target-<name>/release/libapple_purchase_receipt_verifier_ffi.so
set -eu
: "${REPO:?}" "${SCRATCH:?}"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
FU="$REPO/docs/evidence/2026-09-26-substrate-followup"
NAME="$1"
AD="$SCRATCH/fu/spike-cms"
rm -rf "$AD"; mkdir -p "$AD"
cp -r "$SPIKE/security-openssl" "$AD/"
patch -s -d "$AD/security-openssl" -p1 < "$FU/adapter-cms/adapter-cms.patch"
cp "$FU/adapter-cms/cms_path.rs" "$AD/security-openssl/src/cms_path.rs"
TREE="$SCRATCH/tree-$NAME"
rm -rf "$TREE"; mkdir -p "$TREE/rust"
tar -C "$REPO/rust" --exclude=./target --exclude=./ffi/target --exclude=./fuzz/target -cf - . | tar -C "$TREE/rust" -xf -
cp "$REPO/version.txt" "$TREE/"
cp "$SPIKE/core-patch/substrate.rs" "$TREE/rust/src/substrate.rs"
sed "s#@SPIKE@#$AD#" "$SPIKE/core-patch/core.patch" | patch -s -d "$TREE/rust" -p1
sed -i 's#^substrate-aws-lc = .*#&\nsubstrate-cms = ["substrate", "aprv-security-openssl/cms"]#' "$TREE/rust/Cargo.toml"
cargo build --release --manifest-path "$TREE/rust/ffi/Cargo.toml" --target-dir "$SCRATCH/target-$NAME" \
  --features "apple-purchase-receipt-verifier/substrate-cms${PRESCAN:+,apple-purchase-receipt-verifier/substrate-prescan}"
cp "$TREE/rust/ffi/Cargo.lock" "$SCRATCH/target-$NAME/Cargo.lock.used"
