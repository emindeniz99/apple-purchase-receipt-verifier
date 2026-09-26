#!/bin/sh
# Task 1: can a normal `cargo build` get OpenSSL 4.0.2 with no hand-built
# tree? openssl-src 400.0.1+4.0.2 (crates.io, 2026-08-25) builds OpenSSL
# 4.0.2 from source inside the build script, but openssl-sys 0.9.117
# declares `openssl-src = "300.2.0"` (i.e. ^300.2.0), so its `vendored`
# feature can only reach OpenSSL 3.x.
#
# This copies openssl-sys 0.9.117 from the registry, changes that ONE
# requirement to "400.0.1", wires the copy in with [patch.crates-io], and
# builds the native CMS C ABI with the adapter's `vendored` feature (no
# OPENSSL_DIR anywhere). Then it runs the corpus against the OPENSSL_DIR
# build.
#   scripts/vendored.sh native
set -eu
. "$(dirname "$0")/env.sh"
: "${CORPORA:?}"
O="$C/openssl-sys-src400"
rm -rf "$O"
cp -r "$(ls -d "$CARGO_HOME"/registry/src/*/openssl-sys-0.9.117 | head -1)" "$O"
sed -i '/^\[build-dependencies.openssl-src\]/,/^\[/ s/^version = "300.2.0"$/version = "400.0.1"/' "$O/Cargo.toml"
diff "$(ls -d "$CARGO_HOME"/registry/src/*/openssl-sys-0.9.117 | head -1)/Cargo.toml" "$O/Cargo.toml" || true
"$EV/scripts/build.sh" adapter
T="$SCRATCH/tree-cms-vendored"
rm -rf "$T"; mkdir -p "$T/rust"
tar -C "$REPO/rust" --exclude=./target --exclude=./ffi/target --exclude=./fuzz/target -cf - . | tar -C "$T/rust" -xf -
cp "$REPO/version.txt" "$T/"
cp "$SPIKE/core-patch/substrate.rs" "$T/rust/src/substrate.rs"
sed "s#@SPIKE@#$C/adapter#" "$SPIKE/core-patch/core.patch" | patch -s -d "$T/rust" -p1
sed -i 's#^substrate-aws-lc = .*#&\nsubstrate-cms = ["substrate", "aprv-security-openssl/cms"]#' "$T/rust/Cargo.toml"
printf '\n[patch.crates-io]\nopenssl-sys = { path = "%s" }\n' "$O" >> "$T/rust/ffi/Cargo.toml"
env -u OPENSSL_DIR -u OPENSSL_STATIC cargo build --release --manifest-path "$T/rust/ffi/Cargo.toml" \
  --target-dir "$SCRATCH/target-cms-vendored" \
  --features apple-purchase-receipt-verifier/substrate-cms,apple-purchase-receipt-verifier/substrate-prescan,apple-purchase-receipt-verifier/substrate-vendored
cp "$T/rust/ffi/Cargo.lock" "$C/art/cms-vendored.Cargo.lock"
grep "Compiling openssl-src\|Compiling openssl-sys" "$C/build-vendored.log" 2>/dev/null || true
mkdir -p "$C/art/vendored"
cp "$SCRATCH/target-cms-vendored/release/libapple_purchase_receipt_verifier_ffi.so" "$C/art/vendored/"
strings "$C/art/vendored/libapple_purchase_receipt_verifier_ffi.so" | grep -m1 '^OpenSSL 4' || true
"$EV/scripts/parity.sh" native cms-vendored "$C/art/vendored"
