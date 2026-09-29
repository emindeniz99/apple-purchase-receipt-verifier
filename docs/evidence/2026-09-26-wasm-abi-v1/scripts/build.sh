#!/bin/sh
# Spike only (2026-09-26). Builds the ABI v1 module: round 4's no-asn1
# template tree (OpenSSL 4.0.2, CMS path; the recipe of round 4's
# scripts/build.sh routec-new, unchanged) linked by this folder's shim
# instead of rust/ffi. Same OpenSSL install, same RUSTFLAGS, same
# wasi-none.c (so the only imports stay aprv.clock_now_ms and
# aprv.random_get).
#   build.sh   -> $S/art/aprv-abi1.wasm
set -eu
. "$(dirname "$0")/env.sh"
WS="$WASI_SDK"
AD="$S/adapter"; T="$S/tree"; TGT="$S/target"
rm -rf "$AD"; mkdir -p "$AD"
cp -r "$SPIKE/security-openssl" "$AD/"
patch -s -d "$AD/security-openssl" -p1 < "$FUP/adapter-cms/adapter-cms.patch"
cp "$FUP/adapter-cms/cms_path.rs" "$AD/security-openssl/src/cms_path.rs"
patch -s -d "$AD/security-openssl" -p2 < "$A4/adapter/adapter-asn1.patch"
cp "$A4/adapter/payload.rs" "$A4/adapter/payload_templates.rs" "$A4/adapter/payload_any.rs" \
   "$A4/adapter/payload.c" "$AD/security-openssl/src/"
rm -rf "$T"; mkdir -p "$T/rust"
tar -C "$REPO/rust" --exclude=./target --exclude=./ffi/target --exclude=./fuzz/target -cf - . | tar -C "$T/rust" -xf -
cp "$REPO/version.txt" "$T/"
cp "$SPIKE/core-patch/substrate.rs" "$T/rust/src/substrate.rs"
sed "s#@SPIKE@#$AD#" "$SPIKE/core-patch/core.patch" | patch -s -d "$T/rust" -p1
sed -i 's#^substrate-aws-lc = .*#&\nsubstrate-cms = ["substrate", "aprv-security-openssl/cms"]#' "$T/rust/Cargo.toml"
patch -s --no-backup-if-mismatch -d "$T/rust" -p1 < "$PREV/core-patch/clock-seam.patch"
sed -i 's/unix_millis_of(SystemTime::now())/unix_millis_of(crate::clock::system_now())/' "$T/rust/src/substrate.rs"
( cd "$T/rust" && rm src/asn1.rs src/x509.rs src/cms.rs src/crypto.rs src/chain.rs \
    fuzz/fuzz_targets/parse-der.rs fuzz/fuzz_targets/parse-certificate.rs fuzz/fuzz_targets/parse-cms.rs )
patch -s -d "$T/rust" -p1 < "$A4/patch/no-asn1.patch"
# The shim, plus the receipt JSON view extracted from rust/ffi (the part
# aprv-wire would own): from `fn hex_of` up to the `exported: version` banner.
mkdir -p "$T/shim/src"
sed "s#@TREE@#$T#g" "$AB/shim/Cargo.toml.in" > "$T/shim/Cargo.toml"
cp "$AB/shim/src/lib.rs" "$T/shim/src/lib.rs"
F="$T/rust/ffi/src/lib.rs"
grep -q '^fn hex_of' "$F" && grep -q '^// --- exported: version' "$F"
sed -n '/^fn hex_of/,/^\/\/ --- exported: version/p' "$F" | sed '$d' > "$T/shim/src/wire_view.rs"
cp "$T/rust/ffi/Cargo.lock" "$T/shim/Cargo.lock"
TT="--target=wasm32-wasip1 --sysroot=$WS/share/wasi-sysroot"
R="-L native=$WS/share/wasi-sysroot/lib/wasm32-wasip1"
for l in wasi-emulated-signal wasi-emulated-process-clocks wasi-emulated-mman wasi-emulated-getpid; do R="$R -l static=$l"; done
R="$R -C link-arg=$WS/share/wasi-sysroot/lib/wasm32-wasip1/crt1-reactor.o -C link-arg=--export=_initialize --cfg aprv_host_clock"
"$WS/bin/clang" --target=wasm32-wasip1 -O2 -c -DAPRV_HOST_RANDOM -o "$S/wasi-none.o" "$PREV/c/wasi-none.c"
R="$R -C link-arg=$S/wasi-none.o"
CC_wasm32_wasip1=$WS/bin/clang CFLAGS_wasm32_wasip1="$TT" AR_wasm32_wasip1=$WS/bin/llvm-ar \
OPENSSL_DIR="$SCRATCH/inst-wasm/openssl-4.0.2" OPENSSL_STATIC=1 RUSTFLAGS="$R" \
  cargo build --release --target wasm32-wasip1 --manifest-path "$T/shim/Cargo.toml" \
    --target-dir "$TGT" --features "aprv/substrate-cms" > "$S/cargo.log" 2>&1 || { tail -40 "$S/cargo.log"; exit 1; }
cp "$TGT/wasm32-wasip1/release/aprv_wasm_abi.wasm" "$MOD"
cp "$T/shim/Cargo.lock" "$S/art/aprv-abi1.Cargo.lock"
echo "module: $(wc -c < "$MOD") bytes, sha256 $(sha256sum "$MOD" | cut -c1-64)"
echo "imports: $(wasm-tools print "$MOD" | grep -oE '\(import "[^"]*" "[^"]*"' | sed 's/(import "//; s/" "/./; s/"//' | tr '\n' ' ')"
echo "exports: $(wasm-tools print "$MOD" | grep -oE '\(export "[^"]*"' | sed 's/(export "//; s/"//' | tr '\n' ' ')"
