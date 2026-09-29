#!/bin/sh
# Builds the two cores this round compares, with rustc 1.98.1 and OpenSSL
# 4.0.2 (OPENSSL_DIR builds under $SCRATCH/inst and $SCRATCH/inst-wasm):
#
#   base  the round-3 CMS path WITHOUT the asn1.rs prescan (feature
#         substrate-cms): certificates, CMS and signatures in OpenSSL, the
#         receipt payload still read by rust/src/asn1.rs.
#   new   the same, with asn1.rs deleted: patch/no-asn1.patch removes
#         asn1.rs and everything built on it (x509.rs, cms.rs, crypto.rs,
#         chain.rs), and the payload is read by the adapter's payload.rs
#         (OpenSSL templates from payload.c; feature payload-any for the
#         generic SET/SEQUENCE OF ANY walk instead).
#
#   scripts/build.sh native-base      $C/art/base/libapple_purchase_receipt_verifier_ffi.so
#   scripts/build.sh native-new       $C/art/new/...          (templates)
#   scripts/build.sh native-any       $C/art/any/...          (payload-any)
#   scripts/build.sh routec-new       $C/art/new-c.wasm       Route C (imports aprv.clock_now_ms + aprv.random_get)
#   scripts/build.sh routec-any       $C/art/any-c.wasm
#   scripts/build.sh check-new        cargo test --lib + clippy on the new tree (no asn1.rs)
#   scripts/build.sh examples         the payload replay example in both trees
#
# Inputs, all unchanged: the substrate bake-off's adapter and policy
# ($SPIKE), the follow-up's CMS patch ($FUP), the wasm bake-off's clock seam,
# shim and wasi-none.c ($PREV). This folder adds adapter/ and patch/.
set -eu
. "$(dirname "$0")/env.sh"

adapter() { # name, 0|1 (with the round-4 payload module)
  AD="$C/adapter-$1"; rm -rf "$AD"; mkdir -p "$AD"
  cp -r "$SPIKE/security-openssl" "$AD/"
  patch -s -d "$AD/security-openssl" -p1 < "$FUP/adapter-cms/adapter-cms.patch"
  cp "$FUP/adapter-cms/cms_path.rs" "$AD/security-openssl/src/cms_path.rs"
  if [ "$2" = 1 ]; then
    patch -s -d "$AD/security-openssl" -p2 < "$EV/adapter/adapter-asn1.patch"
    cp "$EV/adapter/payload.rs" "$EV/adapter/payload_templates.rs" "$EV/adapter/payload_any.rs" \
       "$EV/adapter/payload.c" "$AD/security-openssl/src/"
  fi
}

# A scratch copy of rust/ with the round-3 policy and CMS adapter, the wasm
# clock seam (a no-op on native targets), and the comparison probe. With
# $3 = 1 it becomes the no-asn1 tree.
tree() { # name, adapter name, 0|1 (no-asn1)
  T="$SCRATCH/tree-$1"; rm -rf "$T"; mkdir -p "$T/rust"
  tar -C "$REPO/rust" --exclude=./target --exclude=./ffi/target --exclude=./fuzz/target -cf - . | tar -C "$T/rust" -xf -
  cp "$REPO/version.txt" "$T/"
  cp "$SPIKE/core-patch/substrate.rs" "$T/rust/src/substrate.rs"
  sed "s#@SPIKE@#$C/adapter-$2#" "$SPIKE/core-patch/core.patch" | patch -s -d "$T/rust" -p1
  sed -i 's#^substrate-aws-lc = .*#&\nsubstrate-cms = ["substrate", "aprv-security-openssl/cms"]#' "$T/rust/Cargo.toml"
  patch -s --no-backup-if-mismatch -d "$T/rust" -p1 < "$PREV/core-patch/clock-seam.patch"
  sed -i 's/unix_millis_of(SystemTime::now())/unix_millis_of(crate::clock::system_now())/' "$T/rust/src/substrate.rs"
  cp "$EV/patch/spike_probe.rs" "$T/rust/src/spike_probe.rs"
  printf '\n#[doc(hidden)]\npub mod spike_probe;\n' >> "$T/rust/src/lib.rs"
  mkdir -p "$T/rust/examples"; cp "$EV/examples/spike_payload.rs" "$T/rust/examples/"
  if [ "$3" = 1 ]; then
    ( cd "$T/rust" && rm src/asn1.rs src/x509.rs src/cms.rs src/crypto.rs src/chain.rs \
        fuzz/fuzz_targets/parse-der.rs fuzz/fuzz_targets/parse-certificate.rs fuzz/fuzz_targets/parse-cms.rs )
    patch -s -d "$T/rust" -p1 < "$EV/patch/no-asn1.patch"
  fi
}

native() { # tree name, adapter name, no-asn1, artifact dir, extra features
  tree "$1" "$2" "$3"
  OPENSSL_DIR="$SCRATCH/inst/openssl-4.0.2" OPENSSL_STATIC=1 \
    cargo build --release --manifest-path "$SCRATCH/tree-$1/rust/ffi/Cargo.toml" \
      --target-dir "$SCRATCH/target-$1" --features "apple-purchase-receipt-verifier/substrate-cms$5"
  mkdir -p "$C/art/$4"
  cp "$SCRATCH/target-$1/release/libapple_purchase_receipt_verifier_ffi.so" "$C/art/$4/"
  cp "$SCRATCH/tree-$1/rust/ffi/Cargo.lock" "$C/art/$4.Cargo.lock"
}

WS="${WASI_SDK:?source \$SCRATCH/env.sh (the wasm bake-off toolchains) first}"
routec() { # tree name, adapter name, output name, extra features
  tree "$1" "$2" 1
  T="$SCRATCH/tree-$1"
  mkdir -p "$T/shim/src"
  sed "s#@TREE@#$T#g" "$PREV/shim/Cargo.toml.in" > "$T/shim/Cargo.toml"
  cp "$PREV/shim/src/lib.rs" "$T/shim/src/lib.rs"
  sed -i 's/^crate-type = \["cdylib", "staticlib"\]/crate-type = ["cdylib", "staticlib", "rlib"]/' "$T/rust/ffi/Cargo.toml"
  cp "$T/rust/ffi/Cargo.lock" "$T/shim/Cargo.lock"
  TT="--target=wasm32-wasip1 --sysroot=$WS/share/wasi-sysroot"
  R="-L native=$WS/share/wasi-sysroot/lib/wasm32-wasip1"
  for l in wasi-emulated-signal wasi-emulated-process-clocks wasi-emulated-mman wasi-emulated-getpid; do R="$R -l static=$l"; done
  R="$R -C link-arg=$WS/share/wasi-sysroot/lib/wasm32-wasip1/crt1-reactor.o -C link-arg=--export=_initialize --cfg aprv_host_clock"
  "$WS/bin/clang" --target=wasm32-wasip1 -O2 -c -DAPRV_HOST_RANDOM -o "$C/wasi-none-$1.o" "$PREV/c/wasi-none.c"
  R="$R -C link-arg=$C/wasi-none-$1.o"
  CC_wasm32_wasip1=$WS/bin/clang CFLAGS_wasm32_wasip1="$TT" AR_wasm32_wasip1=$WS/bin/llvm-ar \
  OPENSSL_DIR="$SCRATCH/inst-wasm/openssl-4.0.2" OPENSSL_STATIC=1 RUSTFLAGS="$R" \
    cargo build --release --target wasm32-wasip1 --manifest-path "$T/shim/Cargo.toml" \
      --target-dir "$SCRATCH/target-$1" --features "aprv/substrate-cms$4"
  cp "$SCRATCH/target-$1/wasm32-wasip1/release/aprv_wasm_shim.wasm" "$C/art/$3.wasm"
  cp "$T/shim/Cargo.lock" "$C/art/$3.Cargo.lock"
}

case "$1" in
native-base) adapter base 0; native base base 0 base "" ;;
native-new)  adapter new 1;  native new new 1 new "" ;;
native-any)  adapter new 1;  native any new 1 any ",apple-purchase-receipt-verifier/substrate-payload-any" ;;
routec-new)  adapter new 1;  routec new-c new new-c "" ;;
routec-any)  adapter new 1;  routec any-c new any-c ",aprv/substrate-payload-any" ;;
check-new)
  # The no-asn1 tree's own unit tests (receipt_payload's included, now
  # against OpenSSL) and clippy with the crate's lint set, for both walks.
  # unexpected_cfgs is allowed: `aprv_host_clock` is the wasm bake-off's
  # clock-seam cfg, which the shim declares and this crate does not.
  adapter new 1; tree check new 1
  for f in "" ",substrate-payload-any"; do
    OPENSSL_DIR="$SCRATCH/inst/openssl-4.0.2" OPENSSL_STATIC=1 \
      cargo test --release --lib --manifest-path "$SCRATCH/tree-check/rust/Cargo.toml" \
        --target-dir "$SCRATCH/target-check" --features "substrate-cms$f"
    OPENSSL_DIR="$SCRATCH/inst/openssl-4.0.2" OPENSSL_STATIC=1 \
      cargo clippy --release --lib --manifest-path "$SCRATCH/tree-check/rust/Cargo.toml" \
        --target-dir "$SCRATCH/target-check" --features "substrate-cms$f" -- -D warnings -A unexpected_cfgs
  done
  ls "$SCRATCH/tree-check/rust/src" ;;
examples)
  for t in ${2:-base new any}; do
    f=""; [ "$t" = any ] && f=",substrate-payload-any"
    OPENSSL_DIR="$SCRATCH/inst/openssl-4.0.2" OPENSSL_STATIC=1 \
      cargo build --release --example spike_payload --manifest-path "$SCRATCH/tree-$t/rust/Cargo.toml" \
        --target-dir "$SCRATCH/target-$t" --features "substrate-cms$f"
    cp "$SCRATCH/target-$t/release/examples/spike_payload" "$C/art/spike_payload-$t"
  done ;;
esac
