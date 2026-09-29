#!/bin/sh
# Builds the OpenSSL 4.0.2 CMS path (the follow-up's adapter-cms, with the
# substrate bake-off's asn1.rs prescan on: features substrate-cms +
# substrate-prescan) for every route, with rustc 1.98.1.
#
#   scripts/build.sh adapter                the patched adapter copy only
#   scripts/build.sh native                 native C ABI (.so), OPENSSL_DIR route
#   scripts/build.sh routec                 Route C: wasm32-wasip1 + c/wasi-none.c
#                                           (-DAPRV_HOST_RANDOM), host clock: imports
#                                           only aprv.clock_now_ms + aprv.random_get
#   scripts/build.sh wasip1                 Route A: wasm32-wasip1, WASI imports,
#                                           answered by a minimal JS host
#   scripts/build.sh emscripten             Route B: wasm32-unknown-emscripten
#                                           staticlib + emcc, node+web and web glue
#   scripts/build.sh component              Route D: wit-bindgen guest, WASI 0.2
#                                           reactor adapter, jco transpile
#
# Inputs, all from the earlier rounds and unchanged: the substrate
# bake-off's adapter ($SPIKE/security-openssl) + policy
# ($SPIKE/core-patch), the follow-up's CMS patch ($FUP/adapter-cms), the
# wasm bake-off's clock seam, shim, guest, wasi-none.c and link fixes
# ($PREV), and its OpenSSL 4.0.2 builds in $SCRATCH/inst{,-wasm,-em}.
# Outputs: $SCRATCH/cms/art/<artifact>.
set -eu
. "$(dirname "$0")/env.sh"
AD="$C/adapter"
adapter() {
  rm -rf "$AD"; mkdir -p "$AD"
  cp -r "$SPIKE/security-openssl" "$AD/"
  patch -s -d "$AD/security-openssl" -p1 < "$FUP/adapter-cms/adapter-cms.patch"
  cp "$FUP/adapter-cms/cms_path.rs" "$AD/security-openssl/src/cms_path.rs"
}
FEAT="substrate-cms,substrate-prescan"
# A scratch copy of rust/ with the policy, the CMS adapter and (wasm) the
# clock seam; $2 = crate dir to build (shim or guest) or "" for native ffi.
tree() { # name, shim-dir-or-empty
  T="$SCRATCH/tree-$1"
  rm -rf "$T"; mkdir -p "$T/rust"
  tar -C "$REPO/rust" --exclude=./target --exclude=./ffi/target --exclude=./fuzz/target -cf - . | tar -C "$T/rust" -xf -
  cp "$REPO/version.txt" "$T/"
  cp "$SPIKE/core-patch/substrate.rs" "$T/rust/src/substrate.rs"
  sed "s#@SPIKE@#$AD#" "$SPIKE/core-patch/core.patch" | patch -s -d "$T/rust" -p1
  sed -i 's#^substrate-aws-lc = .*#&\nsubstrate-cms = ["substrate", "aprv-security-openssl/cms"]#' "$T/rust/Cargo.toml"
  if [ -n "$2" ]; then
    patch -s -d "$T/rust" -p1 < "$PREV/core-patch/clock-seam.patch"
    sed -i 's/unix_millis_of(SystemTime::now())/unix_millis_of(crate::clock::system_now())/' "$T/rust/src/substrate.rs"
    mkdir -p "$T/shim/src"
    sed "s#@TREE@#$T#g" "$2/Cargo.toml.in" > "$T/shim/Cargo.toml"
    cp "$2/src/lib.rs" "$T/shim/src/lib.rs"
    [ -d "$2/../wit" ] && cp -r "$2/../wit" "$T/shim/wit"
    sed -i 's/^crate-type = \["cdylib", "staticlib"\]/crate-type = ["cdylib", "staticlib", "rlib"]/' "$T/rust/ffi/Cargo.toml"
    cp "$T/rust/ffi/Cargo.lock" "$T/shim/Cargo.lock"
  fi
}
WS="${WASI_SDK:?source \$SCRATCH/env.sh (the wasm bake-off toolchains) first}"
wasip1() { # name, shim dir, stub (0|1), stub cflags, host clock (0|1)
  tree "$1" "$2"
  TT="--target=wasm32-wasip1 --sysroot=$WS/share/wasi-sysroot"
  R="-L native=$WS/share/wasi-sysroot/lib/wasm32-wasip1"
  for l in wasi-emulated-signal wasi-emulated-process-clocks wasi-emulated-mman wasi-emulated-getpid; do R="$R -l static=$l"; done
  R="$R -C link-arg=$WS/share/wasi-sysroot/lib/wasm32-wasip1/crt1-reactor.o -C link-arg=--export=_initialize"
  [ "$5" = 1 ] && R="$R --cfg aprv_host_clock"
  if [ "$3" = 1 ]; then
    "$WS/bin/clang" --target=wasm32-wasip1 -O2 -c $4 -o "$C/wasi-none-$1.o" "$PREV/c/wasi-none.c"
    R="$R -C link-arg=$C/wasi-none-$1.o"
  fi
  CC_wasm32_wasip1=$WS/bin/clang CFLAGS_wasm32_wasip1="$TT" AR_wasm32_wasip1=$WS/bin/llvm-ar \
  OPENSSL_DIR="$SCRATCH/inst-wasm/openssl-4.0.2" OPENSSL_STATIC=1 RUSTFLAGS="$R" \
    cargo build --release --target wasm32-wasip1 --manifest-path "$SCRATCH/tree-$1/shim/Cargo.toml" \
      --target-dir "$SCRATCH/target-$1" --features "aprv/$(echo $FEAT | sed 's#,#,aprv/#')"
  cp "$SCRATCH/tree-$1/shim/Cargo.lock" "$C/art/$1.Cargo.lock"
}
case "$1" in
adapter) adapter ;;
native)
  adapter; tree cms-native ""
  OPENSSL_DIR="$SCRATCH/inst/openssl-4.0.2" OPENSSL_STATIC=1 \
    cargo build --release --manifest-path "$SCRATCH/tree-cms-native/rust/ffi/Cargo.toml" \
      --target-dir "$SCRATCH/target-cms-native" \
      --features "apple-purchase-receipt-verifier/$(echo $FEAT | sed 's#,#,apple-purchase-receipt-verifier/#')"
  mkdir -p "$C/art/native"
  cp "$SCRATCH/target-cms-native/release/libapple_purchase_receipt_verifier_ffi.so" "$C/art/native/"
  cp "$SCRATCH/tree-cms-native/rust/ffi/Cargo.lock" "$C/art/cms-native.Cargo.lock"
  ;;
routec)
  adapter; wasip1 cms-c "$PREV/shim" 1 -DAPRV_HOST_RANDOM 1
  cp "$SCRATCH/target-cms-c/wasm32-wasip1/release/aprv_wasm_shim.wasm" "$C/art/cms-c.wasm"
  ;;
wasip1)
  adapter; wasip1 cms-w1 "$PREV/shim" 0 "" 0
  cp "$SCRATCH/target-cms-w1/wasm32-wasip1/release/aprv_wasm_shim.wasm" "$C/art/cms-w1.wasm"
  ;;
emscripten)
  adapter; tree cms-em "$PREV/shim"
  sed -i 's/^crate-type = \["cdylib", "staticlib", "rlib"\]/crate-type = ["rlib"]/' "$SCRATCH/tree-cms-em/rust/ffi/Cargo.toml"
  sed -i 's/^crate-type = \["cdylib", "staticlib"\]/crate-type = ["staticlib"]/' "$SCRATCH/tree-cms-em/shim/Cargo.toml"
  CC_wasm32_unknown_emscripten=emcc CXX_wasm32_unknown_emscripten=em++ AR_wasm32_unknown_emscripten=emar \
  OPENSSL_DIR="$SCRATCH/inst-em/openssl-4.0.2" OPENSSL_STATIC=1 \
    cargo build --release --target wasm32-unknown-emscripten --manifest-path "$SCRATCH/tree-cms-em/shim/Cargo.toml" \
      --target-dir "$SCRATCH/target-cms-em" --features "aprv/$(echo $FEAT | sed 's#,#,aprv/#')"
  cp "$SCRATCH/tree-cms-em/shim/Cargo.lock" "$C/art/cms-em.Cargo.lock"
  L="$SCRATCH/target-cms-em/wasm32-unknown-emscripten/release/libaprv_wasm_shim.a"
  # The wasm bake-off's link step, unchanged (its build-emscripten.sh link).
  RUSTLIB="$L" OUTNAME=cms-em "$PREV/scripts/build-emscripten.sh" link cms-em
  RUSTLIB="$L" OUTNAME=cms-em-web "$PREV/scripts/build-emscripten.sh" link cms-em -sENVIRONMENT=web,worker
  rm -rf "$C/art/cms-em" "$C/art/cms-em-web"
  mv "$SCRATCH/em/cms-em" "$SCRATCH/em/cms-em-web" "$C/art/"
  cmp "$C/art/cms-em/aprv-em.wasm" "$C/art/cms-em-web/aprv-em.wasm"
  ;;
component)
  adapter; wasip1 cms-comp "$PREV/component/guest" 1 -DAPRV_KEEP_WASI_RANDOM_CLOCK 0
  W="$SCRATCH/target-cms-comp/wasm32-wasip1/release/aprv_component.wasm"
  wasm-tools component new "$W" --adapt wasi_snapshot_preview1="$SCRATCH/dl/wasi_snapshot_preview1.reactor.wasm" \
    -o "$C/art/cms-comp.component.wasm"
  rm -rf "$C/art/cms-comp-jco"
  "$SCRATCH/jco/node_modules/.bin/jco" transpile "$C/art/cms-comp.component.wasm" -o "$C/art/cms-comp-jco" \
    --name aprv --instantiation async
  ;;
esac
