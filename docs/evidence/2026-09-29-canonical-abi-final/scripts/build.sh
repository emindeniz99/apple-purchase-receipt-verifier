#!/bin/sh
# Spike only (2026-09-29, round 13). Builds ../guest (wit-bindgen 0.62.0)
# against ABI v1's core tree with ABI v1's exact RUSTFLAGS and the same
# wasi-none.c object -> $MOD, then `wasm-tools component new` (no adapter)
# -> $COMP. One variant only: release, as generated (no debug-assertions
# build; the owner's interface leaves nothing for the generated lifts to
# check but list lengths). Prints sizes, hashes, imports, exports, custom
# sections and the component's WIT.
#   build.sh > results/build.txt
set -eu
. "$(dirname "$0")/env.sh"
TT="--target=wasm32-wasip1 --sysroot=$WS/share/wasi-sysroot"
R="-L native=$WS/share/wasi-sysroot/lib/wasm32-wasip1"
for l in wasi-emulated-signal wasi-emulated-process-clocks wasi-emulated-mman wasi-emulated-getpid; do R="$R -l static=$l"; done
R="$R -C link-arg=$WS/share/wasi-sysroot/lib/wasm32-wasip1/crt1-reactor.o -C link-arg=--export=_initialize --cfg aprv_host_clock"
"$WS/bin/clang" --target=wasm32-wasip1 -O2 -c -DAPRV_HOST_RANDOM -o "$S/wasi-none.o" "$PREV/c/wasi-none.c"
R="$R -C link-arg=$S/wasi-none.o"
echo "# build.sh, $(date -u +%F); $(rustc --version); wasi-sdk 34.0 clang: $("$WS/bin/clang" --version | head -1); $(wasm-tools --version); $(wit-bindgen --version)"
facts() { # label file
  echo "$1: $(wc -c < "$2") bytes, sha256 $(sha256sum "$2" | cut -c1-64)"
  echo "    imports: $(wasm-tools print "$2" | grep -oE '\(import "[^"]*" "[^"]*"' | sed 's/(import "//; s/" "/ :: /; s/"//' | tr '\n' ';')"
  echo "    exports: $(wasm-tools print "$2" | grep -oE '\(export "[^"]*"' | sed 's/(export "//; s/"//' | tr '\n' ';')"
  echo "    custom sections: $(wasm-tools objdump "$2" 2>/dev/null | grep -E 'custom' | sed -E 's/ +/ /g' | tr '\n' ';')"
}
start=$(date +%s)
G="$S/guest"; rm -rf "$G"; cp -r "$FE/guest" "$G"
sed "s#@TREE@#$TREE#g" "$FE/guest/Cargo.toml.in" > "$G/Cargo.toml"
sed -n '/^fn hex_of/,/^\/\/ --- exported: version/p' "$TREE/rust/ffi/src/lib.rs" | sed '$d' > "$G/src/wire_view.rs"
cmp -s "$G/src/wire_view.rs" "$TREE/shim/src/wire_view.rs" && echo "wire_view.rs: identical to ABI v1's"
CC_wasm32_wasip1=$WS/bin/clang CFLAGS_wasm32_wasip1="$TT" AR_wasm32_wasip1=$WS/bin/llvm-ar \
OPENSSL_DIR="$SCRATCH/inst-wasm/openssl-4.0.2" OPENSSL_STATIC=1 RUSTFLAGS="$R" \
  cargo build --release --target wasm32-wasip1 --manifest-path "$G/Cargo.toml" --target-dir "$S/target" --locked \
    --features "aprv/substrate-cms" > "$S/run/cargo.log" 2>&1 || { tail -40 "$S/run/cargo.log"; exit 1; }
cp "$S/target/wasm32-wasip1/release/aprv_wasm_cabi.wasm" "$MOD"
echo "core module built in $(( $(date +%s) - start )) s"
wasm-tools component new "$MOD" -o "$COMP" 2> "$S/run/component-new.err" && echo "component new: OK (no adapter)" || echo "component new FAILED: $(cat "$S/run/component-new.err")"
facts "ABI v1 module (b14e14b2)" "$V1"
facts "canonical-ABI core module" "$MOD"
echo "component: $(wc -c < "$COMP") bytes, sha256 $(sha256sum "$COMP" | cut -c1-64)"
echo "component wit:"; wasm-tools component wit "$COMP" | sed 's/^/    /'
