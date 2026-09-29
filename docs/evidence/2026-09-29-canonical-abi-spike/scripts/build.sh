#!/bin/sh
# Spike only (2026-09-29, round 12). Builds, one at a time:
#   v1     ABI v1's shim from ABI v1's scratch tree, unchanged, into its own
#          target dir: proves the tree still builds b14e14b2... byte for byte
#          (so "same core, same crypto" is checked, not assumed)
#   cabi   ../guest (wit-bindgen 0.62.0) against the same tree, with ABI v1's
#          exact RUSTFLAGS and the same wasi-none.c object -> $MOD, then
#          `wasm-tools component new` (no adapter) -> $COMP
#   checked  the same with debug-assertions on for the guest crate ONLY
#          (profile.release.package.aprv-wasm-cabi): wit-bindgen's generated
#          lifts then check UTF-8, enum and bool values and trap on a bad
#          one, instead of trusting the caller -> $MODC, $COMPC
# and prints sizes, hashes, imports, exports and custom sections.
#   build.sh [v1] [cabi] > results/build.txt
set -eu
. "$(dirname "$0")/env.sh"
STEPS=${*:-"v1 cabi checked"}
TT="--target=wasm32-wasip1 --sysroot=$WS/share/wasi-sysroot"
R="-L native=$WS/share/wasi-sysroot/lib/wasm32-wasip1"
for l in wasi-emulated-signal wasi-emulated-process-clocks wasi-emulated-mman wasi-emulated-getpid; do R="$R -l static=$l"; done
R="$R -C link-arg=$WS/share/wasi-sysroot/lib/wasm32-wasip1/crt1-reactor.o -C link-arg=--export=_initialize --cfg aprv_host_clock"
"$WS/bin/clang" --target=wasm32-wasip1 -O2 -c -DAPRV_HOST_RANDOM -o "$S/wasi-none.o" "$PREV/c/wasi-none.c"
R="$R -C link-arg=$S/wasi-none.o"
echo "# build.sh, $(date -u +%F); $(rustc --version); wasi-sdk 34.0 clang: $("$WS/bin/clang" --version | head -1); $(wasm-tools --version); $(wit-bindgen --version)"
cb() { # manifest target-dir
  CC_wasm32_wasip1=$WS/bin/clang CFLAGS_wasm32_wasip1="$TT" AR_wasm32_wasip1=$WS/bin/llvm-ar \
  OPENSSL_DIR="$SCRATCH/inst-wasm/openssl-4.0.2" OPENSSL_STATIC=1 RUSTFLAGS="$R" \
    cargo build --release --target wasm32-wasip1 --manifest-path "$1" --target-dir "$2" $3 --features "aprv/substrate-cms"
}
facts() { # label file
  echo "$1: $(wc -c < "$2") bytes, sha256 $(sha256sum "$2" | cut -c1-64)"
  echo "    imports: $(wasm-tools print "$2" | grep -oE '\(import "[^"]*" "[^"]*"' | sed 's/(import "//; s/" "/ :: /; s/"//' | tr '\n' ';')"
  echo "    exports: $(wasm-tools print "$2" | grep -oE '\(export "[^"]*"' | sed 's/(export "//; s/"//' | tr '\n' ';')"
  echo "    custom sections: $(wasm-tools objdump "$2" 2>/dev/null | grep -E 'custom' | sed -E 's/ +/ /g' | tr '\n' ';')"
}
for step in $STEPS; do
  start=$(date +%s)
  case $step in
  v1)
    rm -rf "$S/v1"; mkdir -p "$S/v1"; cp -r "$TREE/shim" "$S/v1/shim"
    sed -i "s#path = \"[^\"]*/rust\"#path = \"$TREE/rust\"#" "$S/v1/shim/Cargo.toml"
    cb "$S/v1/shim/Cargo.toml" "$S/target-v1" --locked > "$S/run/cargo-v1.log" 2>&1 || { tail -30 "$S/run/cargo-v1.log"; exit 1; }
    cp "$S/target-v1/wasm32-wasip1/release/aprv_wasm_abi.wasm" "$S/art/aprv-abi1.rebuilt.wasm"
    got=$(sha256sum "$S/art/aprv-abi1.rebuilt.wasm" | cut -c1-64)
    echo "v1 rebuilt from the ABI v1 tree in $(( $(date +%s) - start )) s: sha256 $got ($( [ "$got" = "$V1_SHA256" ] && echo "IDENTICAL to b14e14b2..." || echo "DIFFERS from $V1_SHA256"))"
    rm -rf "$S/target-v1" ;;
  cabi|checked)
    G="$S/guest"; rm -rf "$G"; cp -r "$FE/guest" "$G"
    sed "s#@TREE@#$TREE#g" "$FE/guest/Cargo.toml.in" > "$G/Cargo.toml"
    F="$TREE/rust/ffi/src/lib.rs"
    sed -n '/^fn hex_of/,/^\/\/ --- exported: version/p' "$F" | sed '$d' > "$G/src/wire_view.rs"
    cmp -s "$G/src/wire_view.rs" "$TREE/shim/src/wire_view.rs" && echo "wire_view.rs: identical to ABI v1's"
    if [ -f "$FE/guest/Cargo.lock" ]; then lock=--locked; else cp "$TREE/shim/Cargo.lock" "$G/Cargo.lock"; lock=; fi
    if [ $step = checked ]; then extra="--config profile.release.package.aprv-wasm-cabi.debug-assertions=true"; m=$MODC; c=$COMPC; else extra=; m=$MOD; c=$COMP; fi
    cb "$G/Cargo.toml" "$S/target" "$lock $extra" > "$S/run/cargo-$step.log" 2>&1 || { tail -40 "$S/run/cargo-$step.log"; exit 1; }
    [ -n "$lock" ] || cp "$G/Cargo.lock" "$FE/guest/Cargo.lock"
    cp "$S/target/wasm32-wasip1/release/aprv_wasm_cabi.wasm" "$m"
    echo "$step core module built in $(( $(date +%s) - start )) s"
    wasm-tools component new "$m" -o "$c" 2> "$S/run/component-new.err" && echo "$step component new: OK (no adapter)" || { echo "$step component new FAILED: $(cat "$S/run/component-new.err")"; }
    ;;
  esac
done
facts "ABI v1 module (b14e14b2)" "$V1"
if [ -f "$MOD" ]; then facts "canonical-ABI core module (as generated)" "$MOD"; fi
if [ -f "$MODC" ]; then facts "canonical-ABI core module (checked)" "$MODC"; fi
if [ -f "$COMPC" ]; then echo "component (checked): $(wc -c < "$COMPC") bytes, sha256 $(sha256sum "$COMPC" | cut -c1-64)"; fi
if [ -f "$COMP" ]; then
  echo "component: $(wc -c < "$COMP") bytes, sha256 $(sha256sum "$COMP" | cut -c1-64)"
  echo "component wit:"; wasm-tools component wit "$COMP" | sed 's/^/    /'
fi
