#!/bin/sh
# Builds the shim ($EV/shim: the unchanged rust/ffi C ABI + aprv_alloc,
# aprv_dealloc, aprv_init) for one wasm target over a patched scratch copy
# of the core. Derived from the previous bake-off's scripts/build-wasm.sh;
# the two WASI link fixes are carried over unchanged.
#
#   REPO=... SCRATCH=... scripts/build-core.sh <name> <target> "<core features>"
#
#   <target>    wasm32-wasip1 | wasm32-unknown-unknown | wasm32-unknown-emscripten
#   features    "" (pure Rust) | substrate (OPENSSL_DIR) | substrate-aws-lc
#   CLOCK_SEAM=0   leave out core-patch/clock-seam.patch (reproduces the
#                  previous bake-off's 58 wasm32-unknown-unknown traps)
#   HOST_CLOCK=1   build with --cfg aprv_host_clock: the core reads "now"
#                  from the aprv.clock_now_ms import on wasip1/emscripten too
#   REACTOR=0      wasip1 only: skip the reactor start file (link fix 2)
#
# Output: $SCRATCH/target-<name>/<target>/release/{aprv_wasm_shim.wasm,libaprv_wasm_shim.a}
set -eu
: "${REPO:?}" "${SCRATCH:?}"
EV="$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
NAME="$1"; TARGET="$2"; FEATURES="${3:-}"
# SHIM=<dir> builds another crate over the same patched tree (the component
# guest, component/guest); a sibling wit/ folder is copied next to it.
SHIM="${SHIM:-$EV/shim}"
TREE="$SCRATCH/tree-$NAME"
rm -rf "$TREE"
mkdir -p "$TREE/rust" "$TREE/shim/src"
tar -C "$REPO/rust" --exclude=./target --exclude=./ffi/target --exclude=./fuzz/target -cf - . \
  | tar -C "$TREE/rust" -xf -
cp "$REPO/version.txt" "$TREE/"
if [ "${CLOCK_SEAM:-1}" = 1 ]; then
  patch -s -d "$TREE/rust" -p1 < "$EV/core-patch/clock-seam.patch"
fi
if [ -n "$FEATURES" ]; then
  cp "$SPIKE/core-patch/substrate.rs" "$TREE/rust/src/substrate.rs"
  if [ "${CLOCK_SEAM:-1}" = 1 ]; then
    # The substrate policy reads "now" in the same two fallbacks as the core.
    sed -i 's/unix_millis_of(SystemTime::now())/unix_millis_of(crate::clock::system_now())/' "$TREE/rust/src/substrate.rs"
  fi
  sed "s#@SPIKE@#$SPIKE#" "$SPIKE/core-patch/core.patch" | patch -s -d "$TREE/rust" -p1
  set -- --features "aprv/$(echo "$FEATURES" | sed 's#,#,aprv/#g')"
else
  set --
fi
if [ "$TARGET" != wasm32-wasip1 ]; then
  # rsa/p256/p384 "std" pulls getrandom, which refuses wasm32-unknown-unknown
  # (2026-09-25 spike). Verification draws no randomness; dropped on every
  # non-WASI wasm target so the three builds share one dependency graph.
  sed -i -e 's/features = \["std", "u64_digit"\]/features = ["u64_digit"]/' \
         -e 's/features = \["ecdsa", "arithmetic", "std"\]/features = ["ecdsa", "arithmetic"]/' \
         "$TREE/rust/Cargo.toml"
fi
sed -i 's/^crate-type = \["cdylib", "staticlib"\]/crate-type = ["cdylib", "staticlib", "rlib"]/' "$TREE/rust/ffi/Cargo.toml"
sed "s#@TREE@#$TREE#g" "$SHIM/Cargo.toml.in" > "$TREE/shim/Cargo.toml"
cp "$SHIM/src/lib.rs" "$TREE/shim/src/lib.rs"
[ -d "$SHIM/../wit" ] && cp -r "$SHIM/../wit" "$TREE/shim/wit"
if [ "$TARGET" = wasm32-unknown-emscripten ]; then
  # emcc links the final module (scripts/build-emscripten.sh link); a
  # cdylib here would make rustc drive emcc itself and fail on "no main".
  sed -i 's/^crate-type = \["cdylib", "staticlib", "rlib"\]/crate-type = ["rlib"]/' "$TREE/rust/ffi/Cargo.toml"
  sed -i 's/^crate-type = \["cdylib", "staticlib"\]/crate-type = ["staticlib"]/' "$TREE/shim/Cargo.toml"
fi
cp "$TREE/rust/ffi/Cargo.lock" "$TREE/shim/Cargo.lock"
[ "${HOST_CLOCK:-0}" = 1 ] && RUSTFLAGS="${RUSTFLAGS:-} --cfg aprv_host_clock" && export RUSTFLAGS
if [ -n "$FEATURES" ] && [ "$TARGET" = wasm32-wasip1 ] && [ -n "${WASI_SDK:-}" ]; then
  RUSTFLAGS="${RUSTFLAGS:-} -L native=$WASI_SDK/share/wasi-sysroot/lib/wasm32-wasip1"
  for l in wasi-emulated-signal wasi-emulated-process-clocks wasi-emulated-mman wasi-emulated-getpid; do
    RUSTFLAGS="$RUSTFLAGS -l static=$l"
  done
  export RUSTFLAGS
fi
if [ "$TARGET" = wasm32-wasip1 ] && [ "${REACTOR:-1}" = 1 ]; then
  if [ -n "$FEATURES" ] && [ -n "${WASI_SDK:-}" ]; then
    START="$WASI_SDK/share/wasi-sysroot/lib/wasm32-wasip1/crt1-reactor.o"
  else
    SC="$(rustc --print sysroot)/lib/rustlib/wasm32-wasip1/lib/self-contained"
    START="$SC/crt1-reactor.o -C link-arg=$SC/libc.a"
  fi
  RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=$START -C link-arg=--export=_initialize"
  export RUSTFLAGS
fi
# Route C: STUB_WASI=1 links c/wasi-none.c, which DEFINES every WASI p1
# function wasi-libc imports, so the module imports none of them (only
# aprv.clock_now_ms, plus aprv.random_get with STUB_CFLAGS=-DAPRV_HOST_RANDOM).
if [ "${STUB_WASI:-0}" = 1 ]; then
  "$WASI_SDK/bin/clang" --target=wasm32-wasip1 -O2 -c ${STUB_CFLAGS:-} \
    -o "$SCRATCH/wasi-none-$NAME.o" "$EV/c/wasi-none.c"
  RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=$SCRATCH/wasi-none-$NAME.o"
  export RUSTFLAGS
fi
[ "${CLOCK_SEAM:-1}" = 1 ] || set -- "$@" --no-default-features
[ -n "${CRATE_FEATURES:-}" ] && set -- "$@" --features "$CRATE_FEATURES"
echo "RUSTFLAGS=${RUSTFLAGS:-}"
cargo build --release --target "$TARGET" --manifest-path "$TREE/shim/Cargo.toml" \
  --target-dir "$SCRATCH/target-$NAME" "$@"
cp "$TREE/shim/Cargo.lock" "$SCRATCH/target-$NAME/Cargo.lock.used"
ls -l "$SCRATCH/target-$NAME/$TARGET/release/" | grep -E 'aprv_'
