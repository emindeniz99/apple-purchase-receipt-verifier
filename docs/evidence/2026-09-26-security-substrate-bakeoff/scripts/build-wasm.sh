#!/bin/sh
# Builds the wasm shim (wasm/shim: the unchanged rust/ffi C ABI plus
# aprv_alloc/aprv_dealloc) for one wasm target, over a patched scratch copy
# of the core with the substrate picked by cargo features.
#
#   REPO=... SCRATCH=... scripts/build-wasm.sh <name> <target> "<core features>"
#
#   <target>   wasm32-wasip1 or wasm32-unknown-unknown
#   features   "" for the pure-Rust baseline, else as build-variant.sh:
#              substrate, substrate-vendored, substrate-aws-lc
#
# A C substrate needs a C compiler and a libc for the target. The caller
# sets them, for example with wasi-sdk (see README.md, "Wasm"):
#   CC_wasm32_wasip1=$WASI_SDK/bin/clang AR_wasm32_wasip1=$WASI_SDK/bin/llvm-ar
#   OPENSSL_DIR=$SCRATCH/inst-wasm/openssl-4.0.2 OPENSSL_STATIC=1
#
# On wasm32-unknown-unknown the core's rsa/p256/p384 "std" features are
# dropped in the scratch copy: they pull getrandom, which has no source of
# randomness on that target and refuses to compile. Verification never
# draws randomness, so the dropped features change no verdict (the same
# edit as 2026-09-25-rust-core-spikes/core-no-std-features.diff).
#
# Output: $SCRATCH/target-wasm-<name>/<target>/release/aprv_wasm_shim.wasm
set -eu
: "${REPO:?set REPO to the repository root}"
: "${SCRATCH:?set SCRATCH to a scratch directory outside the repository}"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
NAME="$1"
TARGET="$2"
FEATURES="${3:-}"
TREE="$SCRATCH/tree-wasm-$NAME"

rm -rf "$TREE"
mkdir -p "$TREE/rust" "$TREE/shim/src"
tar -C "$REPO/rust" --exclude=./target --exclude=./ffi/target --exclude=./fuzz/target -cf - . \
  | tar -C "$TREE/rust" -xf -
cp "$REPO/version.txt" "$TREE/"
if [ -n "$FEATURES" ]; then
  cp "$SPIKE/core-patch/substrate.rs" "$TREE/rust/src/substrate.rs"
  sed "s#@SPIKE@#$SPIKE#" "$SPIKE/core-patch/core.patch" | patch -s -d "$TREE/rust" -p1
  set -- --features "aprv/$(echo "$FEATURES" | sed 's#,#,aprv/#g')"
else
  set --
fi
if [ "$TARGET" = wasm32-unknown-unknown ]; then
  sed -i -e 's/features = \["std", "u64_digit"\]/features = ["u64_digit"]/' \
         -e 's/features = \["ecdsa", "arithmetic", "std"\]/features = ["ecdsa", "arithmetic"]/' \
         "$TREE/rust/Cargo.toml"
fi
sed -i 's/^crate-type = \["cdylib", "staticlib"\]/crate-type = ["cdylib", "staticlib", "rlib"]/' \
  "$TREE/rust/ffi/Cargo.toml"
sed "s#@TREE@#$TREE#g" "$SPIKE/wasm/shim/Cargo.toml.in" > "$TREE/shim/Cargo.toml"
cp "$SPIKE/wasm/shim/src/lib.rs" "$TREE/shim/src/lib.rs"
# Start from the ffi crate's own lock file, so every shared crate keeps the
# version the native variants used.
cp "$TREE/rust/ffi/Cargo.lock" "$TREE/shim/Cargo.lock"
# wasm-ld as rustc drives it turns an undefined symbol into an import from
# "env" instead of failing the link. OpenSSL built for WASI calls getpid
# and munmap, which wasi-libc provides only in its emulation libraries, so
# without these flags the module links, then fails to instantiate on every
# host with "env.getpid" and "env.munmap" imports. TESTED, see README.md.
if [ -n "$FEATURES" ] && [ "$TARGET" = wasm32-wasip1 ] && [ -n "${WASI_SDK:-}" ]; then
  RUSTFLAGS="${RUSTFLAGS:-} -L native=$WASI_SDK/share/wasi-sysroot/lib/wasm32-wasip1"
  for l in wasi-emulated-signal wasi-emulated-process-clocks wasi-emulated-mman wasi-emulated-getpid; do
    RUSTFLAGS="$RUSTFLAGS -l static=$l"
  done
  export RUSTFLAGS
fi
# Stable rustc links a wasip1 cdylib in the command model: wasm-ld wraps
# every export so it runs the C constructors before the call and the
# destructors after it. With OpenSSL linked in, the first call traps in
# the wrapper (.Lregister_call_dtors, "unreachable"). Linking wasi-libc's
# reactor start file and exporting its _initialize runs the constructors
# once, at instantiation, which is what a library module needs. Nightly
# rustc spells this -Z wasi-exec-model=reactor.
# The start file must match the libc.a that wins the link. With WASI_SDK
# set, the -L above puts wasi-sdk's sysroot ahead of rustc's
# self-contained directory, so "-l c" resolves to wasi-sdk's libc.a and
# its crt1-reactor.o is the one to use. Without it (pure Rust), rustc's own
# pair is used; its start file needs __wasi_init_tp from its libc.a, and
# link-args land after the libraries, so libc.a is named again after it.
# TESTED, see README.md.
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
cargo build --release --target "$TARGET" --manifest-path "$TREE/shim/Cargo.toml" \
  --target-dir "$SCRATCH/target-wasm-$NAME" "$@"
cp "$TREE/shim/Cargo.lock" "$SCRATCH/target-wasm-$NAME/Cargo.lock.used"
ls -l "$SCRATCH/target-wasm-$NAME/$TARGET/release/aprv_wasm_shim.wasm"
