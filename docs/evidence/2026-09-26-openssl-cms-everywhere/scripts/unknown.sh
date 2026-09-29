#!/bin/sh
# Task 3: the same CMS shim, for wasm32-unknown-unknown, with rustc 1.98.1.
# openssl-sys's build script needs a C compiler and headers for the target;
# wasi-sdk's clang with its sysroot is given so the build script gets past
# header probing and the failure shown is the Rust one. The compile errors
# are kept, deduplicated, in results/unknown-unknown.txt.
#   scripts/unknown.sh
set -eu
. "$(dirname "$0")/env.sh"
: "${WASI_SDK:?}"
"$EV/scripts/build.sh" adapter
T="$SCRATCH/tree-cms-uu"; rm -rf "$T"; mkdir -p "$T/rust" "$T/shim/src"
tar -C "$REPO/rust" --exclude=./target --exclude=./ffi/target --exclude=./fuzz/target -cf - . | tar -C "$T/rust" -xf -
cp "$REPO/version.txt" "$T/"
cp "$SPIKE/core-patch/substrate.rs" "$T/rust/src/substrate.rs"
sed "s#@SPIKE@#$C/adapter#" "$SPIKE/core-patch/core.patch" | patch -s -d "$T/rust" -p1
sed -i 's#^substrate-aws-lc = .*#&\nsubstrate-cms = ["substrate", "aprv-security-openssl/cms"]#' "$T/rust/Cargo.toml"
patch -s -d "$T/rust" -p1 < "$PREV/core-patch/clock-seam.patch"
# as the wasm bake-off's build-core.sh does for every non-WASI wasm target
sed -i -e 's/features = \["std", "u64_digit"\]/features = ["u64_digit"]/' \
       -e 's/features = \["ecdsa", "arithmetic", "std"\]/features = ["ecdsa", "arithmetic"]/' "$T/rust/Cargo.toml"
sed "s#@TREE@#$T#g" "$PREV/shim/Cargo.toml.in" > "$T/shim/Cargo.toml"
cp "$PREV/shim/src/lib.rs" "$T/shim/src/lib.rs"
sed -i 's/^crate-type = \["cdylib", "staticlib"\]/crate-type = ["cdylib", "staticlib", "rlib"]/' "$T/rust/ffi/Cargo.toml"
cp "$T/rust/ffi/Cargo.lock" "$T/shim/Cargo.lock"
L="$C/unknown-unknown.log"
CC_wasm32_unknown_unknown="$WASI_SDK/bin/clang" \
CFLAGS_wasm32_unknown_unknown="--sysroot=$WASI_SDK/share/wasi-sysroot" \
OPENSSL_DIR="$SCRATCH/inst-wasm/openssl-4.0.2" OPENSSL_STATIC=1 \
  cargo build --release --target wasm32-unknown-unknown --manifest-path "$T/shim/Cargo.toml" \
    --target-dir "$SCRATCH/target-cms-uu" --features aprv/substrate-cms,aprv/substrate-prescan --keep-going > "$L" 2>&1 || true
{
  echo "# rustc $(rustc --version | cut -d' ' -f2-), target wasm32-unknown-unknown, CMS shim (substrate-cms + substrate-prescan), 2026-09-26"
  echo "# per crate: 'could not compile' lines"
  grep -E '^error: could not compile' "$L" | sed "s#$SCRATCH#\$SCRATCH#g"
  echo "# distinct error messages (count, message), across all crates"
  grep -E '^error(\[E[0-9]+\])?: ' "$L" | grep -v 'could not compile' | sed -E 's/`[^`]*`/`X`/2g' | sort | uniq -c | sort -rn | head -25
  echo "# the first occurrences, with location"
  grep -E -A3 '^error\[E0412\]|^error\[E0425\]|^error\[E0433\]' "$L" | grep -E '^error|-->' | head -16 | sed "s#$SCRATCH#\$SCRATCH#g; s#$CARGO_HOME#\$CARGO_HOME#g"
} > "$EV/results/unknown-unknown.txt"
cat "$EV/results/unknown-unknown.txt"
