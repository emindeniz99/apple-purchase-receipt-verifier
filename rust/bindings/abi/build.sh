#!/usr/bin/env bash
# Builds aprv.wasm and its component, and checks them against the contract
# (docs/rust-core/ARCHITECTURE.md §3, §4 and §9).
#
#   rust/bindings/abi/build.sh <out-dir>
#
# Writes into <out-dir>:
#
#   aprv.wasm             the core module (wasm32-wasip1, canonical ABI),
#                         its `name` section stripped
#   aprv.component.wasm   the same module wrapped by `wasm-tools component
#                         new`, with no adapter
#   aprv.wit              the interface: rust/bindings/abi/wit/aprv.wit,
#                         written only once the component's interface, read
#                         back with `wasm-tools component wit`, is shown to
#                         be that file's
#   SHA256SUMS            the three files' SHA-256, `sha256sum` format
#
# Reads, as tools/wasm-toolchain.sh prints them:
#
#   WASI_SDK_DIR       wasi-sdk 34.0 (clang, the wasip1 sysroot)
#   OPENSSL_WASM_DIR   OpenSSL 4.0.3 built for wasm32-wasip1 (lib/, include/)
#   PATH               wasm-tools 1.259.0 and wit-bindgen 0.62.0, and the
#                      cargo and rustc of rust/rust-toolchain.toml with the
#                      wasm32-wasip1 target
#
# and CARGO_TARGET_DIR if set (default: rust/target). The compiler is the
# channel rust/rust-toolchain.toml pins, whatever directory this runs from:
# RUSTUP_TOOLCHAIN is set to it, and the build stops unless the compiler
# cargo will run names it in `--version` (which also holds the pin for a
# toolchain on PATH without rustup). That compiler is RUSTC or
# CARGO_BUILD_RUSTC when set, `rustc` on PATH otherwise, and cargo is handed
# it explicitly, so no `build.rustc` in a cargo configuration swaps it. A
# compiler wrapper (RUSTC_WRAPPER, RUSTC_WORKSPACE_WRAPPER or their
# CARGO_BUILD_ forms) is refused, and cargo runs with none, since a wrapper
# may run any compiler. The output directory is emptied of this script's
# four files first, so a build that stops, at any check, leaves no module,
# no component and no SHA256SUMS there. It fails, naming the check, when
# the module imports anything but random-get, exports anything beyond the
# interface, or its interface differs from the committed WIT.
#
# The build runs from any directory and must not depend on where the clone
# or the cargo home is: every such path is remapped, so a second build in
# another directory gives the same bytes (tools/reproduce-wasm.sh checks).
set -euo pipefail

if [[ $# -ne 1 || -z "$1" ]]; then
  echo "usage: $0 <out-dir>" >&2
  exit 2
fi
# Nothing from an earlier run stays behind to be mistaken for this one's,
# whichever check below stops the build.
mkdir -p "$1"
OUT="$(cd "$1" && pwd)"
rm -f "$OUT/aprv.wasm" "$OUT/aprv.component.wasm" "$OUT/aprv.wit" "$OUT/SHA256SUMS"
: "${WASI_SDK_DIR:?set WASI_SDK_DIR to wasi-sdk 34.0 (tools/wasm-toolchain.sh)}"
: "${OPENSSL_WASM_DIR:?set OPENSSL_WASM_DIR to OpenSSL 4.0.3 for wasm32-wasip1 (tools/wasm-toolchain.sh)}"
for tool in cargo rustc wasm-tools wit-bindgen sha256sum; do
  command -v "$tool" > /dev/null || { echo "build.sh: $tool is not on PATH" >&2; exit 1; }
done

ABI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST="$(cd "$ABI/../.." && pwd)"
# rustup reads rust-toolchain.toml only from the working directory up, and
# CI runs this from the repository root: name the channel explicitly.
CHANNEL="$(sed -n 's/^channel *= *"\([^"]*\)" *$/\1/p' "$RUST/rust-toolchain.toml")"
[[ -n "$CHANNEL" ]] || { echo "build.sh: no channel in $RUST/rust-toolchain.toml" >&2; exit 1; }
export RUSTUP_TOOLCHAIN="$CHANNEL"
for wrapper in RUSTC_WRAPPER CARGO_BUILD_RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER; do
  if [[ -n "${!wrapper:-}" ]]; then
    echo "build.sh: $wrapper is set; a compiler wrapper may run any compiler, so the pin cannot be checked" >&2
    exit 1
  fi
done
COMPILER="$(command -v "${RUSTC:-${CARGO_BUILD_RUSTC:-rustc}}" || true)"
[[ -n "$COMPILER" ]] || { echo "build.sh: the compiler ${RUSTC:-${CARGO_BUILD_RUSTC:-rustc}} is not found" >&2; exit 1; }
case "$("$COMPILER" --version)" in
  "rustc $CHANNEL "*) ;;
  *) echo "build.sh: $COMPILER is $("$COMPILER" --version), not the pinned $CHANNEL (rust/rust-toolchain.toml)" >&2; exit 1 ;;
esac
REPO="$(cd "$RUST/.." && pwd)"
WS="$(cd "$WASI_SDK_DIR" && pwd)"
OSSL="$(cd "$OPENSSL_WASM_DIR" && pwd)"
SYSROOT="$WS/share/wasi-sysroot"
LIBDIR="$SYSROOT/lib/wasm32-wasip1"
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
TARGET_DIR="${CARGO_TARGET_DIR:-$RUST/target}"
IFACE='aprv:verifier/verify@0.1.0#'
mkdir -p "$TARGET_DIR"
TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/aprv-abi-build.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

echo "build.sh: $("$COMPILER" --version); $(cargo --version); wasi-sdk $(head -1 "$WS/VERSION" 2>/dev/null || echo '?');" \
  "$(wasm-tools --version); $(wit-bindgen --version)" >&2

# Paths that must not reach the module, each mapped to a fixed name.
REMAP=(
  "--remap-path-prefix=$REPO=/aprv/src"
  "--remap-path-prefix=$CARGO_HOME_DIR=/aprv/cargo"
  "--remap-path-prefix=$TARGET_DIR=/aprv/target"
)
if [[ -n "${RUSTUP_HOME:-}" ]]; then REMAP+=("--remap-path-prefix=$RUSTUP_HOME=/aprv/rustup"); fi

# The link-time C file, compiled with wasi-sdk's clang; no debug info, and
# its own path mapped away in case a later flag adds any.
"$WS/bin/clang" --target=wasm32-wasip1 --sysroot="$SYSROOT" -O2 -Wall -Wextra -Werror \
  -ffile-prefix-map="$REPO"=/aprv/src -c "$ABI/wasi-none.c" -o "$WORK/wasi-none.o"

# The flags of every measured module (the canonical-ABI final round): the
# reactor start file and its `_initialize`, wasi-libc's four emulation
# libraries that OpenSSL's no-asm build needs, and the C file above.
FLAGS=(
  -L "native=$LIBDIR"
  -l static=wasi-emulated-signal
  -l static=wasi-emulated-process-clocks
  -l static=wasi-emulated-mman
  -l static=wasi-emulated-getpid
  -C "link-arg=$LIBDIR/crt1-reactor.o"
  -C link-arg=--export=_initialize
  -C "link-arg=$WORK/wasi-none.o"
  "${REMAP[@]}"
)
RUSTFLAGS_WASM="$(printf '%s\x1f' "${FLAGS[@]}")"
RUSTFLAGS_WASM="${RUSTFLAGS_WASM%$'\x1f'}"

# aprv-openssl compiles payload.c and envelope.c through the cc crate: the
# same clang, the same sysroot and the same emulation macros OpenSSL was
# built with.
C_FLAGS="--target=wasm32-wasip1 --sysroot=$SYSROOT -ffile-prefix-map=$REPO=/aprv/src -ffile-prefix-map=$CARGO_HOME_DIR=/aprv/cargo -D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_PROCESS_CLOCKS -D_WASI_EMULATED_MMAN -D_WASI_EMULATED_GETPID"

env -u RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS -u CARGO_BUILD_RUSTC \
  RUSTC="$COMPILER" RUSTC_WRAPPER= RUSTC_WORKSPACE_WRAPPER= \
  CARGO_ENCODED_RUSTFLAGS="$RUSTFLAGS_WASM" \
  CARGO_TARGET_DIR="$TARGET_DIR" \
  CC_wasm32_wasip1="$WS/bin/clang" \
  AR_wasm32_wasip1="$WS/bin/llvm-ar" \
  CFLAGS_wasm32_wasip1="$C_FLAGS" \
  OPENSSL_NO_VENDOR=1 OPENSSL_STATIC=1 OPENSSL_DIR="$OSSL" \
  OPENSSL_LIB_DIR="$OSSL/lib" OPENSSL_INCLUDE_DIR="$OSSL/include" \
  cargo build --locked --manifest-path "$RUST/Cargo.toml" -p aprv-abi \
    --target wasm32-wasip1 --profile wasm >&2

# Built and checked in the work directory; only a module that passes every
# check below reaches the output directory.
MOD="$WORK/aprv.wasm"
COMP="$WORK/aprv.component.wasm"
# The `name` section goes: it is 8.5% of the module (257 KB of 3.0 MB,
# 71 KB gzipped) and no host reads it. Stripping moves no code, so a
# trap's `wasm-function[N]:0x...` is the same function and offset in the
# named module cargo leaves at $TARGET_DIR/wasm32-wasip1/wasm/aprv_abi.wasm,
# which `wasm-tools print` names; the build is reproducible, so rebuilding
# the release's commit gives that module back (rust/bindings/abi/README.md).
wasm-tools strip --delete '^name$' "$TARGET_DIR/wasm32-wasip1/wasm/aprv_abi.wasm" -o "$MOD"
wasm-tools validate "$MOD"
wasm-tools component new "$MOD" -o "$COMP"
wasm-tools validate --features component-model "$COMP"

failed=0
fail() { echo "build.sh: FAIL $*" >&2; failed=1; }

# The import list: exactly random-get.
printed="$(wasm-tools print "$MOD")"
imports="$(grep -oE '^ *\(import "[^"]*" "[^"]*"' <<< "$printed" | sed -E 's/^ *\(import "([^"]*)" "([^"]*)"/\1 \2/' || true)"
if [[ "$imports" != "aprv:verifier/host@0.1.0 random-get" ]]; then
  fail "the module must import exactly aprv:verifier/host@0.1.0 random-get; it imports: $(tr '\n' ';' <<< "$imports")"
fi

# The export list: the interface and nothing else (wit-bindgen's own
# versioned cabi_realloc alias aside).
exports="$(grep -oE '^ *\(export "[^"]*"' <<< "$printed" | sed -E 's/^ *\(export "([^"]*)"/\1/' | sort)"
expected="$(for op in init verify-receipt verify-signed-data verify-receipt-endpoint; do
  echo "$IFACE$op"; echo "cabi_post_$IFACE$op"; done | sort; printf '%s\n' cabi_realloc memory _initialize)"
unexpected="$(comm -13 <(sort <<< "$expected") <(echo "$exports") | grep -vE '^cabi_realloc_wit_bindgen_[0-9]+_[0-9]+_[0-9]+$' || true)"
missing="$(comm -23 <(sort <<< "$expected") <(echo "$exports") || true)"
[[ -z "$unexpected" ]] || fail "unexpected exports: $(tr '\n' ' ' <<< "$unexpected")"
[[ -z "$missing" ]] || fail "missing exports: $(tr '\n' ' ' <<< "$missing")"

# The interface, read back from the component, against the committed WIT:
# both rendered by `wasm-tools component wit` from a component (the
# committed file through a dummy module), so layout and plain comments do
# not count and every name, type and doc comment does.
WIT="$ABI/wit/aprv.wit"
wasm-tools component embed --dummy "$WIT" --world aprv -o "$WORK/dummy.wasm"
wasm-tools component new "$WORK/dummy.wasm" -o "$WORK/dummy.component.wasm"
wasm-tools component wit "$WORK/dummy.component.wasm" > "$WORK/want.wit"
wasm-tools component wit "$COMP" > "$WORK/got.wit"
if ! diff -u "$WORK/want.wit" "$WORK/got.wit" >&2; then
  fail "the component's interface differs from $WIT"
fi

# Paths of this machine that must not be in the module.
for path in "$REPO" "$CARGO_HOME_DIR" "$TARGET_DIR" "$WS" "$OSSL" "$HOME"; do
  if grep -aqF "$path/" "$MOD"; then fail "the module carries the path $path"; fi
done

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi
cp "$MOD" "$COMP" "$OUT/"
cp "$WIT" "$OUT/aprv.wit"
(cd "$OUT" && sha256sum aprv.wasm aprv.component.wasm aprv.wit > SHA256SUMS)

echo "build.sh: aprv.wasm $(wc -c < "$OUT/aprv.wasm") bytes, component $(wc -c < "$OUT/aprv.component.wasm") bytes" >&2
cat "$OUT/SHA256SUMS"
