#!/usr/bin/env bash
# Installs the pinned toolchain that builds aprv.wasm, into one directory.
#
#   tools/wasm-toolchain.sh <dir>
#
# Downloads four release archives, checks each against the SHA-256 pinned
# below, and builds OpenSSL for wasm32-wasip1 with wasi-sdk's clang:
#
#   <dir>/wasi-sdk       wasi-sdk 34.0 (clang, wasi-libc, the wasip1 sysroot)
#   <dir>/openssl-wasm   OpenSSL 4.0.3, static libcrypto/libssl for wasm32-wasip1
#   <dir>/bin            wasm-tools 1.259.0 and wit-bindgen 0.62.0
#
# Prints the environment rust/bindings/abi/build.sh reads, as `export` lines
# on stdout; everything else goes to stderr. Linux x86_64 only: the release
# archives pinned here are that platform's. rustc and the wasm32-wasip1
# target are pinned by rust/rust-toolchain.toml, not here.
#
# A finished install writes <dir>/.complete holding this script's SHA-256,
# and a later run with the same script returns at once. CI caches <dir>
# keyed by that hash in test jobs only; release jobs never restore a cache.
#
# The OpenSSL options are the ones the CMS-everywhere and substrate rounds
# built with (docs/evidence/2026-09-26-security-substrate-bakeoff/scripts/
# build-wasm-libs.sh): openssl-src's "wasm32-wasi" set on the generic
# 32-bit target, no-asm, and the four wasi-libc emulation macros. Two
# things differ, both for reproducibility and neither in the library's
# code: the install prefix is the fixed, nonexistent /aprv/openssl-wasm
# (OpenSSL compiles MODULESDIR, derived from it, into libcrypto, and the
# spike module carried the scratch path that way) and is staged with
# DESTDIR; CC names clang from PATH with wasi-sdk's built-in default
# sysroot, so no install path lands in the compiler line OpenSSL records;
# and SOURCE_DATE_EPOCH fixes the "built on" date OpenSSL compiles in,
# which otherwise made two installs of the same pins differ.
set -euo pipefail

usage() { echo "usage: $0 <dir>" >&2; exit 2; }
[[ $# -eq 1 && -n "$1" ]] || usage

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) ;;
  *) echo "wasm-toolchain: the pinned archives are Linux x86_64 only, not $(uname -s)/$(uname -m)" >&2; exit 1 ;;
esac

# --- pins -------------------------------------------------------------------
# The SHA-256 of every archive, computed from the download on 2026-09-29 and
# equal to the value the evidence rounds recorded on 2026-09-26. The GitHub
# releases of wasi-sdk, wasm-tools and wit-bindgen publish no checksum file,
# so those three are trust on first use; OpenSSL's matches the .sha256 file
# OpenSSL publishes beside the tarball.
WASI_SDK_VERSION=34.0
WASI_SDK_URL=https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-34/wasi-sdk-34.0-x86_64-linux.tar.gz
WASI_SDK_SHA256=b761e3a0721dbae9c09a0059e5fdb2bf917d1b4a8a7b430fb3b5aafb0984b2c4
WASM_TOOLS_VERSION=1.259.0
WASM_TOOLS_URL=https://github.com/bytecodealliance/wasm-tools/releases/download/v1.259.0/wasm-tools-1.259.0-x86_64-linux.tar.gz
WASM_TOOLS_SHA256=3e9b374b4c7715b771b69bf0d65a337990ed4546ec5e97e01c0ff587dfc52160
WIT_BINDGEN_VERSION=0.62.0
WIT_BINDGEN_URL=https://github.com/bytecodealliance/wit-bindgen/releases/download/v0.62.0/wit-bindgen-0.62.0-x86_64-linux.tar.gz
WIT_BINDGEN_SHA256=3e81cc6523729f7532b4aa7968648a04abf0c711b7d1677150e9121f4e6458fe
OPENSSL_VERSION=4.0.3
OPENSSL_URL=https://github.com/openssl/openssl/releases/download/openssl-4.0.3/openssl-4.0.3.tar.gz
OPENSSL_SHA256=325b5c806167c13b40b1ffeadfe0248197c00eccc4cf123ec1e28d2d2fd216d9
# 2026-09-29T00:00:00Z, the day these pins were recorded: OpenSSL's
# buildinf date, fixed so the library is the same bytes on every run.
OPENSSL_SOURCE_DATE_EPOCH=1790640000
# ------------------------------------------------------------------------------

mkdir -p "$1"
DIR="$(cd "$1" && pwd)"
SELF_SHA256="$(sha256sum "${BASH_SOURCE[0]}" | cut -c1-64)"

print_env() {
  printf 'export WASI_SDK_DIR=%q\n' "$DIR/wasi-sdk"
  printf 'export OPENSSL_WASM_DIR=%q\n' "$DIR/openssl-wasm"
  # shellcheck disable=SC2016 # "$PATH" is for the shell that evaluates this line
  printf 'export PATH=%q:"$PATH"\n' "$DIR/bin"
}

if [[ -f "$DIR/.complete" && "$(cat "$DIR/.complete")" == "$SELF_SHA256" ]]; then
  echo "wasm-toolchain: $DIR is complete for this script ($SELF_SHA256)" >&2
  print_env
  exit 0
fi
rm -f "$DIR/.complete"

DL="$DIR/dl"
mkdir -p "$DL" "$DIR/bin"

fetch() { # url sha256 -> path of the verified archive
  local url=$1 sha=$2 file
  file="$DL/$(basename "$url")"
  if [[ ! -f "$file" ]] || ! echo "$sha  $file" | sha256sum -c --status -; then
    echo "wasm-toolchain: downloading $url" >&2
    curl -fsSL --retry 4 --retry-delay 2 -o "$file.part" "$url"
    mv "$file.part" "$file"
  fi
  if ! echo "$sha  $file" | sha256sum -c --status -; then
    echo "wasm-toolchain: $file does not match its pinned SHA-256 $sha; got $(sha256sum "$file" | cut -c1-64)" >&2
    rm -f "$file"
    exit 1
  fi
  echo "wasm-toolchain: verified $(basename "$file") ($sha)" >&2
  printf '%s\n' "$file"
}

wasi_tgz="$(fetch "$WASI_SDK_URL" "$WASI_SDK_SHA256")"
tools_tgz="$(fetch "$WASM_TOOLS_URL" "$WASM_TOOLS_SHA256")"
bindgen_tgz="$(fetch "$WIT_BINDGEN_URL" "$WIT_BINDGEN_SHA256")"
openssl_tgz="$(fetch "$OPENSSL_URL" "$OPENSSL_SHA256")"

# wasi-sdk: the archive's top directory is wasi-sdk-34.0-x86_64-linux.
rm -rf "$DIR/wasi-sdk" "$DIR/wasi-sdk-$WASI_SDK_VERSION-x86_64-linux"
tar -C "$DIR" -xzf "$wasi_tgz"
mv "$DIR/wasi-sdk-$WASI_SDK_VERSION-x86_64-linux" "$DIR/wasi-sdk"

# wasm-tools and wit-bindgen: one binary each.
work="$(mktemp -d "$DIR/.work.XXXXXX")"
trap 'rm -rf "$work"' EXIT
tar -C "$work" -xzf "$tools_tgz"
tar -C "$work" -xzf "$bindgen_tgz"
install -m 0755 "$work/wasm-tools-$WASM_TOOLS_VERSION-x86_64-linux/wasm-tools" "$DIR/bin/wasm-tools"
install -m 0755 "$work/wit-bindgen-$WIT_BINDGEN_VERSION-x86_64-linux/wit-bindgen" "$DIR/bin/wit-bindgen"
"$DIR/bin/wasm-tools" --version >&2
"$DIR/bin/wit-bindgen" --version >&2

# OpenSSL for wasm32-wasip1.
PREFIX=/aprv/openssl-wasm
tar -C "$work" -xzf "$openssl_tgz"
EMU=(-D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_PROCESS_CLOCKS -D_WASI_EMULATED_MMAN -D_WASI_EMULATED_GETPID)
(
  cd "$work/openssl-$OPENSSL_VERSION"
  export PATH="$DIR/wasi-sdk/bin:$PATH" SOURCE_DATE_EPOCH="$OPENSSL_SOURCE_DATE_EPOCH"
  CC="clang --target=wasm32-wasip1" AR=llvm-ar RANLIB=llvm-ranlib \
  ./Configure linux-generic32 no-shared no-module no-dso no-engine no-tests no-docs no-apps \
    no-autoload-config no-asm no-threads no-sock no-ui-console no-afalgeng \
    -DNO_SYSLOG -DNO_CHMOD -DOPENSSL_NO_AFALGENG=1 "${EMU[@]}" \
    --prefix="$PREFIX" --openssldir=/nonexistent/aprv-openssl --libdir=lib >&2
  make -j"$(nproc)" build_libs >&2
  make DESTDIR="$work/stage" install_dev >&2
)
rm -rf "$DIR/openssl-wasm"
mv "$work/stage$PREFIX" "$DIR/openssl-wasm"
for lib in libcrypto.a libssl.a; do
  [[ -f "$DIR/openssl-wasm/lib/$lib" ]] || { echo "wasm-toolchain: $lib was not installed" >&2; exit 1; }
done
if grep -aqF "$DIR" "$DIR/openssl-wasm/lib/libcrypto.a"; then
  echo "wasm-toolchain: libcrypto.a records the install path $DIR; the build would not reproduce elsewhere" >&2
  exit 1
fi

rm -rf "$DL"
echo "$SELF_SHA256" > "$DIR/.complete"
echo "wasm-toolchain: installed into $DIR" >&2
print_env
