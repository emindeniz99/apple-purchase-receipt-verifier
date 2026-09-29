#!/usr/bin/env bash
# Builds OpenSSL natively with AddressSanitizer and libFuzzer's coverage
# instrumentation, for the scheduled rust-fuzz-openssl job:
#
#   tools/openssl-asan.sh <dir>        installs into <dir>; prints OPENSSL_DIR
#
# The same tarball as aprv.wasm, pinned in tools/wasm-toolchain.sh (read from
# there, so there is one pin), configured as the evidence campaigns
# instrumented it (docs/evidence/2026-09-26-substrate-followup/scripts/
# build-libs.sh, "openssl-fuzz"): no-asm, so every path is instrumented C;
# -fsanitize=address,fuzzer-no-link, so libFuzzer is guided by edges inside
# OpenSSL and not only by the Rust code. Needs clang, perl, make, curl.
set -euo pipefail
[[ $# -eq 1 && -n "$1" ]] || { echo "usage: $0 <dir>" >&2; exit 2; }
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pin() { sed -n "s/^$1=\\(.*\\)$/\\1/p" "$here/wasm-toolchain.sh"; }
VERSION="$(pin OPENSSL_VERSION)"
URL="$(pin OPENSSL_URL)"
SHA256="$(pin OPENSSL_SHA256)"
[[ -n "$VERSION" && -n "$URL" && -n "$SHA256" ]] || { echo "openssl-asan: tools/wasm-toolchain.sh pins no OpenSSL" >&2; exit 1; }

mkdir -p "$1"
DIR="$(cd "$1" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl -fsSL --retry 4 --retry-delay 2 -o "$work/openssl.tar.gz" "$URL"
echo "$SHA256  $work/openssl.tar.gz" | sha256sum -c - >&2
tar -C "$work" -xzf "$work/openssl.tar.gz"
(
  cd "$work/openssl-$VERSION"
  CC=clang ./Configure linux-x86_64 no-shared no-module no-dso no-engine no-tests no-docs no-apps \
    no-autoload-config no-asm -fPIC -O1 -g -fno-omit-frame-pointer \
    -fsanitize=address,fuzzer-no-link \
    --prefix="$DIR" --openssldir=/nonexistent/aprv-openssl --libdir=lib >&2
  make -j"$(nproc)" build_libs >&2
  make install_dev >&2
)
echo "openssl-asan: OpenSSL $VERSION with ASan and fuzzer-no-link in $DIR" >&2
printf 'export OPENSSL_DIR=%q\n' "$DIR"
