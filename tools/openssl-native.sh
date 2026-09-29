#!/usr/bin/env bash
# Builds OpenSSL natively as static libraries, for the test leg that links a
# prebuilt OpenSSL instead of openssl-src's (the `rust` job's
# --no-default-features run, OPENSSL_NO_VENDOR=1):
#
#   tools/openssl-native.sh <dir>      installs into <dir>; prints OPENSSL_DIR
#
# The same tarball as aprv.wasm, pinned in tools/wasm-toolchain.sh and read
# from there, so there is one pin; aprv-openssl refuses any OpenSSL older
# than 4.0, which is why the runner's own libssl cannot stand in. The
# configuration directory is the same nonexistent path rust/.cargo/config.toml
# gives the vendored build: nothing is ever read from it. Needs a C compiler,
# perl, make, curl. A finished install writes <dir>/.complete holding this
# script's and the pin file's SHA-256, and a later run with both unchanged
# returns at once (CI caches <dir> in the test job only).
set -euo pipefail
[[ $# -eq 1 && -n "$1" ]] || { echo "usage: $0 <dir>" >&2; exit 2; }
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pin() { sed -n "s/^$1=\\(.*\\)$/\\1/p" "$here/wasm-toolchain.sh"; }
VERSION="$(pin OPENSSL_VERSION)"
URL="$(pin OPENSSL_URL)"
SHA256="$(pin OPENSSL_SHA256)"
[[ -n "$VERSION" && -n "$URL" && -n "$SHA256" ]] || { echo "openssl-native: tools/wasm-toolchain.sh pins no OpenSSL" >&2; exit 1; }

mkdir -p "$1"
DIR="$(cd "$1" && pwd)"
STAMP="$(cat "${BASH_SOURCE[0]}" "$here/wasm-toolchain.sh" | sha256sum | cut -c1-64)"
if [[ -f "$DIR/.complete" && "$(cat "$DIR/.complete")" == "$STAMP" ]]; then
  echo "openssl-native: $DIR is complete" >&2
  printf 'export OPENSSL_DIR=%q\n' "$DIR"
  exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl -fsSL --retry 4 --retry-delay 2 -o "$work/openssl.tar.gz" "$URL"
echo "$SHA256  $work/openssl.tar.gz" | sha256sum -c - >&2
tar -C "$work" -xzf "$work/openssl.tar.gz"
rm -rf "${DIR:?}"/*
(
  cd "$work/openssl-$VERSION"
  ./Configure no-shared no-module no-dso no-engine no-tests no-docs no-apps \
    no-autoload-config -fPIC \
    --prefix="$DIR" --openssldir=/nonexistent/aprv-openssl --libdir=lib >&2
  make -j"$(nproc)" build_libs >&2
  make install_dev >&2
)
echo "$STAMP" > "$DIR/.complete"
echo "openssl-native: OpenSSL $VERSION in $DIR" >&2
printf 'export OPENSSL_DIR=%q\n' "$DIR"
