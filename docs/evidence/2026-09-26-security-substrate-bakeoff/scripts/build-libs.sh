#!/bin/sh
# Downloads, checks and builds the static C libraries the adapter links.
# Everything lands in $SCRATCH; nothing is written to the repository.
#
#   SCRATCH=... scripts/build-libs.sh openssl|openssl-asan|libressl
#
# Pins (checked 2026-09-26):
#   OpenSSL 4.0.2   https://github.com/openssl/openssl/releases/download/openssl-4.0.2/openssl-4.0.2.tar.gz
#                   sha256 736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8
#   LibreSSL 4.3.2  https://cdn.openbsd.org/pub/OpenBSD/LibreSSL/libressl-4.3.2.tar.gz
#                   sha256 edf01aee24c65d69e6a9efcb9d44bcda682ff9d4f3bbbd95e794e1dfa90847b5
#                   (SHA256 file signed by A1EB 079B 8D3E B92B 4EBD 3139 663A F51B D5E4 D8D5,
#                   libressl.asc from the same CDN directory)
#
# Both are configured without a usable config/cert directory: the
# OPENSSLDIR points at a path that does not exist, so a default path the
# library might consult finds nothing (the adapter never asks for one).
set -eu
: "${SCRATCH:?}"
mkdir -p "$SCRATCH/dl" "$SCRATCH/src" "$SCRATCH/inst"
check() { echo "$2  $1" | sha256sum -c -; }
case "$1" in
openssl)
  V=4.0.2
  T="$SCRATCH/dl/openssl-$V.tar.gz"
  [ -f "$T" ] || curl -fsSL -o "$T" "https://github.com/openssl/openssl/releases/download/openssl-$V/openssl-$V.tar.gz"
  check "$T" 736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8
  rm -rf "$SCRATCH/src/openssl-$V"; tar -C "$SCRATCH/src" -xzf "$T"
  cd "$SCRATCH/src/openssl-$V"
  ./Configure linux-x86_64 no-shared no-module no-dso no-engine no-tests no-docs no-apps \
    no-autoload-config -fPIC --prefix="$SCRATCH/inst/openssl-$V" \
    --openssldir=/nonexistent/aprv-openssl --libdir=lib
  make -j4 >/dev/null
  make install_sw >/dev/null
  ;;
openssl-asan)
  # The same OpenSSL, compiled by clang with AddressSanitizer and
  # UndefinedBehaviorSanitizer, for the sanitizer runs (libraries only).
  # -fno-sanitize=function: clang 18's function-type check fires on every
  # run inside OpenSSL's own sparse-array callback cast
  # (crypto/sparse_array.c:93 calling alg_copy), before any input is read.
  # That is an upstream coding pattern, not an input-dependent bug, so it
  # is excluded to let the rest of UBSan see the inputs. TESTED.
  V=4.0.2
  T="$SCRATCH/dl/openssl-$V.tar.gz"
  check "$T" 736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8
  rm -rf "$SCRATCH/src/openssl-$V-asan"; mkdir -p "$SCRATCH/src/openssl-$V-asan"
  tar -C "$SCRATCH/src/openssl-$V-asan" --strip-components=1 -xzf "$T"
  cd "$SCRATCH/src/openssl-$V-asan"
  CC=clang ./Configure linux-x86_64 no-shared no-module no-dso no-engine no-tests no-docs no-apps \
    no-autoload-config no-asm -fPIC -O1 -g -fno-omit-frame-pointer \
    -fsanitize=address,undefined -fno-sanitize=function -fno-sanitize-recover=undefined \
    --prefix="$SCRATCH/inst/openssl-$V-asan" --openssldir=/nonexistent/aprv-openssl --libdir=lib
  make -j4 build_libs >/dev/null
  make install_dev >/dev/null
  ;;
libressl)
  V=4.3.2
  T="$SCRATCH/dl/libressl-$V.tar.gz"
  [ -f "$T" ] || curl -fsSL -o "$T" "https://cdn.openbsd.org/pub/OpenBSD/LibreSSL/libressl-$V.tar.gz"
  check "$T" edf01aee24c65d69e6a9efcb9d44bcda682ff9d4f3bbbd95e794e1dfa90847b5
  rm -rf "$SCRATCH/src/libressl-$V"; tar -C "$SCRATCH/src" -xzf "$T"
  cmake -S "$SCRATCH/src/libressl-$V" -B "$SCRATCH/build-libressl-$V" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DLIBRESSL_APPS=OFF -DLIBRESSL_TESTS=OFF \
    -DOPENSSLDIR=/nonexistent/aprv-libressl \
    -DCMAKE_INSTALL_PREFIX="$SCRATCH/inst/libressl-$V" >/dev/null
  cmake --build "$SCRATCH/build-libressl-$V" -j 4 >/dev/null
  cmake --install "$SCRATCH/build-libressl-$V" >/dev/null
  ;;
*) echo "usage: $0 openssl|openssl-asan|libressl" >&2; exit 2 ;;
esac
