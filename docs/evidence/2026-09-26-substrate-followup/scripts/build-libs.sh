#!/bin/sh
# Static C libraries for the follow-up, built like the substrate bake-off's
# scripts/build-libs.sh (same Configure options), into $SCRATCH.
#
#   scripts/build-libs.sh openssl-4.1.0-beta1   (informational, a BETA)
#   scripts/build-libs.sh openssl-fuzz          (OpenSSL 4.0.2 with ASan and
#                                                libFuzzer coverage, task 4)
#
# Pins (checked 2026-09-26):
#   OpenSSL 4.1.0-beta1 https://github.com/openssl/openssl/releases/download/openssl-4.1.0-beta1/openssl-4.1.0-beta1.tar.gz
#                       sha256 eae0566fc20b6c6056b2409b4fc1ca875d9095cbd54c55dcd69b0b7de17ad0ea
#                       (matches the .sha256 file published next to it)
#   OpenSSL 4.0.2       as in the substrate bake-off (sha256 736b4675...cd543a8)
set -eu
: "${SCRATCH:?}"
mkdir -p "$SCRATCH/dl" "$SCRATCH/src" "$SCRATCH/inst"
check() { echo "$2  $1" | sha256sum -c -; }
case "$1" in
openssl-4.1.0-beta1)
  V=4.1.0-beta1
  T="$SCRATCH/dl/openssl-$V.tar.gz"
  [ -f "$T" ] || curl -fsSL -o "$T" "https://github.com/openssl/openssl/releases/download/openssl-$V/openssl-$V.tar.gz"
  check "$T" eae0566fc20b6c6056b2409b4fc1ca875d9095cbd54c55dcd69b0b7de17ad0ea
  rm -rf "$SCRATCH/src/openssl-$V"; tar -C "$SCRATCH/src" -xzf "$T"
  cd "$SCRATCH/src/openssl-$V"
  ./Configure linux-x86_64 no-shared no-module no-dso no-engine no-tests no-docs no-apps \
    no-autoload-config -fPIC --prefix="$SCRATCH/inst/openssl-$V" \
    --openssldir=/nonexistent/aprv-openssl --libdir=lib
  make -j4 build_libs >/dev/null
  make install_dev >/dev/null
  ;;
openssl-fuzz)
  # For cargo-fuzz: AddressSanitizer plus the libFuzzer coverage
  # instrumentation (-fsanitize=fuzzer-no-link), so the fuzzer is guided by
  # edges inside OpenSSL, not only by the Rust code. no-asm keeps every
  # code path in instrumented C.
  V=4.0.2
  T="$SCRATCH/dl/openssl-$V.tar.gz"
  check "$T" 736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8
  rm -rf "$SCRATCH/src/openssl-$V-fuzz"; mkdir -p "$SCRATCH/src/openssl-$V-fuzz"
  tar -C "$SCRATCH/src/openssl-$V-fuzz" --strip-components=1 -xzf "$T"
  cd "$SCRATCH/src/openssl-$V-fuzz"
  CC=clang ./Configure linux-x86_64 no-shared no-module no-dso no-engine no-tests no-docs no-apps \
    no-autoload-config no-asm -fPIC -O1 -g -fno-omit-frame-pointer \
    -fsanitize=address,fuzzer-no-link \
    --prefix="$SCRATCH/inst/openssl-$V-fuzz" --openssldir=/nonexistent/aprv-openssl --libdir=lib
  make -j4 build_libs >/dev/null
  make install_dev >/dev/null
  ;;
*) echo "usage: $0 openssl-4.1.0-beta1|openssl-fuzz" >&2; exit 2 ;;
esac
