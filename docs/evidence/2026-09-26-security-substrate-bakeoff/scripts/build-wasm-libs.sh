#!/bin/sh
# Fetches wasi-sdk and builds the C libraries for wasm32-wasip1 with it.
# Everything lands in $SCRATCH; nothing is written to the repository.
#
#   SCRATCH=... scripts/build-wasm-libs.sh wasi-sdk|openssl|libressl
#
# Pins (checked 2026-09-26):
#   wasi-sdk 34.0   https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-34/wasi-sdk-34.0-x86_64-linux.tar.gz
#                   sha256 b761e3a0721dbae9c09a0059e5fdb2bf917d1b4a8a7b430fb3b5aafb0984b2c4
#                   (computed here on first download; the release publishes
#                   no checksum file, so this is trust on first use)
#   OpenSSL 4.0.2 and LibreSSL 4.3.2: the tarballs and hashes of build-libs.sh.
#
# OpenSSL's options are the ones openssl-src 300.6.1 passes for its
# "wasm32-wasi" target (no threads, sockets, asm, console UI or syslog, and
# the four wasi-libc emulation macros), on the generic 32-bit target.
set -eu
: "${SCRATCH:?}"
WASI_SDK="$SCRATCH/wasi-sdk-34.0-x86_64-linux"
CC_WASI="$WASI_SDK/bin/clang --target=wasm32-wasip1 --sysroot=$WASI_SDK/share/wasi-sysroot"
EMU="-D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_PROCESS_CLOCKS -D_WASI_EMULATED_MMAN -D_WASI_EMULATED_GETPID"
mkdir -p "$SCRATCH/dl" "$SCRATCH/src-wasm" "$SCRATCH/inst-wasm"
check() { echo "$2  $1" | sha256sum -c -; }
case "$1" in
wasi-sdk)
  T="$SCRATCH/dl/wasi-sdk-34.0-x86_64-linux.tar.gz"
  [ -f "$T" ] || curl -fsSL -o "$T" https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-34/wasi-sdk-34.0-x86_64-linux.tar.gz
  check "$T" b761e3a0721dbae9c09a0059e5fdb2bf917d1b4a8a7b430fb3b5aafb0984b2c4
  rm -rf "$WASI_SDK"; tar -C "$SCRATCH" -xzf "$T"
  ;;
openssl)
  V=4.0.2
  T="$SCRATCH/dl/openssl-$V.tar.gz"
  check "$T" 736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8
  rm -rf "$SCRATCH/src-wasm/openssl-$V"; tar -C "$SCRATCH/src-wasm" -xzf "$T"
  cd "$SCRATCH/src-wasm/openssl-$V"
  CC="$CC_WASI" AR="$WASI_SDK/bin/llvm-ar" RANLIB="$WASI_SDK/bin/llvm-ranlib" \
  ./Configure linux-generic32 no-shared no-module no-dso no-engine no-tests no-docs no-apps \
    no-autoload-config no-asm no-threads no-sock no-ui-console no-afalgeng \
    -DNO_SYSLOG -DNO_CHMOD -DOPENSSL_NO_AFALGENG=1 $EMU \
    --prefix="$SCRATCH/inst-wasm/openssl-$V" --openssldir=/nonexistent/aprv-openssl --libdir=lib
  make -j4 build_libs >/dev/null
  make install_dev >/dev/null
  ;;
libressl)
  V=4.3.2
  T="$SCRATCH/dl/libressl-$V.tar.gz"
  check "$T" edf01aee24c65d69e6a9efcb9d44bcda682ff9d4f3bbbd95e794e1dfa90847b5
  rm -rf "$SCRATCH/src-wasm/libressl-$V"; tar -C "$SCRATCH/src-wasm" -xzf "$T"
  cmake -S "$SCRATCH/src-wasm/libressl-$V" -B "$SCRATCH/build-wasm-libressl-$V" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$WASI_SDK/share/cmake/wasi-sdk-p1.cmake" -DWASI_SDK_PREFIX="$WASI_SDK" \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
    -DLIBRESSL_APPS=OFF -DLIBRESSL_TESTS=OFF -DENABLE_ASM=OFF \
    -DCMAKE_C_FLAGS="$EMU" \
    -DOPENSSLDIR=/nonexistent/aprv-libressl \
    -DCMAKE_INSTALL_PREFIX="$SCRATCH/inst-wasm/libressl-$V"
  cmake --build "$SCRATCH/build-wasm-libressl-$V" -j 4
  cmake --install "$SCRATCH/build-wasm-libressl-$V" >/dev/null
  ;;
*) echo "usage: $0 wasi-sdk|openssl|libressl" >&2; exit 2 ;;
esac
