#!/bin/sh
# Route A and Route C builds: the previous bake-off's wasm32-wasip1 recipes
# (OpenSSL 4.0.2 via wasi-sdk 34 + OPENSSL_DIR; AWS-LC via aws-lc-sys with
# the wasi-sdk CMake toolchain and 5 flags), now over the clock seam.
#
#   scripts/build-wasip1.sh openssl-lib | <name> <openssl|awslc|rust> [HOST_CLOCK=1]
#
# HOST_CLOCK=1 makes the core read "now" from aprv.clock_now_ms instead of
# WASI clock_time_get (Route C input).
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${WASI_SDK:?}"
EV="$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
WS="$WASI_SDK"
T="--target=wasm32-wasip1 --sysroot=$WS/share/wasi-sysroot"
case "$1" in
openssl-lib) "$SPIKE/scripts/build-wasm-libs.sh" openssl; exit ;;
esac
NAME="$1"; LIB="$2"
case "$LIB" in
rust) "$EV/scripts/build-core.sh" "$NAME" wasm32-wasip1 "" ;;
openssl)
  CC_wasm32_wasip1=$WS/bin/clang CFLAGS_wasm32_wasip1="$T" AR_wasm32_wasip1=$WS/bin/llvm-ar \
  OPENSSL_DIR=$SCRATCH/inst-wasm/openssl-4.0.2 OPENSSL_STATIC=1 \
    "$EV/scripts/build-core.sh" "$NAME" wasm32-wasip1 substrate ;;
awslc)
  F="$T -DOPENSSL_NO_SOCK -DOPENSSL_NO_TTY"
  CC_wasm32_wasip1=$WS/bin/clang CXX_wasm32_wasip1=$WS/bin/clang++ AR_wasm32_wasip1=$WS/bin/llvm-ar \
  CFLAGS_wasm32_wasip1="$F" CXXFLAGS_wasm32_wasip1="$F -D__wasilibc___struct_iovec_h -D__DEFINED_struct_iovec" \
  BINDGEN_EXTRA_CLANG_ARGS_wasm32_wasip1="$F" CMAKE_TOOLCHAIN_FILE_wasm32_wasip1=$WS/share/cmake/wasi-sdk-p1.cmake \
    "$EV/scripts/build-core.sh" "$NAME" wasm32-wasip1 substrate-aws-lc ;;
esac
