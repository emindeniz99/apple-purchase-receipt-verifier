#!/bin/sh
# Route D on WASI 0.3 (P3): the same guest (world aprv-wasi), Rust's
# wasm32-wasip3 target (nightly only: stable 1.98.1 ships no rust-std for
# it), AWS-LC compiled by wasi-sdk 34's wasm32-wasip3 CMake toolchain.
# The nightly toolchain lives in $SCRATCH/rustup (RUSTUP_HOME), not in the
# user's rustup.
#   scripts/build-wasip3.sh <name>
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${WASI_SDK:?}"
EV="$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff"
export RUSTUP_HOME="$SCRATCH/rustup" RUSTUP_TOOLCHAIN=nightly
WS="$WASI_SDK"
T="--target=wasm32-wasip3 --sysroot=$WS/share/wasi-sysroot"
F="$T -DOPENSSL_NO_SOCK -DOPENSSL_NO_TTY"
CC_wasm32_wasip3=$WS/bin/clang CXX_wasm32_wasip3=$WS/bin/clang++ AR_wasm32_wasip3=$WS/bin/llvm-ar \
CFLAGS_wasm32_wasip3="$F" CXXFLAGS_wasm32_wasip3="$F -D__wasilibc___struct_iovec_h -D__DEFINED_struct_iovec" \
BINDGEN_EXTRA_CLANG_ARGS_wasm32_wasip3="$F" CMAKE_TOOLCHAIN_FILE_wasm32_wasip3=$WS/share/cmake/wasi-sdk-p3.cmake \
SHIM="$EV/component/guest" "$EV/scripts/build-core.sh" "$1" wasm32-wasip3 "${2:-substrate-aws-lc}"
