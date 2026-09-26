#!/bin/sh
# Route D, the standard way: the component guest (component/guest, world
# aprv-wasi) built for Rust's wasm32-wasip2 target, AWS-LC compiled by
# wasi-sdk 34 for wasm32-wasip2 through aws-lc-sys. rustc links it with
# wasm-component-ld straight into a component. No adapter, no stub file.
#   scripts/build-wasip2.sh <name>
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${WASI_SDK:?}"
EV="$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff"
WS="$WASI_SDK"
T="--target=wasm32-wasip2 --sysroot=$WS/share/wasi-sysroot"
F="$T -DOPENSSL_NO_SOCK -DOPENSSL_NO_TTY"
CC_wasm32_wasip2=$WS/bin/clang CXX_wasm32_wasip2=$WS/bin/clang++ AR_wasm32_wasip2=$WS/bin/llvm-ar \
CFLAGS_wasm32_wasip2="$F" CXXFLAGS_wasm32_wasip2="$F -D__wasilibc___struct_iovec_h -D__DEFINED_struct_iovec" \
BINDGEN_EXTRA_CLANG_ARGS_wasm32_wasip2="$F" CMAKE_TOOLCHAIN_FILE_wasm32_wasip2=$WS/share/cmake/wasi-sdk-p2.cmake \
SHIM="$EV/component/guest" "$EV/scripts/build-core.sh" "$1" wasm32-wasip2 substrate-aws-lc
