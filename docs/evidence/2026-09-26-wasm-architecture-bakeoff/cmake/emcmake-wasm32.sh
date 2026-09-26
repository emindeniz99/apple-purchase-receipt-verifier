#!/bin/sh
# Spike only. cmake-rs runs "emcmake cmake ..." for Emscripten targets and
# lets EMCMAKE_<target> replace the emcmake program. This wrapper adds the
# override Emscripten.cmake documents for its processor name
# ("-DEMSCRIPTEN_SYSTEM_PROCESSOR=arm" in its comments). Emscripten reports
# "x86" by default, so AWS-LC's CMakeLists.txt picks ARCH x86 and adds
# -msse2, which emcc refuses without -msimd128 (TESTED,
# results/build-emscripten.txt). "wasm32" falls through to AWS-LC's ARCH
# "generic" (no assembly), as wasi-sdk's toolchain file already does.
exec emcmake "$@" -DEMSCRIPTEN_SYSTEM_PROCESSOR=wasm32
