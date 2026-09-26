#!/bin/sh
# Route B: Emscripten. The SAME shim + patched core, built for Rust's
# wasm32-unknown-emscripten target as a static library, then linked by emcc
# into one .wasm plus Emscripten's ES-module JS glue.
#
#   scripts/build-emscripten.sh openssl-lib | libressl-lib
#   scripts/build-emscripten.sh core <name> rust|openssl|libressl|awslc
#   scripts/build-emscripten.sh link <name> [extra emcc flags]
#
# Toolchain: Emscripten 6.0.10 from the official release binaries
# (scripts/fetch-tools.sh), EM_CONFIG pointing at them.
# Output: $SCRATCH/em/<name>/aprv-em.mjs + aprv-em.wasm
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${EMSDK_DIR:?}"
EV="$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff"
EM="$EMSDK_DIR/emscripten"
SYSROOT="$EM/cache/sysroot"
[ -d "${EM_CACHE_SYSROOT:-}" ] && SYSROOT="$EM_CACHE_SYSROOT"
check() { echo "$2  $1" | sha256sum -c -; }
EXPORTS=_aprv_alloc,_aprv_dealloc,_aprv_init,_aprv_version,_aprv_verifier_new_jws,_aprv_verifier_new_jws_with_roots,_aprv_verifier_free_jws,_aprv_verifier_new_receipt,_aprv_verifier_new_receipt_with_roots,_aprv_verifier_free_receipt,_aprv_endpoint_new,_aprv_endpoint_new_with_roots,_aprv_endpoint_new_with_roots_and_clock,_aprv_endpoint_free,_aprv_verify_transaction,_aprv_verify_app_transaction,_aprv_verify_raw,_aprv_verify_receipt_der,_aprv_verify_receipt_der_with_device_guid,_aprv_verify_receipt_base64,_aprv_verify_receipt_base64_with_device_guid,_aprv_verify_receipt_endpoint_json,_aprv_string_free
mkdir -p "$SCRATCH/src-em" "$SCRATCH/inst-em" "$SCRATCH/em"
case "$1" in
openssl-lib)
  # OpenSSL has no Emscripten target; this is its generic 32-bit target with
  # the same no-asm/no-threads/no-sock set as the WASI build, and the seed
  # source it documents for Emscripten (getentropy, rand_unix.c).
  V=4.0.2; T="$SCRATCH/dl/openssl-$V.tar.gz"
  check "$T" 736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8
  rm -rf "$SCRATCH/src-em/openssl-$V"; tar -C "$SCRATCH/src-em" -xzf "$T"
  cd "$SCRATCH/src-em/openssl-$V"
  CC=emcc AR=emar RANLIB=emranlib ./Configure linux-generic32 no-shared no-module no-dso no-engine \
    no-tests no-docs no-apps no-autoload-config no-asm no-threads no-sock no-ui-console no-afalgeng \
    --with-rand-seed=getrandom -DNO_SYSLOG \
    --prefix="$SCRATCH/inst-em/openssl-$V" --openssldir=/nonexistent/aprv-openssl --libdir=lib
  make -j4 build_libs >/dev/null
  make install_dev >/dev/null
  ;;
libressl-lib)
  # LibreSSL's documented path: "prepend emcmake to your cmake configuration
  # command" (README.md, Emscripten 3.1.44 and later).
  V=4.3.2; T="$SCRATCH/dl/libressl-$V.tar.gz"
  check "$T" edf01aee24c65d69e6a9efcb9d44bcda682ff9d4f3bbbd95e794e1dfa90847b5
  rm -rf "$SCRATCH/src-em/libressl-$V" "$SCRATCH/build-em-libressl-$V"; tar -C "$SCRATCH/src-em" -xzf "$T"
  emcmake cmake -S "$SCRATCH/src-em/libressl-$V" -B "$SCRATCH/build-em-libressl-$V" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DLIBRESSL_APPS=OFF -DLIBRESSL_TESTS=OFF \
    -DOPENSSLDIR=/nonexistent/aprv-libressl -DCMAKE_INSTALL_PREFIX="$SCRATCH/inst-em/libressl-$V"
  cmake --build "$SCRATCH/build-em-libressl-$V" -j 4
  cmake --install "$SCRATCH/build-em-libressl-$V" >/dev/null
  ;;
core)
  NAME="$2"; LIB="$3"
  export CC_wasm32_unknown_emscripten=emcc CXX_wasm32_unknown_emscripten=em++ AR_wasm32_unknown_emscripten=emar
  case "$LIB" in
  rust) "$EV/scripts/build-core.sh" "$NAME" wasm32-unknown-emscripten "" ;;
  openssl|libressl)
    [ "$LIB" = openssl ] && D="$SCRATCH/inst-em/openssl-4.0.2" || D="$SCRATCH/inst-em/libressl-4.3.2"
    OPENSSL_DIR="$D" OPENSSL_STATIC=1 "$EV/scripts/build-core.sh" "$NAME" wasm32-unknown-emscripten substrate ;;
  awslc)
    # AWS-LC's CMakeLists.txt has an Emscripten branch (no Threads, -g
    # instead of -ggdb); aws-lc-sys drives it through the cmake crate with
    # Emscripten's own toolchain file. bindgen needs the Emscripten sysroot.
    EMCMAKE_wasm32_unknown_emscripten="$EV/cmake/emcmake-wasm32.sh" \
    BINDGEN_EXTRA_CLANG_ARGS_wasm32_unknown_emscripten="--sysroot=$SYSROOT -DOPENSSL_NO_SOCK -DOPENSSL_NO_TTY" \
    CFLAGS_wasm32_unknown_emscripten="-DOPENSSL_NO_SOCK -DOPENSSL_NO_TTY" \
    CXXFLAGS_wasm32_unknown_emscripten="-DOPENSSL_NO_SOCK -DOPENSSL_NO_TTY" \
      "$EV/scripts/build-core.sh" "$NAME" wasm32-unknown-emscripten substrate-aws-lc ;;
  esac
  ;;
link)
  NAME="$2"; shift 2
  # OUTNAME: a second glue for the same static library (e.g. web-only).
  OUT="$SCRATCH/em/${OUTNAME:-$NAME}"; rm -rf "$OUT"; mkdir -p "$OUT"
  # One .wasm + one ES module. No filesystem emulation, growable memory,
  # a 1 MiB stack (Rust's own wasm default; Emscripten's is 64 KiB), and
  # the Module hooks a host needs to hand over a precompiled module
  # (instantiateWasm, required on workerd).
  # RUSTLIB: the Rust static library (default: this build's target dir).
  emcc "${RUSTLIB:-$SCRATCH/target-$NAME/wasm32-unknown-emscripten/release/libaprv_wasm_shim.a}" \
    -o "$OUT/aprv-em.mjs" -O3 \
    -sMODULARIZE=1 -sEXPORT_ES6=1 -sENVIRONMENT=web,worker,node \
    -sFILESYSTEM=0 -sALLOW_MEMORY_GROWTH=1 -sSTACK_SIZE=1048576 \
    -sEXPORTED_FUNCTIONS="$EXPORTS" -sEXPORTED_RUNTIME_METHODS=HEAPU8 \
    -sINCOMING_MODULE_JS_API=instantiateWasm,wasmBinary,print,printErr,locateFile \
    "$@"
  ls -l "$OUT"
  ;;
esac
