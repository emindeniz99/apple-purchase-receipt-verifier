#!/bin/sh
# Spike only (2026-09-27). Builds libiwasm (WAMR's embedding library) from
# $WAMR_TAG, Release, one shared library per execution mode, and AOT-compiles
# the module with the prebuilt wamrc of the same release:
#   build-wamr.sh fetch     clone WAMR at $WAMR_TAG; download wamrc (x86_64 Ubuntu 22.04 release asset)
#   build-wamr.sh libs      libiwasm-fast.so    fast interpreter + AOT loader
#                           libiwasm-classic.so classic interpreter + fast JIT + AOT loader
#   build-wamr.sh aot       wamrc -> $S/aprv-abi1.aot (x86_64, default opt level 3)
# No WASI, no libc-builtin: the module imports only aprv.clock_now_ms and aprv.random_get.
set -eu
. "$(dirname "$0")/env.sh"
case "$1" in
fetch)
  [ -d "$WAMR_SRC" ] || git -c gc.auto=0 clone -q --filter=blob:none https://github.com/bytecodealliance/wasm-micro-runtime "$WAMR_SRC"
  git -C "$WAMR_SRC" -c advice.detachedHead=false checkout -q "$WAMR_TAG"
  echo "WAMR source: $WAMR_TAG = $(git -C "$WAMR_SRC" rev-parse HEAD)"
  V=${WAMR_TAG#WAMR-}
  curl -sSL -o "$S/wamrc.tgz" "https://github.com/bytecodealliance/wasm-micro-runtime/releases/download/$WAMR_TAG/wamrc-$V-x86_64-ubuntu-22.04.tar.gz"
  tar xzf "$S/wamrc.tgz" -C "$S"
  echo "wamrc: $("$S/wamrc" --version), release asset $(wc -c < "$S/wamrc.tgz") bytes, sha256 $(sha256sum "$S/wamrc.tgz" | cut -c1-64) (the release publishes no checksum)"
  ;;
libs)
  for v in fast classic; do
    B="$S/build-$v"; rm -rf "$B"; mkdir -p "$B"
    case $v in
      fast) O="-DWAMR_BUILD_FAST_INTERP=1 -DWAMR_BUILD_FAST_JIT=0" ;;
      classic) O="-DWAMR_BUILD_FAST_INTERP=0 -DWAMR_BUILD_FAST_JIT=1" ;;
    esac
    start=$(date +%s)
    cmake -S "$WAMR_SRC/product-mini/platforms/linux" -B "$B" -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
      -DWAMR_BUILD_INTERP=1 -DWAMR_BUILD_AOT=1 -DWAMR_BUILD_JIT=0 $O \
      -DWAMR_BUILD_LIBC_WASI=0 -DWAMR_BUILD_LIBC_BUILTIN=0 -DWAMR_BUILD_SIMD=1 > "$B.log" 2>&1
    cmake --build "$B" --target vmlib >> "$B.log" 2>&1 || { tail -30 "$B.log"; exit 1; }
    cp "$B/libiwasm.so" "$LIBS/libiwasm-$v.so"
    echo "libiwasm-$v.so: $(wc -c < "$LIBS/libiwasm-$v.so") bytes, built in $(( $(date +%s) - start )) s ($O)"
  done
  ;;
aot)
  start=$(date +%s%N)
  "$S/wamrc" --target=x86_64 -o "$S/aprv-abi1.aot" "$MOD" > "$S/wamrc.log" 2>&1 || { tail -20 "$S/wamrc.log"; exit 1; }
  echo "wamrc: $(( ($(date +%s%N) - start) / 1000000 )) ms, $(wc -c < "$S/aprv-abi1.aot") bytes AOT from $(wc -c < "$MOD") bytes of Wasm"
  tail -3 "$S/wamrc.log"
  ;;
*) echo "usage: build-wamr.sh fetch|libs|aot"; exit 2 ;;
esac
