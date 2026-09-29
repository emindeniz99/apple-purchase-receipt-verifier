#!/bin/sh
# Spike only (2026-09-27, round 9). Builds ../wamr-host (libiwasm.so from
# WAMR 2.4.5 plus the aprv-wamr host) once per execution mode into
# $S/wamr/<row>/, and prints, per row: every WAMR_BUILD_* flag passed, what
# WAMR's CMake reported for the running modes, the WASM_ENABLE_* definitions
# the compiler actually received (from compile_commands.json), the build
# time and the sizes. The build directory is deleted afterwards (disk).
#   build-wamr.sh llvm      distro LLVM 18 for the LLVM JIT rows: apt-get download (no install) of
#                           llvm-18-dev, libzstd-dev, libxml2-dev and libpfm4-dev, dpkg-deb -x into $LLVM_ROOT, and
#                           links to the runtime libraries the system already has
#   build-wamr.sh [ROW...]  default: every row below
# Every row: Release, no AOT loader, no WASI, no libc-builtin, no multi-module, no debug interpreter,
# no threads, no SIMD (the module has none), bulk memory and reference types on (the module needs them).
# JIT rows ask for the fast interpreter too (FAST_INTERP=1), so the log shows WAMR switching it off.
set -eu
. "$(dirname "$0")/env.sh"
COMMON="-DCMAKE_BUILD_TYPE=Release -DWAMR_BUILD_INTERP=1 -DWAMR_BUILD_AOT=0 -DWAMR_BUILD_LIBC_BUILTIN=0 -DWAMR_BUILD_LIBC_WASI=0 \
-DWAMR_BUILD_MULTI_MODULE=0 -DWAMR_BUILD_DEBUG_INTERP=0 -DWAMR_BUILD_DEBUG_AOT=0 -DWAMR_BUILD_LIB_PTHREAD=0 \
-DWAMR_BUILD_LIB_WASI_THREADS=0 -DWAMR_BUILD_THREAD_MGR=0 -DWAMR_BUILD_SIMD=0 -DWAMR_BUILD_REF_TYPES=1 \
-DWAMR_BUILD_BULK_MEMORY=1 -DWAMR_BUILD_MINI_LOADER=0 -DWAMR_BUILD_DUMP_CALL_STACK=0 -DWAMR_BUILD_MEMORY_PROFILING=0 \
-DWAMR_BUILD_PERF_PROFILING=0"
LLVM_CMAKE="$LLVM_ROOT/usr/lib/llvm-18/lib/cmake/llvm"
flags() {
  case "$1" in
    classic)        echo "-DWAMR_BUILD_FAST_INTERP=0 -DWAMR_BUILD_FAST_JIT=0 -DWAMR_BUILD_JIT=0" ;;
    fast)           echo "-DWAMR_BUILD_FAST_INTERP=1 -DWAMR_BUILD_FAST_JIT=0 -DWAMR_BUILD_JIT=0" ;;
    fastjit-lazy)   echo "-DWAMR_BUILD_FAST_INTERP=1 -DWAMR_BUILD_FAST_JIT=1 -DWAMR_BUILD_JIT=0 -DWAMR_BUILD_LAZY_JIT=1" ;;
    fastjit-eager)  echo "-DWAMR_BUILD_FAST_INTERP=1 -DWAMR_BUILD_FAST_JIT=1 -DWAMR_BUILD_JIT=0 -DWAMR_BUILD_LAZY_JIT=0" ;;
    llvmjit-lazy)   echo "-DWAMR_BUILD_FAST_INTERP=1 -DWAMR_BUILD_FAST_JIT=0 -DWAMR_BUILD_JIT=1 -DWAMR_BUILD_LAZY_JIT=1 -DLLVM_DIR=$LLVM_CMAKE" ;;
    llvmjit-eager)  echo "-DWAMR_BUILD_FAST_INTERP=1 -DWAMR_BUILD_FAST_JIT=0 -DWAMR_BUILD_JIT=1 -DWAMR_BUILD_LAZY_JIT=0 -DLLVM_DIR=$LLVM_CMAKE" ;;
    multitier-lazy) echo "-DWAMR_BUILD_FAST_INTERP=1 -DWAMR_BUILD_FAST_JIT=1 -DWAMR_BUILD_JIT=1 -DWAMR_BUILD_LAZY_JIT=1 -DLLVM_DIR=$LLVM_CMAKE" ;;
    multitier-eager) echo "-DWAMR_BUILD_FAST_INTERP=1 -DWAMR_BUILD_FAST_JIT=1 -DWAMR_BUILD_JIT=1 -DWAMR_BUILD_LAZY_JIT=0 -DLLVM_DIR=$LLVM_CMAKE" ;;
    *) echo "unknown row $1" >&2; exit 2 ;;
  esac
}
if [ "${1:-}" = llvm ]; then
  mkdir -p "$S/debs" "$LLVM_ROOT"
  ( cd "$S/debs" && apt-get download llvm-18-dev=1:18.1.3-1ubuntu1 libzstd-dev libxml2-dev libpfm4-dev 2>&1 | grep -v '^W:' )
  for d in "$S"/debs/*.deb; do
    echo "$(basename "$d"): $(wc -c < "$d") bytes, sha256 $(sha256sum "$d" | cut -c1-64)"
    dpkg-deb -x "$d" "$LLVM_ROOT"
  done
  # The dev packages' .so links point at runtime libraries this system already has installed.
  ln -sf /usr/lib/x86_64-linux-gnu/libzstd.so.1.5.5 "$LLVM_ROOT/usr/lib/x86_64-linux-gnu/libzstd.so.1.5.5"
  ln -sf /usr/lib/x86_64-linux-gnu/libxml2.so.2.9.14 "$LLVM_ROOT/usr/lib/x86_64-linux-gnu/libxml2.so.2.9.14"
  ln -sf /usr/lib/x86_64-linux-gnu/libpfm.so.4 "$LLVM_ROOT/usr/lib/x86_64-linux-gnu/libpfm.so"
  ln -sf /usr/lib/llvm-18/lib/libLLVM.so.18.1 "$LLVM_ROOT/usr/lib/llvm-18/lib/libLLVM.so.18.1"
  # LLVMExports.cmake refuses to load unless every file of every exported target exists
  # (tools, LTO, Polly, OpenMP, MLIR). WAMR links only LLVM component archives from
  # llvm-18-dev, so: link the ones the system has (llvm-18 is installed), and put an empty
  # placeholder where a file exists nowhere. None of these is linked into libiwasm.
  L="$LLVM_ROOT/usr/lib/llvm-18"; linked=0; placeholders=0
  for f in $(grep -ho '"${_IMPORT_PREFIX}/[^"]*"' "$L"/lib/cmake/llvm/LLVMExports-*.cmake | sed 's/"${_IMPORT_PREFIX}\///; s/"//' | sort -u); do
    [ -e "$L/$f" ] && continue
    mkdir -p "$(dirname "$L/$f")"
    if [ -e "/usr/lib/llvm-18/$f" ]; then ln -s "/usr/lib/llvm-18/$f" "$L/$f"; linked=$((linked + 1))
    else : > "$L/$f"; placeholders=$((placeholders + 1)); fi
  done
  echo "exported-target files absent from llvm-18-dev: $linked linked to the installed llvm-18, $placeholders empty placeholders (MLIR, OpenMP, Polly, test tools)"
  echo "extracted: $(du -sm "$LLVM_ROOT" | cut -f1) MB in \$S/llvm18x"
  exit 0
fi
ROWS=${*:-"classic fast fastjit-lazy fastjit-eager llvmjit-lazy llvmjit-eager multitier-lazy multitier-eager"}
for row in $ROWS; do
  B="$S/wamr-build-$row"; O="$S/wamr/$row"
  rm -rf "$B" "$O"; mkdir -p "$B" "$O"
  F=$(flags "$row")
  start=$(date +%s)
  # shellcheck disable=SC2086
  if ! cmake -S "$EM/wamr-host" -B "$B" -G Ninja -DWAMR_ROOT="$WAMR_SRC" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
       -DCMAKE_PREFIX_PATH="$LLVM_ROOT/usr" $COMMON $F > "$S/wamr-$row.log" 2>&1 \
     || ! cmake --build "$B" >> "$S/wamr-$row.log" 2>&1; then
    tail -25 "$S/wamr-$row.log"; echo "$row: BUILD FAILED"; rm -rf "$B"; continue
  fi
  secs=$(( $(date +%s) - start ))
  cp "$B/libiwasm.so" "$B/aprv-wamr" "$O/"
  cp "$O/libiwasm.so" "$S/wamr-$row.stripped.so"; strip "$S/wamr-$row.stripped.so"
  echo "== $row"
  echo "flags: $(echo "$COMMON $F" | tr -s ' ' | sed "s#$LLVM_CMAKE#\$LLVM_ROOT/usr/lib/llvm-18/lib/cmake/llvm#")"
  echo "cmake said: $(grep -E 'interpreter (enabled|disabled)|Fast JIT (enabled|disabled)|Fast JIT enabled with|LLVM ORC JIT|Multi-tier|Interpreter (enabled|disabled)|Found LLVM' "$S/wamr-$row.log" | sed 's/^ *//; s/^-- //' | tr '\n' ';' )"
  echo "compiler got: $(python3 -c "
import json, re, sys
cmds = json.load(open(sys.argv[1]))
c = next(x['command'] for x in cmds if x['file'].endswith('wasm_runtime.c'))
print(' '.join(sorted(set(re.findall(r'-DWASM_ENABLE_(?:INTERP|FAST_INTERP|FAST_JIT|JIT|LAZY_JIT|AOT|LIBC_WASI|LIBC_BUILTIN|MULTI_MODULE|DEBUG_INTERP|SIMD|REF_TYPES|BULK_MEMORY|THREAD_MGR)=\d', c)))))
" "$B/compile_commands.json")"
  echo "build ${secs} s; libiwasm.so $(wc -c < "$O/libiwasm.so") bytes (stripped $(wc -c < "$S/wamr-$row.stripped.so")), aprv-wamr $(wc -c < "$O/aprv-wamr") bytes; NEEDED: $(readelf -d "$O/libiwasm.so" | grep NEEDED | sed 's/.*\[\(.*\)\]/\1/' | tr '\n' ' ')"
  rm -rf "$B" "$S/wamr-$row.stripped.so"
done
