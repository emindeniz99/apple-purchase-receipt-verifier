#!/bin/sh
# Spike only (2026-09-27). Every wasmtime-py option through round 7's
# harness (run_calls.py, abi_tests.py, concurrency.py from
# ../../2026-09-26-python-wasmtime/py), with this folder's py/aprv_wasm
# first on PYTHONPATH so the harness drives the selectable facade.
#   run.sh precompile            the .cwasm artifacts (cranelift/winch for a baseline x86-64 target, pulley64)
#   run.sh tests OPT             ABI tests            > results/abi-tests-OPT.txt
#   run.sh calls OPT             five corpora, parity + byte identity with Node > results/calls-OPT.txt
#   run.sh bench OPT             1 thread, g5 + JWS   (appended to results/bench.txt)
#   run.sh processes OPT         1/2/4 processes      (appended to results/processes.txt)
#   run.sh cross                 precompile for the other wheels' targets (cross-compiling)
#   run.sh startup               cold start to first result, every option, all cores and one core > results/startup.txt
#   run.sh startup-serial        the same for Cranelift with parallel compilation off, all cores (appended to results/startup.txt)
# OPT: cranelift | cranelift-none | winch | pulley | cranelift-baseline | winch-baseline
set -eu
. "$(dirname "$0")/env.sh"
: "${CORPORA:?}"
R7="$REPO/docs/evidence/2026-09-26-python-wasmtime/py"
CW="$S/cwasm"
opt() {  # sets the APRV_* environment for option $1
  unset APRV_ENGINE APRV_BASELINE APRV_CACHE APRV_FILECACHE APRV_PARALLEL
  export APRV_MODULE="$MOD"
  case "$1" in
    cranelift) export APRV_ENGINE=cranelift ;;
    cranelift-none) export APRV_ENGINE=cranelift-none ;;
    winch) export APRV_ENGINE=winch ;;
    pulley) export APRV_ENGINE=pulley ;;
    cranelift-baseline) export APRV_ENGINE=cranelift APRV_BASELINE=1 APRV_MODULE="$CW/cranelift-baseline.cwasm" ;;
    winch-baseline) export APRV_ENGINE=winch APRV_BASELINE=1 APRV_MODULE="$CW/winch-baseline.cwasm" ;;
    cranelift-serial) export APRV_ENGINE=cranelift APRV_PARALLEL=0 ;;
    pulley-cwasm) export APRV_ENGINE=pulley APRV_MODULE="$CW/pulley64.cwasm" ;;
    *) echo "unknown option $1"; exit 2 ;;
  esac
}
cd "$S"
case "$1" in
precompile)
  mkdir -p "$CW"
  opt cranelift; APRV_BASELINE=1 "$PY" "$RO/py/precompile.py" "$MOD" "$CW/cranelift-baseline.cwasm"
  opt winch; APRV_BASELINE=1 "$PY" "$RO/py/precompile.py" "$MOD" "$CW/winch-baseline.cwasm"
  opt pulley; "$PY" "$RO/py/precompile.py" "$MOD" "$CW/pulley64.cwasm"
  opt cranelift; "$PY" "$RO/py/precompile.py" "$MOD" "$CW/cranelift-native.cwasm"
  ;;
cross)
  # Precompiling the other wheels' modules on this x86-64 Linux machine.
  # 1. wasmtime-py itself: its C library carries only the host's backend.
  mkdir -p "$S/cross"
  for t in aarch64-unknown-linux-gnu x86_64-apple-darwin x86_64-pc-windows-msvc; do
    opt cranelift
    out=$(APRV_TARGET="$t" "$PY" "$RO/py/precompile.py" "$MOD" "$S/cross/py-$t.cwasm" 2>&1 || true)
    echo "wasmtime-py 49.0.0, target $t: $(echo "$out" | grep -m1 -oE 'Support for this target (is|was) disabled|target .* does not match the host|"cwasm_bytes": [0-9]+')$(echo "$out" | grep -q '^Aborted' && echo ' (the process aborted: a Rust panic, not a Python exception)')"
  done
  # 2. The Wasmtime CLI of the same major (49.0.1, x86-64 Linux release asset),
  #    with -C collector=drc to match wasmtime-py's default engine.
  WT="$SCRATCH/tools/wasmtime-v49.0.1-x86_64-linux/wasmtime"
  echo "CLI: $("$WT" --version)"
  for t in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin x86_64-pc-windows-msvc aarch64-pc-windows-msvc; do
    for c in cranelift winch; do
      start=$(date +%s%N)
      if "$WT" compile -C collector=drc -C compiler=$c --target "$t" -o "$S/cross/cli-$c-$t.cwasm" "$MOD" 2> "$S/cross/err" ; then
        f="$S/cross/cli-$c-$t.cwasm"
        echo "CLI $c $t: $(( ($(date +%s%N) - start) / 1000000 )) ms, $(wc -c < "$f") bytes, deflated $(python3 -c "import zlib,sys; print(len(zlib.compress(open(sys.argv[1],'rb').read(), 9)))" "$f") bytes"
      else
        echo "CLI $c $t: refused: $(head -c 200 "$S/cross/err" | tr '\n' ' ')"
      fi
    done
  done
  # The x86-64 Linux ones must load in wasmtime-py 49.0.0 and pass the ABI tests.
  for c in cranelift winch; do
    opt "$c"; [ $c = winch ] && export APRV_BASELINE=1
    export APRV_MODULE="$S/cross/cli-$c-x86_64-unknown-linux-gnu.cwasm"
    echo "CLI-made $c .cwasm in wasmtime-py 49.0.0: $("$PY" "$R7/abi_tests.py" "$CALLS/cases.jsonl" | tail -1)"
  done ;;
tests) opt "$2"; "$PY" "$R7/abi_tests.py" "$CALLS/cases.jsonl" ;;
calls)
  opt "$2"
  echo "# option $2: $(env | grep '^APRV_' | sed "s#$S/##; s#$SCRATCH/##" | sort | tr '\n' ' ')"
  for c in cases hostile algorithms substrate fuzz; do
    start=$(date +%s)
    "$PY" "$R7/run_calls.py" "$CALLS/$c.jsonl" > "$S/run/$2-$c.jsonl" 2> "$S/run/$2-$c.err"
    s=$(( $(date +%s) - start ))
    python3 "$AB/py/abi_compare.py" "$CORPORA/$c.jsonl" "$NATIVENEW-$c.jsonl" "$CALLS/$c.jsonl" "$NODEROWS/node-$c.jsonl" "$S/run/$2-$c.jsonl" \
      | sed "1s#^#$c (node): #; 2s#^other host 1#    $2#"
    echo "    $(cat "$S/run/$2-$c.err") ${s} s wall"
  done ;;
bench) opt "$2"; echo "# option $2"; "$PY" "$R7/concurrency.py" "$CALLS/cases.jsonl" bench ;;
processes) opt "$2"; echo "# option $2"; "$PY" "$R7/concurrency.py" "$CALLS/cases.jsonl" processes ;;
startup)
  G5="$S/g5.b64"
  python3 -c "import json; [open('$G5','w').write(c['input']) for c in map(json.loads, open('$CALLS/cases.jsonl')) if c['id']=='receipt/verify-genuine-sandbox-g5-against-apple-roots']"
  echo "# $(date -u +%F), $(nproc) cores ($(grep -m1 'model name' /proc/cpuinfo | sed 's/.*: //')); load average $(cut -d' ' -f1-3 /proc/loadavg); 7 cold processes per row, median"
  for cpus in all 0; do
    CP=""; [ "$cpus" = 0 ] && CP="--cpus 0"
    for o in cranelift cranelift-none winch pulley cranelift-baseline winch-baseline pulley-cwasm; do
      opt "$o"; "$PY" "$RO/py/startup.py" "$G5" 7 $CP | sed "s#^{#{\"option\":\"$o\",#"
    done
    # Caches that need a writable disk (servers; not a Lambda cold start):
    opt cranelift; rm -rf "$S/cache/file"; mkdir -p "$S/cache/file"; export APRV_FILECACHE="$S/cache/file"
    "$PY" "$RO/py/startup.py" "$G5" 1 $CP | sed 's#^{#{"option":"cranelift+file-cache (first run: miss)",#'
    "$PY" "$RO/py/startup.py" "$G5" 7 $CP | sed 's#^{#{"option":"cranelift+file-cache (hit)",#'
    opt cranelift; rm -rf "$S/cache/wasmtime"; mkdir -p "$S/cache/wasmtime"
    printf '[cache]\ndirectory = "%s"\n' "$S/cache/wasmtime" > "$S/cache/wasmtime.toml"; export APRV_CACHE="$S/cache/wasmtime.toml"
    "$PY" "$RO/py/startup.py" "$G5" 1 $CP | sed 's#^{#{"option":"cranelift+Config.cache (first run: empty)",#'
    "$PY" "$RO/py/startup.py" "$G5" 7 $CP | sed 's#^{#{"option":"cranelift+Config.cache (warm)",#'
  done ;;
startup-serial)
  echo "# $(date -u +%F), $(nproc) cores; load average $(cut -d' ' -f1-3 /proc/loadavg); Cranelift with Config.parallel_compilation = False"
  opt cranelift-serial; "$PY" "$RO/py/startup.py" "$S/g5.b64" 7 | sed 's#^{#{"option":"cranelift-serial",#' ;;
*) echo "usage: run.sh precompile|tests OPT|calls OPT|bench OPT|processes OPT|startup|startup-serial"; exit 2 ;;
esac
