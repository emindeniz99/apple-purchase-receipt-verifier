#!/bin/sh
# Spike only (2026-09-27, round 9). The timing runs, in the order they ran,
# on an otherwise idle machine: start-up (7 cold processes on all CPUs and 7
# on CPU 0) and throughput (1 copy on CPU 0, 4 copies on CPUs 0-3) per row.
#   timing.sh            native rows
#   timing.sh py ROW...  Python facade rows (py-wamr-<WAMR row>), after the native results
#   timing.sh wasmtime-py  round 8's wasmtime-py facade re-measured on this machine (start-up only):
#                        Cranelift and Winch compiled at start, and Cranelift precompiled (.cwasm, baseline x86-64)
set -eu
. "$(dirname "$0")/env.sh"
R="$EM/scripts/run.sh"
if [ "${1:-}" = wasmtime-py ]; then
  R8="$REPO/docs/evidence/2026-09-27-python-runtime-options/py"
  mkdir -p "$S/cwasm"
  APRV_ENGINE=cranelift APRV_BASELINE=1 PYTHONPATH="$R8" "$PY312" "$R8/precompile.py" "$MOD" "$S/cwasm/cranelift-baseline.cwasm" > "$S/cwasm/precompile.txt"
  for o in cranelift winch cranelift-cwasm; do
    case $o in
      cranelift) set -- env APRV_ENGINE=cranelift APRV_MODULE="$MOD" ;;
      winch) set -- env APRV_ENGINE=winch APRV_MODULE="$MOD" ;;
      cranelift-cwasm) set -- env APRV_ENGINE=cranelift APRV_BASELINE=1 APRV_MODULE="$S/cwasm/cranelift-baseline.cwasm" ;;
    esac
    for c in all 0; do
      CP=""; [ $c = 0 ] && CP="--cpus 0"
      # shellcheck disable=SC2086
      PYTHONPATH="$R8" python3 "$EM/py/startup.py" "py-wasmtime-$o" 7 $CP -- "$@" "$PY312" "$EM/py/wasmtime_first.py" "$S/in/g5.bin" >> "$EM/results/startup.txt" || true
    done
  done
  exit 0
fi
if [ "${1:-}" = py ]; then
  shift
  for r in "$@"; do echo "== $r $(date -u +%T) load $(cut -d' ' -f1-3 /proc/loadavg)"; sh "$R" startup "$r"; sh "$R" procs "$r"; done
  exit 0
fi
for r in wasmi1-eager wasmi1-lazytr wasmi1-lazy wasmi2-auto-eager wasmi2-auto-lazytr wasmi2-auto-lazy \
         wasmi2-tail-lazytr wasmi2-tail-ind-lazytr wasmi2-loop-lazytr wasmi2-loop-ind-lazytr wasmi2-unstable-lazytr \
         wamr-classic wamr-fast wamr-fastjit-lazy wamr-fastjit-eager wamr-multitier-lazy \
         wasmtime-cranelift wasmtime-winch wasmtime-pulley \
         wamr-llvmjit-lazy wamr-llvmjit-eager wamr-multitier-eager; do
  echo "== $r $(date -u +%T) load $(cut -d' ' -f1-3 /proc/loadavg)"
  sh "$R" startup "$r"
  sh "$R" procs "$r"
done
# Start-up only: the other dispatch builds in the eager and lazy modes.
for d in tail tail-ind loop loop-ind unstable; do
  for m in eager lazy; do
    echo "== wasmi2-$d-$m $(date -u +%T)"; sh "$R" startup "wasmi2-$d-$m"
  done
done
