#!/bin/sh
# Spike only (2026-09-27, round 9). Runs one row of the matrix through the
# native hosts built by build-wasmi.sh and build-wamr.sh.
#   run.sh tests ROW       37 ABI + facade tests and 2 isolation checks  > results/tests-ROW.txt
#   run.sh calls ROW       five corpora (6,179 rows), parity + byte identity with Node > results/calls-ROW.txt
#   run.sh startup ROW     7 cold processes on all CPUs, 7 pinned to CPU 0 (appends to results/startup.txt)
#   run.sh procs ROW       bench: 1 copy on CPU 0, then 4 copies on CPUs 0-3 (appends to results/procs.txt)
#   run.sh all ROW         the four above
# ROW:
#   Wasmi   wasmi1-{eager,lazytr,lazy}, wasmi2-auto-{eager,lazytr,lazy},
#           wasmi2-{tail,tail-ind,loop,loop-ind,unstable}-{eager,lazytr,lazy}
#   WAMR    wamr-{classic,fast,fastjit-lazy,fastjit-eager,llvmjit-lazy,llvmjit-eager,multitier-lazy,multitier-eager}
#   Wasmtime (native Rust host) wasmtime-{cranelift,winch,pulley}
#   Python  py-wamr-<WAMR row>: py/aprv_wamr (ctypes) over that row's libiwasm.so
set -eu
. "$(dirname "$0")/env.sh"
: "${CORPORA:?}"
G5="$S/in/g5.bin"; JWS="$S/in/jws.bin"
[ -f "$G5" ] || python3 - "$CALLS/cases.jsonl" "$G5" "$JWS" <<'PYEOF'
import base64, json, sys
rows = {c["id"]: c for c in map(json.loads, open(sys.argv[1]))}
open(sys.argv[2], "wb").write(base64.b64decode(rows["receipt/verify-genuine-sandbox-g5-against-apple-roots"]["input"]))
open(sys.argv[3], "wb").write(base64.b64decode(rows["transaction/verify-shared-sandbox"]["input"]))
PYEOF
# host ROW CMD [args...]: the host argv for this row
host() {
  row=$1; cmd=$2; shift 2
  case "$row" in
    wasmi*|wasmtime-*)
      case "$row" in
        wasmtime-*) bin=wasmtime; mode=${row#wasmtime-} ;;
        *) bin=${row%-*}; mode=${row##*-}; [ "$mode" = lazytr ] && mode=lazy-translation ;;
      esac
      echo "$S/bin/aprv-$bin $cmd $MOD $* --mode $mode" ;;
    wamr-*) echo "$S/wamr/${row#wamr-}/aprv-wamr $cmd $MOD $*" ;;
    py-wamr-*)  # the Python ctypes facade over that row's libiwasm.so
      case "$cmd" in
        serve) echo "inproc:aprv_wamr" ;;
        first) echo "$PY312 $EM/py/wamr_first.py $*" ;;
        bench) echo "$PY312 $EM/py/wamr_bench.py $*" ;;
      esac ;;
    *) echo "unknown row $row" >&2; exit 2 ;;
  esac
}
do_tests() { # shellcheck disable=SC2046
  "$DPY" "$EM/py/driver.py" tests "$CALLS/cases.jsonl" -- $(host "$1" serve) > "$EM/results/tests-$1.txt" 2>&1 || true
  tail -1 "$EM/results/tests-$1.txt"; }
do_calls() {
  {
    echo "# row $1: $(host "$1" serve | sed "s#$S/##g; s#$SCRATCH/##g")"
    for c in cases hostile algorithms substrate fuzz; do
      start=$(date +%s)
      # shellcheck disable=SC2046
      if ! "$DPY" "$EM/py/driver.py" calls "$CALLS/$c.jsonl" -- $(host "$1" serve) > "$S/run/$1-$c.jsonl" 2> "$S/run/$1-$c.err"; then
        echo "$c: driver failed: $(tail -2 "$S/run/$1-$c.err" "$S/run/$1-$c.jsonl" | tr '\n' ' ')"; continue
      fi
      python3 "$AB/py/abi_compare.py" "$CORPORA/$c.jsonl" "$NATIVENEW-$c.jsonl" "$CALLS/$c.jsonl" "$NODEROWS/node-$c.jsonl" "$S/run/$1-$c.jsonl" \
        | sed "1s#^#$c (node): #; 2s#^other host 1#    $1#"
      echo "    $(cat "$S/run/$1-$c.err") $(( $(date +%s) - start )) s wall"
    done
  } > "$EM/results/calls-$1.txt" 2>&1
  grep -h 'byte-identical\|DIFFERENT\|failed' "$EM/results/calls-$1.txt" | awk '{print}' | tail -6; }
do_startup() { # shellcheck disable=SC2046
  python3 "$EM/py/startup.py" "$1" 7 -- $(host "$1" first "$G5") >> "$EM/results/startup.txt" || true
  python3 "$EM/py/startup.py" "$1" 7 --cpus 0 -- $(host "$1" first "$G5") >> "$EM/results/startup.txt" || true
  tail -2 "$EM/results/startup.txt" | cut -c1-200; }
do_procs() { # shellcheck disable=SC2046
  python3 "$EM/py/procs.py" "$1" 1 -- $(host "$1" bench "$G5" "$JWS") >> "$EM/results/procs.txt" || true
  python3 "$EM/py/procs.py" "$1" 4 -- $(host "$1" bench "$G5" "$JWS") >> "$EM/results/procs.txt" || true
  tail -2 "$EM/results/procs.txt" | cut -c1-240; }
DPY=python3
case "${2:-}" in
  py-wamr-*) export APRV_LIBIWASM="$S/wamr/${2#py-wamr-}/libiwasm.so" APRV_MODULE="$MOD" PYTHONPATH="$EM/py"; DPY="$PY312" ;;
esac
case "$1" in
  tests) do_tests "$2" ;;
  calls) do_calls "$2" ;;
  startup) do_startup "$2" ;;
  procs) do_procs "$2" ;;
  all) echo "== $2 ($(date -u +%T), load $(cut -d' ' -f1-3 /proc/loadavg))"; do_tests "$2"; do_calls "$2"; do_startup "$2"; do_procs "$2" ;;
  *) echo "usage: run.sh tests|calls|startup|procs|all ROW"; exit 2 ;;
esac
