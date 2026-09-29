#!/bin/sh
# Spike only (2026-09-27, round 11). Runs one Python row through round 9's
# harness (driver tests/calls via py/driver.py, startup.py, procs.py).
#   run.sh tests ROW     37 ABI + facade tests and 2 isolation checks   > results/tests-ROW.txt
#   run.sh calls ROW     five corpora (6,179 rows), parity + byte identity with Node > results/calls-ROW.txt
#   run.sh startup ROW   7 cold processes on all CPUs, 7 pinned to CPU 0 (appends to results/startup.txt)
#   run.sh procs ROW     bench: 1 copy on CPU 0, then 4 copies on CPUs 0-3 (appends to results/procs.txt)
#   run.sh all ROW
# ROW: py-wasmi-capi-{lazytr,lazy}         py/aprv_wasmi_capi over $S/lib/libwasmi.so
#      py-wasmi-rs-{lazytr,lazy}[-fuel][-xc]  py/aprv_wasmi_rs over $S/lib/libaprv_wasmi.so
#                                          (-xc: the extra-checks build, $S/lib/xc/libaprv_wasmi.so)
#                                          (-fuel: metering on, budget $FUEL per call, and
#                                          linear memory capped at $MAXMEM bytes)
set -eu
. "$(dirname "$0")/env.sh"
: "${CORPORA:?}"
EMPY="$EM/py"
G5="$S/in/g5.bin"; JWS="$S/in/jws.bin"
FUEL=${FUEL:-5000000000}      # 2.05x the heaviest corpus row (results/fuel-heaviest.txt)
MAXMEM=${MAXMEM:-67108864}    # 64 MiB: 2.8x the corpus peak of 23,789,568 bytes (results/fuel-envelope.txt)
row=${2:-}
case "$row" in
  py-wasmi-capi-*) export APRV_FACADE=aprv_wasmi_capi APRV_LIBWASMI="$S/lib/libwasmi.so"; m=${row#py-wasmi-capi-} ;;
  py-wasmi-rs-*) export APRV_FACADE=aprv_wasmi_rs APRV_LIBAPRVWASMI="$S/lib/libaprv_wasmi.so"; m=${row#py-wasmi-rs-}
    case "$m" in *-xc) export APRV_LIBAPRVWASMI="$S/lib/xc/libaprv_wasmi.so"; m=${m%-xc} ;; esac
    case "$m" in *-fuel) export APRV_WASMI_FUEL="$FUEL" APRV_WASMI_MAXMEM="$MAXMEM"; m=${m%-fuel} ;; esac ;;
  *) echo "usage: run.sh tests|calls|startup|procs|all ROW"; exit 2 ;;
esac
case "$m" in lazytr) export APRV_WASMI_MODE=lazy-translation ;; *) export APRV_WASMI_MODE="$m" ;; esac
export APRV_MODULE="$MOD" PYTHONPATH="$FE/py"
do_tests() {
  "$PY312" "$FE/py/driver.py" tests "$CALLS/cases.jsonl" -- "inproc:$APRV_FACADE" > "$FE/results/tests-$row.txt" 2>&1 || true
  tail -2 "$FE/results/tests-$row.txt"; }
do_calls() {
  {
    echo "# row $row: inproc:$APRV_FACADE, mode $APRV_WASMI_MODE, fuel ${APRV_WASMI_FUEL:-off}, memory cap ${APRV_WASMI_MAXMEM:-none}"
    for c in cases hostile algorithms substrate fuzz; do
      start=$(date +%s)
      if ! "$PY312" "$FE/py/driver.py" calls "$CALLS/$c.jsonl" -- "inproc:$APRV_FACADE" > "$S/run/$row-$c.jsonl" 2> "$S/run/$row-$c.err"; then
        echo "$c: driver failed: $(tail -2 "$S/run/$row-$c.err" "$S/run/$row-$c.jsonl" | tr '\n' ' ')"; continue
      fi
      python3 "$AB/py/abi_compare.py" "$CORPORA/$c.jsonl" "$NATIVENEW-$c.jsonl" "$CALLS/$c.jsonl" "$NODEROWS/node-$c.jsonl" "$S/run/$row-$c.jsonl" \
        | sed "1s#^#$c (node): #; 2s#^other host 1#    $row#"
      echo "    $(cat "$S/run/$row-$c.err") $(( $(date +%s) - start )) s wall"
    done
  } > "$FE/results/calls-$row.txt" 2>&1
  grep -h 'byte-identical\|DIFFERENT\|failed' "$FE/results/calls-$row.txt" | tail -6; }
do_startup() {
  python3 "$EMPY/startup.py" "$row" 7 -- "$PY312" "$FE/py/first.py" "$G5" >> "$FE/results/startup.txt" || true
  python3 "$EMPY/startup.py" "$row" 7 --cpus 0 -- "$PY312" "$FE/py/first.py" "$G5" >> "$FE/results/startup.txt" || true
  tail -2 "$FE/results/startup.txt" | cut -c1-220; }
do_procs() {
  python3 "$EMPY/procs.py" "$row" 1 -- "$PY312" "$FE/py/bench.py" "$G5" "$JWS" >> "$FE/results/procs.txt" || true
  python3 "$EMPY/procs.py" "$row" 4 -- "$PY312" "$FE/py/bench.py" "$G5" "$JWS" >> "$FE/results/procs.txt" || true
  tail -2 "$FE/results/procs.txt" | cut -c1-260; }
case "$1" in
  tests) do_tests ;;
  calls) do_calls ;;
  startup) do_startup ;;
  procs) do_procs ;;
  all) echo "== $row ($(date -u +%T), load $(cut -d' ' -f1-3 /proc/loadavg))"; do_tests; do_calls; do_startup; do_procs ;;
  *) echo "usage: run.sh tests|calls|startup|procs|all ROW"; exit 2 ;;
esac
