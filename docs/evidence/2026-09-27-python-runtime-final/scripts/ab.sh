#!/bin/sh
# Spike only (2026-09-27, round 11). Interleaved A/B on one pinned CPU, so
# row-to-row noise does not masquerade as a cost: ROUNDS rounds, each
# running the four variants in turn (native Wasmi 2.0 LazyTranslation from
# round 9's build, py/aprv_wasmi_rs with fuel off and on, py/aprv_wasmi_capi),
# one bench process each (round 9's procs.py, 1 copy on CPU 0).
#   ab.sh [ROUNDS]   > results/ab.txt  (one JSON line per run; summarize with py/ab_summary.py)
set -eu
. "$(dirname "$0")/env.sh"
G5="$S/in/g5.bin"; JWS="$S/in/jws.bin"
R=${1:-5}
NATIVE="$SCRATCH/r9/bin/aprv-wasmi2-auto"   # round 9's build-wasmi.sh wasmi2-auto (reused, not rebuilt)
export APRV_MODULE="$MOD" PYTHONPATH="$FE/py" APRV_WASMI_MODE=lazy-translation
export APRV_LIBAPRVWASMI="$S/lib/libaprv_wasmi.so" APRV_LIBWASMI="$S/lib/libwasmi.so"
i=0
while [ $i -lt "$R" ]; do
  i=$((i + 1))
  python3 "$EM/py/procs.py" native-wasmi2-lazytr 1 -- "$NATIVE" bench "$MOD" "$G5" "$JWS" --mode lazy-translation
  APRV_FACADE=aprv_wasmi_rs APRV_WASMI_FUEL=0 python3 "$EM/py/procs.py" py-wasmi-rs-lazytr 1 -- "$PY312" "$FE/py/bench.py" "$G5" "$JWS"
  APRV_FACADE=aprv_wasmi_rs APRV_WASMI_FUEL=10000000000 python3 "$EM/py/procs.py" py-wasmi-rs-lazytr-fuel 1 -- "$PY312" "$FE/py/bench.py" "$G5" "$JWS"
  APRV_FACADE=aprv_wasmi_capi python3 "$EM/py/procs.py" py-wasmi-capi-lazytr 1 -- "$PY312" "$FE/py/bench.py" "$G5" "$JWS"
done
