#!/bin/sh
# Spike only (2026-09-27, round 11). Start-up A/B, interleaved: ROUNDS
# rounds of round 9's startup.py (7 cold processes pinned to CPU 0) for
# round 9's native Wasmi 2.0 host (LazyTranslation, reused from $SCRATCH/r9/bin),
# then py/aprv_wasmi_rs LazyTranslation with fuel and the memory cap off,
# then on (5e9 per call, 64 MiB).
#   startup-ab.sh [ROUNDS] > results/startup-ab.txt
set -eu
. "$(dirname "$0")/env.sh"
R=${1:-3}
export APRV_MODULE="$MOD" PYTHONPATH="$FE/py" APRV_WASMI_MODE=lazy-translation APRV_FACADE=aprv_wasmi_rs APRV_LIBAPRVWASMI="$S/lib/libaprv_wasmi.so"
i=0
while [ $i -lt "$R" ]; do
  i=$((i + 1))
  python3 "$EM/py/startup.py" native-wasmi2-lazytr 7 --cpus 0 -- "$SCRATCH/r9/bin/aprv-wasmi2-auto" first "$MOD" "$S/in/g5.bin" --mode lazy-translation
  APRV_WASMI_FUEL=0 APRV_WASMI_MAXMEM=0 python3 "$EM/py/startup.py" py-wasmi-rs-lazytr 7 --cpus 0 -- "$PY312" "$FE/py/first.py" "$S/in/g5.bin"
  APRV_WASMI_FUEL=5000000000 APRV_WASMI_MAXMEM=67108864 python3 "$EM/py/startup.py" py-wasmi-rs-lazytr-bounded 7 --cpus 0 -- "$PY312" "$FE/py/first.py" "$S/in/g5.bin"
done
