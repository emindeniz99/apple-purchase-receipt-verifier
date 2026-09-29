#!/bin/sh
# Spike only (2026-09-27, round 11). Interleaved A/B of the Rust cdylib built
# with and without Wasmi's `extra-checks` feature, both with fuel (5e9) and
# the 64 MiB cap on, ROUNDS rounds, one bench process on CPU 0 each.
#   cargo build --release --locked --features extra-checks --manifest-path wasmi-cdylib/Cargo.toml
#     -> $S/lib/xc/libaprv_wasmi.so (stripped); the default build is $S/lib/libaprv_wasmi.so
#   ab-extra-checks.sh [ROUNDS] > results/ab-extra-checks.txt
set -eu
. "$(dirname "$0")/env.sh"
G5="$S/in/g5.bin"; JWS="$S/in/jws.bin"
R=${1:-5}
export APRV_MODULE="$MOD" PYTHONPATH="$FE/py" APRV_WASMI_MODE=lazy-translation APRV_FACADE=aprv_wasmi_rs \
  APRV_WASMI_FUEL=5000000000 APRV_WASMI_MAXMEM=67108864
i=0
while [ $i -lt "$R" ]; do
  i=$((i + 1))
  APRV_LIBAPRVWASMI="$S/lib/libaprv_wasmi.so" python3 "$EM/py/procs.py" py-wasmi-rs-bounded 1 -- "$PY312" "$FE/py/bench.py" "$G5" "$JWS"
  APRV_LIBAPRVWASMI="$S/lib/xc/libaprv_wasmi.so" python3 "$EM/py/procs.py" py-wasmi-rs-bounded-extra-checks 1 -- "$PY312" "$FE/py/bench.py" "$G5" "$JWS"
done
