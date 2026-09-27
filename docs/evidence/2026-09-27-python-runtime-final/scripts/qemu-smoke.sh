#!/bin/sh
# Spike only (2026-09-27, round 11). aarch64 CORRECTNESS SMOKE under QEMU
# user-mode emulation. NOT a performance measurement: QEMU translates every
# aarch64 instruction, so no time printed here says anything about ARM64
# speed. The native ARM64 rows stay pending (scripts/arm64-native.sh).
#
# There is no aarch64 CPython or libc in this container, so the Python
# facade cannot be loaded under QEMU. What runs instead is the same engine
# configuration (Wasmi 2.0.0, stable + std + validate + memory64 +
# auto-dispatch, LazyTranslation) inside round 9's native host
# (../../2026-09-27-wasm-execution-modes/wasmi-host, unchanged), built as a
# static aarch64-unknown-linux-musl executable with cargo-zigbuild, and
# driven by round 9's driver.py over its line protocol:
#   1. `first`: one cold process to its first verified g5
#   2. the 37 ABI tests and the 2 isolation checks
#   3. the five corpora (6,179 rows), byte identity against Node's answers
#   qemu-smoke.sh > results/qemu-smoke.txt
set -u
. "$(dirname "$0")/env.sh"
: "${CORPORA:?}"
export PATH="$S/venv-zig/bin:$PATH" CARGO_PROFILE_RELEASE_STRIP=symbols
T=aarch64-unknown-linux-musl
HOST="$S/cross/aprv-rt-host-$T"
echo "# qemu-smoke.sh, $(date -u +%F): CORRECTNESS SMOKE ONLY under $(qemu-aarch64 --version | head -1); timings are emulated, not ARM64 performance"
if [ ! -x "$HOST" ]; then
  timeout -s KILL 1200 cargo zigbuild --release --locked --target $T --features v2-auto \
    --manifest-path "$EM/wasmi-host/Cargo.toml" > "$S/cross/qemu-host.log" 2>&1 || { tail -20 "$S/cross/qemu-host.log"; exit 1; }
  cp "$CARGO_TARGET_DIR/$T/release/aprv-rt-host" "$HOST"
  echo "wasmi cfg: $(cat "$CARGO_TARGET_DIR/$T"/release/build/wasmi-*/output | grep 'rustc-cfg=' | grep -o 'wasmi_[a-z_]*' | sort -u | tr '\n' ' ')"
  rm -rf "${CARGO_TARGET_DIR:?}/$T"
fi
echo "host: $(file -b "$HOST" | cut -d, -f1-2,5-6)"
Q="qemu-aarch64 $HOST"
echo "## 1. first"
timeout -s KILL 600 $Q first "$MOD" "$S/in/g5.bin" --mode lazy-translation | python3 -c 'import json,sys; r=json.load(sys.stdin); print({k: r[k] for k in ("engine", "mode", "verified")})'
echo "## 2. ABI tests + isolation"
# shellcheck disable=SC2086
APRV_STEP_TIMEOUT=600 timeout -s KILL 3000 python3 "$EM/py/driver.py" tests "$CALLS/cases.jsonl" -- $Q serve "$MOD" --mode lazy-translation > "$S/run/qemu-tests.txt" 2>&1
grep -c '^PASS' "$S/run/qemu-tests.txt" | sed 's/^/PASS lines: /'; grep '^FAIL\|summary\|HANG' "$S/run/qemu-tests.txt"
echo "## 3. corpora"
for c in cases hostile algorithms substrate fuzz; do
  # shellcheck disable=SC2086
  if APRV_STEP_TIMEOUT=600 timeout -s KILL 7200 python3 "$EM/py/driver.py" calls "$CALLS/$c.jsonl" -- $Q serve "$MOD" --mode lazy-translation \
       > "$S/run/qemu-$c.jsonl" 2> "$S/run/qemu-$c.err"; then
    python3 "$AB/py/abi_compare.py" "$CORPORA/$c.jsonl" "$NATIVENEW-$c.jsonl" "$CALLS/$c.jsonl" "$NODEROWS/node-$c.jsonl" "$S/run/qemu-$c.jsonl" \
      | sed -n "2s#^other host 1#    $c qemu-aarch64#p"
  else
    echo "$c: driver failed: $(tail -2 "$S/run/qemu-$c.err" | tr '\n' ' ')"
  fi
done
