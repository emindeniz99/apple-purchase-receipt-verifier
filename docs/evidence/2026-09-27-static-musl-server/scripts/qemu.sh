#!/bin/sh
# Spike only (2026-09-27, round 10). aarch64 CORRECTNESS SMOKE under
# qemu-aarch64 user mode. NOT a performance measurement: QEMU translates
# every aarch64 instruction, and no time here says anything about ARM64.
#   qemu.sh > results/qemu.txt
# 1. smoke.sh qemu on the static aarch64 musl server (CLI + HTTP routes)
# 2. the five corpora over HTTP through it (the spike's corpus_http.py)
# 3. the 37 ABI tests + 2 isolation checks: the server exposes no raw
#    exports, so these run on round 9's Rust host built with Wasmtime 49.0.1
#    (feature wt) for aarch64-unknown-linux-musl, compiling the module with
#    Cranelift's aarch64 backend at start, driven by round 9's driver.py
set -u
. "$(dirname "$0")/env.sh"
: "${CORPORA:?}"
B="$S/bin"
echo "# qemu.sh, $(date -u +%F): CORRECTNESS SMOKE ONLY under $(qemu-aarch64 --version | head -1); timings are emulated, not ARM64 performance"
sh "$FE/scripts/smoke.sh" qemu "$B/a64-musl-spike"
echo "## corpora over HTTP (a64-musl-spike under QEMU, lifecycle fresh, 4 workers)"
out="$S/run/qemu.$$.out"; : > "$out"
setsid qemu-aarch64 "$B/a64-musl-spike" serve --listen 127.0.0.1:0 --lifecycle fresh --workers 4 > "$out" 2> "$out.err" &
pid=$!
i=0; while ! grep -q '^APRV_LISTEN=' "$out"; do i=$((i + 1)); [ $i -gt 1200 ] && { echo "no server"; kill -9 -$pid; exit 1; }; sleep 0.1; done
start=$(date +%s)
timeout -s KILL 7200 python3 "$EV/py/corpus_http.py" "$(sed -n 's/^APRV_LISTEN=//p' "$out")" "$CALLS" "$NODEROWS"
echo "    ($(( $(date +%s) - start )) s wall, emulated)"
kill -TERM -$pid 2>/dev/null; sleep 0.5; kill -9 -$pid 2>/dev/null; wait $pid 2>/dev/null
rm -f "$out" "$out.err"
echo "## ABI tests: round 9's host, Wasmtime 49.0.1 Cranelift, aarch64 musl, under QEMU"
APRV_STEP_TIMEOUT=900 timeout -s KILL 3600 python3 "$EM/py/driver.py" tests "$CALLS/cases.jsonl" -- qemu-aarch64 "$B/a64-rt-host-wt" serve "$WASM" --mode cranelift > "$S/run/qemu-tests.txt" 2>&1
grep -c '^PASS' "$S/run/qemu-tests.txt" | sed 's/^/PASS lines: /'; grep '^FAIL\|summary\|HANG' "$S/run/qemu-tests.txt"
