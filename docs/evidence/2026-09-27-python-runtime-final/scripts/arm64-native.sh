#!/bin/sh
# Spike only (2026-09-27, round 11). The native ARM64 rows this round could
# not measure (its container is x86-64 only). Run it on Linux AArch64 or on
# an Apple Silicon Mac, from a checkout of this repository:
#
#   sh docs/evidence/2026-09-27-python-runtime-final/scripts/arm64-native.sh MODULE CASES [OUT]
#
#   MODULE  aprv-abi1.wasm, the canonical ABI v1 module (sha256 checked below;
#           copy it from the machine that built it with ../../2026-09-26-wasm-abi-v1/scripts/build.sh,
#           it is architecture-independent)
#   CASES   the ABI v1 calls file for the repository's cases (cases.jsonl
#           from ../../2026-09-26-wasm-abi-v1/py/abi_calls.py; it supplies the
#           g5 receipt and the shared-sandbox JWS and drives the 37 ABI tests)
#   OUT     results directory (default ./arm64-results-<os>-<arch>)
#
# Needs: rustup (installs the 1.98.1 toolchain with the minimal profile if
# it is missing), python3 >= 3.10 (ctypes only, no pip packages), a C
# toolchain for linking (Xcode command line tools on macOS). Nothing is
# installed system-wide; the build goes to a temporary directory and is
# deleted at the end.
#
# What it measures, per row (the same harness as the x86-64 rows):
#   native-wasmi2-lazytr   round 9's Rust host, Wasmi 2.0.0 auto-dispatch, LazyTranslation
#   py-wasmi-rs-lazytr     py/aprv_wasmi_rs over the Rust cdylib (../wasmi-cdylib)
#   py-wasmi-capi-lazytr   py/aprv_wasmi_capi over the official C API (../wasmi-capi)
#   - the 37 ABI tests and 2 isolation checks (the Python rows)
#   - fresh process to first verified g5, 7 runs, all CPUs and pinned to CPU 0
#   - calls #1..#100 and steady g5/s, JWS/s: 1 process, then 4 at once
#   - threads.py (1, 2, 4 threads) for the Python rows
#   - library sizes (stripped) and the dispatch Wasmi's build script chose
# macOS has no taskset: a shim that ignores `-c N` stands in for it, so
# "pinned" rows there are unpinned, and the summary says so.
set -eu
[ $# -ge 2 ] || { sed -n '2,20p' "$0"; exit 2; }
MOD=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
CASES=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
FE=$(cd "$(dirname "$0")/.." && pwd)
EM=$(cd "$FE/../2026-09-27-wasm-execution-modes" && pwd)
OS=$(uname -s); ARCH=$(uname -m)
OUT=${3:-$PWD/arm64-results-$OS-$ARCH}
MOD_SHA256=b14e14b2c3b8a38953c6ac03d941e42647321fdb86cfb0e3629c006687b636b3
PY=${PYTHON:-python3}
export PYTHONDONTWRITEBYTECODE=1
case "$OS/$ARCH" in
  Linux/aarch64|Darwin/arm64) ;;
  *) echo "this script is for Linux aarch64 or macOS arm64, not $OS/$ARCH" >&2; exit 2 ;;
esac
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
[ "$(sha "$MOD")" = "$MOD_SHA256" ] || { echo "MODULE sha256 is $(sha "$MOD"), expected $MOD_SHA256" >&2; exit 2; }
"$PY" -c 'import sys; assert sys.version_info >= (3, 10), sys.version' || exit 2
command -v rustup >/dev/null || { echo "needs rustup (https://rustup.rs)" >&2; exit 2; }
rustup toolchain list | grep -q '^1\.98\.1' || rustup toolchain install 1.98.1 --profile minimal
W=$(mktemp -d "${TMPDIR:-/tmp}/aprv-arm64.XXXXXX")
trap 'rm -rf "$W"' EXIT
mkdir -p "$OUT" "$W/bin" "$W/lib"
export CARGO_TARGET_DIR="$W/target"
if [ "$OS" = Darwin ]; then
  EXT=dylib
  printf '#!/bin/sh\n[ "$1" = -c ] && shift 2\nexec "$@"\n' > "$W/bin/taskset"; chmod +x "$W/bin/taskset"
  export PATH="$W/bin:$PATH"
  CPU=$(sysctl -n machdep.cpu.brand_string); NCPU=$(sysctl -n hw.ncpu); PIN="no (macOS: taskset shim)"
else
  EXT=so
  CPU=$(grep -m1 -i 'model name\|^CPU part' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//'); NCPU=$(nproc); PIN=yes
fi
{
  echo "# arm64-native.sh, $(date -u +%FT%TZ)"
  echo "os $OS $(uname -r), arch $ARCH, cpu: $CPU, $NCPU CPUs, pinning: $PIN"
  echo "python $("$PY" --version 2>&1), $(rustup run 1.98.1 rustc --version)"
} > "$OUT/summary.txt"

# Inputs: g5 and the shared-sandbox JWS from the calls file.
"$PY" - "$CASES" "$W/g5.bin" "$W/jws.bin" <<'PYEOF'
import base64, json, sys
rows = {c["id"]: c for c in map(json.loads, open(sys.argv[1]))}
open(sys.argv[2], "wb").write(base64.b64decode(rows["receipt/verify-genuine-sandbox-g5-against-apple-roots"]["input"]))
open(sys.argv[3], "wb").write(base64.b64decode(rows["transaction/verify-shared-sandbox"]["input"]))
PYEOF

# Builds, one at a time.
build() { # manifest features artifact -> $W/lib or $W/bin
  start=$(date +%s)
  rustup run 1.98.1 cargo build --release --locked -vv --manifest-path "$1" ${2:+--features "$2"} > "$W/build.log" 2>&1 \
    || { tail -30 "$W/build.log"; echo "BUILD FAILED: $1" >&2; exit 1; }
  echo "built $(basename "$(dirname "$1")") in $(( $(date +%s) - start )) s; wasmi cfgs: $(grep -o 'rustc-cfg=wasmi_[a-z_]*' "$W/build.log" | sort -u | tr '\n' ' ')" >> "$OUT/summary.txt"
}
build "$EM/wasmi-host/Cargo.toml" v2-auto
cp "$CARGO_TARGET_DIR/release/aprv-rt-host" "$W/bin/aprv-wasmi2-auto"
build "$FE/wasmi-cdylib/Cargo.toml" ""
cp "$CARGO_TARGET_DIR/release/libaprv_wasmi.$EXT" "$W/lib/"
build "$FE/wasmi-capi/Cargo.toml" ""
cp "$CARGO_TARGET_DIR/release/libwasmi.$EXT" "$W/lib/"
for f in "$W/lib/libaprv_wasmi.$EXT" "$W/lib/libwasmi.$EXT" "$W/bin/aprv-wasmi2-auto"; do
  if [ "$OS" = Darwin ]; then strip -x "$f" 2>/dev/null || true; else strip "$f"; fi
  echo "stripped $(basename "$f"): $(wc -c < "$f" | tr -d ' ') bytes, gzip -9 $(gzip -9c "$f" | wc -c | tr -d ' ')" >> "$OUT/summary.txt"
done
rm -rf "$CARGO_TARGET_DIR"

export APRV_MODULE="$MOD" PYTHONPATH="$FE/py" APRV_WASMI_MODE=lazy-translation
export APRV_LIBAPRVWASMI="$W/lib/libaprv_wasmi.$EXT" APRV_LIBWASMI="$W/lib/libwasmi.$EXT"
# Native baseline.
"$PY" "$EM/py/startup.py" native-wasmi2-lazytr 7 -- "$W/bin/aprv-wasmi2-auto" first "$MOD" "$W/g5.bin" --mode lazy-translation >> "$OUT/startup.txt" || true
"$PY" "$EM/py/startup.py" native-wasmi2-lazytr 7 --cpus 0 -- "$W/bin/aprv-wasmi2-auto" first "$MOD" "$W/g5.bin" --mode lazy-translation >> "$OUT/startup.txt" || true
"$PY" "$EM/py/procs.py" native-wasmi2-lazytr 1 -- "$W/bin/aprv-wasmi2-auto" bench "$MOD" "$W/g5.bin" "$W/jws.bin" --mode lazy-translation >> "$OUT/procs.txt" || true
"$PY" "$EM/py/procs.py" native-wasmi2-lazytr 4 -- "$W/bin/aprv-wasmi2-auto" bench "$MOD" "$W/g5.bin" "$W/jws.bin" --mode lazy-translation >> "$OUT/procs.txt" || true
# Python rows.
for facade in aprv_wasmi_rs aprv_wasmi_capi; do
  row=py-${facade#aprv_}; row=$(echo "$row" | tr _ -)-lazytr
  export APRV_FACADE=$facade
  "$PY" "$FE/py/driver.py" tests "$CASES" -- "inproc:$facade" > "$OUT/tests-$row.txt" 2>&1 || true
  echo "$row tests: $(grep -h 'summary' "$OUT/tests-$row.txt" | tr '\n' ' ')" >> "$OUT/summary.txt"
  "$PY" "$EM/py/startup.py" "$row" 7 -- "$PY" "$FE/py/first.py" "$W/g5.bin" >> "$OUT/startup.txt" || true
  "$PY" "$EM/py/startup.py" "$row" 7 --cpus 0 -- "$PY" "$FE/py/first.py" "$W/g5.bin" >> "$OUT/startup.txt" || true
  "$PY" "$EM/py/procs.py" "$row" 1 -- "$PY" "$FE/py/bench.py" "$W/g5.bin" "$W/jws.bin" >> "$OUT/procs.txt" || true
  "$PY" "$EM/py/procs.py" "$row" 4 -- "$PY" "$FE/py/bench.py" "$W/g5.bin" "$W/jws.bin" >> "$OUT/procs.txt" || true
  "$PY" "$FE/py/threads.py" "$W/g5.bin" "$W/jws.bin" 5 1 2 4 | tail -1 >> "$OUT/threads.txt" || true
done
"$PY" - "$OUT" >> "$OUT/summary.txt" <<'PYEOF'
import json, os, sys
out = sys.argv[1]
for l in open(os.path.join(out, "startup.txt")):
    r = json.loads(l)
    print(f"first result  {r['label']:<24} cpus {r['cpus']:<3} median {r.get('first_result_ms_median')} ms  rss {r.get('median_run', {}).get('hwm_kb')} KB  {r.get('error', r.get('hang', ''))}")
for l in open(os.path.join(out, "procs.txt")):
    r = json.loads(l)
    if "g5" in r:
        print(f"throughput    {r['label']:<24} procs {r['cpus']}  g5/s {r['g5']['per_s_mean']}  JWS/s {r['jws']['per_s_mean']}  peak RSS {r['hwm_kb_max']} KB  not verified {r['g5']['not_verified'] + r['jws']['not_verified']}")
    else:
        print(f"throughput    {r['label']:<24} {r}")
PYEOF
echo "done: send back the directory $OUT (check its files for local paths before sharing them)"
