#!/bin/sh
# Spike only (2026-09-27, round 11). Builds the two Wasmi shared libraries
# for the Python facades, each from a clean target directory, one at a time:
#   $S/lib/libaprv_wasmi.so      ../wasmi-cdylib (APRV-specific C ABI over safe Wasmi 2.0.0 Rust APIs)
#   $S/lib/xc/libaprv_wasmi.so   the same with Wasmi's `extra-checks` feature
#   $S/lib/libwasmi.so           ../wasmi-capi (Wasmi's official C API, wasmi_c_api_impl 2.0.0)
# and prints sizes, exported surface, the cdylib's `unsafe` count and the
# resolved crate versions.
#   build.sh > results/build.txt
set -eu
. "$(dirname "$0")/env.sh"
echo "# build.sh, $(date -u +%F); $(rustc --version); $(cargo --version)"
one() { # label manifest features artifact dest
  rm -rf "$CARGO_TARGET_DIR/release"
  start=$(date +%s)
  cargo build -q --release --locked --manifest-path "$2" ${3:+--features "$3"} > "$S/build-$1.log" 2>&1 || { tail -30 "$S/build-$1.log"; exit 1; }
  secs=$(( $(date +%s) - start ))
  mkdir -p "$(dirname "$5")"
  cp "$CARGO_TARGET_DIR/release/$4" "$5.new"; strip "$5.new"; mv "$5.new" "$5"
  echo "$1: clean build ${secs} s; $4 $(wc -c < "$CARGO_TARGET_DIR/release/$4") bytes as built, $(wc -c < "$5") stripped, gzip -9 $(gzip -9c "$5" | wc -c); exported functions: $(nm -D --defined-only "$5" | grep -c ' T '); NEEDED: $(readelf -d "$5" | grep NEEDED | grep -o '\[.*\]' | tr '\n' ' ')"
}
one aprv-wasmi "$FE/wasmi-cdylib/Cargo.toml" "" libaprv_wasmi.so "$S/lib/libaprv_wasmi.so"
one aprv-wasmi-extra-checks "$FE/wasmi-cdylib/Cargo.toml" extra-checks libaprv_wasmi.so "$S/lib/xc/libaprv_wasmi.so"
one wasmi-c-api "$FE/wasmi-capi/Cargo.toml" "" libwasmi.so "$S/lib/libwasmi.so"
rm -rf "$CARGO_TARGET_DIR/release"
echo "aprv-wasmi exports: $(nm -D --defined-only "$S/lib/libaprv_wasmi.so" | awk '$2 == "T" {print $3}' | sort | tr '\n' ' ')"
echo "wasmi-c-api exports: $(nm -D --defined-only "$S/lib/libwasmi.so" | awk '$2 == "T" {print $3}' | grep -c '^wasm_') wasm_* and $(nm -D --defined-only "$S/lib/libwasmi.so" | awk '$2 == "T" {print $3}' | grep -c '^wasmi_') wasmi_* functions"
echo "wasmi-cdylib/src/lib.rs: $(wc -l < "$FE/wasmi-cdylib/src/lib.rs") lines, $(grep -c 'unsafe {' "$FE/wasmi-cdylib/src/lib.rs") unsafe blocks, $(grep -c '#\[no_mangle\]' "$FE/wasmi-cdylib/src/lib.rs") extern \"C\" entry points"
for lock in "$FE/wasmi-cdylib/Cargo.lock" "$FE/wasmi-capi/Cargo.lock"; do
  echo "$(basename "$(dirname "$lock")") Cargo.lock: $(python3 - "$lock" <<'PYEOF'
import re, sys
text = open(sys.argv[1]).read()
pk = dict(re.findall(r'\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"', text))
print(", ".join(f"{n} {pk[n]}" for n in sorted(pk) if n.startswith(("wasmi", "wasmparser", "spin", "getrandom"))))
PYEOF
)"
done
