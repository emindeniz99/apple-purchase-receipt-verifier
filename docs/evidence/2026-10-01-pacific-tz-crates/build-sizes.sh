#!/usr/bin/env bash
# Builds every variant under sizes/ for wasm32-wasip1 (release = the repo's
# wasm profile + strip) into $SCRATCH/<variant> and prints the .wasm size
# and the Cargo.lock package count. OPT overrides opt-level (e.g. OPT=s).
set -u
S="$(dirname "$(readlink -f "$0")")"
: "${SCRATCH:?set SCRATCH to a directory outside the repository}"
for d in "$S"/sizes/*/; do
  n="$(basename "$d")"
  t="$SCRATCH/$n"
  mkdir -p "$t"
  extra=()
  [[ "$n" == chrono-tz-filtered || "$n" == chrono-tz-filtered-dyn ]] && extra=(env CHRONO_TZ_TIMEZONE_FILTER='^America/Los_Angeles$')
  "${extra[@]}" env ${OPT:+CARGO_PROFILE_RELEASE_OPT_LEVEL=$OPT} \
    cargo build -q --release --target wasm32-wasip1 --manifest-path "$d/Cargo.toml" --target-dir "$t/target" 2> "$t/build.log" \
    || { echo "$n BUILD FAILED"; tail -20 "$t/build.log"; continue; }
  w="$t/target/wasm32-wasip1/release/tzspike-$n.wasm"
  pk="$(grep -c '^\[\[package\]\]' "$d/Cargo.lock")"
  printf '%-20s %9d bytes  gzip %7d  lock-packages %d\n' "$n" "$(stat -c %s "$w")" "$(gzip -9c "$w" | wc -c)" "$pk"
done
