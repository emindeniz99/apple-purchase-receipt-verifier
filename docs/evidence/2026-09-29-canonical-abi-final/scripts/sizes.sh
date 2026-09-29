#!/bin/sh
# Spike only (2026-09-29, round 13). Module sizes against ABI v1: as built,
# with every custom section stripped (wasm-tools strip --all: name,
# producers, component-type, target_features), and gzip -9 of both; then
# the code and data sections. Temporary files go to $S/sizes and are removed.
#   sizes.sh > results/sizes.txt
set -eu
. "$(dirname "$0")/env.sh"
t="$S/sizes"; mkdir -p "$t"
gz() { gzip -9 -c "$1" | wc -c | tr -d ' '; }
base=""
echo "# $(date -u +%F), wasm-tools $(wasm-tools --version | cut -d' ' -f2), gzip -9"
printf '%-34s %10s %10s %10s %10s  %s\n' module bytes gzip stripped "gz(strip)" "delta stripped vs ABI v1"
for m in "$V1" "$MOD" "$COMP"; do
  wasm-tools strip --all "$m" -o "$t/s.wasm"
  s=$(wc -c < "$t/s.wasm" | tr -d ' ')
  [ -n "$base" ] || base=$s
  printf '%-34s %10s %10s %10s %10s  %+d (%+.2f%%)\n' "$(basename "$m")" "$(wc -c < "$m" | tr -d ' ')" "$(gz "$m")" "$s" "$(gz "$t/s.wasm")" $((s - base)) "$(echo "($s - $base) * 100 / $base" | bc -l)"
done
rm -rf "$t"
echo "## code and data sections (bytes | functions or segments)"
for m in "$V1" "$MOD"; do
  echo "$(basename "$m"): $(wasm-tools objdump "$m" | grep -E '^ *(code|data) ' | sed -E 's/ +/ /g; s/\| 0x[0-9a-f]+ - 0x[0-9a-f]+ //' | tr '\n' ';')"
done
