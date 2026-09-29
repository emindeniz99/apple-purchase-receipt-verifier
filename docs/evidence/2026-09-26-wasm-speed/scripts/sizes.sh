#!/bin/sh
# Spike only (2026-09-26). Size of each candidate module: raw, stripped of
# custom sections (wasm-tools strip), and stripped + gzip -9; plus its code,
# data and name sections.
#   sizes.sh > results/sizes.txt
set -eu
. "$(dirname "$0")/env.sh"
echo "# name | raw | wasm-tools strip (default: drops producers and target_features, keeps name) | the same + gzip -9 | code | data | name section | sha256 (16)"
for n in r4-repro base nistp o2 nopic rust2 base-wo2 base-wo3; do
  W="$ART/$n.wasm"
  wasm-tools strip "$W" -o "$S/strip.wasm"
  sec() { wasm-tools objdump "$W" | awk -F'|' -v k="$1" '$1 ~ k { gsub(/[^0-9]/, "", $3); print $3 }' | head -1; }
  echo "$n | $(wc -c < "$W") | $(wc -c < "$S/strip.wasm") | $(gzip -9c "$S/strip.wasm" | wc -c) | $(sec '^ *code') | $(sec '^ *data  ') | $(sec 'name') | $(sha256sum "$W" | cut -c1-16)"
done
rm -f "$S/strip.wasm"
echo "# r4-repro is round 4's recipe on round 4's OpenSSL install: byte-identical to \$SCRATCH/asn1/art/new-c.wasm ($(sha256sum "$REFWASM" | cut -c1-16))"
