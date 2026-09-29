#!/bin/sh
# Artifact size (raw, stripped, stripped+gzip -9), dynamic dependencies and
# exported symbols of each variant's C ABI library.
#   SCRATCH=... scripts/sizes.sh <variant>...
set -eu
: "${SCRATCH:?}"
printf '%-14s %10s %10s %10s  %-28s %s\n' variant raw stripped gzip needed exported
for v in "$@"; do
  so="$SCRATCH/target-$v/release/libapple_purchase_receipt_verifier_ffi.so"
  tmp="$SCRATCH/sizes-$v.so"
  cp "$so" "$tmp"; strip "$tmp"
  raw=$(stat -c %s "$so"); st=$(stat -c %s "$tmp"); gz=$(gzip -9 -c "$tmp" | wc -c)
  needed=$(readelf -d "$so" | sed -n 's/.*Shared library: \[\(.*\)\]/\1/p' | tr '\n' ' ')
  exported=$(nm -D --defined-only "$so" | awk '{print $3}' | grep -c . || true)
  foreign=$(nm -D --defined-only "$so" | awk '{print $3}' | grep -v -c '^aprv_' || true)
  printf '%-14s %10s %10s %10s  %-28s %s (non-aprv: %s)\n' "$v" "$raw" "$st" "$gz" "$needed" "$exported" "$foreign"
  rm -f "$tmp"
done
