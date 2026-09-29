#!/bin/sh
# Imports and sizes of this round's artifacts (wasm-tools 1.259.0, gzip -9).
#   scripts/inspect.sh > results/imports-sizes.txt
set -eu
. "$(dirname "$0")/env.sh"
A="$C/art"
echo "# Final module imports (wasm-tools print)"
for m in new-c any-c; do
  echo "$m.wasm: $(wasm-tools print "$A/$m.wasm" | grep '(import ' | sed -E 's/.*\(import "([^"]*)" "([^"]*)".*/\1.\2/' | tr '\n' ' ')"
done
echo "# payload.c in the module: item functions present (wasm-tools print | grep)"
for m in new-c any-c; do
  echo "$m.wasm: APRV_RECEIPT_PAYLOAD_it $(wasm-tools print "$A/$m.wasm" | grep -c 'APRV_RECEIPT_PAYLOAD_it' || true), DISPLAYTEXT_it $(wasm-tools print "$A/$m.wasm" | grep -c 'DISPLAYTEXT_it' || true), ASN1_SET_ANY_it $(wasm-tools print "$A/$m.wasm" | grep -c 'ASN1_SET_ANY_it' || true)"
done
echo "# bytes. raw | after wasm-tools strip | strip + gzip -9. Round 3's cms-c.wasm (CMS + asn1.rs payload): 3,000,116 raw, 986,315 strip+gz."
for m in new-c any-c; do
  t="$C/strip.tmp"; wasm-tools strip "$A/$m.wasm" -o "$t"
  echo "$m.wasm raw $(stat -c %s "$A/$m.wasm") | strip $(stat -c %s "$t") | strip+gz $(gzip -9c "$t" | wc -c)"; rm -f "$t"
done
for d in base new any; do
  f="$A/$d/libapple_purchase_receipt_verifier_ffi.so"
  echo "native C ABI ($d) raw $(stat -c %s "$f") | stripped+gz $(strip -o "$C/so.tmp" "$f" && gzip -9c "$C/so.tmp" | wc -c)"; rm -f "$C/so.tmp"
done
