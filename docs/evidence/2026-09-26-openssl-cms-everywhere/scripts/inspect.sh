#!/bin/sh
# Imports and sizes of every CMS artifact (wasm-tools 1.259.0, gzip -9).
#   scripts/inspect.sh imports > results/imports.txt
#   scripts/inspect.sh sizes   > results/sizes.txt
set -eu
. "$(dirname "$0")/env.sh"
A="$C/art"
case "$1" in
imports)
  echo "# Final module imports, 2026-09-26 (wasm-tools print / component wit)"
  for m in cms-c cms-w1; do
    echo "$m.wasm: $(wasm-tools print "$A/$m.wasm" | grep '(import ' | sed -E 's/.*\(import "([^"]*)" "([^"]*)".*/\1.\2/' | tr '\n' ' ')"
  done
  echo "cms-em aprv-em.wasm (module 'a', minified; the glue's wasmImports map names them): $(grep -o 'wasmImports={[^}]*}' "$A/cms-em/aprv-em.mjs")"
  echo "cms-comp.component.wasm WIT imports: $(wasm-tools component wit "$A/cms-comp.component.wasm" | grep -E '^\s*import ' | sed -E 's/^\s*import //; s/;$//' | tr '\n' ' ')"
  for f in "$A"/cms-comp-jco/aprv.core*.wasm; do
    echo "  jco $(basename "$f") imports: $(wasm-tools print "$f" | grep '(import ' | sed -E 's/.*\(import "([^"]*)" "([^"]*)".*/\1.\2/' | sort -u | tr '\n' ' ' | cut -c1-600)"
  done
  echo "# glue capability markers (grep counts)"
  for g in cms-em/aprv-em.mjs cms-em-web/aprv-em.mjs cms-comp-jco/aprv.js; do
    f="$A/$g"; echo "$g: process.env:$(grep -o 'process\.env' "$f" | wc -l) WebSocket:$(grep -o WebSocket "$f" | wc -l) SOCKFS:$(grep -o SOCKFS "$f" | wc -l) MEMFS:$(grep -o MEMFS "$f" | wc -l) fetch(:$(grep -o 'fetch(' "$f" | wc -l) node:fs:$(grep -o 'node:fs' "$f" | wc -l)"
  done
  echo "# Wasm features (py/features.py of the wasm bake-off)"
  "$SCRATCH/pyvenv/bin/python" "$PREV/py/features.py" "$A/cms-c.wasm" "$A/cms-w1.wasm" "$A/cms-em/aprv-em.wasm" "$A/cms-comp.component.wasm" 2>&1 | sed "s#$A/##g"
  ;;
sizes)
  echo "# bytes. raw | after wasm-tools strip | strip + gzip -9 | sha256. JS = glue a host loads besides the wasm."
  s() { f="$1"; t="$C/strip.tmp"; wasm-tools strip "$f" -o "$t" 2>/dev/null || cp "$f" "$t"
        echo "$2 raw $(stat -c %s "$f") | strip $(stat -c %s "$t") | strip+gz $(gzip -9c "$t" | wc -c) | sha256 $(sha256sum "$f" | cut -c1-64)"; rm -f "$t"; }
  s "$A/cms-c.wasm" cms-c.wasm
  s "$A/cms-w1.wasm" cms-w1.wasm
  s "$A/cms-em/aprv-em.wasm" cms-em/aprv-em.wasm
  echo "cms-em glue: node+web $(stat -c %s "$A/cms-em/aprv-em.mjs") B, web-only $(stat -c %s "$A/cms-em-web/aprv-em.mjs") B; the two .wasm files are identical: $(cmp -s "$A/cms-em/aprv-em.wasm" "$A/cms-em-web/aprv-em.wasm" && echo yes || echo NO)"
  s "$A/cms-comp.component.wasm" cms-comp.component.wasm
  for f in "$A"/cms-comp-jco/aprv.core*.wasm; do echo "  jco $(basename "$f") $(stat -c %s "$f")"; done
  echo "  jco aprv.js $(stat -c %s "$A/cms-comp-jco/aprv.js") B, gzip $(gzip -9c "$A/cms-comp-jco/aprv.js" | wc -c) B"
  for d in native vendored; do f="$A/$d/libapple_purchase_receipt_verifier_ffi.so"; echo "native C ABI ($d) raw $(stat -c %s "$f") | stripped+gz $(strip -o "$C/so.tmp" "$f" && gzip -9c "$C/so.tmp" | wc -c) | sha256 $(sha256sum "$f" | cut -c1-64)"; rm -f "$C/so.tmp"; done
  echo "# the PKCS7-path artifacts of the earlier rounds, for comparison: ossl-c.wasm 2,933,868; ossl-w1.wasm 2,941,778; ossl-em aprv-em.wasm 2,161,403; ossl-wasi component 2,974,268; ossl402 .so 8,428,112 (wasm bake-off results/sizes.txt)"
  ;;
esac
