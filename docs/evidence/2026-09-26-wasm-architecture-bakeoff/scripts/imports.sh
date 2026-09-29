#!/bin/sh
# Every host import of every artifact (results/imports.txt), plus the
# capability markers in the generated JS glue.
set -eu
: "${REPO:?}" "${SCRATCH:?}"
imp() { wasm-tools print "$1" | grep "(import" | sed -E 's/^ *\(import "([^"]+)" "([^"]+)".*/\1.\2/' | tr '\n' ' '; echo; }
echo "# $(date +%F), wasm-tools 1.259.0"
for n in rust-uu rust-uu-noseam rust-w1 rust-w1h rust-c awslc-w1 awslc-w1h awslc-c ossl-w1 ossl-w1h ossl-c; do
  printf '%-16s %3s imports: ' "$n" "$(wasm-tools print "$SCRATCH/art/$n.wasm" | grep -c '(import')"; imp "$SCRATCH/art/$n.wasm"
done
echo; echo "## Emscripten builds: wasm imports (minified names) -> JS functions in the glue"
for n in awslc-em ossl-em libressl-em; do
  printf '%-12s %s\n' "$n" "$(grep -o 'wasmImports={[^}]*}' "$SCRATCH/em/$n/aprv-em.mjs")"
done
echo; echo "## Emscripten glue capability markers (grep counts)"
for n in awslc-em ossl-em libressl-em; do
  g="$SCRATCH/em/$n/aprv-em.mjs"
  printf '%-12s process.env:%s  WebSocket:%s  SOCKFS:%s  MEMFS:%s  NODEFS:%s  fetch(:%s  XMLHttpRequest:%s\n' "$n" \
    "$(grep -o 'process\.env' "$g" | wc -l)" "$(grep -o 'WebSocket' "$g" | wc -l)" "$(grep -o 'SOCKFS' "$g" | wc -l)" \
    "$(grep -o 'MEMFS' "$g" | wc -l)" "$(grep -o 'NODEFS' "$g" | wc -l)" "$(grep -o 'fetch(' "$g" | wc -l)" "$(grep -o 'XMLHttpRequest' "$g" | wc -l)"
done
echo; echo "## Components: WIT world imports"
for c in awslc-min ossl-wasi awslc-p2 awslc-p3; do
  printf '%-10s %s\n' "$c" "$(wasm-tools component wit "$SCRATCH/comp/$c.component.wasm" | sed -n '/^world root/,/^}/p' | grep import | sed 's/^ *import //' | tr '\n' ' ')"
done
echo; echo "## jco glue capability markers"
for c in awslc-min-jco ossl-wasi-jco; do
  g="$SCRATCH/comp/$c/aprv.js"
  printf '%-14s process.env:%s  WebSocket:%s  fetch(:%s  node:fs:%s  preview2-shim:%s\n' "$c" \
    "$(grep -o 'process\.env' "$g" | wc -l)" "$(grep -o 'WebSocket' "$g" | wc -l)" "$(grep -o 'fetch(' "$g" | wc -l)" \
    "$(grep -o "node:fs" "$g" | wc -l)" "$(grep -o 'preview2-shim' "$g" | wc -l)"
done
