#!/bin/sh
# Usage: core.sh OUT COREDIFF
#   OUT       where `PresignatureCost make` wrote the inputs
#   COREDIFF  the corediff binary built from
#             docs/evidence/2026-10-05-java-bc-round3/corediff/, which runs
#             the aprv.wasm committed under go/internal/wasm/ on the Go
#             package's wazero host
# Prints the core's verdict for each input, under the TestPki root and under
# Apple's roots, with the wall time of each corediff process.
set -u
OUT=$1
BIN=$2

for input in baseline tiny-attributes unsigned-attribute; do
  for roots in root.der default; do
    if [ "$roots" = default ]; then
      set -- "$OUT/$input.b64"
    else
      set -- -root "$OUT/root.der" "$OUT/$input.b64"
    fi
    start=$(date +%s%N)
    verdict=$("$BIN" "$@" | sed 's#^.*/##')
    end=$(date +%s%N)
    echo "roots $roots: $verdict ($(((end - start) / 1000000)) ms for the process, module compile included)"
  done
done
