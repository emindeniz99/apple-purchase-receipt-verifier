#!/bin/sh
# G1 in one command: put a module in place, run the suite, run the corpora
# against the module's reference rows, measure. Run again for a new module.
#   REPO=... SCRATCH=... G1=<folder with aprv.wasm, calls/, rows/, same.py> sh g1.sh
# The module goes to the ignored path in the package (never committed) and its
# pin is refreshed; commit the pin. Results go to $S/g1-results.
set -eu
. "$(dirname "$0")/env.sh"
: "${G1:?the folder with aprv.wasm, calls/, rows/ and same.py}"
HERE="$(dirname "$0")"
OUT="$S/g1-results"; mkdir -p "$OUT"
W="$REPO/dotnet/src/ApplePurchaseReceiptVerifier/wasm"
cp "$G1/aprv.wasm" "$W/aprv.wasm"
(cd "$W" && sha256sum aprv.wasm > aprv.wasm.sha256 && cat aprv.wasm.sha256) | tee "$OUT/module.txt"
wc -c < "$W/aprv.wasm" >> "$OUT/module.txt"
for tfm in net10.0 net8.0; do
  dotnet build -c Release -f $tfm "$REPO/dotnet/tests/ApplePurchaseReceiptVerifier.Tests" > "$OUT/build-$tfm.log" 2>&1 \
    || { grep -E ' error ' "$OUT/build-$tfm.log" | head; exit 1; }
  "$REPO/dotnet/tests/ApplePurchaseReceiptVerifier.Tests/bin/Release/$tfm/ApplePurchaseReceiptVerifier.Tests" > "$OUT/tests-$tfm.log" 2>&1 || true
  echo "tests $tfm: $(grep -E '^  (total|failed|succeeded|skipped):' "$OUT/tests-$tfm.log" | tr -s ' \n' ' ')"
done
for tfm in net10.0 net8.0; do
  F="$REPO/dotnet/tests/ApplePurchaseReceiptVerifier.Tests.Floor"
  dotnet build -c Release -f $tfm "$F" > "$OUT/build-floor-$tfm.log" 2>&1 || { grep -E ' error ' "$OUT/build-floor-$tfm.log" | head; exit 1; }
  echo "floor $tfm: $("$F/bin/Release/$tfm/ApplePurchaseReceiptVerifier.Tests.Floor" 2>&1 | grep -E '^  (total|failed|succeeded):' | tr -s ' \n' ' ')"
done
sh "$HERE/corpus.sh" | tee "$OUT/corpus.txt"
sh "$HERE/speed.sh" | tee "$OUT/speed.txt"
