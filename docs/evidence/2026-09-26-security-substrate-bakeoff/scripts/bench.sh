#!/bin/sh
# Same method as the Native Image spike (its c/harness.c, unchanged):
# single-thread latency after a 3 s warm-up (2,000 timed calls), then
# throughput at 1, 4 and 16 threads for 8 s, every output compared with the
# first. Inputs: the genuine g5 sandbox receipt, the generated transaction.
#
#   REPO=... SCRATCH=... scripts/bench.sh <variant>...  > results/bench.jsonl
set -eu
: "${REPO:?}" "${SCRATCH:?}"
PREV="$REPO/docs/evidence/2026-09-25-java-native-image-spike"
F="$REPO/fixtures"
for v in "$@"; do
  LIB="$SCRATCH/target-$v/release"
  gcc -O2 -DUSE_RUST -I"$REPO/rust/ffi/include" "$PREV/c/harness.c" -L"$LIB" \
    -lapple_purchase_receipt_verifier_ffi -Wl,-rpath,"$LIB" -lpthread -o "$SCRATCH/h-$v"
  for op in receipt jws endpoint; do
    for t in 1 4 16; do
      line=$(env -i "$SCRATCH/h-$v" bench "$F/public-receipts/receipt-sandbox-g5.b64" \
        "$F/generated/transaction.jws" "$F/generated/jws-root.der" "$op" "$t" 8)
      echo "{\"variant\":\"$v\",${line#\{}"
    done
  done
done
