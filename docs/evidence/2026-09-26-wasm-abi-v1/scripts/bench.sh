#!/bin/sh
# Spike only (2026-09-26, ABI v1). No-regression check against round 6
# (docs/evidence/2026-09-26-wasm-speed, module "base" = round 4's new-c):
# Node, three runs of 1,000 timed calls after 200 warm-up, g5 (op 1) and
# the shared-sandbox JWS (op 258); then Endive JDK 21 ByteArrayMemory
# scaling at 1/2/4 threads (scripts/endive.sh scale). One run at a time.
#   bench.sh > results/bench.txt   (after node.sh and endive.sh build)
set -eu
. "$(dirname "$0")/env.sh"
echo "# $(date -u +%F), $(uname -m), $(nproc) cores; load average before: $(cut -d' ' -f1-3 /proc/loadavg)"
for id in receipt/verify-genuine-sandbox-g5-against-apple-roots transaction/verify-shared-sandbox; do
  for run in 1 2 3; do
    node "$AB/js/bench.mjs" "$MOD" "$S/calls/cases.jsonl" "$id" 1000
  done
done
sh "$AB/scripts/endive.sh" scale
