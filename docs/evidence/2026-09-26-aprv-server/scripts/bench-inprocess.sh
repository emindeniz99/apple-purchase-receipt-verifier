#!/bin/sh
# Spike only. The lifecycles without HTTP: `aprv bench` (spike feature) times
# invoke() in-process. fresh-pooling = fresh instances from Wasmtime's
# pooling allocator, to see whether allocation is the cost of `fresh`.
#   bench-inprocess.sh > results/bench-inprocess.txt
set -eu
. "$(dirname "$0")/env.sh"
B="$SV/bin/aprv-spike"
echo "# $(date -u +%F) $(uname -m), $(nproc) vCPUs; load before: $(cut -d' ' -f1-3 /proc/loadavg)"
for lc in pool fresh fresh-pooling; do "$B" bench 1 "$SV/in/g5.b64" $lc 1 300; done
for lc in pool fresh; do "$B" bench 258 "$SV/in/jws-envelope.bin" $lc 1 200; done
for t in 2 4; do for lc in pool fresh; do "$B" bench 1 "$SV/in/g5.b64" $lc $t 300; done; done
