#!/bin/sh
# Spike only (2026-09-26). Throughput scaling on Endive: one instance per
# thread, 1, 2 and 4 threads, warm, g5 receipt and shared-sandbox JWS,
# JDK 21; round 4's module (the one kept) with the default memory and with
# ByteArrayMemory. Uses round 5's library (rebuilt on round 4's new-c.wasm)
# and consumer classes, plus java/spike/consumer/Scale.java from this folder.
#   scale.sh > results/scaling.txt
set -eu
. "$(dirname "$0")/env.sh"
: "${CORPORA:?}" "${JDK21:?}"
E="$SCRATCH/endive"
WASM="$REFWASM" "$R5/scripts/build.sh" lib > "$S/endive-scale.log" 2>&1
unset JAVA_TOOL_OPTIONS
rm -rf "$S/scale-classes"; mkdir -p "$S/scale-classes"
LIBCP="$E/work/lib/target/aprv-endive-0.0.0-spike.jar:$E/m2-consumer/run/endive/runtime/1.1.0/runtime-1.1.0.jar:$E/m2-consumer/run/endive/wasm/1.1.0/wasm-1.1.0.jar"
"$JDK21/bin/javac" --release 11 -d "$S/scale-classes" -cp "$E/work/consumer/target/classes:$LIBCP" "$SP/java/spike/consumer/Scale.java"
CP="$E/work/consumer/target/classes:$S/scale-classes:$LIBCP"
echo "# $(date -u +%F), $(uname -m), $(nproc) cores ($(grep -m1 'model name' /proc/cpuinfo | sed 's/.*: //')), JDK 21. One instance per thread; warm then timed, per thread."
echo "# load average before: $(cut -d' ' -f1-3 /proc/loadavg); other busy processes: $(ps -eo pcpu,comm --sort=-pcpu | awk 'NR>1 && $1 > 5 {print $2"("$1"%)"}' | tr '\n' ' ')"
for M in default bytearray; do
  for id in receipt/verify-genuine-sandbox-g5-against-apple-roots transaction/verify-shared-sandbox; do
    case "$id" in receipt*) W=600; N=600 ;; *) W=300; N=300 ;; esac
    for T in 1 2 4; do
      echo "$("$JDK21/bin/java" -Dspike.aprv.memory=$M -cp "$CP" spike.consumer.Scale "$CORPORA/cases.jsonl" "$id" "$T" "$W" "$N")"
    done
  done
done
