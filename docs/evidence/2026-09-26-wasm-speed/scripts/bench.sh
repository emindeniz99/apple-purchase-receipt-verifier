#!/bin/sh
# Spike only (2026-09-26). Round 5's method, per candidate module:
#   bench.sh node <name>     Node 22, the bake-off's js/run.mjs --bench: 1,000 timed calls after 200 warm-up
#   bench.sh endive <name>   Endive 1.1.0 build-time compiler (round 5's lib, rebuilt on this module),
#                            JDK 21 and 25, default memory and ByteArrayMemory: 1,000 warm-up, 500 timed
# Rows: the genuine g5 receipt and the shared-sandbox JWS. One run at a time.
set -eu
. "$(dirname "$0")/env.sh"
: "${CORPORA:?}"
IDS="receipt/verify-genuine-sandbox-g5-against-apple-roots transaction/verify-shared-sandbox"
N="$2"; W="$ART/$N.wasm"
case "$1" in
node)
  for id in $IDS; do
    printf '%s node %s\n' "$N" "$(node "$PREV/js/run.mjs" --host trap "$W" "$CORPORA/cases.jsonl" --bench "$id" 1000 2>/dev/null)"
  done ;;
endive)
  E="$SCRATCH/endive"
  WASM="$W" "$R5/scripts/build.sh" lib > "$S/endive-$N.log" 2>&1 || { echo "$N endive: BUILD FAILED"; tail -20 "$S/endive-$N.log"; exit 1; }
  unset JAVA_TOOL_OPTIONS
  CP="$E/work/consumer/target/classes:$E/work/lib/target/aprv-endive-0.0.0-spike.jar:$E/m2-consumer/run/endive/runtime/1.1.0/runtime-1.1.0.jar:$E/m2-consumer/run/endive/wasm/1.1.0/wasm-1.1.0.jar"
  for V in 21 25; do
    case "$V" in 21) J="$JDK21" ;; 25) J="$JDK25" ;; esac
    for M in default bytearray; do
      for id in $IDS; do
        printf '%s endive jdk%s memory=%s %s\n' "$N" "$V" "$M" "$("$J/bin/java" -Dspike.aprv.memory=$M -cp "$CP" spike.consumer.Main bench "$CORPORA/cases.jsonl" "$id" 1000 500)"
      done
    done
  done ;;
esac
