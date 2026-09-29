#!/bin/sh
# Spike only (2026-09-26). Candidate 1 (ByteArrayMemory) through the gate:
# round 5's consumer on the library built from round 4's new-c.wasm, JDK 21
# with -Dspike.aprv.memory=bytearray, all 1,179 rows and the 5,000 mutants,
# byte-compared with round 4's native rows (round 5's py/exact.py).
# Run after scale.sh (which rebuilds the library on $REFWASM).
#   endive-parity.sh > results/endive-parity.txt
set -eu
. "$(dirname "$0")/env.sh"
: "${CORPORA:?}" "${JDK21:?}"
unset JAVA_TOOL_OPTIONS
E="$SCRATCH/endive"
CP="$E/work/consumer/target/classes:$E/work/lib/target/aprv-endive-0.0.0-spike.jar:$E/m2-consumer/run/endive/runtime/1.1.0/runtime-1.1.0.jar:$E/m2-consumer/run/endive/wasm/1.1.0/wasm-1.1.0.jar"
for c in cases hostile algorithms substrate fuzz; do
  OUT="$S/run/endive21-bytearray-$c.jsonl"
  "$JDK21/bin/java" -Dspike.aprv.memory=bytearray -cp "$CP" spike.consumer.Main corpus "$CORPORA/$c.jsonl" > "$OUT" 2> "$OUT.err"
  echo "jdk21 bytearray $c: native $(python3 "$R5/py/exact.py" "$NATIVENEW-$c.jsonl" "$OUT") | $(tail -1 "$OUT.err")"
done
