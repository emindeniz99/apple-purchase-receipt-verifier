#!/bin/sh
# Spike only (2026-09-26). Runs the clean consumer (built by build.sh
# consumer) on one JDK. Every command uses only the consumer's classpath:
# its own classes plus what Maven resolved for it (cp.txt).
#
#   run.sh parity  <8|11|17|21|25> [corpora]   rows for each corpus (default: the
#                                          four 1,179-row corpora; "fuzz" for the
#                                          5,000 mutants), compared with round 4's
#                                          native baseline (same.py, the verdict),
#                                          and byte for byte (exact.py) with round
#                                          4's native C ABI build of the same source
#                                          (new) and its Node rows of the same .wasm
#   run.sh java    <8|11|17|21|25> <Main args...>  any other consumer mode
# JOPTS adds JVM options (e.g. JOPTS=-Dspike.aprv.memory=bytearray); TAG
# names the run's row files and parity lines (default jdk<V>).
set -eu
. "$(dirname "$0")/env.sh"
MODE="$1"; V="$2"; shift 2
case "$V" in 8) J="$JDK8" ;; 11) J="$JDK11" ;; 17) J="$JDK17" ;; 21) J="$JDK21" ;; 25) J="$JDK25" ;; *) J="$V" ;; esac
CW="$E/work/consumer"
CP="$CW/target/classes:$(cat "$CW/cp.txt")"
case "$MODE" in
parity)
  LIST="${*:-cases hostile algorithms substrate}"
  for c in $LIST; do
    OUT="$E/run/${TAG:-jdk$V}-$c.jsonl"
    "$J/bin/java" ${JOPTS:-} -cp "$CP" spike.consumer.Main corpus "$CORPORA/$c.jsonl" > "$OUT" 2> "$OUT.err"
    s=$(python3 "$SPIKE/py/same.py" "$CORPORA/$c.jsonl" "$BASE-$c.jsonl" "$OUT" | tail -1)
    n=$(python3 "$EV/py/exact.py" "$NATIVENEW-$c.jsonl" "$OUT")
    if [ -f "$NODEROWS-$c.jsonl" ]; then x=$(python3 "$EV/py/exact.py" "$NODEROWS-$c.jsonl" "$OUT"); else x="none for this corpus"; fi
    echo "${TAG:-jdk$V} $c: same.py vs native base: $s | exact vs native new: $n | exact vs Node new-c: $x | $(grep -v JAVA_TOOL "$OUT.err" | tail -1)" | tee -a "$EV/results/parity.txt"
  done ;;
java)
  "$J/bin/java" ${JOPTS:-} -cp "$CP" spike.consumer.Main "$@" ;;
*) echo "usage"; exit 2 ;;
esac
