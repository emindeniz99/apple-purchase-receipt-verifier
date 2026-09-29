#!/bin/sh
# Spike only (2026-09-26). Orientation numbers, not a selection criterion.
#   bench.sh jvm   > results/bench.txt     warm latency, JDK 17/21/25 x Endive's two memory implementations
#   bench.sh node >> results/bench.txt     the same .wasm on Node (the bake-off's run.mjs --bench), same machine
#   bench.sh instances >> results/bench.txt  time to create 10 instances in one JVM, JDK 17/21/25
#   bench.sh build                         Endive compile goal duration (generate-sources minus a bare validate)
#   bench.sh jfr                           JFR profile of the JWS row (JDK 21, ByteArrayMemory) -> results/profile-jws.txt
set -eu
. "$(dirname "$0")/env.sh"
CW="$E/work/consumer"
CP="$CW/target/classes:$(cat "$CW/cp.txt")"
IDS="receipt/verify-genuine-sandbox-g5-against-apple-roots transaction/verify-shared-sandbox"
WARM=${WARM:-1000}; N=${N:-500}
case "$1" in
jvm)
  unset JAVA_TOOL_OPTIONS
  echo "# $(date -u +%F) $(uname -m), $(nproc) cores. One thread, one instance. warm=$WARM then n=$N timed calls of the same row."
  echo "# init_ms: first AprvWasm (class loading + instantiation + _initialize + aprv_init); first_call_ms: first verification (includes JIT warm-up)."
  for V in 17 21 25; do
    case "$V" in 17) J="$JDK17" ;; 21) J="$JDK21" ;; 25) J="$JDK25" ;; esac
    for M in default bytearray; do
      for id in $IDS; do
        printf 'jdk%s memory=%s %s\n' "$V" "$M" "$("$J/bin/java" -Dspike.aprv.memory=$M -cp "$CP" spike.consumer.Main bench "$CORPORA/cases.jsonl" "$id" "$WARM" "$N")"
      done
    done
  done ;;
node)
  echo "# Node $(node --version), the bake-off's js/run.mjs --host trap --bench (1000 calls after min(200, n) warm-up) on the same new-c.wasm"
  for id in $IDS; do
    printf 'node %s\n' "$(node "$PREV/js/run.mjs" --host trap "$WASM" "$CORPORA/cases.jsonl" --bench "$id" 1000 2>/dev/null)"
  done ;;
instances)
  unset JAVA_TOOL_OPTIONS
  echo "# instance creation (AprvWasm.create: instantiate + _initialize + aprv_init), 10 in a row in one JVM; the first also loads the classes and parses .meta"
  for V in 17 21 25; do
    case "$V" in 17) J="$JDK17" ;; 21) J="$JDK21" ;; 25) J="$JDK25" ;; esac
    printf 'jdk%s %s\n' "$V" "$("$J/bin/java" -cp "$CP" spike.consumer.Main instances 10)"
  done ;;
build)
  rm -rf "$E/work/lib-t"; cp -r "$EV/lib" "$E/work/lib-t"
  for i in 1 2 3; do
    a=$(date +%s%N); (cd "$E/work/lib-t" && JAVA_HOME="$JDK17" mvn -B -q -o -Dmaven.repo.local="$E/m2-build" -Daprv.wasm="$WASM" validate) >/dev/null 2>&1; b=$(date +%s%N)
    (cd "$E/work/lib-t" && JAVA_HOME="$JDK17" mvn -B -q -o -Dmaven.repo.local="$E/m2-build" -Daprv.wasm="$WASM" generate-sources) >/dev/null 2>&1; c=$(date +%s%N)
    echo "run $i: mvn validate $(( (b - a) / 1000000 )) ms, mvn generate-sources (endive:compile) $(( (c - b) / 1000000 )) ms, difference $(( (c - b - (b - a)) / 1000000 )) ms"
  done
  echo "generated: $(find "$E/work/lib-t/target/generated-resources" -name '*.class' | wc -l) classes, $(du -sk "$E/work/lib-t/target/generated-resources" | cut -f1) KiB"
  ;;
jfr)
  unset JAVA_TOOL_OPTIONS
  "$JDK21/bin/java" -Dspike.aprv.memory=bytearray -XX:StartFlightRecording=filename="$E/work/jws.jfr",settings=profile -cp "$CP" \
    spike.consumer.Main bench "$CORPORA/cases.jsonl" transaction/verify-shared-sandbox 500 500 > /dev/null 2>&1
  "$JDK21/bin/jfr" print --stack-depth 64 --events jdk.ExecutionSample "$E/work/jws.jfr" > "$E/work/jws-samples.txt"
  { echo "# JFR (settings=profile), JDK 21, ByteArrayMemory, 1,000 verifications of transaction/verify-shared-sandbox"; python3 "$EV/py/jfr_top.py" "$E/work/jws-samples.txt" 12
    echo "## one full sample, as a stack trace shows it (method names from the wasm name section)"
    grep -m1 -A26 'bn_mul_comba8' "$E/work/jws-samples.txt" | sed 's/^ *//'; } ;;
esac
