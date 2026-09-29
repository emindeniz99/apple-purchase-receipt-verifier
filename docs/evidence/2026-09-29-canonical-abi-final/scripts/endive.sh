#!/bin/sh
# Spike only (2026-09-29, round 13). Endive 1.1.0 compiles the canonical-ABI
# core module and, for the start-up comparison only, the ABI v1 module at
# build time (hosts/endive/pom.xml, ABI v1's plugin setup), offline from the
# round-5 Maven cache; everything runs on JDK 21.
#   endive.sh build            mvn package into $S/endive-work
#   endive.sh java             print the java command line for corpus.sh
#   endive.sh tests            the ABI tests (Tests.java)
#   endive.sh startup [RUNS]   RUNS (7) fresh JVMs per module, interleaved, taskset -c 0
set -eu
. "$(dirname "$0")/env.sh"
unset JAVA_TOOL_OPTIONS
JDK=${JDK21:-/usr/lib/jvm/java-21-openjdk-amd64}
M2="$SCRATCH/endive/m2-build"
WK="$S/endive-work"
CP="$WK/target/classes:$M2/run/endive/runtime/1.1.0/runtime-1.1.0.jar:$M2/run/endive/wasm/1.1.0/wasm-1.1.0.jar"
case "$1" in
build)
  rm -rf "$WK"; cp -r "$FE/hosts/endive" "$WK"
  # ABI v1's minimal JSON reader/writer, package renamed (not copied into this folder).
  sed 's/^package spike.aprv.abi;/package spike.aprv.cabi;/' "$AB/endive/src/main/java/spike/aprv/abi/Json.java" > "$WK/src/main/java/spike/aprv/cabi/Json.java"
  start=$(date +%s%N)
  (cd "$WK" && JAVA_HOME="$JDK" mvn -B -o -q -Dmaven.repo.local="$M2" -Dcabi.wasm="$MOD" -Dv1.wasm="$V1" package) > "$S/run/endive-build.log" 2>&1 \
    || { tail -40 "$S/run/endive-build.log"; exit 1; }
  echo "endive build: $(( ($(date +%s%N) - start) / 1000000 )) ms for mvn package (offline, both modules); jar $(wc -c < "$WK/target/aprv-cabi-endive-0.0.0-spike.jar") bytes; $(basename "$MOD") sha256 $(sha256sum "$MOD" | cut -c1-64); $("$JDK/bin/java" -version 2>&1 | head -1)"
  ;;
java) echo "$JDK/bin/java -cp $CP" ;;
tests) "$JDK/bin/java" -cp "$CP" spike.aprv.cabi.Tests "$S/calls/cases.jsonl" ;;
startup)
  echo "# Endive start-up, $(date -u +%F), taskset -c 0, fresh JVM per run, load before: $(cut -d' ' -f1-3 /proc/loadavg)"
  for i in $(seq "${2:-7}"); do
    for m in v1 cabi; do
      t=$(date +%s%N)
      o=$(taskset -c 0 "$JDK/bin/java" -cp "$CP" spike.aprv.cabi.StartBench $m "$S/calls/cases.jsonl")
      echo "${o%\}},\"process_wall_ms\":$(( ($(date +%s%N) - t) / 1000000 ))}"
    done
  done ;;
esac
