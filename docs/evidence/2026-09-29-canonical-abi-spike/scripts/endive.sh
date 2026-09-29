#!/bin/sh
# Spike only (2026-09-29, round 12). Endive 1.1.0 compiles the canonical-ABI
# core module at build time (hosts/endive/pom.xml, ABI v1's plugin setup),
# offline from the round-5 Maven cache; then the corpus on JDK 21.
#   endive.sh build MODULE     mvn package into $S/endive-work
#   endive.sh java             print the java command line for corpus.sh
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
  (cd "$WK" && JAVA_HOME="$JDK" mvn -B -o -q -Dmaven.repo.local="$M2" -Dcabi.wasm="$2" package) > "$S/run/endive-build.log" 2>&1 \
    || { tail -40 "$S/run/endive-build.log"; exit 1; }
  echo "endive build: $(( ($(date +%s%N) - start) / 1000000 )) ms for mvn package (offline); jar $(wc -c < "$WK/target/aprv-cabi-endive-0.0.0-spike.jar") bytes; module $(basename "$2") sha256 $(sha256sum "$2" | cut -c1-64); $("$JDK/bin/java" -version 2>&1 | head -1)"
  ;;
java) echo "$JDK/bin/java -cp $CP" ;;
esac
