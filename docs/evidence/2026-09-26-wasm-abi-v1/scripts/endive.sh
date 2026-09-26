#!/bin/sh
# Spike only (2026-09-26, ABI v1). Endive 1.1.0: compiles $MOD at build time
# (endive/pom.xml, round 5's plugin setup), then on JDK 21 with
# ByteArrayMemory:
#   endive.sh build   mvn package (JDK 17 runs the plugin; any JDK >= 11 does)
#   endive.sh tests   the ABI tests (endive/.../AbiTests.java)
#   endive.sh calls   the five corpora through RunCalls; every row compared
#                     byte for byte with the Node rows of scripts/node.sh
#   endive.sh scale   1, 2 and 4 threads, one instance each, g5 (op 1) and
#                     the shared-sandbox JWS (op 258)
set -eu
. "$(dirname "$0")/env.sh"
: "${CORPORA:?}" "${JDK17:?}" "${JDK21:?}"
unset JAVA_TOOL_OPTIONS
M2="$SCRATCH/endive/m2-build"
WK="$S/endive"
CP="$WK/target/classes:$M2/run/endive/runtime/1.1.0/runtime-1.1.0.jar:$M2/run/endive/wasm/1.1.0/wasm-1.1.0.jar"
J="$JDK21/bin/java"
case "$1" in
build)
  rm -rf "$WK"; cp -r "$AB/endive" "$WK"
  start=$(date +%s%N)
  (cd "$WK" && JAVA_HOME="$JDK17" mvn -B -o -Dmaven.repo.local="$M2" -Dabi.wasm="$MOD" package) > "$S/endive-build.log" 2>&1 \
    || { tail -40 "$S/endive-build.log"; exit 1; }
  echo "build: $(( ($(date +%s%N) - start) / 1000000 )) ms wall for mvn package (offline, cached plugin)"
  grep -E 'BUILD|Total time' "$S/endive-build.log"
  echo "jar: $(wc -c < "$WK/target/aprv-abi1-endive-0.0.0-spike.jar") bytes; module sha256 $(sha256sum "$MOD" | cut -c1-64)"
  ;;
tests)
  "$J" -cp "$CP" spike.aprv.abi.AbiTests "$S/calls/cases.jsonl"
  ;;
calls)
  echo "# $("$J" -version 2>&1 | head -1), Endive 1.1.0 ByteArrayMemory"
  for c in cases hostile algorithms substrate fuzz; do
    "$J" -cp "$CP" spike.aprv.abi.RunCalls "$S/calls/$c.jsonl" > "$S/run/endive-$c.jsonl" 2> "$S/run/endive-$c.err"
    python3 "$AB/py/abi_compare.py" "$CORPORA/$c.jsonl" "$NATIVENEW-$c.jsonl" "$S/calls/$c.jsonl" "$S/run/node-$c.jsonl" "$S/run/endive-$c.jsonl" \
      | sed "1s#^#$c (node): #; 2s#^other host 1#    endive#"
    echo "    $(cat "$S/run/endive-$c.err")"
  done
  ;;
scale)
  echo "# $(date -u +%F), $(uname -m), $(nproc) cores ($(grep -m1 'model name' /proc/cpuinfo | sed 's/.*: //')), JDK 21, ByteArrayMemory. One instance per thread; warm then timed, per thread."
  echo "# load average before: $(cut -d' ' -f1-3 /proc/loadavg); other busy processes: $(ps -eo pcpu,comm --sort=-pcpu | awk 'NR>1 && $1 > 5 {print $2"("$1"%)"}' | tr '\n' ' ')"
  for id in receipt/verify-genuine-sandbox-g5-against-apple-roots transaction/verify-shared-sandbox; do
    case "$id" in receipt*) W=600; N=600 ;; *) W=300; N=300 ;; esac
    for T in 1 2 4; do
      "$J" -cp "$CP" spike.aprv.abi.Scale "$S/calls/cases.jsonl" "$id" "$T" "$W" "$N"
    done
  done
  ;;
*) echo "usage: endive.sh build|tests|calls|scale"; exit 2 ;;
esac
