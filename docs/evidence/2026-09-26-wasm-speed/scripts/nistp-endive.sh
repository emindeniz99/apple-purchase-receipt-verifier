#!/bin/sh
# Spike only (2026-09-26). Why enable-ec_nistp_64_gcc_128 is slower on
# Endive: the round 5 library rebuilt on the nistp module, the bytecode
# size of its generated methods (round 5's py/method_sizes.py), and the JWS
# row with and without HotSpot's -XX:-DontCompileHugeMethods (JDK 21,
# ByteArrayMemory). Diagnosis only: that flag is a JVM option a library
# cannot rely on.
#   nistp-endive.sh > results/nistp-endive.txt
set -eu
. "$(dirname "$0")/env.sh"
: "${CORPORA:?}" "${JDK21:?}"
E="$SCRATCH/endive"
WASM="$ART/nistp.wasm" "$R5/scripts/build.sh" lib > "$S/endive-nistp-diag.log" 2>&1
unset JAVA_TOOL_OPTIONS
rm -rf "$S/jx"; mkdir -p "$S/jx"; (cd "$S/jx" && unzip -q "$E/work/lib/target/aprv-endive-0.0.0-spike.jar")
echo "## generated method sizes, nistp module (compare round 5's results/method-sizes.txt: 6 above 8,000 bytes, largest 14,274)"
javap -c -p -cp "$S/jx" spike.aprv.endive.AprvModuleMachineFuncGroup_0 > "$S/fg0-nistp.javap" 2>/dev/null
python3 "$R5/py/method_sizes.py" "$S/fg0-nistp.javap" | head -14
CP="$E/work/consumer/target/classes:$E/work/lib/target/aprv-endive-0.0.0-spike.jar:$E/m2-consumer/run/endive/runtime/1.1.0/runtime-1.1.0.jar:$E/m2-consumer/run/endive/wasm/1.1.0/wasm-1.1.0.jar"
echo "## JWS, JDK 21, ByteArrayMemory, 1,000 warm-up + 500 timed"
for f in "" "-XX:-DontCompileHugeMethods"; do
  echo "flags=[$f] $("$JDK21/bin/java" $f -Dspike.aprv.memory=bytearray -cp "$CP" spike.consumer.Main bench "$CORPORA/cases.jsonl" transaction/verify-shared-sandbox 1000 500)"
done
rm -rf "$S/jx" "$S/fg0-nistp.javap"
