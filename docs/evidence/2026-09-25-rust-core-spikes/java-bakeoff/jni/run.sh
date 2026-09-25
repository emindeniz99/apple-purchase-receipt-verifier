#!/usr/bin/env bash
# Builds the jni-rs entry from scratch, runs Demo on JDK 8/17/21, then the
# full Bench on the JDK whose `java` binary is given as $1 (default JDK 21).
set -euo pipefail
B="$(dirname "$(readlink -f "$0")")"
S=$SCRATCH
JAVAS=("$S/jdk8/jdk8u504-b01/bin/java" "$S/jdk17/jdk-17.0.20.1+1/bin/java" /usr/bin/java)
BENCH_JAVA="${1:-/usr/bin/java}"

rm -rf "$B/target" "$B/classes"
CARGO_TARGET_DIR="$B/target" cargo build --release --manifest-path "$B/Cargo.toml"
LIB="$B/target/release/libaprv_jni.so"
/usr/bin/javac --release 8 -Xlint:all -d "$B/classes" "$B"/java/bakeoff/jni/*.java

for j in "${JAVAS[@]}"; do
  echo "=== Demo on $j"
  "$j" -Dbakeoff.jni.lib="$LIB" -cp "$B/classes" bakeoff.jni.Demo
done

echo "=== Bench on $BENCH_JAVA"
"$BENCH_JAVA" -Dbakeoff.jni.lib="$LIB" -cp "$B/classes" bakeoff.jni.Bench
