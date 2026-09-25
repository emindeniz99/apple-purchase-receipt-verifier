#!/usr/bin/env bash
# Builds the flapigen binding from scratch, runs Demo on JDK 8/17/21, then the
# full Bench on the JDK given as $1 (path to a `java` binary; default JDK 21).
set -euo pipefail
B=$SCRATCH/java-bakeoff/flapigen
S=$SCRATCH
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64   # jni.h for bindgen
rm -rf "$B/target" "$B/java/gen" "$B/classes"
CARGO_TARGET_DIR="$B/target" cargo build --release --manifest-path "$B/Cargo.toml"
mkdir -p "$B/classes"
/usr/bin/javac --release 8 -Xlint:-options -d "$B/classes" \
  $(find "$B/java/gen" "$B/java/src" "$B/java/app" -name '*.java')
LIB="$B/target/release"
for J in "$S/jdk8/jdk8u504-b01/bin/java" "$S/jdk17/jdk-17.0.20.1+1/bin/java" /usr/bin/java; do
  echo "== Demo on $J"
  "$J" -Djava.library.path="$LIB" -cp "$B/classes" Demo
done
BENCH_JAVA="${1:-/usr/bin/java}"
echo "== Bench on $BENCH_JAVA"
"$BENCH_JAVA" -Djava.library.path="$LIB" ${BENCH_N:+-Dbench.n=$BENCH_N} -cp "$B/classes" Bench
