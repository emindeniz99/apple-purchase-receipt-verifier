#!/usr/bin/env bash
# Builds libapple_purchase_receipt_verifier_java.so from the repository's
# unchanged Java verifier. Everything is written under $SCRATCH.
#
#   REPO=/path/to/repo SCRATCH=/some/dir GRAALVM_HOME=$SCRATCH/graalvm ./build.sh [config-dir] [out-name]
#
# config-dir defaults to ./config/minimal (the committed metadata).
# out-name defaults to libapple_purchase_receipt_verifier_java.
set -euo pipefail

SPIKE="$(cd "$(dirname "$0")" && pwd)"
: "${REPO:?set REPO to the repository root}"
: "${SCRATCH:?set SCRATCH to a scratch directory}"
: "${GRAALVM_HOME:=$SCRATCH/graalvm}"
CONFIG="${1:-$SPIKE/config/minimal}"
NAME="${2:-libapple_purchase_receipt_verifier_java}"
MARCH="${MARCH:-compatibility}"
unset JAVA_TOOL_OPTIONS

# 1. The repository jar, built by its own pom from a copy of java/ (the
#    repository tree is not written to).
if [ ! -f "$SCRATCH/java-src/target/apple-purchase-receipt-verifier-0.6.0.jar" ]; then
  mkdir -p "$SCRATCH/java-src"
  cp -r "$REPO/java/pom.xml" "$REPO/java/src" "$REPO/java/LICENSE" "$SCRATCH/java-src/"
  mvn -q -f "$SCRATCH/java-src/pom.xml" -Daprv.fixtures.dir="$REPO/fixtures" -DskipTests \
    package dependency:copy-dependencies -DincludeScope=runtime -DoutputDirectory="$SCRATCH/java-src/target/deps"
fi
LIB_CP="$SCRATCH/java-src/target/apple-purchase-receipt-verifier-0.6.0.jar:$(ls "$SCRATCH"/java-src/target/deps/*.jar | tr '\n' ':')"

# 2. The bridge (Java 8 bytecode, also used by the JVM oracle) and the
#    @CEntryPoint shims (need the GraalVM SDK classes).
rm -rf "$SCRATCH/build"
mkdir -p "$SCRATCH/build/bridge" "$SCRATCH/build/native"
"$GRAALVM_HOME/bin/javac" --release 8 -nowarn -cp "$LIB_CP" -d "$SCRATCH/build/bridge" "$SPIKE"/bridge/src/aprvj/*.java
"$GRAALVM_HOME/bin/jar" --create --file "$SCRATCH/build/aprvj-bridge.jar" -C "$SCRATCH/build/bridge" .
"$GRAALVM_HOME/bin/javac" -nowarn -cp "$LIB_CP:$SCRATCH/build/aprvj-bridge.jar" -d "$SCRATCH/build/native" \
  "$SPIKE"/native/src/aprvj/nativeimage/*.java
echo "$SCRATCH/build/aprvj-bridge.jar:$LIB_CP" > "$SCRATCH/build/cp.txt"

# 3. The shared library.
OUT="$SCRATCH/out/$NAME"
rm -rf "$OUT"; mkdir -p "$OUT"
python3 "$SPIKE/py/timev.py" "$OUT/build-time.txt" \
  "$GRAALVM_HOME/bin/native-image" --shared -march="$MARCH" \
    -cp "$SCRATCH/build/aprvj-bridge.jar:$LIB_CP:$SCRATCH/build/native" \
    -H:ConfigurationFileDirectories="$CONFIG" \
    -o "$OUT/$NAME" \
    ${EXTRA_NI_FLAGS:-} 2>&1 | tee "$OUT/build.log"
grep -E 'Elapsed \(wall|Maximum resident' "$OUT/build-time.txt"
ls -l "$OUT"
