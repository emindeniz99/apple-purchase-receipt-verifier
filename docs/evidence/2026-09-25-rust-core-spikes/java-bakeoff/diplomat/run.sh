#!/usr/bin/env bash
# Builds the Diplomat entry from scratch, runs Demo on JDK 8/17/21, then the
# full Bench on the JDK whose java binary is given as $1 (default: /usr/bin/java).
set -euo pipefail
D=$SCRATCH/java-bakeoff/diplomat
S=$SCRATCH
TOOLCHAIN=+1.95   # diplomat_core 0.16.x uses `if let` guards (stable since Rust 1.95)
BENCH_JAVA=${1:-/usr/bin/java}

# 1. diplomat-tool (pinned), 2. cdylib, 3. Kotlin bindings, 4. Maven build
[ -x "$D/tool/bin/diplomat-tool" ] || CARGO_TARGET_DIR=$D/tooltarget cargo $TOOLCHAIN install diplomat-tool --version 0.16.1 --locked --root "$D/tool"
CARGO_TARGET_DIR=$D/target cargo $TOOLCHAIN build --release --manifest-path "$D/rust/Cargo.toml"
rm -rf "$D/java/src/main/kotlin"
"$D/tool/bin/diplomat-tool" -e "$D/rust/src/lib.rs" -c "$D/rust/diplomat.toml" kotlin "$D/java"
mvn -q -f "$D/java/pom.xml" clean package

CP="$D/java/target/classes:$D/java/target/dependency/kotlin-stdlib-2.2.20.jar:$D/java/target/dependency/annotations-13.0.jar:$D/java/target/dependency/jna-5.17.0.jar"
for J in "$S/jdk8/jdk8u504-b01/bin/java" "$S/jdk17/jdk-17.0.20.1+1/bin/java" /usr/bin/java; do
  "$J" -Djna.library.path="$D/target/release" -cp "$CP" bakeoff.diplomat.Demo
done
"$BENCH_JAVA" ${BENCH_OPTS:-} -Djna.library.path="$D/target/release" -cp "$CP" bakeoff.diplomat.Bench
