#!/usr/bin/env bash
# Builds the SWIG bake-off entry from scratch and runs Demo on JDK 8/17/21,
# then Bench (full, 10,000 x 3 rounds) on the JDK given as $1.
set -euo pipefail

D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FFI=$REPO/rust/ffi
JDK8=$SCRATCH/jdk8/jdk8u504-b01
JDK17=$SCRATCH/jdk17/jdk-17.0.20.1+1
JDK21_JAVAC=/usr/bin/javac
JDK21_HOME=/usr/lib/jvm/java-21-openjdk-amd64

echo "== 1/5 cargo build (release), CARGO_TARGET_DIR=$D/target =="
CARGO_TARGET_DIR="$D/target" cargo build --release --manifest-path "$FFI/Cargo.toml"

echo "== 2/5 swig -java =="
rm -rf "$D/gen"
mkdir -p "$D/gen/java" "$D/gen/c"
swig -java -DSWIGWORDSIZE64 -package bakeoff.swig.raw \
  -outdir "$D/gen/java" -o "$D/gen/c/aprv_wrap.c" \
  -I"$FFI/include" \
  "$D/aprv.i"

echo "== 3/5 compile + link libaprv.so (JNI glue + Rust cdylib) =="
gcc -shared -fPIC -O2 \
  -I"$JDK21_HOME/include" -I"$JDK21_HOME/include/linux" \
  -I"$FFI/include" \
  "$D/gen/c/aprv_wrap.c" \
  -L"$D/target/release" -lapple_purchase_receipt_verifier_ffi \
  -o "$D/target/release/libaprv.so" \
  -Wl,-rpath,'$ORIGIN'

echo "== 4/5 javac --release 8 (generated + hand-written), then run Demo on 8/17/21 =="
rm -rf "$D/classes"
mkdir -p "$D/classes"
"$JDK21_JAVAC" --release 8 -d "$D/classes" $(find "$D/gen/java" "$D/java" -name '*.java')

for jdk in "$JDK8/bin/java" "$JDK17/bin/java" /usr/bin/java; do
  echo "---- Demo on $jdk ----"
  "$jdk" -cp "$D/classes" -Djava.library.path="$D/target/release" bakeoff.swig.Demo
done

echo "== 5/5 Bench (full) on \$1=${1:-/usr/bin/java} =="
JDK_BIN="${1:-/usr/bin/java}"
"$JDK_BIN" -cp "$D/classes" -Djava.library.path="$D/target/release" bakeoff.swig.Bench
