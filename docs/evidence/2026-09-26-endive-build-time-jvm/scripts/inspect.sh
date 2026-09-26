#!/bin/sh
# Spike only (2026-09-26). What the build produced and what the consumer
# needs at run time, from the artifacts themselves.
#   scripts/inspect.sh jar     > results/jar-inspection.txt
#   scripts/inspect.sh native  > results/native-check.txt
#   scripts/inspect.sh methods > results/method-sizes.txt   (after `jar`)
set -eu
. "$(dirname "$0")/env.sh"
unset JAVA_TOOL_OPTIONS   # the sandbox proxy settings; nothing here downloads
LIBJAR="$E/m2-consumer/spike/aprv/aprv-endive/0.0.0-spike/aprv-endive-0.0.0-spike.jar"
CW="$E/work/consumer"
CP="$CW/target/classes:$(cat "$CW/cp.txt")"
case "$1" in
jar)
  echo "# The library jar as the consumer resolved it ($(basename "$LIBJAR")): $(wc -c < "$LIBJAR") bytes"
  echo "# Input: $(cut -c1-64 "$E/work/lib.wasm.sha256") sha256, $(wc -c < "$WASM") bytes ($(basename "$WASM"), round 4's routec-new)"
  echo "## entries (unzip -l): size name"
  unzip -l "$LIBJAR" | awk 'NR > 3 && $4 != "" { print $1, $4 }' | grep -v '/$'
  echo "## by kind"
  unzip -l "$LIBJAR" | awk 'NR > 3 && $4 ~ /\./ { n = $4; sub(/.*\./, "", n); c[n]++; s[n] += $1 } END { for (k in c) print k, c[k], "files", s[k], "bytes" }' | sort
  echo "## generated Java source (target/generated-sources): not in the jar, compiled into AprvModule.class"
  find "$E/work/lib/target/generated-sources" -name '*.java' | sed "s|$E/work/lib/||"
  echo "## AprvModule.meta: the wasm module Endive keeps at run time (wasm-tools objdump)"
  unzip -p "$LIBJAR" spike/aprv/endive/AprvModule.meta > "$E/work/meta.wasm"
  wasm-tools objdump "$E/work/meta.wasm"
  echo "## function bodies in .meta: every one is replaced (count of bodies that are exactly 'unreachable')"
  wasm-tools print "$E/work/meta.wasm" | awk '/^  \(func /{f++; getline; if ($1 == "unreachable") u++} END { print f, "functions,", u, "with an unreachable-only body" }'
  echo "## the original module, for comparison"
  wasm-tools objdump "$WASM"
  echo "## javap: the compiled machine (class shape)"
  (cd "$E/work" && rm -rf jx && mkdir jx && cd jx && unzip -q "$LIBJAR")
  javap -cp "$E/work/jx" spike.aprv.endive.AprvModuleMachine | head -20
  echo "## methods per generated class"
  for c in AprvModuleMachine AprvModuleMachineFuncGroup_0 AprvModuleMachineShaded AprvModuleMachineDispatch_0 AprvModuleMachineIndirect_0_0; do
    echo "$c: $(javap -p -cp "$E/work/jx" spike.aprv.endive.$c | grep -c '(')"
  done
  echo "## method names come from the wasm name section (methodPrefixer), sample:"
  javap -p -cp "$E/work/jx" spike.aprv.endive.AprvModuleMachineFuncGroup_0 | grep -E 'aprv_verify_receipt_der|CMS_verify|ASN1_item_d2i|X509_verify_cert' | head -8
  echo "## references from the generated classes to an interpreter, a runtime compiler, ASM, or native code (javap -c -p, counted)"
  for pat in InterpreterMachine 'run/endive/compiler' 'org/objectweb/asm' MachineFactoryCompiler 'java/lang/System.load' 'java/lang/foreign' 'com/sun/jna' 'jnr/' 'com/kenai/jffi' 'redline'; do
    n=$(javap -c -p -cp "$E/work/jx" $(cd "$E/work/jx" && find spike -name '*.class' | sed 's/\.class$//; s|/|.|g') 2>/dev/null | grep -c "$pat" || true)
    echo "$pat: $n"
  done
  echo "## the one InterpreterMachine reference: a field of AprvModuleMachine; is it ever assigned (putfield)?"
  javap -c -p -cp "$E/work/jx" spike.aprv.endive.AprvModuleMachine | grep -E 'CompilerInterpreterMachine' | sed 's/^ *//'
  echo "putfield compilerInterpreterMachine: $(javap -c -p -cp "$E/work/jx" spike.aprv.endive.AprvModuleMachine | grep -c 'putfield.*compilerInterpreterMachine' || true)"
  echo "## the consumer's resolved dependencies (mvn dependency:tree)"
  sed -n '/--- dependency:.*:tree/,/--- dependency:.*:build-classpath/p' "$E/work/consumer-build.log" | grep -E '^\[INFO\] ([|+ ]|\\|spike)' | sed 's/^\[INFO\] //'
  echo "## the consumer's runtime classpath (cp.txt), jar sizes"
  { tr ':' '\n' < "$CW/cp.txt"; echo; } | grep . | while read -r j; do echo "$(wc -c < "$j") $(basename "$j")"; done
  echo "## everything the consumer's EMPTY local repository ended up holding, grouped (build plugins included)"
  (cd "$E/m2-consumer" && find . -name '*.jar' | sed 's|^\./||' | awk -F/ '{ print $1"/"$2 }' | sort | uniq -c)
  echo "## run.endive artifacts in it (no compiler, build-time-compiler, codegen, plugin, redline):"
  (cd "$E/m2-consumer" && find run -name '*.jar' | sort)
  echo "## ASM in it (org/ow2/asm)? Only through Maven's own plugins (plexus-java, maven-dependency-analyzer), never on the runtime classpath:"
  (cd "$E/m2-consumer" && find org/ow2 -name '*.jar' 2>/dev/null | sort)
  echo "on cp.txt: $(tr ':' '\n' < "$CW/cp.txt" | grep -c asm || true)"
  ;;
methods)
  echo "# Bytecode size per generated method of AprvModuleMachineFuncGroup_0 (every compiled wasm function lives there)"
  javap -c -p -cp "$E/work/jx" spike.aprv.endive.AprvModuleMachineFuncGroup_0 > "$E/work/fg0.javap"
  python3 "$EV/py/method_sizes.py" "$E/work/fg0.javap"
  ;;
native)
  echo "# Native-code check, $(date -u +%F). Consumer classpath: $(tr ':' '\n' < "$CW/cp.txt" | xargs -n1 basename | tr '\n' ' ')"
  echo "## native libraries inside any jar on the consumer classpath (.so .dll .dylib .jnilib)"
  for j in $(tr ':' ' ' < "$CW/cp.txt"); do echo "$(basename "$j"): $(unzip -l "$j" | grep -cE '\.(so|dll|dylib|jnilib)$' || true)"; done
  echo "## calls into native loading or foreign-function APIs, in any class on the consumer classpath (javap -c -p, counted)"
  rm -rf "$E/work/nx" && mkdir -p "$E/work/nx"
  for j in $(tr ':' ' ' < "$CW/cp.txt"); do (cd "$E/work/nx" && unzip -q -o "$j" '*.class'); done
  cp -r "$CW/target/classes/." "$E/work/nx/"
  CLASSES=$(cd "$E/work/nx" && find . -name '*.class' | sed 's|^\./||; s/\.class$//; s|/|.|g')
  javap -c -p -cp "$E/work/nx" $CLASSES > "$E/work/nx.javap" 2>/dev/null
  echo "classes disassembled: $(echo "$CLASSES" | wc -l)"
  for pat in 'java/lang/System.load' 'java/lang/System.loadLibrary' 'java/lang/Runtime.load' 'java/lang/foreign' 'jdk/internal/foreign' 'com/sun/jna' 'com/kenai/jffi' 'jnr/ffi' 'sun/misc/Unsafe' 'jdk/internal/misc/Unsafe' ' native '; do
    echo "$pat: $(grep -c -- "$pat" "$E/work/nx.javap" || true)"
  done
  echo "## native methods declared (javap -p, 'native' modifier)"
  javap -p -cp "$E/work/nx" $CLASSES 2>/dev/null | grep -c ' native ' || true
  for V in 17 21 25; do
    case "$V" in 17) J="$JDK17" ;; 21) J="$JDK21" ;; 25) J="$JDK25" ;; esac
    echo "## JDK $V: shared objects mapped into the process (/proc/self/maps), baseline (no instance) vs after verifying all of cases.jsonl"
    "$J/bin/java" -cp "$CP" spike.consumer.Main maps 2>/dev/null > "$E/work/maps-base-$V.txt"
    "$J/bin/java" -cp "$CP" spike.consumer.Main maps "$CORPORA/cases.jsonl" 2>/dev/null > "$E/work/maps-run-$V.txt"
    echo "baseline: $(tr '\n' ' ' < "$E/work/maps-base-$V.txt")"
    echo "added by verification: $(comm -13 "$E/work/maps-base-$V.txt" "$E/work/maps-run-$V.txt" | tr '\n' ' ')"
    echo "## JDK $V: classes loaded during a verification run (-verbose:class), by origin"
    "$J/bin/java" -verbose:class -cp "$CP" spike.consumer.Main corpus "$CORPORA/cases.jsonl" 2>/dev/null > "$E/work/vc-$V.txt" || true
    grep -E '^\[.*class,load' "$E/work/vc-$V.txt" | sed -E 's/.*source: //' | sed -E 's|.*/||; s/^jrt:.*/jrt (the JDK itself)/; s/^shared objects file.*/CDS archive (the JDK itself)/' | sort | uniq -c | sort -rn | head -12
    echo "run.endive classes loaded: $(grep -cE 'class,load\] run\.endive\.' "$E/work/vc-$V.txt" || true); InterpreterMachine loaded: $(grep -c 'run.endive.runtime.InterpreterMachine ' "$E/work/vc-$V.txt" || true); run.endive.compiler.* loaded: $(grep -c 'class,load\] run\.endive\.compiler' "$E/work/vc-$V.txt" || true); jdk.internal.foreign/java.lang.foreign loaded: $(grep -cE 'class,load\] (java\.lang\.foreign|jdk\.internal\.foreign)' "$E/work/vc-$V.txt" || true)"
    echo "java.lang.foreign / jdk.internal.foreign classes, verification run: $(grep -E 'class,load\] (java\.lang\.foreign|jdk\.internal\.foreign)' "$E/work/vc-$V.txt" | sed 's/.*class,load\] //; s/ source.*//' | tr '\n' ' ')"
    echo "the same, a JVM that creates no instance (Main maps): $("$J/bin/java" -verbose:class -cp "$CP" spike.consumer.Main maps 2>/dev/null | grep -E 'class,load\] (java\.lang\.foreign|jdk\.internal\.foreign)' | sed 's/.*class,load\] //; s/ source.*//' | tr '\n' ' ')"
  done
  ;;
esac
