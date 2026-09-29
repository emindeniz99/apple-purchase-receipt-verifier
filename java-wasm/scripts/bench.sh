#!/bin/sh
# Start-up and throughput of the Endive engine for the record (MIGRATION
# step 3.7): BenchMain in a fresh JVM, the genuine g5 sandbox receipt and
# the shared sandbox transaction JWS, each thread on an instance of its own.
#
#   bench.sh [SECONDS] [THREADS...]      (default 10 s at 1, 2 and 4 threads)
#
# Needs the jar and test classes built (mvn -f java-wasm verify). JAVA
# picks the java binary (default: java on PATH). Numbers depend on the
# machine and its load; print the load average beside them.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
java=${JAVA:-java}
cp="$here/target/bench-classpath.txt"
[ -s "$cp" ] || mvn -q -f "$here/pom.xml" dependency:build-classpath -Dmdep.includeScope=test -Dmdep.outputFile="$cp" >/dev/null
jar=$(ls "$here"/target/apple-purchase-receipt-verifier-wasm-*.jar | grep -v -e sources -e javadoc -e linux- | head -1)
echo "# $(date -u +%FT%TZ) load $(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo unknown), $(nproc 2>/dev/null || echo '?') CPUs"
cd "$here"
"$java" -cp "$jar:$here/target/test-classes:$(cat "$cp")" \
  io.github.emindeniz99.applepurchasereceiptverifier.BenchMain "$@"
