#!/bin/sh
# G1 for java-wasm in one command: the module in place, the whole suite on
# the default JDK, the 311 Endive cases on each other JDK, the corpus on one
# and on four threads, and the benchmark; with a server binary, also the
# Java 8 leg (the server engine) and the corpus through the server engine.
#
#   g1.sh G1_DIR OUT_DIR
#
# G1_DIR is lane A's bundle: aprv.wasm, calls/<corpus>.pinned.jsonl,
# rows/module-<corpus>.jsonl. The module must hash to the pin committed in
# src/main/wasm/aprv.wasm.sha256; it is copied to src/main/wasm/aprv.wasm,
# which git ignores. Build tooling settings, not the library's:
#   ENDIVE_JVMS   java binaries for the extra 311-case runs (space-separated)
#   APRV_SERVER   the static aprv-server binary, pinned in
#                 src/main/server/SHA256SUMS; without it the server tests
#                 (tag "server") and server steps are left out, and the
#                 output says so
#   JAVA8         a Java 8 java binary for the Java 8 leg (needs APRV_SERVER)
#   BENCH_SECONDS seconds per benchmark point (default 20)
# Logs go to OUT_DIR; the summary lines go to stdout.
set -eu
g1=$1
out=$2
here=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$out"
pin=$(cut -c1-64 "$here/src/main/wasm/aprv.wasm.sha256")
got=$(sha256sum "$g1/aprv.wasm" | cut -c1-64)
if [ "$pin" != "$got" ]; then
  echo "g1: $g1/aprv.wasm hashes to $got, the pin is $pin" >&2
  exit 1
fi
cp "$g1/aprv.wasm" "$here/src/main/wasm/aprv.wasm"
status=0

if [ -n "${APRV_SERVER:-}" ]; then
  server="-Daprv.server.linux-x86_64=$APRV_SERVER"
else
  server="-DexcludedGroups=server"
  echo "suite: server tests left out (no APRV_SERVER)"
fi
echo "# load $(cut -d' ' -f1-3 /proc/loadavg), $(nproc) CPUs"
mvn -B -f "$here/pom.xml" verify "$server" > "$out/verify.log" 2>&1 || status=1
echo "suite ($(java -version 2>&1 | grep -m1 version)): $(grep -E '^\[(INFO|ERROR|WARNING)\] Tests run: [0-9]+, Failures' "$out/verify.log" | tail -1)"
grep -h '^conformance (' "$out/verify.log" | grep ' ran, ' || true

for jvm in ${ENDIVE_JVMS:-}; do
  log="$out/cases-$(echo "$jvm" | tr '/' '_' | tail -c 60).log"
  mvn -B -f "$here/pom.xml" test -Dtest=ConformanceCasesTest -Dsurefire.failIfNoSpecifiedTests=false \
    -Dtest.jvm="$jvm" > "$log" 2>&1 || status=1
  grep -h '^conformance (' "$log" | grep ' ran, ' || { echo "cases on $jvm: no summary, see $log"; status=1; }
done

if [ -n "${APRV_SERVER:-}" ] && [ -n "${JAVA8:-}" ]; then
  mvn -B -f "$here/pom.xml" verify -Pjava8-tests -Dtest.jvm="$JAVA8" "$server" > "$out/verify-java8.log" 2>&1 || status=1
  echo "suite (Java 8, $JAVA8): $(grep -E '^\[(INFO|ERROR|WARNING)\] Tests run: [0-9]+, Failures' "$out/verify-java8.log" | tail -1)"
  grep -h '^conformance (' "$out/verify-java8.log" | grep ' ran, ' || true
  grep -h '^BENCH' "$out/verify-java8.log" || true
fi
grep -h '^BENCH' "$out/verify.log" || true

for threads in 1 4; do
  echo "corpus (Endive), $threads thread(s):"
  APRV_SERVER= "$here/scripts/corpus.sh" "$g1/calls" "$g1/rows" "$out/corpus" "$threads" > "$out/corpus-t$threads.txt" || status=1
  cat "$out/corpus-t$threads.txt"
  if [ -n "${APRV_SERVER:-}" ]; then
    echo "corpus (server engine), $threads thread(s):"
    "$here/scripts/corpus.sh" "$g1/calls" "$g1/rows" "$out/corpus" "$threads" > "$out/corpus-server-t$threads.txt" || status=1
    cat "$out/corpus-server-t$threads.txt"
    tail -qn1 "$out"/corpus/server-t"$threads"-*.err
  fi
done
if [ -n "${APRV_SERVER:-}" ] && [ -n "${JAVA8:-}" ]; then
  echo "corpus (server engine, Java 8), 1 thread:"
  JAVA="$JAVA8" "$here/scripts/corpus.sh" "$g1/calls" "$g1/rows" "$out/corpus-java8" 1 > "$out/corpus-server-java8.txt" || status=1
  cat "$out/corpus-server-java8.txt"
fi

"$here/scripts/bench.sh" "${BENCH_SECONDS:-20}" 1 2 4 > "$out/bench.txt" 2>&1 || status=1
cat "$out/bench.txt"
exit $status
