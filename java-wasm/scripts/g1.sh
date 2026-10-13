#!/bin/sh
# The corpus parity run for java-wasm (DECISIONS.md R35): the module in
# place, the jar and test classes built without running the tests, and the
# corpus through the Endive engine on one and on four threads; with a server
# binary, also the corpus through the server engine, and with JAVA8 that
# engine on Java 8. Rows only: the suite, the cases on each JDK and the
# Java 8 leg run in ci.yml against the freshly built module, and the
# archive's module predates whatever the core and the shared cases changed
# since its release; scripts/bench.sh times the engine on its own.
#
#   g1.sh G1_DIR OUT_DIR
#
# G1_DIR has the corpus archive's layout: aprv.wasm, aprv.component.wasm and
# aprv.wit with the SHA256SUMS over them, calls/<corpus>.pinned.jsonl,
# rows/module-<corpus>.jsonl. The module must hash to the pin committed in
# src/main/wasm/aprv.wasm.sha256; .github/scripts/place-module.sh then checks
# G1_DIR against its SHA256SUMS and puts the module in
# src/main/wasm/aprv.wasm, which git ignores, for this run only (the release
# tooling refreshes the pin). Build tooling settings, not the library's:
#   APRV_SERVER   the static aprv-server binary, pinned in
#                 src/main/server/SHA256SUMS; without it the server-engine
#                 corpus is left out, and the output says so
#   JAVA8         a Java 8 java binary for the server-engine corpus on
#                 Java 8 (needs APRV_SERVER)
# Logs go to OUT_DIR; the summary lines go to stdout. Exit status is 0 only
# when every row is identical with no trap.
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
bash "$here/../.github/scripts/place-module.sh" "$g1" java
status=0

[ -n "${APRV_SERVER:-}" ] || echo "corpus: server engine left out (no APRV_SERVER)"
# scripts/corpus.sh runs the jar and the test classes (CorpusMain,
# ServerCorpusMain): build both, run no test.
mvn -B -f "$here/pom.xml" package -DskipTests > "$out/package.log" 2>&1 \
  || { tail -20 "$out/package.log"; echo "g1: the build failed, see $out/package.log" >&2; exit 1; }

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
exit $status
