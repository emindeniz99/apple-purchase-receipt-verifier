#!/bin/sh
# TransportBench on every JVM given.
#
#   REPO=... SCRATCH=... JARS=... APRV=path/to/aprv run-bench.sh JAVA_HOME...
#
# APRV is an aprv-server binary from rust/server/scripts/build-static.sh.
# Compiled with the first JAVA_HOME's javac at --release 8.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
: "${REPO:?}" "${SCRATCH:?}" "${JARS:?}" "${APRV:?}"
out=$SCRATCH/bench
rm -rf "$out"
mkdir -p "$out"
pkg=$REPO/java-wasm/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier
"$1/bin/javac" -nowarn --release 8 -cp "$JARS/jspecify-1.0.0.jar" -d "$out" "$pkg/HttpConn.java" "$here/TransportBench.java"
for home in "$@"; do
  env -u JAVA_TOOL_OPTIONS "$home/bin/java" -cp "$JARS/jspecify-1.0.0.jar:$out" \
    io.github.emindeniz99.applepurchasereceiptverifier.TransportBench \
    "$APRV" "$REPO/fixtures/public-receipts/receipt-sandbox-g5.b64" "${N:-1000}"
done
