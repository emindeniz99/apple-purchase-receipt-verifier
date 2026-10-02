# The server engine's client: HttpURLConnection, buffered or streamed

The note is [../2026-10-02-java-httpurlconnection.md](../2026-10-02-java-httpurlconnection.md).

| File | Question |
|---|---|
| `streaming.patch` | What do a streamed POST body (`setFixedLengthStreamingMode`) and its lack of a resend cost, against the buffered body the engine ships? |
| `LargeBodyBench.java` | Does the buffered body keep up with the hand-written client on a 105 KB receipt, past the 8 KiB buffer, as well as on g5? |
| `ResendProbe.java` | How many connections can one `ServerConnection.send` put a POST on when the server keeps failing? |
| `SocksProbe.java` | Does a SOCKS answer from the default `ProxySelector` carry a connection opened with `Proxy.NO_PROXY`, per scheme and JDK, and did it carry the hand-written client's? |

The latency measurements are the server-engine tests' own benchmarks
(`ServerEngineTest.roundTripTimes`, `ServerUrlTest`) and
`LargeBodyBench`, run three ways: the hand-written client at `fce1407`,
the `HttpURLConnection` client as committed, and the same with
`streaming.patch` applied. `LargeBodyBench` and `ResendProbe` are JUnit
classes in the engine's test package; each run copies them in and
removes them after. `SocksProbe` is a standalone class with no
dependencies.

```sh
# The static server, as CI's aprv-server-linux job builds it.
rust/server/scripts/build-static.sh "$SCRATCH/aprv.component.wasm" \
  x86_64-unknown-linux-musl "$SCRATCH/server"
(cd "$SCRATCH/server" && sha256sum aprv-x86_64-unknown-linux-musl > SHA256SUMS)

E=docs/evidence/2026-10-02-java-httpurlconnection
T=java-wasm/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier
run() {  # run <java home> <goal> [maven args...]
  mvn -B -f java-wasm "$2" "-Dtest.jvm=$1/bin/java" \
    "-Daprv.wasm=$SCRATCH/aprv.wasm" "-Daprv.wasm.pin=$SCRATCH/aprv.wasm.sha256" \
    "-Daprv.server.linux-x86_64=$SCRATCH/server/aprv-x86_64-unknown-linux-musl" \
    "-Daprv.server.sha256sums=$SCRATCH/server/SHA256SUMS" "${@:3}" \
    | grep -E 'BENCH|PROBE|Tests run|expected'
}
only() {  # only <java home> <test classes>, then add -Pjava8-tests on Java 8
  run "$1" test "-Dtest=$2" -Dsurefire.failIfNoSpecifiedTests=false "${@:3}"
}
bench() {  # bench <java home>, then add -Pjava8-tests on Java 8
  only "$1" 'ServerEngineTest,ServerUrlTest' "${@:2}"
  cp "$E/LargeBodyBench.java" "$T/"
  only "$1" LargeBodyBench "${@:2}"
  rm "$T/LargeBodyBench.java"
}
bench "$JAVA21"; bench "$JAVA8" -Pjava8-tests    # buffered, as committed
# The buffered client's answers: the whole suite, ServerConformanceCasesTest included.
run "$JAVA21" verify; run "$JAVA8" verify -Pjava8-tests
git apply "$E/streaming.patch"
bench "$JAVA21"; bench "$JAVA8" -Pjava8-tests    # streamed
git apply -R "$E/streaming.patch"
git checkout fce1407 -- java-wasm                 # the hand-written client
bench "$JAVA21"; bench "$JAVA8" -Pjava8-tests
git checkout HEAD -- java-wasm

# Resends: as committed, on each JDK.
cp "$E/ResendProbe.java" "$T/"
only "$JAVA21" ResendProbe; only "$JAVA8" ResendProbe -Pjava8-tests
rm "$T/ResendProbe.java"

# SOCKS: compiled once for Java 8, run on each JDK.
"$JAVA8/bin/javac" -d "$SCRATCH/socks" "$E/SocksProbe.java"
"$JAVA8/bin/java" -cp "$SCRATCH/socks" SocksProbe
"$JAVA21/bin/java" -cp "$SCRATCH/socks" SocksProbe
```

The streamed runs fail `aRequestWithoutTheTokenOrWithAWrongOneIsRefused`
with `expected: <UNAUTHORIZED> but was: <HTTP_401>`: that is the finding,
not a broken setup.
