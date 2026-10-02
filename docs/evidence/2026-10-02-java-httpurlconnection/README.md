# The server engine's client: HttpURLConnection, buffered or streamed

The note is [../2026-10-02-java-httpurlconnection.md](../2026-10-02-java-httpurlconnection.md).

| File | Question |
|---|---|
| `streaming.patch` | What do a streamed POST body (`setFixedLengthStreamingMode`) and its lack of a resend cost, against the buffered body the engine ships? |

The measurements are the server-engine tests' own benchmarks
(`ServerEngineTest.roundTripTimes`, `ServerUrlTest`), run three ways: the
hand-written client at `fce1407`, the `HttpURLConnection` client as
committed, and the same with `streaming.patch` applied.

```sh
# The static server, as CI's aprv-server-linux job builds it.
rust/server/scripts/build-static.sh "$SCRATCH/aprv.component.wasm" \
  x86_64-unknown-linux-musl "$SCRATCH/server"
(cd "$SCRATCH/server" && sha256sum aprv-x86_64-unknown-linux-musl > SHA256SUMS)

run() {  # run <java home>, then add -Pjava8-tests on Java 8
  mvn -B -f java-wasm test -Dtest='ServerEngineTest,ServerUrlTest' \
    -Dsurefire.failIfNoSpecifiedTests=false "-Dtest.jvm=$1/bin/java" \
    "-Daprv.wasm=$SCRATCH/aprv.wasm" "-Daprv.wasm.pin=$SCRATCH/aprv.wasm.sha256" \
    "-Daprv.server.linux-x86_64=$SCRATCH/server/aprv-x86_64-unknown-linux-musl" \
    "-Daprv.server.sha256sums=$SCRATCH/server/SHA256SUMS" "${@:2}" | grep -E 'BENCH|Tests run|expected'
}
run "$JAVA21"; run "$JAVA8" -Pjava8-tests        # buffered, as committed
git apply docs/evidence/2026-10-02-java-httpurlconnection/streaming.patch
run "$JAVA21"; run "$JAVA8" -Pjava8-tests        # streamed
git apply -R docs/evidence/2026-10-02-java-httpurlconnection/streaming.patch
git checkout fce1407 -- java-wasm                 # the hand-written client
run "$JAVA21"; run "$JAVA8" -Pjava8-tests
```

The streamed runs fail `aRequestWithoutTheTokenOrWithAWrongOneIsRefused`
with `expected: <UNAUTHORIZED> but was: <HTTP_401>`: that is the finding,
not a broken setup.
