# How the server engine should talk to aprv-server: the code

The note is [../2026-10-02-java-http-options.md](../2026-10-02-java-http-options.md).

| File | Question it answered |
|---|---|
| `ClientMatrix.java` | What each candidate client does with a misbehaving server, and under JVM-wide state other code (or a `-D` flag) can set: framing, transfer codings, duplicate lengths, the cap, a dripped body, a 401 challenge with a default `Authenticator`, redirects, resends, a default `ProxySelector`, proxy system properties, TLS trust and names, `SSLContext.setDefault`, logging. Clients: main's `HttpConn`, Apache HttpClient 5.6.4 classic (hardened and default), `java.net.http` (hardened and default, Java 11+). |
| `Hc5Clients.java` | The HttpClient 5 configuration the engine would need, and the checks HttpClient 5 leaves to the caller. |
| `JnhClients.java` | The same for `java.net.http.HttpClient`. |
| `run-matrix.sh` | Builds and runs `ClientMatrix` on each JVM given, in three modes (plain, TLS, logging), plus the `jdk.internal.httpclient.disableHostnameVerification` run. |
| `HttpConnServerHttpTest.java` | PR #222's `ServerHttpTest` ported to `HttpConn` (12 tests), plus 6 new ones for the gaps the matrix found. |
| `httpconn-hardening.patch` | The 34-line change to `HttpConn` that makes all 18 pass. Applied on PR #222 by f1bbeff and 6d3231d; it applies as is to `main`'s `HttpConn` at fce1407, the checkout the steps below start from. |
| `TransportBench.java`, `run-bench.sh` | The managed child over HTTP against one `aprv verify-receipt` process per call, and a length-prefixed frame through a pipe (the floor of a stdio transport). |
| `results/` | The output each number in the note comes from. |

## Reproduce

`$REPO` is a checkout whose `HttpConn` is `main`'s before the patch:
fce1407, or the note's base 756b1d7, where the file is the same. On
PR #222's branch the patch is already in and `git apply` refuses it.
`$SCRATCH` is any directory outside the checkout.
`$JARS` holds, from Maven Central: `httpclient5-5.6.4.jar`,
`httpcore5-5.4.3.jar`, `httpcore5-h2-5.4.3.jar`, `slf4j-api-1.7.36.jar`,
`slf4j-simple-1.7.36.jar` and `jspecify-1.0.0.jar`.

```sh
# the client matrix (results/matrix.txt, results/jnh-disable-hostname-verification.txt)
REPO=$REPO SCRATCH=$SCRATCH JARS=$JARS \
  sh run-matrix.sh "$JDK21_HOME" "$TEMURIN8_HOME" > $SCRATCH/matrix.txt 2>&1

# an aprv-server binary for the bench and the server tests
CARGO_TARGET_DIR=$SCRATCH/target \
  sh $REPO/rust/server/scripts/build-static.sh aprv.component.wasm \
  x86_64-unknown-linux-musl $SCRATCH/srv

# one process per call against the managed child (results/bench-round*.txt)
REPO=$REPO SCRATCH=$SCRATCH JARS=$JARS APRV=$SCRATCH/srv/aprv-x86_64-unknown-linux-musl \
  sh run-bench.sh "$JDK21_HOME" "$TEMURIN8_HOME"

# the ported tests against main's HttpConn: 12 pass, 6 fail
cp HttpConnServerHttpTest.java $REPO/java-wasm/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/
mvn -B -f $REPO/java-wasm test -Dtest=HttpConnServerHttpTest -Dsurefire.failIfNoSpecifiedTests=false \
  -Daprv.wasm=$REPO/go/internal/wasm/aprv.wasm -Dtest.jvm="$JDK_UNDER_TEST/bin/java" \
  [-Pjava8-tests on Java 8]

# with the patch: 18 pass, and every server-engine test with them
git -C $REPO apply docs/evidence/2026-10-02-java-http-options/httpconn-hardening.patch
printf '%s  aprv-x86_64-unknown-linux-musl\n' "$(sha256sum < $SCRATCH/srv/aprv-x86_64-unknown-linux-musl | cut -c1-64)" \
  > $SCRATCH/SHA256SUMS
mvn -B -f $REPO/java-wasm test '-Dtest=HttpConnServerHttpTest,Server*Test' \
  -Dsurefire.failIfNoSpecifiedTests=false -Daprv.wasm=$REPO/go/internal/wasm/aprv.wasm \
  -Daprv.server.linux-x86_64=$SCRATCH/srv/aprv-x86_64-unknown-linux-musl \
  -Daprv.server.sha256sums=$SCRATCH/SHA256SUMS -Dtest.jvm="$JDK_UNDER_TEST/bin/java" [-Pjava8-tests]
```

`run-matrix.sh` and `run-bench.sh` clear `JAVA_TOOL_OPTIONS` for the JVMs
they start, so a shell's proxy or trust store settings do not reach them.
