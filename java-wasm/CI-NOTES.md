# CI notes for `java-wasm/` (for the integrator)

What the `-wasm` artifact needs from `.github/`, which this lane does not
edit. Every job follows the repository's rules: actions pinned by SHA with
the tag in a comment, `persist-credentials: false` on every checkout, a
least-privilege `permissions:` block (`contents: read`), and no cache in a
publish job (test jobs may cache `~/.m2`).

The Maven build needs network access to Maven Central on first run: the
`endive-compiler-maven-plugin` pulls Endive's compiler and, although this
build leaves Redline off, Redline's experimental build-time artifacts. None
of them reaches the consumer's classpath.

`aprv.wasm` is not in git (R14): every job copies the release build's
`aprv.wasm` to `java-wasm/src/main/wasm/` first, or passes `-Daprv.wasm=PATH`.

Every job that runs the tests also needs lane D's static Linux x86_64
`aprv-server` binary, passed as `-Daprv.server.linux-x86_64=PATH`: the
build copies it into the `linux-x86_64` classifier directory and the
server-engine tests (tag `server`) run it from there. Without the path they
fail with that instruction, never skip; `-DexcludedGroups=server` leaves
them out on purpose. The path's SHA-256 must be pinned in
`src/main/server/SHA256SUMS` (or in the file given as
`-Daprv.server.sha256sums=PATH`), or the build fails.

A JRE cannot compile (the Temurin 11 used here is a JRE), so every leg
compiles with the runner's modern JDK and runs the tests on the JVM under
test through the surefire `jvm` setting: `-Dtest.jvm=<java home>/bin/java`.

## `java-wasm-endive`

The artifact with the Endive engine. One job per JDK in the matrix; the
floor is 11 (Endive's), and the plan asks for 11 to 27.

- Matrix: Temurin 11, 17, 21, 25 (and 27 once it has a GA build) on
  `ubuntu-latest`, compiled with JDK 21.
- Steps:
  ```sh
  mvn -B -f java-wasm verify -Dtest.jvm="$JAVA_UNDER_TEST/bin/java" \
    -Daprv.server.linux-x86_64="$APRV_SERVER"
  ```
  `verify` runs, in order: the SHA-256 check of `src/main/wasm/aprv.wasm`
  against `aprv.wasm.sha256` (validate phase), Endive's build-time
  compilation with `interpreterFallback` FAIL, the Java 8 and Java 11
  compiler executions, and every test: the 311 cases of
  `fixtures/cases.json` on Endive (`ConformanceCasesTest`, one dynamic test
  per case plus a last test that asserts every case id ran), the round-13
  ABI tests (`EndiveAbiTest`), the facade (`WasmVerifierTest`), the engine
  API (`EngineApiTest`), the answer decoder (`WireTest`), the class-file
  majors and the native-code scan of the consumer classpath
  (`ClassFileTest`), the source grep for system properties and environment
  variables (`SourceRulesTest`) and the classpath guard's rule
  (`ClasspathGuardTest`). The server-engine tests run on these JDKs too:
  see `java-runtime-8` below for the list.
- Time: about 2.5 minutes for `verify` on JDK 21 on a loaded 4-CPU
  machine, most of it the 311 cases.
- **The corpus** (MIGRATION 3.7): the 1,179 corpus rows plus 5,000
  mutants through the built jar, on Linux x64 and arm64, macOS arm64,
  Windows x64 and arm64.
  `scripts/corpus.sh CALLS_DIR ROWS_DIR OUT_DIR [THREADS]` runs the five
  pinned call files (`<corpus>.pinned.jsonl`, every clock pinned) and
  compares each row byte for byte with the module's reference rows
  (`module-<corpus>.jsonl`, the same `aprv.wasm` through the Node trap
  host, identical to the native core); it exits non-zero on any differing
  row or trap. Both inputs come from lane A's release bundle, not from the
  repository. Run it once single-threaded and once with 4 threads.
- **One command** for all of the above: `scripts/g1.sh BUNDLE_DIR OUT_DIR`
  checks the bundle's `aprv.wasm` against the committed pin, copies it into
  place, runs `verify`, the 311 cases on each JVM in `ENDIVE_JVMS`, the
  corpus on 1 and 4 threads, and `scripts/bench.sh`.
- Failure means: a case that answers differently from `fixtures/cases.json`,
  an ABI misuse that no longer traps, a Java 11 class in the facade, a
  native-loading reference, or a `System.getProperty`/`System.getenv` in
  `src/main`.

### Measured in this lane (2026-09-29, the G1 module)

On a shared 4-CPU Linux x86_64 machine with a load average of 6 to 18
from other builds, so timings are for the record, not for comparison.
`scripts/g1.sh` with the G1 bundle (module `4cbe2b02...8826e`):

- `mvn verify -DexcludedGroups=server` on JDK 21 (OpenJDK 21.0.10): 372
  tests, 0 failures, 1 skipped (the Java-8-only Endive test), 3 min 40 s.
  `ClassFileTest`: 52 classes at major 52, 37 at major 55; 497 classes
  scanned on the consumer classpath, no native method and no
  native-loading reference.
- The 311 cases on Endive: 311 of 311 on JDK 21, Temurin 17.0.20.1 and
  Temurin 11.0.32.1 (a JRE; tests forked onto it), 0 failed, 0 skipped,
  no stand-in list.
- Corpus through the built jar, JDK 21, against the module's reference
  rows: cases 153/153, hostile 811/811, algorithms 22/22, substrate
  193/193, fuzz 5,000/5,000 identical, 0 traps: 6,179 of 6,179, on 1
  thread and on 4.
- `scripts/bench.sh 45 1 2 4` on JDK 21 (load 6 to 9): first instance
  1,121 ms, later instances 56.6 ms (median of 20), first g5 call 222 ms;
  g5 receipts 111.2, 230.7 and 328.8 per second and JWS 24.9, 37.3 and
  66.3 per second at 1, 2 and 4 threads (one instance per thread). Memory:
  one instance's linear memory 1.9 MiB after `init`, 2.0 MiB after a g5
  call; heap used after GC with the module loaded and one instance live
  12.8 MiB; RSS 147 MiB then, 357 MiB peak after the 4-thread runs. The
  0.6 stand-in measured, on the same machine under similar load, first
  instance 842 ms, later instances 7.0 ms, first g5 call 489 ms, g5 81.0,
  136.3 and 96.3 per second and JWS 25.6, 32.2 and 20.0 per second. The
  eightfold later-instance time came with the 0.7 core and is not
  profiled yet (instance creation plus `init`); the pool pays it once per
  instance, not per call. Rerun on a quiet runner before quoting any of these.
- The main artifact after the guard change: `mvn -f java verify` 516
  tests, 0 failures, 1 skipped (the fixture generator, as before), on
  JDK 21 and with `-Pjdk8-runtime` on Temurin 8u504; `spotless:check`
  clean in both modules.
- `-Pclasspath-guard`: `ClasspathGuardJarsIT` 3 of 3; the Gradle
  project above fails with "Cannot select module with conflict on
  capability 'io.github.emindeniz99:apple-purchase-receipt-verifier:0.7.0'"
  (Gradle 8.14.3), and resolves the `-wasm` artifact alone to its jar,
  Endive's `runtime` and `wasm`, and jackson-core.

### The module

The pin in `src/main/wasm/aprv.wasm.sha256` names the 0.7 core's module
(lane A2, G1): SHA-256
`4cbe2b02056afc41c352fbbacdf6b3804f6f081beaaa8e8ff104340e9ed8826e`,
3,005,922 bytes. Every case must pass on it; the stand-in list of the 0.6
module is gone.

Replacing the module is one committed file and one copy: write the new
hash, in `sha256sum`'s format, to `java-wasm/src/main/wasm/aprv.wasm.sha256`,
and copy the module to `java-wasm/src/main/wasm/aprv.wasm` (not in git).
The build refuses a module whose hash differs from the pin.

## `java-runtime-8`: the server engine on Java 8

A step in the existing `java-runtime-8` job (or a job of its own): the
`-wasm` artifact on a real Java 8 JVM, where `Verifier.create(config)`
picks the server engine. The Endive tests are tagged `endive` and left
out by the `java8-tests` profile.

```sh
mvn -B -f java-wasm verify -Pjava8-tests -Dtest.jvm="$JAVA_HOME_8_X64/bin/java" \
  -Daprv.server.linux-x86_64="$APRV_SERVER"
```

What runs, on Java 8 and on every Endive JDK:

- `ServerEngineTest`: the managed child through `executable(path)`, the
  spike's 13 managed-mode checks: start on loopback with the token on
  stdin, the operations, 401 without or with a wrong token, 413 answered
  as the core answers an input over its cap (`TOO_LARGE`/21002),
  restart after `SIGABRT` and after `SIGKILL`,
  `close()` stops the child, and the round-trip timings (`BENCH` lines).
- `ServerUrlTest`: the spike's 6 URL-mode checks against a standalone
  `aprv serve`, a wrong token refused at `create` (and `INTERNAL_ERROR`
  with the probe off), a server with other roots refused.
- `ServerLifecycleTest`: no orphan after `System.exit`, after `kill -9` of
  the JVM, or after the verifier is garbage collected.
- `ServerDownloadTest`: two JVMs of four threads installing at once make
  one GET; `r-x------` binary in an `rwx------` directory; the download
  source end to end; a changed cache entry fetched again; a wrong hash
  never made executable and nothing left; a binary changed after install
  deleted, not started; HTTPS only; unsafe cache directories refused.
- `ServerSourcesTest`: `maven()` alone, `github()` alone (fails while
  this version has no release asset), the first working source used, every
  reason in order when none works, the probe off, and a root the module
  refuses (the child exits 2; the module's `init` answer comes back, and
  `create` throws `IllegalArgumentException` as on Endive).
- `ServerProblemTest` (no binary needed): 401, 413 and 500 `WASM_TRAP` /
  `ABI_ERROR` / non-problem bodies, the clock read once per call and sent
  as `X-Aprv-Now-Ms`, a throwing clock, a roots mismatch, the 413 answer,
  the roots-refusal parser, the mountinfo parser behind `noexec`
  detection.
- `ServerNoexecTest`: mounts a `noexec` tmpfs and checks the advice a user
  gets. Mounting needs root, so on a GitHub runner it is reported
  **skipped** with the reason. To run it there, add a step
  `sudo -E mvn -B -f java-wasm test -Dtest=ServerNoexecTest -Dsurefire.failIfNoSpecifiedTests=false -Daprv.server.linux-x86_64="$APRV_SERVER"`.
- `ServerConformanceCasesTest`: the 311 cases through the server engine,
  one managed child per root set. The 33 `decodeBase64` cases have no
  route of their own on the server; like Endive's, they go through
  `verifyReceipt` and `verifySignedData` (see `ConformanceCases`).
- `EngineApiTest`'s Java 8 test runs the default path, `maven()` from the
  classifier directory, so it writes `~/.cache/aprv` on the runner.

Temurin 8 moves to Zulu or Corretto 8 before Temurin 8 builds end in late
2026 (R25).

Every case must pass: the stand-in list of the 0.6 server is gone.

The corpus through the server engine is `APRV_SERVER=PATH
scripts/corpus.sh ...` (see `java-wasm-endive`): one managed child per
`init` configuration, each call one request with its pinned clock. The
27 calls over the server's 3,145,728-byte body cap get 413 before the
module sees them, and the engine answers them as the module does, so the
rows must still equal the module's reference rows byte for byte.

### Measured in lane E (2026-09-29, the G1 server)

Lane B's G1 build, sha256 `972cd42d...18f0c55`, 11,989,936 bytes,
`component_sha256` `8f758c0b...4460dd5`; the same shared 4-CPU machine,
load average 7 to 21. `scripts/g1.sh` with `APRV_SERVER` and `JAVA8`:

- `mvn -B -f java-wasm verify -Daprv.server.linux-x86_64=...` on JDK 21:
  716 tests (the 311 cases on both engines), 0 failures, 2 skipped (the
  two Java-8-only tests), 3 min 32 s.
- Java 8 leg (Temurin 8u504): 382 tests, 0 failures, 1 skipped (the
  Java-11-only test), 1 min 37 s.
- The 311 cases through the server engine: 311 of 311 on JDK 21 and on
  Temurin 8 (33 of them `decodeBase64` through the public API), 0 failed,
  0 skipped.
- Corpus through the server engine against the module's reference rows,
  on JDK 21 with 1 and 4 threads and on Temurin 8 with 1: cases 153/153,
  hostile 811/811, algorithms 22/22, substrate 193/193, fuzz 5,000/5,000
  identical, 0 problems: 6,179 of 6,179, of which 27 were 413s answered as
  the module answers them (cases 7, hostile 2, fuzz 18) and 1 a roots
  refusal at start (hostile). 223 children in all.
- g5 round trip through the child, at load 7 to 8: from Temurin 8 mean
  8.2 ms (p50 7.4, p99 13.7), 122 per second on one thread, 288 on four;
  from JDK 21 mean 8.6 ms (p50 8.2, p99 17.0), 116 per second. `GET
  /healthz` 56 us, child start plus `/v1/info` 123 ms. The transport is
  under 0.1 ms of that, so the rest is the verification itself, which
  takes about 9 ms in process on Endive on the same machine too. The
  spike measured 3.87 ms on an idle machine with its own build; rerun on
  a quiet runner before comparing.
- Sizes: the jar 1,925,790 bytes; the `linux-x86_64` classifier jar
  4,210,771 bytes, holding the 11,989,936-byte binary and its `.sha256`.
- `-Pclasspath-guard` was not re-run on G1 (3 of 3 on the stand-in; it
  does not depend on the module).

## JVM consumers (MIGRATION 3.9)

`jvm-interop` and the Spring Boot smoke take the artifact under test as
`-Dverifier.artifactId` (default: the main artifact). Add a `-wasm` leg
to each after `mvn -B -f java-wasm install -DskipTests` (with the
`aprv.wasm` copy in place):

```sh
mvn -B -f jvm-interop test -Dverifier.artifactId=apple-purchase-receipt-verifier-wasm
mvn -B -f java/samples/spring-boot-smoke/pom.xml test -Dverifier.version="$version" \
  -Dspring-boot.version="$BOOT" -Dverifier.artifactId=apple-purchase-receipt-verifier-wasm
```

Both consumers need Java 17 or later, so on them the `-wasm` artifact runs
Endive; neither exercises the server engine, which only Java 8 picks by
default. Run locally on JDK 21 on 2026-09-29: with the main artifact,
`jvm-interop` 11 of 11 and the smoke 5 of 5 on Boot 4.0.8 and 4.1.1; with
`-wasm` on the G1 module, the same: 11 of 11, and 5 of 5 on each Boot
line.

Only CI runs `java-distroless`: this machine has no Docker daemon. Its
`-wasm` leg runs `java-wasm`'s tests on each image's JVM the way the main
artifact's leg does (the console launcher over `target/classes`,
`target/test-classes` and `target/dep`); the server tests need the static
binary, which runs on distroless as it is (no libc needed).

## `java-classpath-guard`

Both artifacts on one classpath must fail; Gradle must refuse both.

```sh
mvn -B -f java package -DskipTests
mvn -B -f java-wasm verify -Pclasspath-guard
```

The profile copies BouncyCastle, jackson-core and Endive's jars into
`target/guard-lib` and runs `ClasspathGuardJarsIT` (failsafe, after
`package`): the real main jar (`java/target/`) and the real `-wasm` jar in
one class loader, in both orders, make `Verifier.create` throw the guard's
`IllegalStateException`; each alone gets past it; and every public type
and member of the main jar exists in the `-wasm` jar with the same
signature.

The Gradle half deploys both artifacts to a file repository and resolves
both:

```sh
repo="$RUNNER_TEMP/guard-repo"
mvn -B -f java deploy -DskipTests -DaltDeploymentRepository="guard::file://$repo"
mvn -B -f java-wasm deploy -DskipTests -DaltDeploymentRepository="guard::file://$repo"
version=$(cat version.txt)
if gradle -q -p java-wasm/src/it/gradle-capability -PaprvRepo="file://$repo" -PaprvVersion="$version" resolveBoth > out.txt 2>&1; then
  echo "Gradle resolved both artifacts"; exit 1
fi
grep -q "apple-purchase-receipt-verifier" out.txt && grep -qi "capability" out.txt
```

`java-wasm/pom.xml` carries the `do_not_remove: published-with-gradle-metadata`
comment and the `gradle-module-metadata-maven-plugin` (org.gradlex, 1.2),
which writes `apple-purchase-receipt-verifier-wasm-<version>.module` and
attaches it, so it is deployed and published beside the POM like any other
file. Maven Central accepts `.module` files; Gradle publishes them there
routinely. It declares two capabilities: the artifact's own and
`io.github.emindeniz99:apple-purchase-receipt-verifier`.

## `wasm-copies`

Check that `java-wasm/src/main/wasm/aprv.wasm.sha256` names the release
`aprv.wasm`'s SHA-256. The module itself is not in git: the jobs above and
the publish job copy it into place, and the build refuses a copy whose hash
differs from the pin.

## `java-wasm-s390x` (before each release)

The corpus through the built jar on s390x under QEMU, the big-endian
check. `ByteArrayMemory` names `ByteOrder.LITTLE_ENDIAN` in its code (the
Endive round's facts addendum counts the references), but nothing has run
it on a big-endian JVM yet.

## Release

- `release-please-config.json` `extra-files`, in the commit that wires the
  artifact in:
  - `{"type": "pom", "path": "java-wasm/pom.xml"}`
  - `{"type": "generic", "path": "java-wasm/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/Version.java"}`
  - `{"type": "generic", "path": "java-wasm/README.md"}`
- `publish-maven`: `mvn -B -f java-wasm -P central deploy` beside the main
  artifact's, with the same GPG and Central credentials, and no cache.
  Files per release: the jar (1.9 MB with the G1 module), sources,
  javadoc (the public API only: the `central` profile points javadoc at
  `src/main/java`), the `.module` file, the CycloneDX SBOM, their
  signatures, and the two server classifier jars (MIGRATION 3.4):
  ```sh
  mvn -B -f java-wasm -P central deploy \
    -Daprv.server.linux-x86_64=dist/aprv-x86_64-unknown-linux-musl \
    -Daprv.server.linux-aarch64=dist/aprv-aarch64-unknown-linux-musl \
    -Daprv.server.sha256sums=dist/SHA256SUMS
  ```
  Each `-Daprv.server.<classifier>=PATH` activates a profile that copies
  the binary to
  `io/github/emindeniz99/applepurchasereceiptverifier/server/aprv-<target>`
  (mode 755) with its `.sha256`, fails if `SHA256SUMS` does not pin it,
  and attaches the jar with that classifier. `SHA256SUMS` (the release's,
  in `sha256sum`'s format) goes into the main jar as the pins `maven()` and
  `github()` check; the committed one pins only lane B's G1 x86_64 binary.
  Only the x86_64 jar has been built here (4.2 MB); the aarch64 one is
  built the same way from lane D's binary. Neither binary nor classifier
  jar is ever committed.
- Maven Central budget: the classifier jars add about 8.4 MB per release,
  about 10.5 MB with this jar and the main artifact's 85 KB jar. Seven
  releases in a month would use about 74 MB of the 80 MB monthly size
  allowance; count it before cutting a release.
- The jar embeds code compiled from OpenSSL, wasi-libc and the Rust
  standard library. Their licence texts must ship inside it (ARCHITECTURE
  §9, "Licences ship with the code"); this lane found no licence bundle in
  the repository to copy into `META-INF/`, so that is still open.
