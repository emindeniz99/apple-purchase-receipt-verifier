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
  mvn -B -f java-wasm verify -Dtest.jvm="$JAVA_UNDER_TEST/bin/java"
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
  (`ClasspathGuardTest`).
- Time: about 2.5 minutes for `verify` on JDK 21 on a loaded 4-CPU
  machine, most of it the 311 cases.
- **The corpus** (MIGRATION 3.7): the 1,179 corpus rows plus 5,000
  mutants through the built jar, on Linux x64 and arm64, macOS arm64,
  Windows x64 and arm64. `scripts/corpus.sh OUT_DIR [THREADS]` runs it and
  prints round 13's `classify.py` lines; it needs `CALLS_V1` and
  `NODEROWS` (the ABI v1 calls and Node reference rows, which are not in
  the repository today) and python3. For the release module, the reference
  becomes native rows and the expectation is lane A's; the job must fail
  on any row that is not byte-identical (after the `request_date*` mask).
  Run it once single-threaded and once with 4 threads: the rows must be the
  same.
- Failure means: a case that answers differently from `fixtures/cases.json`,
  an ABI misuse that no longer traps, a Java 11 class in the facade, a
  native-loading reference, or a `System.getProperty`/`System.getenv` in
  `src/main`.

### Measured in this lane (2026-09-29, the stand-in module)

On a shared 4-CPU Linux x86_64 machine with a load average of 6 to 20
from other builds, so timings are for the record, not for comparison:

- `mvn verify`: 366 tests, 0 failures, 2 skipped (the two Java-8-only
  tests) on JDK 21 (OpenJDK 21.0.10), Temurin 11.0.32.1 (a JRE; tests
  forked onto it) and Temurin 17.0.20.1. `ClassFileTest`: 33 classes at
  major 52, 34 at major 55; 475 classes scanned on the consumer
  classpath, no native method and no native-loading reference. The 311 cases on each JDK: 311 ran, 90 passed,
  221 listed stand-in differences, 0 failed, 0 skipped.
- Java 8 leg (`-Pjava8-tests`, Temurin 8u504): 32 tests, 0 failures,
  1 skipped (the Java-11-only test).
- The main artifact after the guard change: `mvn -f java verify` 516
  tests, 0 failures, 1 skipped (the fixture generator, as before), on
  JDK 21 and with `-Pjdk8-runtime` on Temurin 8u504; `spotless:check`
  clean in both modules.
- `-Pclasspath-guard`: `ClasspathGuardJarsIT` 3 of 3; the Gradle
  project above fails with "Cannot select module with conflict on
  capability 'io.github.emindeniz99:apple-purchase-receipt-verifier:0.7.0'"
  (Gradle 8.14.3), and resolves the `-wasm` artifact alone to its jar,
  Endive's `runtime` and `wasm`, and jackson-core.
- Corpus through the built jar, JDK 21: 6,176 identical, 2
  `clock-moves-chain`, 1 `init-refusal` (AS EXPECTED), 0 traps, both
  single-threaded and on 4 threads; the 4-thread rows equal the
  single-thread rows on all 6,179 (30 wall-clock endpoint rows compared
  with `request_date*` masked).
- `scripts/bench.sh 45 1 2 4` on JDK 21: first instance 842 ms, later
  instances 7.0 ms (median of 20), first g5 call 489 ms; g5 receipts
  81.0, 136.3 and 96.3 per second and JWS 25.6, 32.2 and 20.0 per second
  at 1, 2 and 4 threads. The Endive evaluation measured 154.7 g5 and
  52.6 JWS per second on one thread on an idle machine; rerun on a quiet
  runner before quoting these.

### The stand-in module

Until lane A's release build replaces `src/main/wasm/aprv.wasm` (and its
`.sha256`), the committed module is the round-13 stand-in: the
canonical-ABI build of the 0.6 core, SHA-256
`da786ac853464e7b837c5483f9b04a27a3a5c2ff0340fa526f60482fd80fdb68`. It
writes 0.6's reason names and result shapes, so 221 of the 311 cases
answer differently. `src/test/resources/.../stand-in-differences.txt` lists
them by id and category; `ConformanceCasesTest` applies the list only while
the module's SHA-256 is the stand-in's, and fails if a listed case starts
passing. With the release module every case must pass; delete the list
then.

Replacing the module is two files: copy the release `aprv.wasm` to
`java-wasm/src/main/wasm/aprv.wasm` and write its hash, in `sha256sum`'s
format, to `java-wasm/src/main/wasm/aprv.wasm.sha256`. The build refuses a
module whose hash differs from that file.

## `java-wasm-java8`

The facade and the engine API on a real Java 8 JVM (fold it into
`java-runtime-8` if preferred). The Endive tests are tagged `endive` and
left out by the `java8-tests` profile; nothing else is skipped.

```sh
mvn -B -f java-wasm verify -Pjava8-tests -Dtest.jvm="$JDK8/bin/java"
```

On Java 8 the Endive classes are never loaded; `Verifier.create(config)`
throws `UnsupportedOperationException("server engine: pending")` and
`Engine.endive()` throws `IllegalStateException` at `create`, both
asserted. When the server engine lands, this leg runs the 311 cases
through it (SURFACE.md §7), and Temurin 8 moves to Zulu or Corretto 8
before Temurin 8 builds end in late 2026 (R25).

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

Add `java-wasm/src/main/wasm/aprv.wasm` to the copies checked against the
release's SHA-256 (with `go/internal/wasm/aprv.wasm` and the others), and
check that `java-wasm/src/main/wasm/aprv.wasm.sha256` names the same hash.
The Endive input is committed like Go's and Swift's copies, so the
`release-please.yml` step that refreshes those copies refreshes this one
too.

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
  Files per release: the jar (about 1.8 MB with the stand-in), sources,
  javadoc (the public API only: the `central` profile points javadoc at
  `src/main/java`), the `.module` file, the CycloneDX SBOM, their
  signatures. The two server classifier jars (`linux-x86_64`,
  `linux-aarch64`, MIGRATION 3.4) join this deployment when the server
  engine lands.
- The jar embeds code compiled from OpenSSL, wasi-libc and the Rust
  standard library. Their licence texts must ship inside it (ARCHITECTURE
  §9, "Licences ship with the code"); this lane found no licence bundle in
  the repository to copy into `META-INF/`, so that is still open.
