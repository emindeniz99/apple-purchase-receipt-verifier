# Fuzz targets

Five [Jazzer] targets under [libFuzzer], over the readers this port writes by
hand and the entry points a consumer calls. `run.sh` pairs each with the shared
fixtures that seed it, so nothing under `fixtures/` is copied here.

```bash
./run.sh all                    # every target, 60 s each
./run.sh all 300                # …five minutes each
JOBS=3 ./run.sh all 300         # three at a time
./run.sh receipt 600            # one target, ten minutes
./run.sh list                   # the target names
MVN_ARGS=-o ./run.sh readers    # build offline
```

`run.sh` fetches the Jazzer jars itself (sha256-pinned) and builds the library
and the harness; nothing else needs installing beyond a JDK and Maven.

| target | what it reaches | invariant beyond "nothing but `VerificationException` escapes" |
|---|---|---|
| `receipt` | `ReceiptVerifier.verifyReceiptCore` on raw DER: BouncyCastle's CMS reader, the attribute walk, the PKIX chain build, the CMS signature check | an accepted receipt fails against an unrelated anchor set |
| `receipt-base64` | `ReceiptVerifier.verify(String)` and its device-GUID overload — the string a client sends, so `ReceiptBase64` in front of all of the above, plus the SHA-1 device binding | the same anchor-set invariant, through the string entry point |
| `jws` | `JwsVerifier.verifyTransaction` / `verifyAppTransaction` / `verifyRaw`: strict base64url, Jackson header and payload, x5c decode, marker OIDs, chain, ES256 | a JWS `verifyRaw` accepts under the fixture root is refused under Apple's production JWS roots |
| `endpoint-json` | `VerifyReceiptEndpoint.verifyReceiptJson` on a raw request body | it never throws at all, and the answer is always a JSON object with a numeric `status` |
| `readers` | `ReceiptVerifier.parsePayload`, `ReceiptBase64.decode` and `JwsVerifier.parseJson` called directly, with no CMS parse or chain build in front of them | see "Two containment invariants" below |

Every accepted result is then taken apart. `Harness.touch` reads every accessor
`AppReceipt`, `InAppPurchase`, `TransactionPayload` and `AppTransactionPayload`
declare, plus every claim of an accepted `verifyRaw` map. A receipt the library
has just called Apple-signed is one your next line of code reads, so an
accessor that throws on an accepted-but-strange receipt leaks as surely as a
verifier that throws. `Harness` collects that accessor list by reflection at
startup, so an accessor added to the library gets covered whether or not anyone
remembers this file.

## The containment invariant

The only exception a public entry point may throw is `VerificationException`.
It is asserted as "is not a `VerificationException`" rather than as a list of
forbidden types, because the leak that matters is always the type nobody
thought to list. BouncyCastle reports malformed ASN.1 with *unchecked*
exceptions, and which ones is neither documented nor stable across releases;
`StackOverflowError` from a nested structure and `OutOfMemoryError` from a
length prefix are not exceptions at all. One phrasing covers all of them, and
enumerating types is exactly what let eleven characters of attacker base64
escape the declared contract once already (see
`ReceiptVerifier.verifyCore`'s comment).

`endpoint-json` is stricter still, because its javadoc is: `verifyReceiptJson`
never throws, and its answer is always a JSON object carrying a numeric
`status`. A body that produced a null, a bare stack trace or a response Jackson
cannot read back would each end the run.

### Two containment invariants, and why `readers` has the weaker one

`readers` drives private methods, so the contract to hold them to is the
contract of whoever calls them — not the public one, which would report leaks
that are contained by design one frame up:

* **`ReceiptVerifier.parsePayload`** is reached only through
  `ReceiptVerifier.verifyCore`, which catches `RuntimeException` and rewraps it
  as `INVALID_RECEIPT_FORMAT`. An unchecked exception out of BouncyCastle here
  is therefore contained and is *not* a finding — but an `Error` walks straight
  through that `catch` and out of `verify()`, so a `StackOverflowError` from a
  deeply nested SET or an `OutOfMemoryError` from a length prefix **is** one.
* **`ReceiptBase64.decode`** and **`JwsVerifier.parseJson`** have no such guard
  above them: `verify(String)` decodes *before* it enters the guarded core, and
  the whole JWS path is unguarded end to end. For those two the invariant is
  the strict one.

The split records where the library's containment sits; it is not there to
keep the target quiet. Remove `verifyCore`'s `catch (RuntimeException)` and
`FuzzReaders` has to change with it.

## The anchor-set invariants

These are what let a fuzzer find "accepts what it should not" rather than only
crashes: without them, an input that verifies tells you nothing about *why* it
verified — a chain build that ignored its anchors and a run that found nothing
look identical.

`receipt` and `receipt-base64` trust Apple's three receipt roots **plus**
`fixtures/generated/receipt-root.der`, so both the generated fixtures and the
Apple-signed public receipts get past the chain check and the mutations land on
the code beyond it. Anything they accept must then be refused under the fixture
*JWS* root, which signed no receipt in this repository. `jws` is the mirror
image: the fixture JWS root trusted, Apple's production JWS roots the unrelated
set.

The unrelated set is always a real, well-formed root rather than an empty or
corrupt one. "Rejected because the anchor set was unusable" would prove
nothing.

## Why Jazzer

Jazzer is the JVM's libFuzzer engine, the one OSS-Fuzz runs for Java projects,
and the only maintained coverage-guided fuzzer for the JVM. It instruments
bytecode at class-load time through a Java agent and feeds libFuzzer's 8-bit
counters, so `cov:` and `ft:` in the output mean what they mean everywhere
else. (The .NET port's driver is the exception: there `cov:` counts the native
shim and only `ft:` reflects the library.)

Maintenance, read off Maven Central rather than a changelog: **0.30.0 was
published 2026-02-24**, 0.29.1 on 2025-12-22, and releases have landed every
few months since 0.10 in 2021. The licence is Apache-2.0. It was AGPL before
0.22.0, which matters if anyone ever pins an older version, because this
project is MIT.

## Why the standalone driver, from Maven Central, in two jars

The alternative is a `jazzer-junit` test dependency in the library's own
`pom.xml`. That would put a fuzzing engine in the artifact's dependency graph,
run it in the `java` matrix on five JDKs that have no business fuzzing, and
make the harness subject to the pom's `--release 8` floor. Driving the
standalone driver from `run.sh` instead keeps `pom.xml` a description of what
ships.

Central rather than the GitHub release zip: it is the same driver — the
`jazzer` artifact carries `libjazzer_driver` and the fuzzed-data-provider
natives for Linux, macOS and Windows on x86-64 and aarch64 — and it comes from
the mirror this project's Maven build already reaches, with the publisher's own
`.sha256` file to check the pin against. (It is also the only one reachable
from some networks: GitHub release downloads are blocked outright behind
certain proxies, Central is not.)

**Two coordinates, not one**, and the failure is unhelpful if you get it wrong:
`jazzer` carries the driver, the agent and the natives, but the handful of
`com.code_intelligence.jazzer.api` classes the driver reflects over live only
in `jazzer-api`. Without it the run dies before its first execution with
`NoClassDefFoundError: AutofuzzConstructionException` and nothing to suggest
the cause is packaging. For the same class of reason `run.sh` uses `java -cp
jazzer.jar:… com.code_intelligence.jazzer.Jazzer` rather than the driver's own
`--cp` flag: that flag is documented "native launcher only" and is silently
ignored when Jazzer starts from the jar, leaving the target class not-found on
a class path holding nothing but Jazzer.

## Layout, and what it deliberately does not touch

`java/fuzz` is **not** a Maven module and is not in the pom's source roots.
`run.sh` builds the library with Maven, asks Maven for the runtime classpath
(`dependency:build-classpath`), and compiles `src/` against that with a plain
`javac`. Consequences, all of them intended:

* The published artifact and the `java` matrix are untouched — no fuzzing
  dependency exists anywhere in the reactor.
* The harness is **not** held to the pom's `--release 8` floor. It is never
  shipped and never runs on a Java 8 JVM; it is compiled by the same modern JDK
  that runs Jazzer, which is what CI does too. The library it fuzzes is still
  the real Java 8 bytecode out of `target/`.
* It *is* held to the same format as the library: the pom's Spotless
  configuration names `fuzz/src/**/*.java` in its `includes`, so the
  `java-format` CI job (`mvn spotless:check`) covers the harness. Spotless is
  bound to no lifecycle phase, so this costs `mvn test` nothing.

The three package-private and private readers a target reaches directly are
reached by reflection (`FuzzReaders`), bound once at startup. The alternative
is widening their visibility, which would mean changing the shipped jar in
order to test it. Reflection costs a few hundred nanoseconds against readers
that take microseconds, and because it is the library's own bytecode that runs,
Jazzer's instrumentation reports the coverage either way.

Nothing under `fixtures/` is copied here. `run.sh` passes the fixture
directories to libFuzzer as read-only corpora, and builds the `endpoint-json`
seeds — `verifyReceipt` request bodies, which no fixture is — at run time under
`.seeds/` (gitignored) from the shared base64 receipts.

## Throughput

Measured here on a shared 4-core x86-64 box, three targets at a time, 240 s
each, from a corpus warmed by an earlier pass. `cov` is Jazzer's edge coverage
over the instrumented set (this port, BouncyCastle, Jackson); `ft` is
libFuzzer's feature count.

| target | execs | exec/s | cov | ft |
|---|---|---|---|---|
| `jws` | 3 009 392 | 12 487 | 5 152 | 7 900 |
| `receipt` | 1 593 641 | 6 612 | 2 246 | 6 877 |
| `readers` | 869 442 | 3 607 | 2 889 | 8 367 |
| `endpoint-json` | 482 655 | 2 002 | 5 102 | 11 229 |
| `receipt-base64` | 143 453 | 595 | 1 910 | 4 706 |

The two slow targets are slow for a good reason: `receipt-base64` and
`endpoint-json` seed from whole base64 receipts, so libFuzzer raises `max_len`
to tens of kilobytes and every unit is a full decode plus chain build. They buy
depth rather than executions. `jws` is fast for a less good one: most mutations
die at "expected 3 dot-separated segments", so its execution count buys less
than its rank suggests — read its `cov`, which is the highest here, instead.

### The acceptance rates are the number to watch

A target whose seeds never verify still reports coverage, still finds no crash,
and still looks healthy — while its anchor-set invariant never runs once. What
the fixtures do under each target's own anchors, measured:

| target | fixtures accepted |
|---|---|
| `receipt` | 6 of 28 `fixtures/generated/*.der` |
| `receipt-base64` | 8 of 16 `fixtures/generated/receipt-b64/*` |
| `jws` | 3 of 14 `fixtures/generated/*.jws` |
| `endpoint-json` | a genuine body answers `{"status":0,…}` |

`receipt-base64` read 0 of 16 until its verifier was bound to
`Harness.RECEIPT_BUNDLE_ID`: the base64 corpus is a genuine public receipt for
`dev.bonzer.weeka.app`, not the generated fixture for `com.example.app`, so
every seed was refused for its bundle id before the anchor comparison could
happen. Re-check these counts after touching the anchors, the bundle ids or the
seed lists.

## Corpus and findings

`.jazzer/`, `.build/`, `.seeds/`, `corpus/` and `artifacts/` are gitignored. A
crasher lands under `artifacts/<target>/` together with a Java reproducer;
reduce it and pin it as a test under `../src/test`, where it runs on every JDK
in the matrix rather than only where a fuzzer is installed.

Replaying one needs no environment beyond the fixtures, which `Harness` finds
at `../../fixtures` when `APRV_FIXTURES` is unset:

```bash
java -cp .jazzer/jazzer-0.30.0.jar:.jazzer/jazzer-api-0.30.0.jar:$(cat .build/deps.txt) \
     com.code_intelligence.jazzer.Jazzer \
     --target_class=io.github.emindeniz99.applepurchasereceiptverifier.fuzz.FuzzReceiptDer \
     artifacts/receipt/crash-…
```

CI (`java-fuzz` in `.github/workflows/ci.yml`) runs each target for a fixed
budget on every push.

[Jazzer]: https://github.com/CodeIntelligenceTesting/jazzer
[libFuzzer]: https://llvm.org/docs/LibFuzzer.html
