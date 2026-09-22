# java-bench

JMH benchmarks for the Java port. Not published: like `jvm-interop/`, this is
a standalone Maven project that resolves the library as a Maven coordinate
from the local repository. It is not a module of `java/pom.xml` and has no
release-please entry.

## Build and run

From the repository root:

```bash
mvn -B -f java/pom.xml -Dmaven.test.skip=true install
mvn -B -f java-bench/pom.xml -Dlibrary.version="$(cat version.txt)" package
java -jar java-bench/target/benchmarks.jar                 # timings
java -jar java-bench/target/benchmarks.jar -prof gc        # + bytes/op
java -jar java-bench/target/benchmarks.jar -rf json -rff jmh-result.json
```

Run from anywhere inside the repository: the benchmark finds `fixtures/` by
walking up from the working directory. `library.version` in the pom is only a
default and is not bumped on release, which is why the build line passes
`version.txt`. The `benchmark` workflow (`.github/workflows/benchmark.yml`,
manual dispatch only) runs the same steps and uploads the JSON.

The code is compiled with `--release 8`, the release the library's public
API targets, so it can only call what a Java 8 consumer can call.
`mvn -f java-bench/pom.xml spotless:check` applies the library's formatter
configuration.

## What is measured

One `@State(Scope.Benchmark)` class, `ReceiptBenchmark`, with
`@Param fixture` over two committed, genuine Apple-signed sandbox receipts:

| fixture | in-app purchases | chain | base64 chars | DER bytes |
|---|---:|---|---:|---:|
| `receipt-sandbox-g5` | 2 | SHA-256 | 7,556 | 5,665 |
| `receipt-sandbox-legacy` | 187 | SHA-1 | 105,472 | 79,104 |

Both are verified as `ConformanceCasesTest` verifies them: the built-in
`AppleRootCerts.receiptRoots()`, the bundle id `fixtures/cases.json` pins
(`dev.bonzer.weeka.app`, `com.nutcall.alert`), the file decoded with the MIME
decoder and checked against its `contentSha256`, and re-encoded as canonical
base64 for the string entry points. The endpoint gets a fixed `Clock`
(2026-01-01T00:00:00Z); `ReceiptVerifier` accepts no clock.

| benchmark | call |
|---|---|
| `core` | `ReceiptVerifier.verifyReceiptCore(der, roots)` on pre-decoded DER |
| `verifierBase64` | `new ReceiptVerifier(roots, bundleId).verify(base64)` (verifier built in setup) |
| `endpointMap` | `VerifyReceiptEndpoint` in `SANDBOX`, `verifyReceipt({"receipt-data": base64})`, status 0 with the full receipt |
| `endpointJson` | the same endpoint, `verifyReceiptJson("{\"receipt-data\":\"...\"}")` |
| `endpointWrongEnv` | the endpoint in `PRODUCTION` on the same sandbox receipt, status 21007 |
| `rejectTamperedSignature` | `verifyReceiptCore` on the DER with one bit flipped in the middle of the SignerInfo signature; the `VerificationException` is caught and consumed |

`@Setup` prepares every input and runs each call once, failing the run unless
it gives the expected answer: the right bundle id and in-app count, status 0
with every `in_app` entry rendered, status 21007, and `INVALID_SIGNATURE` for
the tampered receipt (checked for both fixtures). A benchmark therefore cannot
time a fast failure by accident.

Settings: `Mode.AverageTime`, µs/op, 5 warmup and 5 measurement iterations of
1 s each, 2 forks (10 samples per score), one thread, JMH's default (compiler)
blackholes. Error is JMH's 99.9% confidence interval.

## Baseline

Recorded 2026-09-22 at `87e1dea` (library 0.5.1).

- JMH 1.37 (the current release on Maven Central)
- JDK: Eclipse Temurin 21.0.12.1+1, OpenJDK 64-Bit Server VM, default flags
- CPU: Intel(R) Xeon(R) Processor @ 2.80GHz, 4 vCPUs (KVM guest, 1 thread
  per core), 15 GiB RAM; a shared cloud VM

µs/op is from the plain run; bytes/op is `gc.alloc.rate.norm` from a second,
separate run with `-prof gc`, whose own µs/op is shown for comparison.

| benchmark | fixture | µs/op (plain) | µs/op (`-prof gc` run) | bytes/op |
|---|---|---:|---:|---:|
| `core` | g5 | 625.1 ± 274.4 ¹ | 511.8 ± 21.8 | 309,893 |
| `core` | legacy | 3,893.8 ± 269.1 | 3,854.8 ± 189.1 | 4,424,869 |
| `verifierBase64` | g5 | 694.3 ± 37.0 | 699.9 ± 57.0 | 345,681 |
| `verifierBase64` | legacy | 5,240.3 ± 177.8 | 5,323.9 ± 381.3 | 4,926,005 |
| `endpointMap` | g5 | 707.5 ± 45.2 | 727.2 ± 63.0 | 359,357 |
| `endpointMap` | legacy | 5,874.3 ± 168.2 | 5,898.0 ± 352.3 | 5,759,397 |
| `endpointJson` | g5 | 768.1 ± 51.7 | 779.8 ± 70.8 | 370,460 |
| `endpointJson` | legacy | 7,652.6 ± 567.7 | 7,412.1 ± 319.6 | 6,634,021 |
| `endpointWrongEnv` | g5 | 686.5 ± 30.9 | 706.3 ± 41.7 | 346,560 |
| `endpointWrongEnv` | legacy | 5,429.2 ± 352.3 | 5,281.8 ± 209.7 | 4,927,096 |
| `rejectTamperedSignature` | g5 | 484.4 ± 20.1 | 551.9 ± 54.6 | 311,863 |
| `rejectTamperedSignature` | legacy | 3,918.3 ± 168.0 | 3,994.5 ± 284.5 | 4,427,000 |

¹ In the plain run one iteration in each fork of `core`/g5 read 1,006 and
923 µs against about 530 for the rest. A re-run of `core` alone gave
**g5 506.6 ± 42.9** and **legacy 3,873.6 ± 195.9** µs/op, with no outliers.
The derived numbers below use these re-run `core` values; every other input
is the plain column.

## Derived numbers

In µs/op. "g5" and "legacy" as above.

**Map rendering overhead, endpointMap minus core.**
g5: 707.5 − 506.6 = 200.9. Legacy: 5,874.3 − 3,873.6 = 2,000.7.
This difference includes the endpoint's base64 decode, not only rendering;
see the breakdown below.

**JSON overhead, endpointJson minus core.**
g5: 768.1 − 506.6 = 261.5. Legacy: 7,652.6 − 3,873.6 = 3,779.0.

**As a share of endpointJson.**
Map overhead: g5 200.9 / 768.1 = 26.2%; legacy 2,000.7 / 7,652.6 = 26.1%.
JSON overhead: g5 261.5 / 768.1 = 34.0%; legacy 3,779.0 / 7,652.6 = 49.4%.

**Breakdown of endpointJson.** `endpointWrongEnv` runs the same decode and
`verifyReceiptCore` as `endpointMap` and stops before rendering, so the steps
separate:

| step | arithmetic | g5 | share | legacy arithmetic | legacy | share |
|---|---|---:|---:|---|---:|---:|
| verifyReceiptCore | core | 506.6 | 66.0% | core | 3,873.6 | 50.6% |
| decode and routing | 686.5 − 506.6 | 179.9 | 23.4% | 5,429.2 − 3,873.6 | 1,555.6 | 20.3% |
| map rendering | 707.5 − 686.5 | 21.0 | 2.7% | 5,874.3 − 5,429.2 | 445.1 | 5.8% |
| JSON parse and write | 768.1 − 707.5 | 60.6 | 7.9% | 7,652.6 − 5,874.3 | 1,778.3 | 23.2% |
| total | | 768.1 | | | 7,652.6 | |

Allocation for the same steps, from the bytes/op column: rendering
359,357 − 346,560 = 12,797 B (g5) and 5,759,397 − 4,927,096 = 832,301 B
(legacy); JSON 370,460 − 359,357 = 11,103 B and 6,634,021 − 5,759,397 =
874,624 B.

**Scaling from 2 purchases to 187.** Purchases grow 187 / 2 = 93.5×, DER size
79,104 / 5,665 = 14.0×.

| quantity | arithmetic | growth |
|---|---|---:|
| core | 3,873.6 / 506.6 | 7.6× |
| core bytes/op | 4,424,869 / 309,893 | 14.3× |
| map overhead (endpointMap − core) | 2,000.7 / 200.9 | 10.0× |
| JSON overhead (endpointJson − core) | 3,779.0 / 261.5 | 14.5× |
| map rendering alone | 445.1 / 21.0 | 21.2× |
| JSON parse and write alone | 1,778.3 / 60.6 | 29.3× |
| endpointJson total | 7,652.6 / 768.1 | 10.0× |

Everything grows far less than the purchase count. The two output stages grow
fastest, and at 187 purchases they are 2,223.4 µs (445.1 + 1,778.3), 29% of
the JSON endpoint.

**What the 21007 retry costs.** A production endpoint answers 21007 only after
full verification, so a sandbox receipt sent to production first pays almost
a whole verification for nothing: `endpointWrongEnv` is 686.5 / 707.5 = 97.0%
of `endpointMap` for g5 and 5,429.2 / 5,874.3 = 92.4% for legacy.
Production-then-sandbox therefore costs 686.5 + 707.5 = 1,394.0 µs instead of
707.5 (1.97×) for g5, and 5,429.2 + 5,874.3 = 11,303.5 µs instead of 5,874.3
(1.92×) for legacy. Allocation: 346,560 + 359,357 = 705,917 B against 359,357
(1.96×), and 4,927,096 + 5,759,397 = 10,686,493 B against 5,759,397 (1.86×).

**Rejecting a tampered signature costs as much as accepting.**
`rejectTamperedSignature` is 484.4 / 506.6 = 95.6% of `core` for g5 and
3,918.3 / 3,873.6 = 101.2% for legacy, with allocation within 1% (311,863
against 309,893 B; 4,427,000 against 4,424,869 B). This follows the order in
`ReceiptVerifier.verifyCoreUnguarded`: the payload is parsed and the chain
validated before the CMS signature is checked.

## Where the decode time goes

`verifierBase64` is 694.3 − 506.6 = 187.7 µs (g5) and 5,240.3 − 3,873.6 =
1,366.7 µs (legacy) slower than `core`. It also allocates 35,788 B and
501,136 B more. The extra work is `ReceiptBase64.decode` and a bundle-id string
comparison. An ad hoc run with three temporary benchmarks (not
committed; same settings) separated the steps:

| ad hoc benchmark | g5 | legacy |
|---|---:|---:|
| `ReceiptBase64.decode(base64)`, called reflectively | 137.0 ± 6.9 | 1,426.5 ± 112.9 |
| `java.util.Base64.getDecoder().decode(base64)` | 2.9 ± 0.1 | 49.3 ± 1.9 |
| `verifier.verify(der)` (DER, no decode) | 509.8 ± 25.5 | 3,827.4 ± 160.2 |
| `verifier.verify(base64)`, same run | 690.2 ± 52.8 | 5,111.7 ± 131.0 |

In that run, verify(base64) − verify(der) = 690.2 − 509.8 = 180.4 µs (g5) and
5,111.7 − 3,827.4 = 1,284.3 µs (legacy), which the library decoder's own time
covers. The library decoder takes 137.0 / 2.9 = 47× (g5) and 1,426.5 / 49.3 =
29× (legacy) as long as the JDK decoder on the same canonical string. A third
run, with `verifyReceiptCore` on a fresh `der.clone()` per call, gave
529.8 ± 31.6 and 3,935.4 ± 237.4 µs/op, the same as `core`. Reusing one array
across calls does not flatter `core`.

## Caveats

This is one run pair on a shared 4-vCPU cloud VM. The plain `core`/g5 outlier
shows the host can move an iteration by about 90%, and apart from it the same
benchmark differs by up to 67 µs (g5) and 240 µs (legacy) between the two
runs. Read the absolute
numbers as indicative and the ratios between benchmarks in the same run as
the finding. Differences smaller than the combined error, such as rejection
against acceptance, are not distinguishable here. Two receipts are two data
points, and they differ in chain algorithm and DER size as well as purchase
count, so the scaling figures are not a per-purchase cost model. The ad hoc
decode rows come from a separate run using reflection, which adds a little
call overhead to that row. No GC, heap or JIT flags were tuned. Everything
ran single-threaded, so nothing here speaks to contention.
