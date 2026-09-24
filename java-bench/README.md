# java-bench

JMH benchmarks for the Java port. Not published: like `jvm-interop/`, this is
a standalone Maven project that resolves the library as a Maven coordinate
from the local repository. It is not a module of `java/pom.xml`.

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
default. release-please bumps it together with `version.txt`, and the build
line passes `version.txt` anyway so the two can never disagree.
The `benchmark` workflow (`.github/workflows/benchmark.yml`,
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
| `decodeBase64` | the package-private `ReceiptBase64.decode(base64)`, bound once by reflection; added for the cross-port set in `BENCHMARKS.md` and not in the baseline below |
| `core` | `ReceiptVerifier.verifyReceiptCore(der, roots)` on pre-decoded DER |
| `verifierBase64` | `new ReceiptVerifier(roots, bundleId).verify(base64)` (verifier built in setup) |
| `endpointMap` | `VerifyReceiptEndpoint` in `SANDBOX`, `verifyReceiptResult({"receipt-data": base64}).toResponse()`, status 0 with the full receipt |
| `endpointJson` | the same endpoint, `verifyReceiptJson("{\"receipt-data\":\"...\"}")` |
| `endpointWrongEnv` | the endpoint in `PRODUCTION` on the same sandbox receipt, `verifyReceiptResult(...).toResponse()`, status 21007 |
| `resultOnly` | the `SANDBOX` endpoint, `verifyReceiptResult(...)` with no rendering |
| `retryViaResult` | the `PRODUCTION` endpoint, `verifyReceiptResult(...).toJson(Environment.SANDBOX)`: the 21007 retry without a second verification |
| `rejectTamperedSignature` | `verifyReceiptCore` on the DER with one bit flipped in the middle of the SignerInfo signature; the `VerificationException` is caught and consumed |

`@Setup` prepares every input and runs each call once, failing the run unless
it gives the expected answer: the right bundle id and in-app count, status 0
with every `in_app` entry rendered, status 21007, a result with status 0
and a receipt, a Sandbox status-0 body from the production result, and `INVALID_SIGNATURE` for
the tampered receipt (checked for both fixtures). A benchmark therefore cannot
time a fast failure by accident.

Settings: `Mode.AverageTime`, µs/op, 5 warmup and 5 measurement iterations of
1 s each, 2 forks (10 samples per score), one thread, JMH's default (compiler)
blackholes. Error is JMH's 99.9% confidence interval.

## Baseline, 2026-09-24

Recorded 2026-09-24 on branch `fix/java-prerelease-polish` at `ddda8c0`
(library version string 0.5.1, the 0.6.0 candidate), built as above.

- JMH 1.37, default (compiler) blackholes
- JDK: OpenJDK 21.0.10 (Ubuntu build 21.0.10+7-Ubuntu-124.04), 64-Bit
  Server VM, default flags
- CPU: Intel(R) Xeon(R) Processor @ 2.10GHz, `nproc` 4, 15 GiB RAM; a
  shared cloud VM, nothing else CPU-heavy running
- µs/op: the settings in the pom (5 warmup and 5 measurement iterations of
  1 s, 2 forks, 10 samples per score); the run took 6 min 36 s
- bytes/op: `gc.alloc.rate.norm` from a second, shorter run,
  `-prof gc -f 1 -wi 3 -i 3`; allocation is stable across iterations, its
  timings (3 samples) are not and are left out

| benchmark | fixture | µs/op | bytes/op |
|---|---|---:|---:|
| `decodeBase64` | g5 | 2.4 ± 0.1 | 13,264 |
| `decodeBase64` | legacy | 29.2 ± 2.7 | 184,608 |
| `core` | g5 | 593.5 ± 33.2 | 426,790 |
| `core` | legacy | 3,517.5 ± 180.6 | 4,613,084 |
| `verifierBase64` | g5 | 594.7 ± 25.7 | 439,469 |
| `verifierBase64` | legacy | 3,666.5 ± 247.6 | 4,789,916 |
| `endpointMap` | g5 | 612.2 ± 61.5 | 453,373 |
| `endpointMap` | legacy | 4,040.8 ± 282.4 | 5,599,422 |
| `endpointJson` | g5 | 647.2 ± 56.2 | 480,217 |
| `endpointJson` | legacy | 4,488.1 ± 245.8 | 6,446,106 |
| `endpointWrongEnv` | g5 | 600.1 ± 44.6 | 439,658 |
| `endpointWrongEnv` | legacy | 3,598.0 ± 182.7 | 4,790,158 |
| `resultOnly` | g5 | 627.8 ± 30.0 | 439,448 |
| `resultOnly` | legacy | 3,717.0 ± 150.1 | 4,797,485 |
| `retryViaResult` | g5 | 624.7 ± 87.3 | 455,877 |
| `retryViaResult` | legacy | 4,515.9 ± 202.3 | 6,203,549 |
| `rejectTamperedSignature` | g5 | 604.3 ± 61.3 | 368,886 |
| `rejectTamperedSignature` | legacy | 1,111.2 ± 57.2 | 799,014 |

Against the 2026-09-22 baseline below, the endpoint on the legacy receipt
is faster (`endpointJson` 7,652.6 to 4,488.1 µs); the base64 changes in
the sections at the end account for much of it (`decodeBase64` legacy is
now 29.2 µs). `core` on g5 reads higher (506.6 then, 593.5 now) on a
different, slower-clocked host, so compare ratios within one run rather
than absolute numbers across the two.

Rejecting a tampered signature no longer costs as much as accepting for
legacy: 1,111.2 against 3,517.5 µs for `core`, and 0.8 MB against 4.6 MB
allocated. `ReceiptVerifier.verifyCoreUnguarded` now checks the chain and
the CMS signature before parsing the payload beyond its creation date, so
a receipt that fails the signature skips the 187-purchase parse. The
"Derived numbers" section below describes the older order.

## Baseline, 2026-09-22

Recorded 2026-09-22 at `87e1dea` (library 0.5.1). The derived numbers,
decode breakdown and caveats that follow refer to this run.

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

## 2026-09-22: base64 fast path

`ReceiptBase64.decode` now tries `Base64.getDecoder().decode(receipt)` first
and falls back to the tolerant parser only when the JDK decoder refuses the
string. Every benchmark that decodes base64 got faster; `core`, which starts
from DER, did not move.

Both columns come from one session on the same machine, run back to back:
"before" is `5e8652f` (origin/main, the code the baseline measured), "after"
is the fast-path commit. JDK 21.0.10 (OpenJDK 64-Bit Server VM, Ubuntu build
21.0.10+7), 4 vCPUs of an Intel(R) Xeon(R) Processor @ 2.80GHz, 15 GiB RAM.
Same JMH settings as the baseline, plain run, no `-prof gc`. µs/op.

| benchmark | fixture | before | after | change |
|---|---|---:|---:|---:|
| `core` | g5 | 498.1 ± 38.0 | 513.9 ± 32.0 | within error |
| `core` | legacy | 3,796.5 ± 183.5 | 3,743.5 ± 184.8 | within error |
| `verifierBase64` | g5 | 689.5 ± 34.6 | 545.8 ± 36.4 | −143.7 (−20.8%) |
| `verifierBase64` | legacy | 5,264.3 ± 210.7 | 4,219.1 ± 364.9 | −1,045.2 (−19.9%) |
| `endpointMap` | g5 | 711.6 ± 47.1 | 581.7 ± 55.8 | −129.9 (−18.3%) |
| `endpointMap` | legacy | 5,935.9 ± 241.9 | 4,634.9 ± 220.2 | −1,301.0 (−21.9%) |
| `endpointJson` | g5 | 783.6 ± 60.0 | 593.7 ± 57.7 | −189.9 (−24.2%) |
| `endpointJson` | legacy | 7,649.8 ± 483.7 | 5,960.8 ± 401.3 | −1,689.0 (−22.1%) |
| `endpointWrongEnv` | g5 | 702.0 ± 41.6 | 550.3 ± 39.5 | −151.7 (−21.6%) |
| `endpointWrongEnv` | legacy | 5,299.6 ± 255.1 | 4,092.9 ± 244.9 | −1,206.7 (−22.8%) |

**What decoding costs now.** `verifierBase64` minus `core` fell from
689.5 − 498.1 = 191.4 to 545.8 − 513.9 = 31.9 µs (g5) and from
5,264.3 − 3,796.5 = 1,467.8 to 4,219.1 − 3,743.5 = 475.6 µs (legacy). The
g5 gap is now in the range of the JDK decoder's own 2.9 µs plus noise. The
legacy gap is larger than the JDK decoder's 49.3 µs, but it sits inside the
combined error of the two rows (± 365 and ± 185), so this run cannot say
whether any of it is real.

**Why the answers cannot change.** The JDK's strict decoder accepts exactly
the strings made of `[A-Za-z0-9+/]` whose data length is not congruent to 1
mod 4, followed by either no padding or exactly the canonical `=` run, with
nothing after it. The empty string is the one such input the contract
rejects, and `decode` refuses it (and whitespace-only strings) before the
fast path. Every other string the JDK accepts passes each rule of the
tolerant parser: there is nothing to strip, one alphabet, only `=` after the
padding, a length that is not 1 mod 4, and a padding count that is zero or
correct. The tolerant parser then hands the JDK decoder the same data with
canonical padding, which decodes to the same bytes. Anything the JDK refuses
falls through to the tolerant parser unchanged, so every rejection keeps its
reason and message. `ReceiptBase64FastPathTest` checks this on 20,000 seeded
inputs plus hand-picked edges, comparing `decode` with the tolerant path
alone.

Superseded on 2026-09-23: `receipt-data` is now canonical standard base64
only, as Apple's verifyReceipt measured, so the tolerant parser and
`ReceiptBase64FastPathTest` are gone and `decode` is the JDK decoder behind
a length check.

## 2026-09-22: `VerifyReceiptResult`

The endpoint benchmarks moved to `verifyReceiptResult`, and two were added:
`resultOnly` (verification with no rendering) and `retryViaResult` (a
production endpoint's result re-rendered for Sandbox, the 21007 retry
without a second verification).

"Before" is `5e8652f` (origin/main, the old `verifyReceipt(Map)` API),
"after" is the `VerifyReceiptResult` commit. Both ran in one session on the
same machine: JDK 21.0.10 (OpenJDK 64-Bit Server VM, Ubuntu build
21.0.10+7), 4 vCPUs of an Intel(R) Xeon(R) Processor @ 2.80GHz, 15 GiB RAM.
Same JMH settings as the baseline, plain run, no `-prof gc`. µs/op. Both
runs predate the base64 fast path above, so decoding costs what it did in
the baseline.

| benchmark | fixture | before | after |
|---|---|---:|---:|
| `core` | g5 | 498.1 ± 38.0 | 509.0 ± 30.5 |
| `core` | legacy | 3,796.5 ± 183.5 | 3,825.3 ± 174.7 |
| `endpointMap` | g5 | 711.6 ± 47.1 | 716.7 ± 38.9 |
| `endpointMap` | legacy | 5,935.9 ± 241.9 | 6,023.0 ± 378.7 |
| `endpointJson` | g5 | 783.6 ± 60.0 | 780.7 ± 77.6 |
| `endpointJson` | legacy | 7,649.8 ± 483.7 | 7,349.0 ± 392.0 |
| `endpointWrongEnv` | g5 | 702.0 ± 41.6 | 680.9 ± 22.6 |
| `endpointWrongEnv` | legacy | 5,299.6 ± 255.1 | 5,523.6 ± 374.3 |
| `resultOnly` | g5 | | 701.9 ± 49.7 |
| `resultOnly` | legacy | | 5,271.1 ± 176.7 |
| `retryViaResult` | g5 | | 737.4 ± 55.4 |
| `retryViaResult` | legacy | | 6,954.2 ± 402.3 |

**The existing entry points did not move.** Every before/after pair above is
within its combined error. Building the result and rendering it later costs
nothing measurable against rendering inline.

**`resultOnly` costs what `endpointWrongEnv` did**: 701.9 against 702.0
(g5) and 5,271.1 against 5,299.6 (legacy). Both run the decode and
`verifyReceiptCore` and render nothing, which is the expected match.

**What the 21007 retry costs now.** Before, a sandbox receipt sent to
production first had to be verified twice. Like for like against
`retryViaResult`, which ends in JSON:

| path | g5 | legacy |
|---|---:|---:|
| before: `endpointWrongEnv` + `endpointJson` | 702.0 + 783.6 = 1,485.6 | 5,299.6 + 7,649.8 = 12,949.4 |
| after: `retryViaResult` | 737.4 | 6,954.2 |
| saved | 748.2 (50.4%) | 5,995.2 (46.3%) |

The before row adds two separately measured means and the JSON request
parse, which `retryViaResult` does not do (it takes the map), so the saving
is slightly overstated; the JSON parse was measured at 60.6 (g5) and
1,778.3 µs (legacy) for parse and write together in the baseline breakdown.
`retryViaResult` minus `resultOnly`, 35.5 (g5) and 1,683.1 µs (legacy), is
the price of rendering the Sandbox body as JSON.

The caveats of the baseline apply: one run pair on a shared cloud VM.
