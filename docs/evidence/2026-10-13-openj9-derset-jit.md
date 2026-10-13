# OpenJ9 0.61.0 miscompiles BouncyCastle's DERSet.encode

**Question.** Why does the Java suite fail on IBM Semeru in some runs and
pass in others, always with the same counts? The answer decides whether
the Semeru legs stay in the vendor matrix and what a deployment on OpenJ9
has to do.

**Answer.** It is a JIT bug in OpenJ9 0.61.0, not a library bug and not a
test bug. Once OpenJ9 recompiles `org.bouncycastle.asn1.DERSet.encode` at
its `scorching` optimisation level, the compiled method writes every
DER SET's length as the byte `0xFF`, which is `(byte) -1`. That -1 is the
value of DERSet's "length not computed yet" field. Everything else follows
from that: unparseable receipts, certificates whose re-encoded
`TBSCertificate` no longer matches its signature, a failed
`Verifier.create`. Keeping DERSet out of the JIT
(`-Xjit:exclude={org/bouncycastle/asn1/DERSet.*}`) removed the failure in
every run.

## Setup

- 2026-10-13. Ubuntu 24.04 container, 4 vCPU Intel Xeon (AVX-512), 16 GB.
- IBM Semeru Runtime Open Edition 21.0.12.15 (build 21.0.12.1+1-LTS,
  OpenJ9 0.61.0 `a1daf225f5`, OMR `ebd02d912`) and 8.0.504.5 (1.8.0_504-b01,
  OpenJ9 0.61.0), the JDK tarballs from the AdoptOpenJDK `semeru21-binaries`
  and `semeru8-binaries` GitHub releases that CI's setup-java downloads.
- BouncyCastle 1.86 (bcprov, bcutil, bcpkix), JUnit 5.14.4, the Java tree
  at `e6fdce72` (PR #365's head). Tests compiled by OpenJDK 21.0.10 with
  `--release 8`.
- CI's view: the `java on semeru {8,21,25}` legs (Semeru 8.0.504, 21.0.12,
  25.0.4, all OpenJ9 0.61.0) on GitHub's `ubuntu-latest` runners. Four
  failing jobs on 2026-10-13 had identical counts:
  `UnauthenticatedKeyCostTest` 24 run, 6 failures, 16 errors, and every
  later class failing in `DefaultVerifier.probeRuntime`.

## Method

Surefire's own run (`mvn test -Pjdk8-runtime -Djdk8.jvm=<semeru java>`)
ran the classes in a different order on this machine than on CI (surefire's
default is filesystem order), and it passed. The harness in
[2026-10-13-openj9-derset-jit/](2026-10-13-openj9-derset-jit/) therefore
runs CI's order in one JVM with a small JUnit launcher: the 17 classes
before the cost class, the cost class, `ConformanceCasesTest` and
`SignedDataTest`. `Diag` runs inside the same JVM before and after the cost
class (the first runs had no `Diag`). Each run is one JVM. "Corrupt"
means the cost class and every class after it failed with CI's errors:
`0xFF` lengths and `probeRuntime`. Where `Diag` ran, its second block
failed too.
Every run also counts one failure that is not one: `FixtureGeneratorTest`
is skipped by an assumption, and the launcher counts an aborted test as
failed.

## Results

From [logs/results.txt](2026-10-13-openj9-derset-jit/logs/results.txt):

| JVM and options | runs through the cost class | corrupt | other |
|---|---|---|---|
| Semeru 21, no options | 5 | 2 | 2 more runs hung in a JIT thread before the cost class (below) |
| Semeru 21, `-Xjit:verbose={compileStart,compileEnd}` | 4 | 3 | |
| Semeru 21, `-Xjit:disableStoreSinking` | 4 | 2 | 1 run had 4 timing-only failures (two batches ran side by side) |
| Semeru 21, `-Xjit:exclude={org/bouncycastle/asn1/DERSet.*}` | 5 | **0** | |
| Semeru 21, `-Xjit:exclude={org/bouncycastle/asn1/DERSet.encode*}` | 5 | **0** | |
| Semeru 21, `-Xjit:exclude=` and `dontInline=` on `DERSet.getContentsLength*` only | 5 | **0** | |
| Semeru 21, `traceFull` logging of DERSet's two methods | 4 | 0 | tracing slows those compiles; `encode` never went above `hot` |
| Semeru 21, `-Xjit:count=0` | 3 | 0 | each run failed one digest-timing assertion, as compiling everything at first call shifts the timing ratios |
| Semeru 8, no options | 3 | 0 | CI's Semeru 8 leg failed this way in 1 of the 3 job logs read |
| Semeru 21, `-Xint` | 0 | | stopped: the first class alone took over 2 minutes against 7 s with the JIT |
| Semeru 21, surefire, filesystem order | 1 | 0 | |

Without an exclusion, 5 of 9 Semeru 21 runs were corrupt. With any of the
three exclusions, 0 of 15 were.

### The first bad operation

- **A DERSet known answer.** `new DERSet(SEQUENCE{INTEGER 9999, INTEGER 1,
  OCTET STRING[16]}).getEncoded()` gives `31 1b 30 19 ...` in the first
  `Diag` and `31 ff 30 19 ...` in the second, in each of the four corrupt
  runs that had this check
  ([logs/failing-run-excerpt.txt](2026-10-13-openj9-derset-jit/logs/failing-run-excerpt.txt)).
  DER SEQUENCE and OCTET STRING known answers, including long-form lengths,
  stay correct.
- **The receipt TestPki builds.** In one JVM, a receipt encoded before the
  cost class and one encoded after it differ structurally in three places
  only. Each is a SET whose length byte is `0xff`: the payload SET, the
  SignerInfos SET and the RDN SET in the SignerInfo's issuer
  ([logs/receipt-diff.txt](2026-10-13-openj9-derset-jit/logs/receipt-diff.txt)).
  This is CI's `invalid long form definite-length 0xFF`. The encoder is at
  fault: BouncyCastle's parser and the JDK's (CI's `X500 RDN` errors) both
  read the bytes correctly and refuse them.
- **`probeRuntime`.** The bundled Apple roots are intact. Their
  `getEncoded()` matches the base64 constants byte for byte. Raw
  `BigInteger.modPow` recovers the correct PKCS#1 block from each RSA
  root's signature, and the SHA-1 and SHA-256 known answers pass in both
  BouncyCastle and the SUN provider. What fails is the TBS that
  BouncyCastle's `X509CertificateImpl.getTBSCertificate()` re-encodes in
  DER. Its names are SETs, they now carry `0xff`, and the digest no longer
  matches the signature under any provider (SunRsaSign, SunEC,
  BouncyCastle). So the cause is not RSA arithmetic, not a digest and not
  heap corruption.
- **Timing.** In each of the three verbose-logged corrupt runs, the cost
  class's tests passed until OpenJ9 started the `scorching` compile of
  `DERSet.encode`, and the next test failed within 1.5 s. In s21-vlog-3
  the `profiled very-hot` body of `encode` had then been running for 24 s
  without a fault
  ([logs/jit-vlog-derset-failing-run.txt](2026-10-13-openj9-derset-jit/logs/jit-vlog-derset-failing-run.txt)).
  In the five verbose-logged runs that passed, `encode` never got past
  `hot`, even when `getContentsLength` itself reached `scorching`
  ([logs/jit-vlog-derset-passing-runs.txt](2026-10-13-openj9-derset-jit/logs/jit-vlog-derset-passing-runs.txt)).
- **Fail closed.** A verifier built before the miscompile and one built
  after it (with `runtimeProbe(false)`) both answer `UNTRUSTED_CHAIN` for
  the two genuine sandbox receipts under `fixtures/public-receipts/`.
  `Verifier.create` with the probe on throws `IllegalStateException`. In
  CI's four failing jobs, every assertion failure is "unexpected exception
  type" (an `IllegalStateException` where a refusal was expected) and every
  error is an exception. No test that expects a refusal saw an acceptance.

## Hypothesis

An OpenJ9 JIT bug in the `scorching` recompilation of
`DERSet.encode(ASN1OutputStream, boolean)` in bcprov 1.86. The method is
184 bytecodes. It reads the cached field `contentsLength` (initially -1)
and either writes it through the inlined private `getContentsLength()`,
which computes and stores the length when the field is negative, or, for
an unsorted SET of at most 16 elements, computes the length into a local
and writes that. The faulty body writes the uncomputed field. The likely
cause is a field load that the optimiser keeps across the store
`getContentsLength()` makes, or a branch the profile marked never-taken
whose compiled form skips the computation. Which optimisation does it is
not known; the `traceFull` runs that would show the trees never reached
`scorching`.

The trigger is nondeterministic because recompilation to `scorching`
depends on sampling ticks and on how hot `encode` is when the cost class
starts. The cost class builds and encodes cap-sized structures full of
SETs, and that is when the recompilation happened in every logged run. When it does not happen before the suite
ends, the run passes. That explains why CI counts are identical in every
failure (the same test is the first one after the recompile) and why the
same tree passes and fails on the same runner image.

What does not explain it: BouncyCastle (the bytecode is correct, every
HotSpot JVM in the matrix passes every time, and on OpenJ9 the same
method at lower tiers encodes correctly until the `scorching` body is
installed), the tests, heap corruption (the cached roots are intact), and
store sinking
(`-Xjit:disableStoreSinking` still fails).

## A second OpenJ9 bug seen here

On this container, not in CI's logs, a JIT compilation thread sometimes
never finishes compiling `SHA256Digest.processBlock()` at `hot`. It recurses
without end in `TR_SinkStores::genStoreToTempSyms`
([logs/jit-hang-backtrace.txt](2026-10-13-openj9-derset-jit/logs/jit-hang-backtrace.txt)).
The JVM then blocks at its next exclusive operation or at exit, and
surefire kills the fork 30 s after `System.exit` and fails the build with
0 test failures. 11 of 38 Semeru 21 runs and 1 of 3 Semeru 8 runs hung
(`HANG` in results.txt), with or without the DERSet exclusion, and 0 of 4
with `-Xjit:disableStoreSinking`. The stack was captured for two of them;
the others were not checked and could have hung somewhere else. The CI change does not cover it, because CI
has not shown it. If it appears there, add `disableStoreSinking` to the
same `-Xjit:` option: OpenJ9 honours only the last `-Xjit:` on a command
line (checked: of two `-Xjit:` options, only the second took effect).

## Where this stops holding

- One machine type locally (AVX-512 Xeon) and GitHub's runners in CI. The
  miscompile reproduced locally on Semeru 21 only. Semeru 8 and 25 are
  covered by CI's failures, not by local runs. Semeru 8 locally passed 3 of
  3.
- OpenJ9 0.61.0 and bcprov 1.86. Another OpenJ9 release, another
  bcprov, or another call profile may not hit it, or may hit another
  method. The exclusion covers only DERSet.
- Not reproduced outside the suite. Two standalone loops (`DerSetRepro`,
  `DerSetRepro2`) stayed correct, including with DERSet forced to
  `scorching`, so the profile that triggers the bug is not known.
- Not measured: `-Xint` (too slow for the harness), the `-wasm`
  artifact on Semeru, and production traffic patterns.
