# GraalVM 21: a UTF-8 length check its JIT miscompiles

**Question.** Is `InputSizeBoundsTest.receiptStringIsMeasuredInUtf8Bytes`,
which failed on the `java on graalvm 21` CI job, a bug in
`Utf8Length.exceeds`? It feeds whether the Java size cap needs a change. The
answer is no: the code is correct. Graal's JIT compiles it wrong on GitHub's
hosted runners (the update below), and no change was made.

**What failed.** A receipt of 1,572,865 `é` characters is 3,145,730 UTF-8
bytes, over the 3,145,728-byte cap. It should be `TOO_LARGE` and came back
`MALFORMED`. That answer is only reachable if `Utf8Length.exceeds` returned
`false`. It failed on PR #280 at 843c93e and at 2029d20, and passed on that
branch at eda651f and e5908d1. On the other 14 runs checked that day it
passed, PR #285's 6039828 at 16:11 between the two failures among them.
843c93e changed no Java at all from eda651f, and no commit in between
touched `Utf8Length` or the size check. Every other JVM in the matrix,
GraalVM 25 included, passed every run.

**Versions.** Oracle GraalVM 21.0.12+7.1 (`jvmci-23.1-b96`), the build
`actions/setup-java` installs from `download.oracle.com/graalvm/21/latest`;
runner image ubuntu-24.04 (20260927.320.1 and 20261004.327.1). Local
machine: Intel Xeon at 2.80 GHz with AVX-512, 4 cores. Date 2026-10-06.

**Results, all local, same GraalVM build:**

| Run | Wrong answers |
|---|---|
| Full Java suite, as CI runs it (`-Pjdk8-runtime`), 6 times | 0 (6 of 6 passed) |
| `Probe`, one JVM, 300 calls | 0 |
| `Probe`, 300 fresh JVMs, one call each | 0 |
| `Probe2`, ASCII warm-up of 0 to 100 calls first | 0 |
| `VerifierApiTest` and `InputSizeBoundsTest` with `-XX:UseAVX=3`, `2`, `1`, `0` | 0 |

**Reading.** The code is deterministic, so a wrong answer on identical
bytecode points at the JVM, most likely its JIT on a CPU unlike the local
one. A guess that fits the number exactly, and is not confirmed: the `é` is
stored as a Latin-1 byte, and a load that sign-extends it would count it as
ASCII, which sums to exactly 1,572,865 bytes. No verdict changes either way.
A base64 receipt holds no non-ASCII character, so an undercount can only
turn `TOO_LARGE` into `MALFORMED`, and both refuse.

## Update, 2026-10-06 evening: reproduced on GitHub's runners

It failed a third time, on a docs-only PR (#289). The probes then ran on
GitHub's hosted runners, the only place it had been seen (sources in the
folder).

| Runner probe | Wrong answers |
|---|---|
| `Probe`: 300 calls in one JVM, then 50 fresh JVMs, on 6 runners | 0 |
| `Probe2`, every warm-up count, on 6 runners | 0 |
| Two test classes, Graal JIT (the default) | 8 of 48 runs, round 1; 8 of 24, round 2 |
| Full suite, Graal JIT | 3 of 12 runs |
| Two test classes, C2 (`-XX:-UseJVMCICompiler`) | 0 of 48 |
| Two test classes, no Graal (`-XX:TieredStopAtLevel=3`) | 0 of 24 |
| Graal with `VectorizeLoops`, `PartialUnroll` or `LoopPeeling` off | 6, 7 and 6 of 24 |

It fails on AMD EPYC 7763 and 9V45 and on Intel Xeon 6973P-C and Platinum
8573C alike. The local machine stays at 0, as above.

After a wrong answer, the test called `Utf8Length.exceeds` 20 more times:
in 20 of 27 failures it was wrong all 20 times, so the compiled method
stays wrong until it is recompiled. A copy of its loop without the early
exit counted 3,145,730 bytes every time.

**Reading, revised.** Graal's JIT in Oracle GraalVM 21.0.12 miscompiles
`Utf8Length.exceeds` after the test suite's earlier calls have profiled
it. C2 compiles the same bytecode correctly. None of the three loop
optimizations tried is the cause. The code is correct, so no change was
made (owner, Q83 b, 2026-10-06). The `java on graalvm 21` leg stays in
the matrix and fails some runs; it is not a required check.

**What it can change.** A receipt or a JWS is base64, so an undercount
there only turns `TOO_LARGE` into `MALFORMED`. The endpoint's request JSON
can carry non-ASCII text, and on this JVM a body over 3,145,728 UTF-8
bytes but under that many characters can be read instead of refused.
Neither accepts anything unsigned.

**Where this stops holding.** Reopen if it fails on another JVM or a later
GraalVM 21 update, or if a different method gives a wrong answer on
GraalVM. Reconsider the code if a team runs the endpoint on GraalVM 21.
One simpler form exists, `text.getBytes(UTF_8).length > limit` for the
long strings only; it allocates up to three times the input, and nobody
has shown that Graal compiles it correctly.
