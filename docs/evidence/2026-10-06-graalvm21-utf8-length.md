# GraalVM 21: a UTF-8 length check CI saw fail and no one could reproduce

**Question.** Is `InputSizeBoundsTest.receiptStringIsMeasuredInUtf8Bytes`,
which failed on the `java on graalvm 21` CI job, a bug in
`Utf8Length.exceeds`? It feeds whether the Java size cap needs a change. The
answer is no: the code is correct, the failure could not be reproduced, and
no change was made.

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

**Where this stops holding.** Only GraalVM 21.0.12 on GitHub's hosted
runners showed it. Reopen if it fails on another JVM, on a string a real
receipt could carry, or on a later GraalVM 21 update.
