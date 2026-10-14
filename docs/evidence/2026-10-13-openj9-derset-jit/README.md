# OpenJ9 DERSet JIT miscompile: harness

The code behind
[../2026-10-13-openj9-derset-jit.md](../2026-10-13-openj9-derset-jit.md).

| file | question it answered |
|---|---|
| `OrderedRun.java` | Runs test classes in a fixed order (CI's surefire order) in one JVM and prints each test with its JVM uptime. The token `DIAG` runs `Diag` at that point instead. |
| `Diag.java` | What is broken inside a JVM that has just failed? It runs digest, BigInteger and DER known-answer checks, encodes a DERSet, builds a TestPki receipt and parses it, compares the cached Apple roots with the bundled constants, verifies each root's signature through the JDK's providers and BouncyCastle, and verifies the two genuine sandbox receipts with a verifier built before the failure and one built after it. With `-Ddiag.dump=<prefix>` it writes the TestPki receipt to `<prefix>-<tag>.der`. |
| `runj.sh` | One run: the 17 classes CI runs before `UnauthenticatedKeyCostTest`, then `DIAG`, the cost class, `DIAG`, `ConformanceCasesTest` and `SignedDataTest`. Kills the JVM after 240 s without output (`WATCHDOG` overrides this), because OpenJ9 also hangs a JIT thread (see the note), and prints one summary line. |
| `batch.sh` | N runs with the same JVM options, appending to `results.txt`. |
| `DerSetRepro.java`, `DerSetRepro2.java` | Can the miscompile be reproduced without the test suite, by encoding DERSets in a hot loop, either uniformly or shaped like the suite's profile? No: `DerSetRepro` stayed correct for 3,000,000 iterations (three runs by default, one with `-Xjit:{org/bouncycastle/asn1/DERSet.*}(optLevel=scorching,count=10)`, one with all of `org/bouncycastle/asn1/*` at scorching), and `DerSetRepro2` for 20,000,000 (two runs). Kept because the answer was no. |
| `logs/results.txt` | Every run's summary line, by configuration. |
| `logs/failing-run-excerpt.txt` | A failing run: the cost class around the first failure, and both `DIAG` blocks. |
| `logs/receipt-diff.txt` | The structural diff between a TestPki receipt encoded before the failure and one encoded after it, in the same JVM. |
| `logs/jit-vlog-derset-*.txt` | OpenJ9 `-Xjit:verbose` lines for DERSet's methods in a failing run and in passing runs. |
| `logs/jit-hang-backtrace.txt` | The JIT compilation thread of a hung run (a separate OpenJ9 bug, in `TR_SinkStores`). |

## Reproduce

Semeru from the GitHub releases CI uses, for example
`https://github.com/AdoptOpenJDK/semeru21-binaries/releases/download/jdk-21.0.12.15/ibm-semeru-open-jdk_x64_linux_21.0.12.15.tar.gz`,
extracted under `$SCRATCH/jdk21`. Build the tests once with any JDK 11 or
later (javac targets 8):

```sh
export REPO=/path/to/repo SCRATCH=/path/outside/repo
mvn -o -q -f "$REPO/java/pom.xml" test-compile
mvn -o -q -f "$REPO/java/pom.xml" dependency:build-classpath \
  -Dmdep.includeScope=test -Dmdep.outputFile="$SCRATCH/cp.txt"
E="$REPO/docs/evidence/2026-10-13-openj9-derset-jit"
mkdir -p "$SCRATCH/scripts" "$SCRATCH/launcher" "$SCRATCH/dumps"
cp "$E"/*.sh "$SCRATCH/scripts/"
CP="$REPO/java/target/test-classes:$REPO/java/target/classes:$(cat "$SCRATCH/cp.txt"):$HOME/.m2/repository/org/junit/platform/junit-platform-launcher/1.14.4/junit-platform-launcher-1.14.4.jar"
javac --release 8 -cp "$CP" -d "$SCRATCH/launcher" "$E/OrderedRun.java" "$E/Diag.java"

J="$SCRATCH/jdk21/jdk-21.0.12.15/bin/java"
"$SCRATCH/scripts/batch.sh" s21-default 4 "$J" ""
"$SCRATCH/scripts/batch.sh" s21-exclDERSet 5 "$J" '-Xjit:exclude={org/bouncycastle/asn1/DERSet.*}'
cat "$SCRATCH/results.txt"
```

A run reproduces the CI failure when its summary shows `diagBad` above 0
and `ff` above 0. The second `DIAG` block then shows
`DER SET{SEQ{9999,1,OCTET[16]}} == 311b3019... :: 31ff3019...`.
Running two batches side by side is fine for the miscompile, but it makes
the cost class's 2 s timing assertions fail now and then. Those failures
show up as `timing` in the summary and are not the bug.
