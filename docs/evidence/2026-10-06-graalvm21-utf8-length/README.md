# GraalVM 21 and the UTF-8 length check

| File | Question |
|---|---|
| `Probe.java` | Does `Utf8Length.exceeds`, copied verbatim, ever answer `false` for 1,572,865 `é` characters (3,145,730 UTF-8 bytes) against the 3,145,728-byte cap? Runs it N times in one JVM. |
| `Probe2.java` | Same call after warming the loop with an all-ASCII string of the cap's length, so the JIT compiles it with an ASCII-only profile first. |
| `runner-probe-round1.yml` | On six GitHub-hosted runners: the two probes, then `VerifierApiTest` and `InputSizeBoundsTest` together under Graal's JIT and under C2, then the full suite. |
| `runner-probe-round2.yml` | The two test classes with single Graal loop optimizations turned off, and with Graal off (`-XX:TieredStopAtLevel=3`). |
| `runner-probe-round3.yml` | The two test classes, 48 runs under Graal's JIT, on `Utf8Length` rewritten as `text.getBytes(UTF_8).length`. |
| `runner-probe-instrumentation.patch` | What round 2 added to `InputSizeBoundsTest`: after a wrong answer, call `Utf8Length.exceeds` 20 more times and count the bytes with a copy of its loop. |

Oracle GraalVM for JDK 21 is downloaded to `$SCRATCH`; it is not kept here.

```sh
curl -sSL -o "$SCRATCH/graal21.tgz" https://download.oracle.com/graalvm/21/latest/graalvm-jdk-21_linux-x64_bin.tar.gz
tar -xzf "$SCRATCH/graal21.tgz" -C "$SCRATCH"
J="$(ls -d "$SCRATCH"/graalvm-jdk-21*)/bin"
"$J/javac" -d "$SCRATCH/probe" Probe.java Probe2.java

# One JVM, 300 calls; then 300 fresh JVMs, one call each.
"$J/java" -cp "$SCRATCH/probe" Probe 300
for i in $(seq 300); do "$J/java" -cp "$SCRATCH/probe" Probe 1; done | grep -c 'wrong 0'

# Warmed with ASCII first, at several warm-up counts.
for w in 0 1 2 3 5 10 30 100; do "$J/java" -cp "$SCRATCH/probe" Probe2 $w; done

# The real suite on GraalVM, as CI runs it, at each AVX level.
for avx in 3 2 1 0; do
  mvn -B -q -f "$REPO/java/pom.xml" test -Pjdk8-runtime "-Djdk8.jvm=$J/java" \
    "-DargLine=-XX:UseAVX=$avx" -Dtest=VerifierApiTest,InputSizeBoundsTest
done
```

The workflows ran from the branch `spike/graalvm21-runner-probe`, each as
`.github/workflows/graalvm21-probe.yml`: round 1 at `5976bf6`, round 2 at
`27b0f80` and round 3 at `0cdcc0c`, the last two with the patch applied to
`java/`. Its commits are kept in the closed, unmerged [#295](https://github.com/emindeniz99/apple-purchase-receipt-verifier/pull/295).
