# GraalVM 21 and the UTF-8 length check

| File | Question |
|---|---|
| `Probe.java` | Does `Utf8Length.exceeds`, copied verbatim, ever answer `false` for 1,572,865 `é` characters (3,145,730 UTF-8 bytes) against the 3,145,728-byte cap? Runs it N times in one JVM. |
| `Probe2.java` | Same call after warming the loop with an all-ASCII string of the cap's length, so the JIT compiles it with an ASCII-only profile first. |

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
