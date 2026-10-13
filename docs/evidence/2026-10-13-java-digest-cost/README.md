# Java: the cost of the SignerInfo's digest algorithm: sources

The note is [`../2026-10-13-java-digest-cost.md`](../2026-10-13-java-digest-cost.md).

| File | Question it answered |
|---|---|
| `DigestSurvey.java` | How long every `MessageDigest` BouncyCastle registers takes over 8 MiB, one per implementing class, best of three warm runs after one. The first survey. |
| `DigestSweep.java` | `DigestDenylistCostTest`'s measurement with a fixed round count: every digest OID the CMS verifier's calculator provider resolves, timed interleaved over the same bytes, best of the measured rounds over SHA-256's. Which digests form the slow cluster, and where the test's band edges go. |
| `DigestLeverProbe.java` | What one `verifyReceipt` call costs when a cap-sized receipt's four SignerInfos name the test PKI's genuine leaf and declare a given digest; `cold` is one call in a fresh JVM, `warm` six calls in one. |
| `variants.mjs` | The genuine G5 sandbox receipt with its one SignerInfo's digestAlgorithm set to each of the eight refused digests, spliced as `tools/generate-signer-info-fixtures.mjs` splices; `md2.der` is the shared fixture `refused-digest-alone.der`. |
| `JavaVerdicts.java`, `core_verdicts.rs` | What Java and the core answer for each of those eight receipts under the default roots. |
| `run.sh` | `DigestLeverProbe` for a list of OIDs on JDK 21 and JDK 8, three cold runs and one warm run each. |
| `results/survey-jdk21.txt` | `DigestSurvey` on JDK 21. |
| `results/sweep.txt` | `DigestSweep` three times per JDK (8, 11, 21) and setting; each block is headed by its arguments. |
| `results/test-tables.txt` | `DigestDenylistCostTest`'s table once per JDK, printed by running it with both edges set where no digest can pass. |
| `results/lever-before.txt` | `run.sh` for GOST R 34.11-94, MD2 and SHA-256 on `main` at `da79ce4d`, before the denylist. |
| `results/verdicts.txt` | `core_verdicts.rs` then `JavaVerdicts`, on the branch. |
| `results/lever-three-refused.txt` | `run.sh` with only GOST R 34.11-94, MD2 and Whirlpool refused, for those three, Streebog, DSTU 7564-384 and -512 and SHA-256: what the rest of the cluster cost while it was still digested. |
| `results/lever-after.txt` | `run.sh` on the branch with all eight refused, for the eight, RIPEMD-160 and SHA-256. |

## Reproduce

`$REPO` is a checkout that has this folder, `$SCRATCH` any directory
outside it, `$JAVA8`, `$JAVA11` and `$JAVA21` three `java` launchers. Every build
output goes to `$SCRATCH`. Check out `da79ce4d` for the figures before
the denylist and the branch for the figures after.

```sh
E="$REPO/docs/evidence/2026-10-13-java-digest-cost"
mvn -B -q -f "$REPO/java/pom.xml" test-compile
mvn -B -q -f "$REPO/java/pom.xml" dependency:build-classpath \
  -DincludeScope=test -Dmdep.outputFile="$SCRATCH/deps.txt"
LIB="$REPO/java/target/classes:$REPO/java/target/test-classes:$(cat "$SCRATCH/deps.txt")"
javac -nowarn --release 8 -d "$SCRATCH/classes" -cp "$LIB" "$E"/*.java
node "$E/variants.mjs" "$REPO" "$SCRATCH/variants"
cp "$E/core_verdicts.rs" "$REPO/rust/tests/"
APRV_VARIANTS="$SCRATCH/variants" cargo test --manifest-path "$REPO/rust/Cargo.toml" \
  --test core_verdicts -- --nocapture | grep '^core' > "$SCRATCH/verdicts.txt"
rm "$REPO/rust/tests/core_verdicts.rs"
"$JAVA21" -cp "$SCRATCH/classes:$LIB" JavaVerdicts "$SCRATCH/variants" >> "$SCRATCH/verdicts.txt"
CP="$SCRATCH/classes:$LIB"

"$JAVA21" -cp "$CP" DigestSurvey > "$SCRATCH/survey-jdk21.txt"
for args in "1024 2 5" "2048 2 5" "512 2 5" "512 3 7" "512 4 5" "256 6 8"; do
  echo "== $args"
  for j in "$JAVA8" "$JAVA11" "$JAVA21"; do
    for i in 1 2 3; do "$j" -cp "$CP" DigestSweep $args; done
  done
done > "$SCRATCH/sweep.txt"
sh "$E/run.sh" "$JAVA21" "$JAVA8" "$CP" \
  1.2.643.2.2.9,1.2.840.113549.2.2,1.0.10118.3.0.55,1.2.643.7.1.1.2.2,1.2.643.7.1.1.2.3,1.2.804.2.1.1.1.1.2.2.1,1.2.804.2.1.1.1.1.2.2.2,1.2.804.2.1.1.1.1.2.2.3,1.3.36.3.2.1,2.16.840.1.101.3.4.2.1 \
  > "$SCRATCH/lever-after.txt"
```

Every receipt draws a fresh key, so
the files differ on every run; their sizes do not. A JVM that sets
`JAVA_TOOL_OPTIONS` prints a line about it to stderr, which the committed
results leave out. CI builds none of this; `DigestDenylistCostTest` is the
part that runs on every build.
