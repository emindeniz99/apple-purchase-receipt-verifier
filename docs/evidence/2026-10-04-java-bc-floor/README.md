# Java BouncyCastle floor and pre-trust cost: sources

The note is [`../2026-10-04-java-bc-floor.md`](../2026-10-04-java-bc-floor.md).

| File | Question it answered |
|---|---|
| `DepthSweep.java` | At which `org.bouncycastle.asn1.max_cons_depth` do the sandbox receipts under `fixtures/public-receipts/` stop parsing, and does the 9-deep probe `Verifier.create` parses stop at the same bound? |
| `FloorCheck.java` | Which bcprov does `Verifier.create` accept, and what does each bcprov's ASN.1 parser do with 400,000 nested indefinite-length SEQUENCEs? |
| `HostileCost.java` | What does a cap-sized receipt that no pinned root vouches for cost before it is refused? |

## Reproduce

`$REPO` is the repository root, `$SCRATCH` any directory outside it. Every
download and build output goes to `$SCRATCH`.

```sh
# The library, its test classes (TestPki) and its runtime classpath.
mvn -B -q -f "$REPO/java/pom.xml" test-compile
mvn -B -q -f "$REPO/java/pom.xml" dependency:build-classpath \
  -DincludeScope=runtime -Dmdep.outputFile="$SCRATCH/deps.txt"

# Each bcprov under test, from Maven Central.
for v in 1.81 1.81.1 1.85.2 1.86; do
  mvn -B -q dependency:copy -Dartifact=org.bouncycastle:bcprov-jdk18on:$v \
    -DoutputDirectory="$SCRATCH/jars"
done

# Everything but bcprov: the library, TestPki, bcutil and bcpkix 1.86, jackson-core.
LIB="$REPO/java/target/classes:$REPO/java/target/test-classes:$(tr ':' '\n' < "$SCRATCH/deps.txt" | grep -v bcprov | paste -sd:)"
BC186="$SCRATCH/jars/bcprov-jdk18on-1.86.jar"

javac -nowarn -d "$SCRATCH/classes" -cp "$LIB:$BC186" \
  "$REPO"/docs/evidence/2026-10-04-java-bc-floor/*.java

java -cp "$SCRATCH/classes:$LIB:$BC186" DepthSweep "$REPO/fixtures"
for v in 1.81 1.81.1 1.85.2 1.86; do
  java -cp "$SCRATCH/classes:$LIB:$SCRATCH/jars/bcprov-jdk18on-$v.jar" FloorCheck
done
java -cp "$SCRATCH/classes:$LIB:$BC186" HostileCost
```

`FloorCheck` swaps only bcprov: bcutil and bcpkix stay at 1.86, as when a
consumer's tree pulls in an older bcprov alone. CI builds none of this.
