# 2026-10-03 fuzz-seed-anchor scripts

| File | Question it answered |
|---|---|
| `CountSeeds.java` | How many seeds of the Java receipt fuzz targets the Java implementation verifies under Apple's roots plus the 0.6 fixture receipt root, and plus the 0.7 one. |
| `count-core.sh` | The same for the Rust core, over the DER seeds PHP's `verify-receipt` target reads. |

## Reproduce

Base commit: `a699ec0`. `$REPO` is the repository root, `$SCRATCH` any
directory outside it.

```sh
mvn -B -q -f "$REPO/java/pom.xml" -DskipTests package
mvn -B -q -f "$REPO/java/pom.xml" dependency:build-classpath \
  -DincludeScope=runtime -Dmdep.outputFile="$SCRATCH/deps.txt"
java -cp "$REPO/java/target/apple-purchase-receipt-verifier-0.7.0.jar:$(cat "$SCRATCH/deps.txt")" \
  "$REPO/docs/evidence/2026-10-03-fuzz-seed-anchor/CountSeeds.java" "$REPO/fixtures"

sh "$REPO/docs/evidence/2026-10-03-fuzz-seed-anchor/count-core.sh" "$REPO" "$SCRATCH/core"
```

Both verify at the current time, so a fixture certificate that expires
changes the counts.
