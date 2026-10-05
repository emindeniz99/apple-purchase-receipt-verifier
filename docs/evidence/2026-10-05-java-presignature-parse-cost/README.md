# Java's parse before trust: sources

The note is [`../2026-10-05-java-presignature-parse-cost.md`](../2026-10-05-java-presignature-parse-cost.md).

| File | Question it answered |
|---|---|
| `PresignatureCost.java` | `make` writes the three inputs, all signed by one `TestPki` leaf and under the 3,145,728-character cap. `measure` prints the verdict, the heap the result keeps after GC, and the wall time and bytes allocated per call over 20 warm calls. `once` makes one call and exits 3 on `OutOfMemoryError`, for the bisection. |
| `run.sh` | For each input, under the `TestPki` root and under Apple's roots: three `measure` runs, then the smallest `-Xmx` at which one call completes, bisected three times. A third argument passes a collector flag to the bisection alone. |
| `results/two-parses-3a31f14-g1.txt` | `run.sh` on `main` at `3a31f14`, which parses the payload twice, default G1. |
| `results/single-parse-4254101-g1.txt` | `run.sh` with `ReceiptCore` and `ReceiptDecoder` from commit `4254101`, which parsed the payload once and was reverted in `28c31de`, default G1. |
| `results/single-parse-4254101-serial.txt` | The same bisection on `4254101` with `-XX:+UseSerialGC`. |

## Reproduce

`$REPO` is the repository root, `$SCRATCH` any directory outside it. Every
build output and input file goes to `$SCRATCH`.

```sh
# The library, its test classes (TestPki) and its classpath.
mvn -B -q -f "$REPO/java/pom.xml" test-compile
mvn -B -q -f "$REPO/java/pom.xml" dependency:build-classpath \
  -DincludeScope=test -Dmdep.outputFile="$SCRATCH/deps.txt"
LIB="$REPO/java/target/classes:$REPO/java/target/test-classes:$(cat "$SCRATCH/deps.txt")"
E="$REPO/docs/evidence/2026-10-05-java-presignature-parse-cost"

javac -nowarn -d "$SCRATCH/classes" -cp "$LIB" "$E/PresignatureCost.java"
java -cp "$SCRATCH/classes:$LIB" PresignatureCost make "$SCRATCH"
sh "$E/run.sh" "$SCRATCH" "$SCRATCH/classes:$LIB"

# The single-parse attempt: 4254101's two receipt classes, ahead of the
# checkout's on the classpath.
D=java/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier
mkdir -p "$SCRATCH/single-src"
for f in ReceiptCore ReceiptDecoder; do
  git -C "$REPO" show "4254101:$D/$f.java" > "$SCRATCH/single-src/$f.java"
done
javac -nowarn -d "$SCRATCH/single-classes" -cp "$LIB" "$SCRATCH"/single-src/*.java
sh "$E/run.sh" "$SCRATCH" "$SCRATCH/classes:$SCRATCH/single-classes:$LIB"
sh "$E/run.sh" "$SCRATCH" "$SCRATCH/classes:$SCRATCH/single-classes:$LIB" -XX:+UseSerialGC
```

`make` draws fresh keys, so its files differ on every run; their sizes do
not. CI builds none of this.
