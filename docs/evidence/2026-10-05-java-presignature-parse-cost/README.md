# Java's parse before trust: sources

The note is [`../2026-10-05-java-presignature-parse-cost.md`](../2026-10-05-java-presignature-parse-cost.md).

| File | Question it answered |
|---|---|
| `PresignatureCost.java` | `make` writes the three inputs, all signed by one `TestPki` leaf and under the 3,145,728-character cap, and prints their sizes. `measure` prints the verdict, the heap the result keeps after GC, and the wall time and bytes allocated per call over 20 warm calls. `once` makes one call and exits 3 on `OutOfMemoryError`, for the bisection. |
| `run.sh` | For each input, under the `TestPki` root and under Apple's roots: three `measure` runs, then the smallest `-Xmx` at which one call completes, bisected three times. A third argument passes a collector flag to the bisection alone and skips the `measure` runs. |
| `core.sh` | The core's verdict for each input under both sets of roots, through the round-3 `corediff` tool, which runs the `aprv.wasm` committed under `go/internal/wasm/` on the Go package's wazero host. |
| `results/make.txt` | The stdout of `make` for the inputs every other result here was measured on. |
| `results/two-parses-3a31f14-g1.txt` | `run.sh` on `main` at `3a31f14`, which parses the payload twice, default G1. |
| `results/two-parses-3a31f14-serial.txt` | The same bisection on `3a31f14` with `-XX:+UseSerialGC`. |
| `results/single-parse-4254101-g1.txt` | `run.sh` with `ReceiptCore` and `ReceiptDecoder` from commit `4254101`, which parsed the payload once and was reverted in `28c31de`, default G1. |
| `results/single-parse-4254101-serial.txt` | The same bisection on `4254101` with `-XX:+UseSerialGC`. |
| `results/core.txt` | `core.sh` on the same inputs. |

## Reproduce

`$REPO` is a checkout that has this folder, `$SCRATCH` any directory
outside it. Every build output and input file goes to `$SCRATCH`. The
library is pinned to `3a31f14`, the code the main table measures.

```sh
E="$REPO/docs/evidence/2026-10-05-java-presignature-parse-cost"
git -C "$REPO" worktree add --detach "$SCRATCH/src" 3a31f14
SRC="$SCRATCH/src"

# The library, its test classes (TestPki) and its classpath.
mvn -B -q -f "$SRC/java/pom.xml" test-compile
mvn -B -q -f "$SRC/java/pom.xml" dependency:build-classpath \
  -DincludeScope=test -Dmdep.outputFile="$SCRATCH/deps.txt"
LIB="$SRC/java/target/classes:$SRC/java/target/test-classes:$(cat "$SCRATCH/deps.txt")"

javac -nowarn -d "$SCRATCH/classes" -cp "$LIB" "$E/PresignatureCost.java"
java -cp "$SCRATCH/classes:$LIB" PresignatureCost make "$SCRATCH" > "$SCRATCH/make.txt"
sh "$E/run.sh" "$SCRATCH" "$SCRATCH/classes:$LIB" > "$SCRATCH/two-parses-3a31f14-g1.txt"
sh "$E/run.sh" "$SCRATCH" "$SCRATCH/classes:$LIB" -XX:+UseSerialGC > "$SCRATCH/two-parses-3a31f14-serial.txt"

# The single-parse attempt: 4254101's two receipt classes, ahead of
# 3a31f14's on the classpath.
D=java/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier
mkdir -p "$SCRATCH/single-src"
for f in ReceiptCore ReceiptDecoder; do
  git -C "$REPO" show "4254101:$D/$f.java" > "$SCRATCH/single-src/$f.java"
done
javac -nowarn -d "$SCRATCH/single-classes" -cp "$LIB" "$SCRATCH"/single-src/*.java
sh "$E/run.sh" "$SCRATCH" "$SCRATCH/classes:$SCRATCH/single-classes:$LIB" > "$SCRATCH/single-parse-4254101-g1.txt"
sh "$E/run.sh" "$SCRATCH" "$SCRATCH/classes:$SCRATCH/single-classes:$LIB" -XX:+UseSerialGC > "$SCRATCH/single-parse-4254101-serial.txt"

# The core on the same inputs (Go 1.25; offline with a filled module cache).
go -C "$SRC/docs/evidence/2026-10-05-java-bc-round3/corediff" build -o "$SCRATCH/corediff" .
sh "$E/core.sh" "$SCRATCH" "$SCRATCH/corediff" > "$SCRATCH/core.txt"
```

`make` draws fresh keys and dates the receipts at the moment it runs, so
its files differ on every run; their sizes do not. A JVM that sets
`JAVA_TOOL_OPTIONS` prints a line about it to stderr, which the committed
results leave out. CI builds none of this.
