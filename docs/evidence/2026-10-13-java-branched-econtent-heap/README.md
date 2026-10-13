# Java: a branched constructed-string eContent: sources

The note is [`../2026-10-13-java-branched-econtent-heap.md`](../2026-10-13-java-branched-econtent-heap.md).

| File | Question it answered |
|---|---|
| `BranchedEContent.java` | `size` prints how large a tree shape is as a receipt. `make` writes a receipt whose eContent is that tree, under the 3,145,728-character cap, around a `TestPki` receipt's certificates and SignerInfo. `once` makes one call under Apple's roots and exits 3 on `OutOfMemoryError`, for the bisection. |
| `run.sh` | The sizes of the research's two shapes and of six that fit the cap; then, for the baseline, the tiny-attributes receipt and those six, the smallest `-Xmx` at which one call completes, bisected three times. |
| `results/make.txt` | The stdout of `PresignatureCost make` (from [`../2026-10-05-java-presignature-parse-cost/`](../2026-10-05-java-presignature-parse-cost/)) for the baseline and tiny-attributes inputs measured here. |
| `results/run.txt` | `run.sh` on `main` at `1cb08f0e`. |

## Reproduce

`$REPO` is a checkout that has this folder, `$SCRATCH` any directory
outside it. Every build output and input file goes to `$SCRATCH`.

```sh
E="$REPO/docs/evidence/2026-10-13-java-branched-econtent-heap"
P="$REPO/docs/evidence/2026-10-05-java-presignature-parse-cost"
git -C "$REPO" worktree add --detach "$SCRATCH/src" 1cb08f0e
SRC="$SCRATCH/src"

mvn -B -q -f "$SRC/java/pom.xml" test-compile
mvn -B -q -f "$SRC/java/pom.xml" dependency:build-classpath \
  -DincludeScope=test -Dmdep.outputFile="$SCRATCH/deps.txt"
LIB="$SRC/java/target/classes:$SRC/java/target/test-classes:$(cat "$SCRATCH/deps.txt")"

javac -nowarn -d "$SCRATCH/classes" -cp "$LIB" "$E/BranchedEContent.java" "$P/PresignatureCost.java"
java -cp "$SCRATCH/classes:$LIB" PresignatureCost make "$SCRATCH" > "$SCRATCH/make.txt"
sh "$E/run.sh" "$SCRATCH" "$SCRATCH/classes:$LIB" > "$SCRATCH/run.txt"
```

Every input draws fresh keys, so the files differ on every run; their
sizes do not. A JVM that sets `JAVA_TOOL_OPTIONS` prints a line about it
to stderr, which the committed results leave out. CI builds none of this.
