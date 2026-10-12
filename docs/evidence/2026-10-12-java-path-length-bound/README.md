# Java's post-build path-length check: probes

| File | Question |
|---|---|
| `PathLengthShapesProbeTest.java` | `probe`: for three receipt shapes, 20 fresh receipts each, what does Java answer? It writes each receipt, its root and Java's answer to `$SCRATCH/pathlen-exp`. `rerun`: in a new JVM, does Java give each of those receipts the same answer again? |
| `pathlen_probe_test.go` | What does the core (the Go wrapper over the committed `aprv.wasm`) answer for the same receipts, and is its verdict Java's? |
| `probe-output.txt` | The output of both probes. |

Reproduce (the probe test is copied into the suite's package and removed
afterwards; the Go probe runs in a copy of `go/`):

```sh
E="$REPO/docs/evidence/2026-10-12-java-path-length-bound"
P="$REPO/java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/PathLengthShapesProbeTest.java"
rm -rf "$SCRATCH/pathlen-exp"
cp "$E/PathLengthShapesProbeTest.java" "$P"
SCRATCH="$SCRATCH" mvn -o -q -f "$REPO/java/pom.xml" test \
  -Dtest='PathLengthShapesProbeTest#probe' -Dspotless.check.skip=true | grep '^JAVA'
SCRATCH="$SCRATCH" mvn -o -q -f "$REPO/java/pom.xml" test \
  -Dtest='PathLengthShapesProbeTest#rerun' -Dspotless.check.skip=true | grep '^JAVA'
rm "$P"
rm -rf "$SCRATCH/gocmp" && cp -r "$REPO/go" "$SCRATCH/gocmp"
cp "$E/pathlen_probe_test.go" "$SCRATCH/gocmp/"
SCRATCH="$SCRATCH" go -C "$SCRATCH/gocmp" test -v -count=1 \
  -run TestPathLengthProbe . | grep '^CORE'
```

Keys are fresh on every run, so the counts of the `self` and
`cross-valid` shapes move between runs; the `cross-expired` counts do
not.
