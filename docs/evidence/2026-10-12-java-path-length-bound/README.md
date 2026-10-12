# Java's post-build path-length check: probes

| File | Question |
|---|---|
| `PathLengthShapesProbeTest.java` | `probe`: for five shapes (`self-6`, `self-7`, `cross-valid-5`, `cross-expired-5`, `cross-expired-4`), 20 fresh receipts each, what does Java answer? It writes each receipt, its root and Java's answer to `$SCRATCH/pathlen-exp`. `rerun`: in a new JVM, does Java give each of those receipts the same answer again? |
| `pathlen_probe_test.go` | What does the core (the Go wrapper over the committed `aprv.wasm`) answer for the same receipts, and is its verdict Java's? |
| `CrossDefectProbeTest.java` | After the check was deleted: does the six- and seven-certificate `TestPki.crossCertifiedReceipt` shape verify, and is it still refused with one defect on the long route (a forged link, a link that is not a CA, the deep copy expired)? |
| `probe-output.txt` | The output of the probes, the third run after the deletion. |

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
D="$REPO/java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/CrossDefectProbeTest.java"
cp "$E/CrossDefectProbeTest.java" "$D"
mvn -o -q -f "$REPO/java/pom.xml" test \
  -Dtest=CrossDefectProbeTest -Dspotless.check.skip=true | grep '^DEFECT'
rm "$D"
rm -rf "$SCRATCH/gocmp" && cp -r "$REPO/go" "$SCRATCH/gocmp"
cp "$E/pathlen_probe_test.go" "$SCRATCH/gocmp/"
SCRATCH="$SCRATCH" go -C "$SCRATCH/gocmp" test -v -count=1 \
  -run TestPathLengthProbe . | grep '^CORE'
```

Keys are fresh on every run, so the counts of the `self` and
`cross-valid` shapes move between runs; the `cross-expired` counts do
not.
