# CMS signer match without a subjectKeyIdentifier: probe

| File | Question it answered |
|---|---|
| `ProbeSkiFallbackTest.java` | Builds the two probe receipts and prints Java's verdict on each. |
| `make-cases.mjs` | Wraps the probe receipts in a `cases.json` so the Go package's conformance runner reports the core's verdict. |

The test reaches the private builders of `StandardShapeFixtures` by
reflection, so it runs against the tree of PR #280, where that class exists.

## Reproduce

```sh
mkdir -p "$SCRATCH/p"
cp docs/evidence/2026-10-06-cms-ski-fallback/ProbeSkiFallbackTest.java \
   java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/
mvn -B -q -f java/pom.xml test -Dtest=ProbeSkiFallbackTest \
    -Dprobe.out="$SCRATCH/p" -Dsurefire.failIfNoSpecifiedTests=false
rm java/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/ProbeSkiFallbackTest.java

node docs/evidence/2026-10-06-cms-ski-fallback/make-cases.mjs "$SCRATCH"
APRV_FIXTURES_DIR="$SCRATCH" go -C go test -count=1 -run Conformance .
```

Java prints `PROBE java rfc: ...` and `PROBE java ms: ...`. Every case
expects ok, so the Go run fails and names the core's reason for each case
that is not ok.
