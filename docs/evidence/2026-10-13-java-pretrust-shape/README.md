# Java: certificate shapes, certificate PSS labels and signed attributes before trust: sources

The note is [`../2026-10-13-java-pretrust-shape.md`](../2026-10-13-java-pretrust-shape.md).

| File | Question it answered |
|---|---|
| `ShapeProbe.java` | What one `ReceiptCore.verifyDer` call costs, and answers, with one sender-chosen shape just under the cap: a bag entry shaped as a certificate with a nested value in its subject, issuer, key or signature parameters or in a subjectAltName, or one RDN of many values; a SignerInfo copy with a nested signed attribute or nested signature parameters; and a JWS at its cap whose x5c[2] has the nested subject. `-Ddump` writes the receipts for the core. |
| `SidIssuerProbe.java` | The Q140 consultation's probe: the nested issuer on a bag entry that also carries the signer's serial, so `ReceiptCertificates.signers` compares it, with one and four SignerInfos. |
| `BagPssProbe.java`, `JwsPssRsaProbe.java` | The same consultation's probes: a bag entry, or an x5c[1], naming an RSA root as its issuer and labelled RSASSA-PSS with a given saltLength. |
| `SignedAttrsOrderProbe.java` | Which bytes each implementation verifies signed attributes over when the attributes, or one attribute's values, are out of DER order. `-Ddump` writes the receipts for the core. |
| `X5cTrailProbe.java` | What `JwsCore` answers for an x5c entry with trailing octets, a second certificate, or PEM text. |
| `EncodeCost.java` | The consultation's probe: DL against DER re-encoding of a parsed 2.3 MB value of nested SEQUENCEs or SETs. |
| `measure.sh` | Every `ShapeProbe`, `SidIssuerProbe`, `BagPssProbe` and `JwsPssRsaProbe` shape in a fresh JVM, for one `java` and one build of the library. |
| `results/before-jdk21.txt`, `results/after-jdk21.txt`, `results/before-jdk8.txt`, `results/after-jdk8.txt` | `measure.sh` at `f309a300` (before) and on the branch (after). |
| `results/before-jdk21-earlier.txt` | An earlier `measure.sh` run at `f309a300`, before `signerparams` gained its CMSAlgorithmProtection attribute. |
| `results/profile-after-*.txt` | `../2026-10-13-java-pretrust-reencoding/callers.sh` over one `ShapeProbe` run on the branch under JFR (`profile.sh` in the same folder): which calls the remaining cost goes to. |
| `results/order-java.txt`, `results/x5c-trail.txt`, `results/encode-cost.txt` | `SignedAttrsOrderProbe` and `X5cTrailProbe` at `f309a300` and on the branch; `EncodeCost` once. |
| `results/core-shapes.txt` | `../2026-10-13-java-pretrust-reencoding/core_shapes.rs` over the dumped receipts. |

## Reproduce

`$REPO` is a checkout of the branch, `$SCRATCH` any directory outside it,
`$JAVA8` and `$JAVA21` two `java` launchers. Build the library at
`f309a300` into `$SCRATCH/before` (copy `java/target/classes` there).

```sh
E="$REPO/docs/evidence/2026-10-13-java-pretrust-shape"
R="$REPO/docs/evidence/2026-10-13-java-pretrust-reencoding"
mvn -B -q -f "$REPO/java/pom.xml" test-compile
mvn -B -q -f "$REPO/java/pom.xml" dependency:build-classpath \
  -DincludeScope=test -Dmdep.outputFile="$SCRATCH/deps.txt"
MAIN="$REPO/java/target/classes"
TEST="$REPO/java/target/test-classes"
DEPS="$(cat "$SCRATCH/deps.txt")"
javac -nowarn --release 8 -d "$SCRATCH/probes" -cp "$MAIN:$TEST:$DEPS" "$E"/*.java

sh "$E/measure.sh" "$JAVA21" "$SCRATCH/before" "$TEST" "$SCRATCH/probes" "$DEPS" > "$SCRATCH/before-jdk21.txt"
sh "$E/measure.sh" "$JAVA21" "$MAIN" "$TEST" "$SCRATCH/probes" "$DEPS" > "$SCRATCH/after-jdk21.txt"
sh "$E/measure.sh" "$JAVA8" "$SCRATCH/before" "$TEST" "$SCRATCH/probes" "$DEPS" > "$SCRATCH/before-jdk8.txt"
sh "$E/measure.sh" "$JAVA8" "$MAIN" "$TEST" "$SCRATCH/probes" "$DEPS" > "$SCRATCH/after-jdk8.txt"

P=io.github.emindeniz99.applepurchasereceiptverifier
for build in "$SCRATCH/before" "$MAIN"; do
  "$JAVA21" -cp "$SCRATCH/probes:$build:$TEST:$DEPS" $P.SignedAttrsOrderProbe
  "$JAVA21" -cp "$SCRATCH/probes:$build:$TEST:$DEPS" $P.X5cTrailProbe
done
"$JAVA21" -cp "$SCRATCH/probes:$DEPS" EncodeCost

for shape in "signedattrs 30" "subject 30" "subject 50" "widerdn 100"; do
  set -- $shape; mkdir -p "$SCRATCH/profile-$1-$2"
  JAVA="$JAVA21" sh "$R/profile.sh" "$SCRATCH/profile-$1-$2" "$SCRATCH/probes:$MAIN:$TEST:$DEPS" \
    $P.ShapeProbe $1 $2 2290000 > /dev/null
  sh "$R/callers.sh" "$SCRATCH/profile-$1-$2/profile.jfr" | head -8
done

mkdir -p "$SCRATCH/shapes"
CP="$SCRATCH/probes:$MAIN:$TEST:$DEPS"
for shape in "subject 30" "spki 30" "san 30" "widerdn 100" "signedattrs 30" "signerparams 30"; do
  set -- $shape; "$JAVA21" -Ddump="$SCRATCH/shapes/shape-$1-$2" -cp "$CP" $P.ShapeProbe $1 $2 2290000
done
"$JAVA21" -Ddump="$SCRATCH/shapes" -cp "$CP" $P.SignedAttrsOrderProbe
cp "$R/core_shapes.rs" "$REPO/rust/tests/"
APRV_SHAPES="$SCRATCH/shapes" cargo test --manifest-path "$REPO/rust/Cargo.toml" \
  --test core_shapes -- --nocapture | grep '^core' > "$SCRATCH/core-shapes.txt"
rm "$REPO/rust/tests/core_shapes.rs"
```

Every receipt draws a fresh test PKI, so the files differ on every run;
their sizes do not. The dumped receipts are up to 2.3 MB each and stay in
`$SCRATCH`. A JVM that sets `JAVA_TOOL_OPTIONS` prints a line about it,
which the committed results leave out. CI builds none of this;
`UnauthenticatedKeyCostTest` and `ReceiptSignerInfoTest` are the parts
that run on every build.
