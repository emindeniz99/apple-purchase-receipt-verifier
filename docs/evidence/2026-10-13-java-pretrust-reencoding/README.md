# Java: ASN.1 re-encoded and unsigned labels acted on before trust: sources

The note is [`../2026-10-13-java-pretrust-reencoding.md`](../2026-10-13-java-pretrust-reencoding.md).

| File | Question it answered |
|---|---|
| `NestedValueProbe.java` | The round-4 review's probe: what one `ReceiptCore.verifyDer` call costs when the SignerInfo's issuer value (`sid`, `plain`) or one bag entry (`cert`) is a cap-sized SEQUENCE of nested SETs or of INTEGERs. Added here: mode `string`, one cap-sized UTF8String, and `-Ddump`. |
| `CertShapeProbe.java` | The same for a bag entry shaped as a certificate, the nested value in its issuer, subject, key parameters or signature parameters (`bag` is `NestedValueProbe cert` again). |
| `SigAlgDigestProbe.java` | The round-4 review's probe: what the signatureAlgorithm label costs when the signed attributes are padded to the cap. Added here: `-Ddump`. |
| `PssSaltProbe.java` | What a SignerInfo relabelled RSASSA-PSS with a given saltLength does to one call. Added for Q142 a: the same parameters under id-TA-RSA-PSS-SHA-256, id-TA-RSA-PSS-SHA-1 or id-alg-composite. |
| `CompositeLabelProbe.java` | Q144 a: what the generic composite label (1.3.6.1.4.1.18227.2.1) costs one call. `signer PARTS PAYLOAD`: the round-6 review's construction, the genuine SignerInfo without signed attributes and with PARTS sha256WithRSAEncryption parts, over a payload of PAYLOAD octets. `cert PARTS KIND`: a bag entry naming the RSA root as its issuer, with PARTS parts of `rsa`, `ecdsa`, `ed25519` or `unknown` and a signature of as many empty BIT STRINGs. |
| `core_shapes.rs` | What the core answers for each receipt the probes dumped, under its own test root. |
| `measure.sh` | Every shape above in a fresh JVM, for one `java` and one build of the library. |
| `profile.sh`, `callers.sh` | One probe run under JFR (10 ms samples, 2,048-frame stacks), and the samples grouped by the first frames outside BouncyCastle's ASN.1 package: which call pays. |
| `results/before-jdk21.txt`, `results/after-jdk21.txt` | `measure.sh ... all` on JDK 21, at `c3ca8225` and on the branch. |
| `results/before-jdk8.txt`, `results/after-jdk8.txt` | `measure.sh` on JDK 8, the same two builds. |
| `results/profile-sid.txt`, `results/profile-cert.txt` | `callers.sh` for `NestedValueProbe sid 30` and `cert 30` at `c3ca8225`. |
| `results/profile-after-sid.txt`, `results/profile-after-plain.txt`, `results/profile-after-issuer-30.txt` | The same on the branch, the last for `CertShapeProbe issuer 30`. |
| `results/denylist-tables.txt` | `DigestDenylistCostTest`'s two sweeps, each table printed once on JDK 21 (a copy of the test with a `main` that prints the table it passes on). |
| `results/pss-routes-before-jdk21.txt`, `results/pss-routes-after-jdk21.txt` | `measure.sh ... routes` on JDK 21: before, `ReceiptCore` and `AppleTrust` from `97dc9ce3` (the RSASSA-PSS label refused) ahead of the branch's classes; after, the branch with the salt bound (Q142 a). |
| `results/composite-before-jdk21.txt`, `results/composite-after-jdk21.txt` | `measure.sh ... composite` on JDK 21: before, the classes at `60f1a4df` (the PSS bound, no composite refusal); after, the branch with the generic composite label refused (Q144 a). |
| `results/core-shapes.txt` | `core_shapes.rs` over the dumped receipts and the shared fixture `receipt-signer-rsa-pss.der`. |

## Reproduce

`$REPO` is a checkout that has this folder, `$SCRATCH` any directory
outside it, `$JAVA8` and `$JAVA21` two `java` launchers. Every build
output goes to `$SCRATCH`. Build the library at `c3ca8225` into
`$SCRATCH/before` (copy `java/target/classes` there) for the figures
before, then check out the branch.

```sh
E="$REPO/docs/evidence/2026-10-13-java-pretrust-reencoding"
mvn -B -q -f "$REPO/java/pom.xml" test-compile
mvn -B -q -f "$REPO/java/pom.xml" dependency:build-classpath \
  -DincludeScope=test -Dmdep.outputFile="$SCRATCH/deps.txt"
MAIN="$REPO/java/target/classes"
TEST="$REPO/java/target/test-classes"
DEPS="$(cat "$SCRATCH/deps.txt")"
javac -nowarn --release 8 -d "$SCRATCH/probes" -cp "$MAIN:$TEST:$DEPS" "$E"/*.java

sh "$E/measure.sh" "$JAVA21" "$SCRATCH/before" "$TEST" "$SCRATCH/probes" "$DEPS" all > "$SCRATCH/before-jdk21.txt"
sh "$E/measure.sh" "$JAVA21" "$MAIN" "$TEST" "$SCRATCH/probes" "$DEPS" all > "$SCRATCH/after-jdk21.txt"
sh "$E/measure.sh" "$JAVA8" "$SCRATCH/before" "$TEST" "$SCRATCH/probes" "$DEPS" > "$SCRATCH/before-jdk8.txt"
sh "$E/measure.sh" "$JAVA8" "$MAIN" "$TEST" "$SCRATCH/probes" "$DEPS" > "$SCRATCH/after-jdk8.txt"

# Q142 a: "before" is ReceiptCore and AppleTrust from 97dc9ce3 ahead of the branch's classes
SRC=java/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier
mkdir -p "$SCRATCH/oldsrc" "$SCRATCH/before-q142"
for f in ReceiptCore AppleTrust; do git -C "$REPO" show "97dc9ce3:$SRC/$f.java" > "$SCRATCH/oldsrc/$f.java"; done
javac -nowarn --release 8 -d "$SCRATCH/before-q142" -cp "$MAIN:$DEPS" "$SCRATCH"/oldsrc/*.java
sh "$E/measure.sh" "$JAVA21" "$SCRATCH/before-q142:$MAIN" "$TEST" "$SCRATCH/probes" "$DEPS" routes > "$SCRATCH/pss-routes-before-jdk21.txt"
sh "$E/measure.sh" "$JAVA21" "$MAIN" "$TEST" "$SCRATCH/probes" "$DEPS" routes > "$SCRATCH/pss-routes-after-jdk21.txt"

# Q144 a: "before" is the library built at 60f1a4df, copied to $SCRATCH/before-q144
sh "$E/measure.sh" "$JAVA21" "$SCRATCH/before-q144" "$TEST" "$SCRATCH/probes" "$DEPS" composite > "$SCRATCH/composite-before-jdk21.txt"
sh "$E/measure.sh" "$JAVA21" "$MAIN" "$TEST" "$SCRATCH/probes" "$DEPS" composite > "$SCRATCH/composite-after-jdk21.txt"

P=io.github.emindeniz99.applepurchasereceiptverifier
mkdir -p "$SCRATCH/profile-sid"
JAVA="$JAVA21" sh "$E/profile.sh" "$SCRATCH/profile-sid" "$SCRATCH/probes:$SCRATCH/before:$TEST:$DEPS" \
  $P.NestedValueProbe sid 30 2300000
sh "$E/callers.sh" "$SCRATCH/profile-sid/profile.jfr" | head -10

mkdir -p "$SCRATCH/shapes"
CP="$SCRATCH/probes:$MAIN:$TEST:$DEPS"
for a in "plain 0" "cert 30" "sid 30"; do
  set -- $a; "$JAVA21" -Ddump="$SCRATCH/shapes/nested-$1-$2" -cp "$CP" $P.NestedValueProbe $1 $2 2300000
done
for a in "issuer 30" "issuer 0" "spki 30" "bag 30"; do
  set -- $a; "$JAVA21" -Ddump="$SCRATCH/shapes/certshape-$1-$2" -cp "$CP" $P.CertShapeProbe $1 $2 2290000
done
"$JAVA21" -Ddump="$SCRATCH/shapes/sigalg" -cp "$CP" $P.SigAlgDigestProbe 2200000 \
  1.2.840.113549.1.1.1,1.2.840.113549.1.1.2 1
"$JAVA21" -Ddump="$SCRATCH/shapes/pss-1e9" -cp "$CP" $P.PssSaltProbe 1000000000
cp "$REPO/fixtures/generated-0.7/receipt-signer-rsa-pss.der" "$SCRATCH/shapes/fixture-receipt-signer-rsa-pss.der"
cp "$REPO/fixtures/generated-0.7/signer-alg-root.der" "$SCRATCH/shapes/fixture-receipt-signer-rsa-pss.root.der"
cp "$E/core_shapes.rs" "$REPO/rust/tests/"
APRV_SHAPES="$SCRATCH/shapes" cargo test --manifest-path "$REPO/rust/Cargo.toml" \
  --test core_shapes -- --nocapture | grep '^core' > "$SCRATCH/core-shapes.txt"
rm "$REPO/rust/tests/core_shapes.rs"
```

Every receipt draws a fresh test PKI, so the files differ on every run;
their sizes do not. The dumped receipts are 2 to 2.3 MB each and stay in
`$SCRATCH`. A JVM that sets `JAVA_TOOL_OPTIONS` prints a line about it,
which the committed results leave out. CI builds none of this;
`UnauthenticatedKeyCostTest` and `DigestDenylistCostTest` are the parts
that run on every build.
