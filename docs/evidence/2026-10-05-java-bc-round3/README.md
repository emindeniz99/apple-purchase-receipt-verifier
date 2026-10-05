# Java port, review round 3: sources

The note is [`../2026-10-05-java-bc-round3.md`](../2026-10-05-java-bc-round3.md).
The findings J1 to J6 below are the ones numbered in it.

The Java probes sit in `src/io/github/emindeniz99/applepurchasereceiptverifier/`,
the library's own package, so they reach its package-private classes. They
also use `TestPki` from the library's test classes. None of them is part of
the Maven build.

| File | Question it answered |
|---|---|
| `Probe1Envelope.java` | J1. With the Apple-signed sandbox receipt's unsigned envelope fields altered one at a time (outer content type OID, the SignedData and SignerInfo versions, `digestAlgorithms`, the encapsulated content type, and the signature algorithm label), which edits does Java still verify? |
| `Probe14Trail.java` | J2. What does Java answer for a JWS whose `x5c` leaf has a zero byte, garbage or a second certificate after the DER, or bytes in front of it? |
| `Probe15Pem.java` | J2. What does Java answer when an `x5c` entry is PEM text, or a PKCS#7 certs-only bundle, instead of one DER certificate? |
| `Probe18Profile.java` | J3. Which certificate profile variants on the JWS chain, all genuinely signed by the test chain (AuthorityKeyIdentifier that does not match the intermediate's SubjectKeyIdentifier, basicConstraints and keyUsage changes, policies and `policyConstraints`, extended key usage, name constraints, critical unknown extensions), does Java accept? |
| `Probe17Curve.java` | J4. Does Java accept an ES256 JWS whose leaf key is not on P-256 (secp256k1, brainpoolP256r1, P-384) with a 64-byte raw signature? |
| `Probe8Rng.java` | J5. Does `create` or a verify call draw from a `SecureRandom`, or look up algorithms through `Security.getProviders()`, and from which stack? |
| `Probe9BadRng.java` | J5. With a first-listed `SecureRandom` provider that fails, what do genuine inputs answer? |
| `Probe6Stack.java` | J6. Does an input nested to BouncyCastle's bound of 64 overflow a small thread stack and escape the error mapping? |
| `Probe7MinStack.java` | J6. What is the smallest thread stack on which a genuine receipt, JWS and endpoint call complete, cold and warm? |
| `Probe3Fuzz.java` | Fuzz. For mutations of the genuine public receipts, what does Java answer? Writes the verdicts to `java.tsv` and each mutated body to a `.b64` file, for the core to read. |
| `Probe10JwsFuzz.java` | Fuzz. For JWS whose header or payload JSON text is edited at random and re-signed, what does Java answer? Writes `java.tsv`, the `.jws` files and `root.der`. |
| `Probe2Global.java` | Globals. Does `create`, `verifyReceipt`, `verifySignedData` or the endpoint change the `Security` providers or properties, the system properties, or the default `Locale` and `TimeZone`? |
| `Probe13Conc.java` | Concurrency. With 24 threads on a mix of genuine and hostile input for 15 s, does any genuine input answer anything but ok, or any exception escape? |
| `Probe12Tz.java` | Time zone. For signed receipts carrying dates from year 0000 to 9999, does the endpoint's `_pst` rendering match the core's? Writes the receipts, `java.json` responses and `root.der`. |
| `Probe11Esc.java` | Escapes. Does a JWS header with legal JSON escapes in `x5c` entries or `alg` (`\/`, `+`, `E`) verify the same way as in the core? |
| `Probe4Attr.java` | Attributes. For genuinely signed test-PKI receipts with a defective attribute envelope, what does Java answer? |
| `Probe16Anchor.java` | Anchors. When the root is expired at the `signedDate` and the rest of the chain is valid, what does Java answer? |
| `corediff/` | The core's verdict. A Go program on the Go package's wazero host, which runs the `aprv.wasm` committed under `go/internal/wasm/`. It prints one line per file (`ok`, or the failure reason; `-kind endpoint` prints the endpoint response), to compare with the Java output for the same bytes. `go.mod` replaces the Go module with the checkout, so it builds against the committed module, which can lag `rust/src` between releases. |
| `locales.sh` | Do the conformance, endpoint-status, verify-receipt endpoint, decoder and public-receipt tests pass under tr-TR, th-TH-TH, ja-JP-JP with `file.encoding=ISO-8859-1`, and ar-SA with the `Pacific/Kiritimati` zone? |
| `sec1.props` | Does disabling SHA1, SHA256, RSA, EC, DSA and ECDSA in `jdk.certpath.disabledAlgorithms` change a verdict? |
| `sec2.props` | Does a different provider order (SunPKCS11 first) and a different `securerandom.source` change a verdict? |

## Reproduce

`$REPO` is the repository root, `$SCRATCH` any directory outside it. Every
build output and result file goes to `$SCRATCH`.

```sh
export REPO SCRATCH
EV="$REPO/docs/evidence/2026-10-05-java-bc-round3"
PKG=io.github.emindeniz99.applepurchasereceiptverifier

# The library, its test classes (TestPki) and its classpath.
mkdir -p "$SCRATCH/evcheck"
mvn -B -q -f "$REPO/java/pom.xml" -DskipTests test-compile
mvn -B -q -f "$REPO/java/pom.xml" dependency:build-classpath \
  -Dmdep.outputFile="$SCRATCH/evcheck/cp.txt"
LIB="$REPO/java/target/classes:$REPO/java/target/test-classes:$(cat "$SCRATCH/evcheck/cp.txt")"

javac -nowarn -d "$SCRATCH/evcheck/classes" -cp "$LIB" "$EV"/src/io/github/emindeniz99/applepurchasereceiptverifier/*.java
RUN() { java -cp "$SCRATCH/evcheck/classes:$LIB" "$PKG.$@"; }
```

The probes that read a public receipt take its location from the `REPO`
environment variable. The others build their input from a test PKI.

Arguments, from each probe's `main`:

```sh
# Output directory only. Mutated inputs and root.der land there.
RUN Probe1Envelope   "$SCRATCH/out/p1"
RUN Probe4Attr       "$SCRATCH/out/p4"
RUN Probe11Esc       "$SCRATCH/out/p11"
RUN Probe14Trail     "$SCRATCH/out/p14"
RUN Probe15Pem       "$SCRATCH/out/p15"
RUN Probe16Anchor    "$SCRATCH/out/p16"
RUN Probe17Curve     "$SCRATCH/out/p17"
RUN Probe18Profile   "$SCRATCH/out/p18"

# Output directory, number of cases, random seed.
RUN Probe3Fuzz       "$SCRATCH/out/p3"  6000 1
RUN Probe10JwsFuzz   "$SCRATCH/out/p10" 8000 1
RUN Probe12Tz        "$SCRATCH/out/p12" 2100 1 # 20 dates per file, 42,000 dates

# No arguments.
RUN Probe2Global
RUN Probe6Stack
RUN Probe7MinStack
RUN Probe8Rng
RUN Probe13Conc                                # runs 15 s
RUN Probe9BadRng                               # genuine inputs with the default providers
RUN Probe9BadRng bad                           # same, with the failing provider installed first
```

The seeds and counts above are a starting point, not the note's recorded
runs. A different seed gives different mutations.

Run the core on what a probe wrote, from a directory outside the tree:

```sh
cd "$EV/corediff" && go build -o "$SCRATCH/corediff" .

# Mutations of the public receipts (Apple roots, no -root).
"$SCRATCH/corediff" -kind receipt "$SCRATCH"/out/p3/*.b64 > "$SCRATCH/out/p3/core.txt"

# Probes that sign with their own PKI: pass that PKI's root.
"$SCRATCH/corediff" -kind jws -root "$SCRATCH/out/p14/root.der" "$SCRATCH"/out/p14/*.jws
"$SCRATCH/corediff" -kind receipt -root "$SCRATCH/out/p4/root.der" "$SCRATCH"/out/p4/*.b64
"$SCRATCH/corediff" -kind endpoint -root "$SCRATCH/out/p12/root.der" -now 1735000000000 "$SCRATCH"/out/p12/*.b64
```

`-now <ms>` sets the clock; without it the core reads the system clock.
`Probe12Tz` fixes its Java clock at 1735000000000, so pass the same value.
Compare the two sets of lines by file name. A line where Java says `ok` and
the core names a reason is a divergence to classify against R20.

Locale, charset and security-property variations:

```sh
# Needs the test classes from test-compile above, and a warm Maven repository (-o).
bash "$EV/locales.sh"          # writes loc-<name>.log and loc-summary.log to $SCRATCH

# A java.security override file, applied to any probe.
java -Djava.security.properties="$EV/sec1.props" -cp "$SCRATCH/evcheck/classes:$LIB" \
  "$PKG.Probe2Global"
java -Djava.security.properties="$EV/sec2.props" -cp "$SCRATCH/evcheck/classes:$LIB" \
  "$PKG.Probe3Fuzz" "$SCRATCH/out/p3-sec2" 6000 1
```

`locales.sh` runs `surefire:test` against the already compiled classes, so
it needs `mvn test-compile` first. `corediff` builds against the committed
`go/internal/wasm/aprv.wasm`, so its verdicts are those of the last
refreshed module. CI builds none of this.
