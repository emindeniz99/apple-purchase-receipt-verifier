# Standalone Java vendor review

14 October 2026. Reviewed main commit
`0b8766f02b473c4e312da24a18b678ea3bea0267`.

**Question:** does `java/` satisfy the requested trust, bounded-work,
future-compatibility and source-cleanliness rules sufficiently to vendor
unchanged?

Read all 17 files in `java/src/main`, all 10 compiled shared-source files,
and `java/README.md`, `java/WALKTHROUGH.md` and
`java/WALKTHROUGH-QUICK.md`. Read the previous Temurin 17 review and R20
as established decisions. No other implementation was used as a yardstick.
The existing resource caps, MD2/PSS/composite refusals, trailing-byte
policy and runtime probe are not reopened here. No production source,
dependency, test or fixture was changed.

Rule 2 is interpreted as requiring ordinary future algorithm and chain
changes that the pinned provider and trust anchors can already validate.
An immutable offline library cannot promise to understand every unknown
future algorithm or independently authenticate an unpublished new root.
The failures below need neither: BC 1.86 already validates the generated
paths and signatures. They are compatibility restrictions already in this
commit, not regressions or evidence of a currently rejected Apple receipt.

## Must fix

1. **JWS algorithm is frozen to ES256 (rule 2).**
   `java/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/JwsCore.java:77`
   rejects every other `alg` before trust or signature verification;
   line 372 fixes the signature length to 64 bytes. A correctly signed
   ES384/P-384 token with the required markers, an independently valid
   three-certificate chain and its root explicitly trusted returns
   `MALFORMED`. A future Apple move to ES384 under an existing root would
   hit exactly this rejection. The corresponding SHA-384/ECDSA CMS
   control verifies. **Smallest fix for this demonstrated refusal:** add
   ES384 through a JWA-aware asymmetric algorithm dispatch, with its
   P-384 key and RFC 7518 signature encoding checks. Keep algorithm/key
   binding, and reject `none` and MAC algorithms. Broader future JWA support
   needs an explicit supported-algorithm contract; accepting arbitrary JCA
   names from the header is not a fix.

2. **JWS chain shape is frozen (rule 2).**
   `java/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/JwsCore.java:80`
   requires exactly three entries, line 332 requires the immediate issuer
   to be signed directly by a root, and line 353 validates only
   `[leaf, intermediate]`. Root omission and an additional CA are normal
   X.509/JWS shapes, not resource-cap edge cases. Fresh, independently
   valid controls return `MALFORMED` for two or four entries, and
   `UNTRUSTED_CHAIN` for `[leaf, immediate issuer, upper CA]` even though
   the configured root signs that upper CA. The same additional CA works
   in CMS. **Smallest complete fix:** authenticate the supplied path
   top-down from configured anchors and PKIX-validate the full path,
   allowing an omitted anchor and excluding any supplied copy of an
   anchor from the path. Keep the leaf and immediate-issuer markers and
   the existing size/pre-trust bounds. Merely relaxing `size() != 3`
   leaves the second failure intact. RFC 7515 section 4.1.6 does not
   prescribe an exact chain count.

3. **Production Javadoc mentions tests (rule 4).**
   `java/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/Verifier.java:12`
   says the interface exists so callers can mock it "in their own tests"
   on line 13. **Smallest fix:** delete that sentence, retaining the
   thread-safety and startup guidance. This is a source-policy violation,
   with no runtime security effect. The word "test" in `Utf8Length` means
   its first comparison and is not a reference to a test suite.

## Should fix

- **Make the base64 explanation match the implementation.**
  `java/WALKTHROUGH.md:261` says only the canonical spelling of each
  encoding is accepted; `java/WALKTHROUGH-QUICK.md:93` repeats canonical
  base64. `StrictBase64.java:32` applies the canonical re-encoding check
  only to base64url; standard base64 intentionally accepts nonzero unused
  bits while requiring canonical padding. Describe that distinction.
  Keep the settled decoding behavior unchanged.
- **Complete the notification example's caller checks.**
  `java/README.md:316` checks the outer bundle before calling the action
  methods, but the example has no environment check and its action stubs
  do not state the product/identity checks it expects. The earlier README
  correctly requires those checks. Add the expected-environment check
  before applying either nested payload, and make the nested claim and
  product checks explicit in the example's handlers. This is caller
  authorization guidance; accepting an authentic sandbox payload is not
  a verifier forgery.

## Fine as is

- **Current legacy acceptance:** both genuine Apple sandbox controls verify on Temurin 17; the new synthetic ECDSA/SHA-384 and extra-CA CMS controls also verify.
- **Trust binding:** foreign roots, a wrong configured root, changed JWS signed bytes and 16 ECDSA boundary signatures all fail closed; no new forgery was found.
- **Bounded work:** larger invalid JWS remained in the low-millisecond range in this probe; existing cap and heap/concurrency decisions stand.
- **Existing guards and runtimeProbe:** no new evidence justifies removing them or adding configuration.
- **KISS/DRY:** no additional dead branch or safe security-code deletion was established by this read.

**Ready to vendor as is: no under the five requested rules. Change the
JWS ES256-only algorithm gate first.**

## Execution evidence

Sources and commands:
[2026-10-14-java-vendor-followup/README.md](2026-10-14-java-vendor-followup/README.md).
All generated artifacts and raw logs stayed outside the repository.

Environment: Eclipse Temurin **17.0.20.1+1**, HotSpot, Linux x86-64;
Maven **3.9.16**; `javac` **17.0.20.1** targeting Java 8; BouncyCastle
bcprov/bcutil/bcpkix **1.86**; Jackson core/databind **2.22.3**, annotations **2.22**;
JSpecify **1.0.1**; JUnit Jupiter **5.14.4**. Runner: Bash **5.2.37**,
Python **3.12.14**, Git **2.52.0**. Versions come from `runtime.log`,
the build classpath and the unchanged POM. The initial executor JDK was
Debian 21; it was not used to qualify the library.

`verify.log`: `mvn -B -f java/pom.xml verify` completed with **699 tests,
0 failures, 0 errors, 1 skipped**. The usual fixture-generation test is
the skip. Both main and test JARs were built. The main JAR is **91,937
bytes**, SHA-256
`0f695e5a16f78313d47c0b253497879fea42f30d4c8b5b2d7c738c8397ed2974`.
No JAR is committed.

`probe.log`: **392 assertions** passed. This is an assertion count,
including repeated timing calls, not 392 independent attacks. Every
fresh PKI path was first validated directly through BC PKIX. Every
generated JWS signature was verified directly using its declared JCA
algorithm before calling the library. Both marker extensions were checked.
Thus the compatibility examples isolate library policy from faulty
signatures, expired certificates or missing markers.

| Probe | Library result |
|---|---|
| ES256, leaf/intermediate/root | `VERIFIED` |
| ES256, leaf/intermediate, root omitted | `MALFORMED` |
| ES384, P-384 leaf, leaf/intermediate/root | `MALFORMED` |
| ES256, leaf/two CAs/root | `MALFORMED` |
| ES256, leaf/two CAs, root omitted | `UNTRUSTED_CHAIN` |
| CMS, ECDSA with SHA-384 | `VERIFIED` |
| CMS, ECDSA with an extra CA | `VERIFIED` |
| Fresh foreign JWS and CMS under default Apple roots | Both `UNTRUSTED_CHAIN` |
| Fresh JWS under the wrong synthetic root | `UNTRUSTED_CHAIN` |
| Signed JWS header changed, signature kept | `INVALID_SIGNATURE` |
| Signed JWS payload changed, signature kept | `INVALID_SIGNATURE` |
| All 16 pairs of ECDSA r/s in {0, 1, n-1, n} | All `INVALID_SIGNATURE` |
| Public legacy and G5 Apple sandbox receipts | Both `VERIFIED` |

The scaling probe changes one signature byte on an otherwise valid JWS
with a single padding member. It checks rejection for 30 warm-up calls
and 50 timed calls per size, with `-Xmx512m`. From `probe.log`:

| JWS bytes | Mean ms/call | Result on every call |
|---:|---:|---|
| 12,753 | 3.187 | `INVALID_SIGNATURE` |
| 45,521 | 2.466 | `INVALID_SIGNATURE` |
| 176,593 | 4.287 | `INVALID_SIGNATURE` |
| 241,830 | 3.930 | `INVALID_SIGNATURE` |

No failed verification returned a payload, `INTERNAL_ERROR` or
`UNREADABLE_PAYLOAD`, and no unchecked exception or JVM error escaped
these probes. These timing results include fixed chain/signature work,
JIT and scheduler noise; they do not prove a complexity bound or establish
worst-case latency. They add no new resource-cap finding to prior reviews.

## Limits

The synthetic PKI is trusted only in dedicated probe verifiers through
the existing `Config.roots` API. It is never installed in the default
Apple verifier. Synthetic success is not a claim that Apple issued these
certificates; synthetic rejection demonstrates the exact branch a future
Apple token of that supported shape would encounter. The two authentic
fixtures exercise legacy receipts, not Apple-root JWS. No production
receipt was used, no live Apple endpoint was queried, and no purchase
identifier or receipt timestamp was printed by the probe. The conclusions
are bounded to this commit, these dependency versions, Temurin HotSpot 17,
the source review and this input set; they do not certify arbitrary future
Apple protocols or other JVMs.

## Decision (owner, 2026-10-14, Q170 and Q171)

The two rule-2 findings stay as they are and are recorded in
DECISIONS.md R20, with the issuer-name finding of the first review.
Apple's own App Store Server Library (Java, `ChainVerifier` and
`SignedDataVerifier` on `main`, read 2026-10-14) refuses the same shapes:
`EXPECTED_CHAIN_LENGTH = 3`, and any `alg` but `"ES256"` is "Unrecognized
JWT algorithm". A shape Apple's own verifier refuses is not one Apple can
ship; when that library changes, this one changes with it (ROADMAP.md,
"Later / hardening"). The `Verifier` comment, the base64 wording of the
walkthroughs and the notification example's environment check were fixed
in a separate pull request.
