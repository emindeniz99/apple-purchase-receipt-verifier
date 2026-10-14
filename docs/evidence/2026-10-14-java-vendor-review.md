# Standalone Java vendor review

14 October 2026. Question: does the Java library meet the requested origin,
bounded-work, future-compatibility and source-cleanliness rules before vendoring?

Reviewed `main` at `0b8766f02b473c4e312da24a18b678ea3bea0267`.
Read every file in `java/src/main/`, all ten production files in
`java/src/shared/`, and `java/README.md`, `WALKTHROUGH.md` and
`WALKTHROUGH-QUICK.md` against the implementation. The earlier Temurin 17
legacy review and R20 supplied the accepted decisions; no other implementation
was used as a correctness reference. No production sources were changed.

The compatibility probes use a generated, explicitly pinned PKI. They prove
which supported trusted shapes the code refuses, not that Apple currently
ships those shapes. Neither genuine Apple sandbox fixture was refused.
An unlimited promise about unknown future cryptography or unpublished roots
cannot coexist with rejecting foreign signatures: provider and anchor updates
will still be necessary. The findings below use BC-supported algorithms and
already-pinned roots, independently of the deliberate resource/label limits.

## Must fix

1. **Equivalent issuer names are rejected before legacy PKIX (rule 2).**
   `java/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/AppleTrust.java:167`
   filters issuers with `X500Principal.equals`. A leaf issuer encoded as
   BMPString or TeletexString and the issuing CA's subject encoded as
   PrintableString can name the same DirectoryString value (RFC 5280 7.1),
   yet that comparison is false. In both probes, BC 1.86 PKIX validates the
   full path and its CMS verifier validates the signature; `verifyReceipt`
   returns `UNTRUSTED_CHAIN`. The equivalent JWS verifies. The restriction
   is an extra name-matching refusal, not a cryptographic or resource limit.
   **Smallest fix:** use the existing linear `BCStrictStyle` comparison on
   parsed X500Names for this filter, preserving RDN order and keeping all
   signature/CA/PKIX checks. That comparator returns true for every tested
   single-valued name encoding. This fixes the demonstrated cases; it is
   not a claim of complete RFC name matching for every multivalued RDN.

2. **JWS requires today's exact chain layout (rule 2).**
   `java/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/JwsCore.java:80`
   requires exactly three `x5c` entries; line 95 authenticates only one
   intermediate, and line 353 validates only `[leaf, intermediate]`.
   Independently validated and correctly signed ES256 chains with the root
   omitted (two entries, allowed by RFC 7515 4.1.6), or with another CA
   above the WWDR issuer (four entries), both return `MALFORMED`. Adding
   only a length exception would leave the fixed path incorrect.
   **Smallest fix:** authenticate and PKIX-validate the supplied ordered
   path to a configured anchor, with an optional carried root, retaining
   the marker on the leaf's direct issuer and reusing an existing certificate
   resource bound. No new caller option is needed.

3. **JWS rejects a supported algorithm change (rule 2).**
   `java/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/JwsCore.java:77`
   rejects every algorithm except ES256; line 372 also fixes the signature
   at 64 bytes. A P-384 leaf with the same markers and a BC-valid path,
   signing a valid ES384 compact JWS, returns `MALFORMED`; the independent
   BC signature check succeeds. A move to ES384 would require this library
   to change despite BC already supporting it.
   **Smallest fix for the demonstrated transition:** dispatch ES256/ES384
   by their JOSE definitions to BC's PLAIN-ECDSA verifier, enforce the
   corresponding curve/hash, and derive the signature width from the curve
   order per RFC 7518 3.4. Keep unsupported algorithms and `none` refused;
   do not pass arbitrary header strings straight to JCA.

4. **A production API comment mentions tests (rule 4).**
   `java/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/Verifier.java:13`
   says the interface exists for callers' tests. That violates the explicit
   source rule even though it has no runtime effect.
   **Smallest fix:** delete the test-specific sentence. Keep the interface.

## Should fix

- `java/src/shared/java/io/github/emindeniz99/applepurchasereceiptverifier/ReceiptPayload.java:30`
  says every genuine date ends in `000`. The decoder and README support
  fractional RFC 3339 dates. Delete the universal whole-second assertion;
  no parser change is needed.
- `java/WALKTHROUGH-QUICK.md:142` and `java/WALKTHROUGH.md:459` say unverified
  input can never produce `INTERNAL_ERROR`. `DefaultVerifier` deliberately
  reads the clock before examining input, so a host clock failure can do
  exactly that. Say attacker-controlled input must not cause these alarms
  on a healthy runtime. The existing implementation and README already
  explain the intended distinction.

## Fine as is

- **Rule 1:** no new forgery or work-bound failure was found in the generated
  negative controls and JSON collision probes; all 406 negative calls refused
  without a payload, unchecked exception or internal/payload-error alarm.
- **Legacy sandbox acceptance:** both genuine public fixtures verify on
  Temurin 17; the reported name issue is a supported-shape compatibility
  failure demonstrated with synthetic keys.
- **Recorded guards and runtimeProbe:** their previously accepted reasons
  still apply; this review adds no reason to remove them or add options.
- **Production structure:** no dead branch or necessary second implementation
  was found; the before-trust screens, top-down proof and full PKIX serve
  different purposes and should remain.
- **README and walkthroughs:** their current algorithm/chain restrictions
  accurately describe the code, apart from the qualified documentation
  corrections above; they do not establish future compatibility.

**The reviewer's verdict, before the decision below: ready to vendor as is, no under the stated rules; first change the issuer-name filter in `AppleTrust.signedByAny` to the existing linear BC name comparison.** The owner kept the filter (see Decision).

## Validation and measured results

Tools: Eclipse Temurin **17.0.20.1+1**, HotSpot (`OpenJDK 64-Bit Server VM`),
Linux amd64; Maven **3.9.16**; Python **3.12.14**. Dependencies: BC
bcprov/bcutil/bcpkix **1.86**, jackson-core/databind **2.22.3**, Jackson
annotations **2.22**, JUnit Jupiter **5.14.4**, JSpecify **1.0.1**.
Sources and probes were compiled for Java 8 with Temurin 17.

`run.py` executed `mvn -B -f java/pom.xml verify` against an unchanged scratch
copy. `verify.log`, `suite-summary.json` and the Surefire XML reports record
**699 tests, 0 failures, 0 errors, 1 skipped**, build success. The skip is
`FixtureGeneratorTest.generate`, which requires the explicit generation
property. Two initial dependency-resolution attempts failed because Maven
needed the managed HTTP proxy; proxy settings and the environment's Java CA
store resolved it without source/build changes.

The final `probe.log` records **842 passed assertions**, including
**406 negative verification calls**. The independent controls check the
certificate path and signature separately; these do not rely on a verdict
from the code being reviewed.

| Probe | Independent control | Library result |
|---|---|---|
| Current ES256, three entries | PKIX and signature pass | `VERIFIED` |
| ES256, root omitted, two entries | Same PKIX path and signature pass | `MALFORMED` |
| ES256, extra CA, four entries | PKIX and signature pass | `MALFORMED` |
| ES384, three entries | PKIX and signature pass | `MALFORMED` |
| Leaf issuer PrintableString or UTF8String | PKIX, CMS signature and linear name comparison pass | Receipt and JWS `VERIFIED` |
| Leaf issuer BMPString or TeletexString | PKIX, CMS signature and linear name comparison pass | Receipt `UNTRUSTED_CHAIN`; JWS `VERIFIED` |
| Foreign roots, non-CA issuer, missing leaf marker, every JWS signature byte and every synthetic payload byte mutated | Negative controls | All refused |
| Two genuine Apple sandbox receipts | Default pinned Apple roots | Both `VERIFIED` |

Additional exploratory inputs are retained in the code: a multivalued
SignerIdentifier with a changed string encoding is `MALFORMED` (the BC
strict comparator also differs, so it is not the isolated top-down finding);
a self-issued tail putting the receipt signer eight certificates below
the root, nine embedded certificates, is `UNTRUSTED_CHAIN`. An initial
assertion that the latter would verify failed; the final probe records its
actual result. It did not disprove the already recorded builder limit and
is not promoted to a new finding.

The JSON-name inputs use `Aa`/`B@` fragments, which collide under the char
parser's polynomial hash, alongside distinct-name controls. Each case is
refused, either at the collision guard or at the bad signature. Final
plain-loop measurements from `probe.log`, 20 warm-up calls then 20 measured
calls per case, one thread, 512 MiB heap:

| Names | Distinct input bytes | Distinct mean ms | Collision input bytes | Collision mean ms | Collision verdict |
|---:|---:|---:|---:|---:|---|
| 64 | 2,969 | 2.398 | 4,603 | 1.736 | `INVALID_SIGNATURE` |
| 256 | 6,505 | 2.165 | 12,795 | 1.291 | `INVALID_SIGNATURE` |
| 1,024 | 20,873 | 3.791 | 45,563 | 0.883 | `MALFORMED` |
| 4,096 | 82,313 | 2.745 | 176,635 | 0.813 | `MALFORMED` |

These noisy microbenchmarks did not expose runaway work. They do not prove
linear cost for every possible input or establish a capacity budget.
The source-level basis for accepting the JSON guard is Jackson's existing
collision-overflow protection, not these latency figures.

Downloads remained in scratch. SHA-256 of the Temurin archive:
`3808d1d15e3ec6bd5b84057fb5d84c33d8a1536a258146bcea2e603fc726e08e`
(193,252,603 bytes).
SHA-256 of the Maven archive:
`80ffca22aed9e8b9713a232f3394fd81d7f20322df75efdb2b047dbd3e3a23bb`
(9,278,065 bytes).
The unchanged scratch build produced the main jar (91,937 bytes), SHA-256
`0f695e5a16f78313d47c0b253497879fea42f30d4c8b5b2d7c738c8397ed2974`,
and the published test-helper jar (21,009 bytes), SHA-256
`b99b85e1b1af1bab424c726a43d30d1933b1cfe40e8e45c8a7b897b5c9d86ec7`.
No binaries, keys, receipt copies or raw logs were committed.
Reproduction code and commands:
[review folder](2026-10-14-java-vendor-review/README.md).

## Decision (owner, 2026-10-14, Q170 and Q171)

The three rule-2 findings stay as they are and are recorded in
DECISIONS.md R20. Apple's own App Store Server Library (Java,
`ChainVerifier` and `SignedDataVerifier` on `main`, read 2026-10-14)
refuses the same shapes: `EXPECTED_CHAIN_LENGTH = 3`, any `alg` but
`"ES256"` is "Unrecognized JWT algorithm", and the chain is validated by
the JDK's `CertPathValidator("PKIX")`, which chains names with
`X500Principal.equals`. A shape Apple's own verifier refuses is not one
Apple can ship; when that library changes, this one changes with it
(ROADMAP.md, "Later / hardening"). The `Verifier` comment and the two
documentation findings were fixed in a separate pull request.
