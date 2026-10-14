# Java BC legacy receipt: Temurin 17 review

14 October 2026. Reviewed main: `4c7941894cbebe21fc1238aac6b4edc8f06880f1`.
The remote main was checked again at the end of the review and was still
at that commit. Review by Codex (GPT-6) in a local session; the note was
written in Turkish and translated into English for the repository, with
line references replaced by method and constant names, since #373 moved
the certificate extension cap into `PreTrustScreen` after the review.

Scope: the legacy PKCS#7 receipt path in `java/`, the shared
trust/config/result code it uses, and the additions of 13 and 14 October.
Rust behaviour was not used as a yardstick. JWS is out of scope.

## Verdict

**No signature or trust hole was found that blocks going to production
on Temurin 17 for standard Apple legacy receipt verification. The new
resource guards should stay.** The HTTP service needs a heap and
concurrency bound against large inputs: the byte cap alone does not
protect a small JVM. This is an operating condition the README already
states.

If the goal is "accept the valid receipts Apple produces", the result is
good: the genuine Apple-signed SHA-1/G1 and SHA-256/G5 sandbox receipts
pass, their corrupted-signature variants are refused, and because the
signing date is used, certificates that expire later do not break an old
receipt.

A wider claim, "accept every possible ASN.1/CMS repackaging Apple would
accept", cannot be made. The library has resource limits. This review did
not compare acceptance one to one against Apple's live `verifyReceipt`
endpoint. No production receipt was supplied; production-only field
combinations can be checked with a private canary. The genuine Apple
chains were exercised with sandbox data.

## Validation

- Eclipse Temurin **17.0.20.1+1**, HotSpot, Linux x86-64.
- BouncyCastle **bcprov/bcutil/bcpkix 1.86**; Jackson **2.22.3**.
- Maven **3.9.16**; the sources were recompiled with Temurin 17 for the
  Java 8 target. `clean verify` passed; the main jar and the tests jar
  were built.
- **699 tests, 0 failures, 0 errors, 1 skipped.** The skip is the
  fixture-generation test enabled by hand. Of the 444 shared cases, 224
  go through `verifyReceipt` and 62 through `verifyReceiptEndpoint`; the
  rest exercise other APIs and base64 checks. A green full suite does not
  mean every test is a legacy-path test.
- Extra probes: the two genuine Apple sandbox receipts, a clock moved
  forward, a corrupted signature, 1,000 and 1,001 unsigned attributes
  added beside the same signature.
- Map-free creation-date trial: **3,344 payloads from the fixture and
  deterministic mutation corpus, 2,210 readable dates, 0 differences.**
- A first Temurin 21 run also passed; the production decision rests on
  the Temurin 17 result.

## Findings and simplification candidates

### 1. Main operating risk: parsing the payload before the signature is expensive

`ReceiptCore.verify` calls `ReceiptDecoder.readCreationDate` before any
trust is established. `readCreationDate` uses only attribute 12, but it
goes through `readAttributes`, which parses every top-level attribute and
fills the `firsts` and `unknown` maps. Those maps are discarded at this
stage. If the chain and the signature pass, the same payload is read again.

An attacker can trigger this work: for a receipt that carries its own
chain and stays under the byte cap, the payload is read first and
`UNTRUSTED_CHAIN` comes back afterwards because of the foreign root. The
trial input is about 3 MiB of base64 and carries 195,562 extra small
attributes.

| Temurin 17 measurement | Mean time | Total allocation per call |
|---|---:|---:|
| Genuine legacy sandbox receipt, 187 purchases | 7.1 ms | 4.6 MiB |
| Genuine G5 sandbox receipt | 2.9 ms | 0.4 MiB |
| Near-cap forged receipt with small attributes, refused under the Apple roots | 128.3 ms | 135.2 MiB |
| The same synthetic receipt, accepted under its own test root | 297.4 ms | 279.5 MiB |
| Near-cap single unsigned attribute, forged chain | 94.4 ms | 75.8 MiB |

These are plain-loop measurements of 20 calls after 30 warm-up calls, not
JMH or a throughput capacity measurement. Times vary by machine. **Total
allocation is not live heap at one instant.**

The same forged receipt threw `OutOfMemoryError` in a single call at
`-Xmx64m` and was refused cleanly at `-Xmx128m`. In a single cold-process
bisection 78 MiB failed and 79 MiB passed. That value is not a heap
guarantee for every input. An OOM is an `Error`, so it escapes the public
API; it does not become a normal `Failure`.

Recommendation: on the HTTP side, a bounded executor or semaphore beside
the byte cap, and a heap sized for the large inputs verified at once. The
most meaningful performance candidate inside the library is not building
the unused maps for the creation date. Trial:

| Creation-date step alone | Time | Total allocation |
|---|---:|---:|
| Current reader | 119.08 ms | 114.28 MiB |
| Trial that checks the whole top-level structure and keeps no maps | 62.57 ms | 85.93 MiB |

The trial keeps the rule that the first attribute 12 wins and that a
malformed later attribute invalidates the date. Corpus equality is good
evidence, not a proof over every possible input. The change needs more
reader code; it is not a mandatory production fix for normal receipts.
The earlier "parse the payload once and keep the result" trial was a
different thing: it was reverted because it did not reduce the
pre-signature cost.

Owner decision (Q160, 2026-10-14): not done. The README's heap and
concurrency rule covers the risk, genuine receipts see no difference, and
a second reader is more code than the gain is worth.

### 2. The acceptance limits are deliberate; "every validly signed package" is too wide a claim

`ReceiptCore.MAX_SIGNER_INFO_ATTRIBUTES` and
`ReceiptCertificates.MAX_EMBEDDED_CERTIFICATES`.

Keeping the payload and signature of the genuine G1 and G5 receipts and
adding only unsigned attributes: with 1,000 attributes both are
`VERIFIED`, with 1,001 both are `MALFORMED`. The library can refuse a
package whose signature is valid, because of its resource policy. This is
not a new hidden hole; it is the concrete consequence of the existing cap.

The caps of 10 embedded certificates, 4 SignerInfos, 1,000 certificate
extensions (`PreTrustScreen.MAX_CERTIFICATE_EXTENSIONS`) and 1,000 total
SignerInfo attributes are of the same kind. Apple's current receipt
shapes sit well below them. Removing them is not my recommendation.
Stating the acceptance goal as "Apple-signed receipts within the
supported resource limits" is more accurate.

`SignedAsSent` also changes the acceptance behaviour for non-DER signed
attributes: it avoids BC's cost of sorting them into DER. DER-form signed
attributes encode to the same bytes. For non-DER input the behaviour is
not identical to BC's earlier canonicalisation; the existing evidence
records this. Neither genuine Apple fixture carries signed attributes. So
I found no breakage evidence for current Apple receipts, and I would not
claim "full RFC/BC behaviour" for a general CMS verifier.

### 3. Long repeated explanations in the sources could be shortened

Between `1cb08f0e` at the start of 13 October and the reviewed main, all
Java changes added 2,217 lines and removed 67. Of the net growth, 1,686
lines are in tests and 464 in main/shared sources.

Taking JWS out and looking at the seven changed production files on the
legacy path, the net growth is **440 physical lines**. Counted without
comments and blank lines, the net code growth is **236 lines**. The count
used an approximate Java comment tokenizer, not an AST-based complexity
metric.

In particular, long benchmark figures, draft history and detailed
descriptions of the same attack in `AppleTrust` and `ReceiptCore` repeat
what the evidence documents already hold. A short "why", an RFC reference
and a link to the relevant evidence would read better. The notes needed
to understand a decision, such as the PSS formula, why an untrusted key is
not read and the DER/DL difference, should stay.

I found no class that is clearly unused on the production path and no
security branch that is safe to delete. Most of the observed growth is
tests, which are not loaded at run time, and explanations.

Owner decision (Q161, 2026-10-14): left as is. Two independent
cleanliness audits of the same sources (Opus and Fable, 14 October)
judged them clean, and the reviewed main carries one numeric figure in a
production comment.

### 4. The benchmark tests have a maintenance cost

`DigestDenylistCostTest` scans the provider's OIDs and BC's private digest
tables and decides on run-time ratios. The test is useful: it reports a
new expensive path when a dependency upgrade adds one. But compared with a
normal functional test it depends more on the JIT, runner load and BC's
internal API. The source also records that it once failed on Temurin 17
over a ratio and that the tolerance was changed.

The current test passed in this review; I am not reporting a live
failure. My maintenance suggestion is to consider running this wide scan
on dependency upgrades or as a periodic benchmark. The deterministic
negative tests and the required DoS regression tests should stay in
normal CI. This code does not enter the shipped jar; deleting it would not
shrink the production code.

Owner decision (Q162, 2026-10-14): stays in CI; the tolerance is revisited
only if the test flaps (Q154).

## Which of the recent additions are necessary?

| Code | Why it is needed / decision |
|---|---|
| `saltFits` and the content-verifier wrapper | Stops the huge array allocation driven by an unsigned PSS salt length. The wrapper checks the algorithm BC actually resolves, so alias OIDs are covered too. Keep. |
| Refusal of the generic composite label | Stops the sender from producing as many signature verifiers as it likes and hashing the content again and again. Keep. |
| Refusal of eight expensive digests and the MD2 signature label | Cuts the expensive hash before an invalid signature is compared. The separate check on the signature label is not a duplicate. Keep. |
| `stringsOnly`, `holdsSet`, `convertible` | Prevents the expensive DER encoding of nested SETs inside unsigned names and parameters. BC's object conversion also encodes, so removing only the first encode is not enough. Keep. |
| Extension and attribute count caps | Bound the collision cost in BC's OID-keyed `Hashtable`. The default receipt byte cap does not stand in for them. Keep. |
| Not retrying copies of the signer and the issuers | Cuts the needless chain and signature checks for the same certificate added to the unsigned bag. Keep. |
| A single-member CMS per signer | Avoids the expensive path of issuer comparison in BC's multi-signer store. Looks unusual, but it has a reason. Keep. |
| `SignedAsSent` | Keeps the nested SET sorting of signed attributes from running before the signature. The DER/DL difference and the non-DER acceptance scope should stay explicit. |

Refusing PSS altogether, or allowlisting only the SHA-1 and SHA-256
algorithms observed today, could narrow the code but raises the risk of
needlessly refusing a new Apple signing algorithm. The current small
resource guards fit the stated acceptance goal better.

## Correctness of the flow

- The UTF-8 byte cap comes before the base64 decode. Standard base64
  padding is checked; the unused-bits acceptance follows the repository's
  Apple measurement.
- The CMS envelope is parsed once; trailing bytes and detached content are
  refused. BER encapsulated content is supported.
- The creation date is taken from the first attribute 12. A missing or
  unreadable date falls back to the clock. The current clock does not
  override a valid historical date.
- The public keys of embedded certificates are not used until a pinned
  root, or a CA whose signature it verified, has vouched for them. An end
  entity cannot vouch for the next certificate.
- Full PKIX validation after the top-down signature proof is necessary.
  The first pass prevents the untrusted-key decode cost; PKIX evaluates
  dates, CA, key usage, constraints and critical extensions. Using the
  first pass instead of PKIX would not be a safe simplification.
- The PKIX target is the exact signer certificate. There is no hole where
  a twin with the same issuer/serial/subject but another key gets the
  trust check applied to a different key.
- The Apple marker checks on the leaf and on the intermediate directly
  above the signer are present. An ordinary developer certificate chained
  to the same root is not accepted as a receipt signer.
- One passing SignerInfo is enough; every certificate match is tried. A
  valid signer beside a corrupt or unsupported signature is protected by
  deterministic tests.
- The payload model is built only after the CMS signature passes. Bundle,
  environment, product and device hash are not the verifier's business
  policy; they are fields left to the caller. Raw values of unknown or
  unreadable fields are preserved. The defensive copies of mutable byte
  arrays are not superfluous.

Apple's [receipt validation document](https://developer.apple.com/documentation/appstorereceipts/validating-receipts-on-the-device)
states in particular the SHA-1 and SHA-256 chain support, not hardcoding
intermediates, and using attribute 12 in signature validation. I found
these three points handled correctly in the current Java path. The
bundle/version/device checks in that document are parts of on-device app
entitlement validation; this library's "Apple signature plus payload"
contract states them explicitly as the caller's responsibility.

## Suggested order

1. Verify the concurrency and heap budget for large inputs in the
   production service; the samples are no guarantee of real receipt sizes.
2. Keep the current crypto and pre-trust guards.
3. Move the long repeated explanations into the existing documentation.
4. If needed, reduce the creation-date map allocation; evaluate it
   separately with tests that keep corpus equality and the
   before/after-signature error order.
5. Decide where the algorithm-scan benchmark runs in CI.

The production Java sources were not changed. The review code and the
instructions to rerun it are in [this folder](2026-10-14-java-legacy-temurin17-review/README.md).
Trial receipts, JDK/BC downloads, class files and raw measurement logs
were kept outside the repository.

## Second pass: legacy receipt security review

This section is an additional review on the same main
`4c7941894cbebe21fc1238aac6b4edc8f06880f1`, with Temurin 17.0.20.1+1 and
BC 1.86. Rust and JWS are out of scope for this pass. Threat model: the
attacker can change the base64 input, the CMS envelope, the certificate
bag and the SignerInfos; they cannot reach Apple's private key, the
application's root config or the JVM settings. Public sandbox receipts
and a synthetic test PKI were used.

### Findings and decision

**No new signature or trust-chain bypass could be shown.** In the
reviewed flow, returning `VERIFIED` requires the same signer certificate
to chain to a root, pass the marker checks and verify the payload's CMS
signature. This result is not a proof that every possible input is safe;
it is bounded by the tests and source review below.

**The open item for production: memory consumption before verification.**
`ReceiptCore` parses the envelope and then `ReceiptDecoder.readCreationDate`
parses the whole attribute SET before any trust is established. The
previous pass showed 135.2 MiB of total allocation for a synthetic forgery
under the cap, and an OOM at a 64 MiB heap. This is not an entitlement or
signature bypass; it is an availability risk for a service that accepts
attacker input. Catching `RuntimeException` does not prevent
`OutOfMemoryError`. An unconditional "production ready" verdict should
not be given until the heap and concurrency budget is verified. The README
already documents this risk; it is not presented as a newly discovered
design flaw. Concurrency should be bounded by the application's free heap
budget as well, not chosen from the CPU count alone. The allocation total
cannot be multiplied by the concurrent request count and used as a peak
heap estimate.

**Simplification candidate: the temporary maps for the creation date.**
`ReceiptDecoder.readCreationDate` collects every other attribute value
into maps and lists for one date. The earlier scanner trial gave the same
result on the same corpus with less allocation. That change does not
remove the first parse cost of the ASN.1 tree and is not a DoS fix on its
own. The first attribute winning, a malformed later attribute sending the
date to the fallback, and the error order must be kept.

**There is no one-to-one equality with Apple's acceptance today.** A
concrete example: `ASN1Primitive.fromByteArray` refuses extra bytes at
the end of the CMS. The repository's
[2026-09-23 Apple endpoint measurement](2026-09-23-verifyreceipt-base64.md)
records that bytes appended to the same receipt are ignored by Apple;
`receipt/reject-one-trailing-byte-after-the-der` pins this as a deliberate
difference. This pass made no new request to the Apple endpoint. This is
not only a possible future incompatibility but a recorded acceptance
difference. If the user's goal is full Apple acceptance equality, this
behaviour needs its own decision. Removing the resource caps does not
solve it.

### New experiments

Source:
[SecurityReviewProbe.java](2026-10-14-java-legacy-temurin17-review/SecurityReviewProbe.java).
Rerun with `run.py --security-only`. The compiled production classes were
not changed. The first results were `binding.log` and `oid-costs.log`; the
rerun wrote `results.txt` to a scratch directory outside the repository.
The logs print no receipt fields or user identifiers.

| Experiment | Result |
|---|---|
| Flipping one bit at 128 positions across the payload of the genuine legacy and G5 receipts | None became `VERIFIED` |
| Flipping one bit at every byte position of the same receipts' RSA signature | None became `VERIFIED` |
| Detached content or an empty certificate bag | Not accepted |
| Carrying the same signed content as a fragmented BER OCTET STRING | Both genuine receipts and the synthetic control accepted |
| Changing the payload and the messageDigest together in a synthetic receipt with signed attributes, keeping the signature | Not accepted |
| Duplicating the signed messageDigest, contentType or cmsAlgorithmProtect attribute | Not accepted; this experiment also changes the signature, so on its own it does not prove the duplicate check runs |
| Presenting a receipt signed by the synthetic PKI to the default Apple roots | Not accepted |
| RSA blocks produced with the test key: each of the 20 bytes of the SHA-1 digest changed separately, plus four malformed padding/DigestInfo forms | 24 malformed blocks refused; the valid control accepted |
| The same RSA experiment for SHA-256 | 36 malformed blocks refused; the valid control accepted |

**1,119 assertions** passed in total. Failed verifications returned no
payload, produced no `INTERNAL_ERROR` and let no unchecked exception
escape. The RSA experiment does not merely corrupt a signature byte: a
signature is prepared with the test private key that yields the desired
EMSA-PKCS1-v1_5 block. The digest-byte and padding checks after the RSA
operation are thereby tested specifically.

For the OID table I tested the earlier source-level estimate with real
collision input: **1,000 distinct OIDs** with the same BC `hashCode()`,
each of **2,300 content octets**. The OIDs' long common prefix makes the
equality check expensive. The OIDs were added to the unsigned attribute
area of the genuine G5 receipt; Apple's signed content and signature were
unchanged. The control group carries the same number and length of OIDs
with distinct hashes.

| Unsigned attributes | Base64 bytes | Control, ms/call | Hash collision, ms/call |
|---|---:|---:|---:|
| 250 | 778,236 | 11.3 | 10.8 |
| 500 | 1,548,900 | 12.6 | 29.2 |
| 1,000 | 3,090,236 | 20.5 | 82.4 |

Every input gives `VERIFIED`; all are under the 3,145,728-byte cap. Mean
of ten calls after five warm-ups, 512 MiB heap. These are not JMH or
worst-case latency guarantees. The experiment shows that the quadratic
table is not only theoretical and that the current cap bounds the work in
this attack. There is no ground for removing the 1,000 limit as
unnecessary code.

### Trust boundaries: the result of the source review

| Boundary | Check and assessment |
|---|---|
| Payload to CMS signature | The returned payload is the same byte array inside `CMSSignedData`. With signed attributes BC compares messageDigest with the computed digest; without them it verifies the payload's direct signature. |
| Signer identity to key | Issuer/serial or SKI matching only selects candidates. The PKIX target is the exact certificate; the candidate's own public key is used for the CMS. Another key with the same name/serial cannot stand in for trust. |
| Apple developer key to receipt signing key | In the top-down walk an end entity cannot approve the next certificate. The receipt leaf and direct issuer WWDR markers are required besides. |
| Top-down to full PKIX | The first stage only provides the issuer signature proof. The second stage is for validity, CA/key usage/constraints/critical extensions. Removing either is not a safe simplification. |
| Unsigned algorithm labels to the BC provider | The PSS salt bound is applied on the algorithm BC actually resolves, before a verifier is built. Generic composite is refused separately; a raw OID check alone is not enough. |
| CMS attribute processing | `SignedAsSent` avoids the DER sorting cost; BC's contentType, messageDigest, algorithm protection and countersignature checks still run. DL use gives no equality guarantee with standard BC for general non-DER CMS acceptance. |
| Certificate URL to network | The reviewed builder is given only a Collection CertStore, no named store, revocation off. BC's issuer search uses these stores; I found no call on this path that adds an HTTP fetch of an attacker's certificate URL. This item is a source review, not a network instrumentation result. |
| Shared verifier to per-call state | The trust config is fixed; CMS, signer verifier and PKIX builder are per call. The critical-extension checker holds no state. The existing concurrency/isolation tests passed in the earlier Temurin 17 suite. |

### Production decision and unnecessary code

No new release blocker for the signature or the trust chain was found in
this review. The 1,119 security assertions of this pass add to the
earlier **699 tests / zero failures / one skip** on Temurin 17; they are
not new JUnit test counts. The public fixtures passing the genuine Apple
chains is an important check for SHA-1 legacy and G5; it does not mean
every Apple receipt variant is covered.

PSS, generic composite, unauthenticated key decode, strict signer lookup,
the exact certificate target, the certificate/SignerInfo/attribute caps
and top-down plus PKIX should stay. This pass found no clearly dead
production security branch that can be deleted safely. The earlier
simplification suggestions stand: the creation-date map allocation and
the long comments repeating the evidence documents. Replacing BC's
signed-attribute verification with a hand-written CMS verifier would not
give a smaller security surface.

`VERIFIED` is only the library's documented signature/trust contract.
Bundle, sandbox/production, product, which user a transaction was granted
to, and idempotency must be checked in the application. Offline
verification does not learn of a later refund/revocation or the latest
subscription state. These are not new findings; they are the limits of
the security assessment.

## Which code is really surplus?

A branch Apple's normal receipt never exercises is not surplus if it
bounds a BC path the attacker can run before verification. On the other
hand, not every added line is a cryptographic necessity. The concrete
simplification decision along that distinction:

| Code | Role in verifying Apple's signature | Suggestion |
|---|---|---|
| All attribute maps/lists inside `readCreationDate` | Only the first attribute 12 is needed; accumulating the other values at this stage is not | Simplification candidate: a map-free scan that keeps the full structural check. Allocation dropped in the trial; no production change was made on this branch. |
| `DigestDenylistCostTest` (315 lines) | Takes no part in run-time verification. A maintenance benchmark that scans algorithm costs | Candidate for moving out of the normal test suite into a benchmark run on BC upgrades or on a schedule. Keep the deterministic bad-input refusal tests in the normal suite. The current suite passed in this environment; the suggestion rests on observed maintenance complexity. |
| Long benchmark/history narration in production comments | Changes no run-time behaviour; the evidence documents already hold the same reasoning | A short invariant plus an evidence link could remain. Do not delete the security reasoning altogether. |
| `REFUSED_DIGESTS` and the MD2 signature label refusal | Not a condition of Apple's signature validity; a local policy bounding pre-verification CPU cost | Keep the small table. Deleting it does not remove signature security directly but reopens the measured expensive digest paths. Ask for measurements before widening the table. |
| `SignedAsSent`, the single-SignerInfo CMS wrapper, `stringsOnly` / `holdsSet` | Bound BC's sorting, hashing and name comparison costs before verification | They have their reasons on the current BC 1.86; do not remove them merely because Apple does not normally produce these forms. Re-evaluate `SignedAsSent` in particular on BC upgrades, since it intervenes in general CMS behaviour. |
| PSS salt check, generic composite refusal, top-down plus PKIX, exact certificate target and the resource caps | Some establish the trust binding, others prevent OOM/excess CPU before the signature check is reached | Keep. The review found no dead branch that can be deleted safely. |

In the 13 to 14 October comparison, the legacy-related production growth
is about **440 physical lines**, about **236 code lines** without comments
and blanks. The net growth in the Java tests is **1,686 lines**. So most
of the visible growth is not new verification logic added to the run
time. These figures belong to the same commit range as the earlier
section; the comment split is an approximate lexical measurement.

The probes on this review branch also stay under `docs/evidence/` only;
they enter neither the Maven production sources nor the published main
JAR. The branch carries the report and reproducible evidence, not a
production refactor.
