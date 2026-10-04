# Java: the BouncyCastle floor, the nesting probe and the pre-trust cost

Date: 2026-10-04. Feeds owner decisions Q33 (a), refuse bcprov below 1.86
and a nesting bound below 9 at `Verifier.create`, Q35 (c), state the
pre-trust cost of a hostile receipt in `java/README.md`, and review
finding L6, record the duplicate chain check as accepted cost. Sources
and commands: [`2026-10-04-java-bc-floor/`](2026-10-04-java-bc-floor/).

## Questions

1. How deep do genuine Apple receipts nest, as BouncyCastle's
   `org.bouncycastle.asn1.max_cons_depth` counts it? Does the 9-deep
   probe at create fail at exactly the bound where they fail?
2. Which bcprov releases does `Verifier.create` refuse, and what does the
   envelope parser of each do with 400,000 nested SEQUENCEs?
3. What does a cap-sized receipt that no pinned root vouches for cost
   before it is refused?
4. What does PKIX's second check of each chain signature cost, after the
   top-down walk has checked it once?

## Setup

- OpenJDK 21.0.10 (Ubuntu build), 4 vCPU, G1, default heap, one thread.
- The library at the PR #253 branch (`fix/java-bc-review`, after
  `72bb2ef`), with jackson-core 2.22.3, bcutil and bcpkix 1.86.
- bcprov jars from Maven Central (`mvn dependency:copy`):

| bcprov | bytes | sha256 |
|---|---|---|
| 1.81 | 8,948,201 | `249f396412b0c0ce67f25c8197da757b241b8be3ec4199386c00704a2457459b` |
| 1.81.1 | 8,950,152 | `e1cd291bf385a7c791a6f93192bed56d012a6bf6bdb972c2dfedaa95de2ed298` |
| 1.85.2 | 10,280,518 | `986b0fb92ec10e0c66b43e036ce0077e6150cfaecd1db9fb92b56672e157afe5` |
| 1.86 | 7,224,011 | `2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f` |

## Results

### 1. Nesting (`DepthSweep.java`, bcprov 1.86)

| `max_cons_depth` | legacy | g5 | xcode-with-purchases | 9-deep probe | `Verifier.create` |
|---|---|---|---|---|---|
| 6, 7, 8 | `MALFORMED` | `MALFORMED` | `MALFORMED` | refused | `IllegalStateException` |
| 9, 10, 11 | ok | ok | `UNTRUSTED_CHAIN` | parses | ok |

The three receipts are `fixtures/public-receipts/receipt-*.b64`. The Xcode
receipt is signed by Xcode's local CA, so under the default roots it ends
at `UNTRUSTED_CHAIN` once it parses. The verifier for the receipt column
was built before the bound was lowered, because create now refuses a bound
below 9. Nine is the exact need: the probe, nine definite-length SEQUENCEs
around an INTEGER, fails and passes at the same bound as all three
receipts.

### 2. bcprov floor (`FloorCheck.java`, bcutil and bcpkix 1.86)

| bcprov | `Verifier.create` | 400,000 nested indefinite SEQUENCEs (2,133,336 base64 chars) through `ASN1Primitive.fromByteArray` |
|---|---|---|
| 1.81 | refused, message names "v1.81" | `StackOverflowError` |
| 1.81.1 | refused, names "v1.81.1" | `StackOverflowError` |
| 1.85.2 | refused, names "v1.85.2" | `ASN1Exception` |
| 1.86 | accepted | `ASN1Exception` |

`ASN1Primitive.fromByteArray` is the envelope parse `ReceiptCore.verifyDer`
runs first. A `StackOverflowError` is an `Error`, so on 1.81 it escaped
`verifyReceipt`, which promises never to throw. The 2026-10 review measured
that through `verifyReceipt` itself, before create refused old jars. Every
release here links, so only the version check tells them apart. 1.85.2 has
the nesting bound but is still refused, because the floor is the pinned and
tested release.

### 3. Pre-trust cost (`HostileCost.java`, bcprov 1.86)

Input: one SET of 190,000 distinct unknown attributes, each 12 bytes (a
3-byte INTEGER type, version 1, an empty OCTET STRING). No creation date
(type 12), so the pre-trust walk reads every attribute. 2,280,005 payload
bytes, CMS-signed by `TestPki`, 3,055,804 base64 chars against the
3,145,728 cap. Verdict under the default roots: `UNTRUSTED_CHAIN`. Each run
does 30 warm-up calls, then measures 20.

| Run | ms per call | MB allocated per call |
|---|---|---|
| 1 | 92.6 | 147 |
| 2 | 94.7 | 147 |
| 3 | 95.2 | 147 |

The 2026-10 review measured the same shape at 152 ms and 133 MiB (no
type 12), and 133 ms and 181 ms with type 12 first and last. That was a
different session, and it reported MiB where these runs report 10^6 bytes.
So the cost is on the order of 100 to 200 ms and about 140 MB of
allocation per call. That is what `java/README.md` now states, in place of
"a 1 MB forgery about 5 ms".

## Where this stops holding

- One machine, one JDK, one thread. CPU time scales with the machine.
  The allocation figure is the steadier one.
- bcprov 1.86 for questions 1 and 3. The default depth bound changed from
  32 to 64 in 1.85, but 9 is below both.
- Only the "no type 12" shape was rerun here. The receipt column of
  question 1 covers the three public sandbox receipts, not production
  receipts, which the repository's privacy rule (CLAUDE.md) keeps out of
  it.
- `FloorCheck` swaps bcprov only. A consumer whose bcutil or bcpkix lags is
  not checked at create; the pom declares all three at one version.

## Duplicate chain check (`ChainLinkCost.java`, bcprov 1.86)

Added the same day for review finding L6. Both paths authenticate the
chain top-down first, so that no key a pinned root has not vouched for is
ever decoded (#161): `ReceiptCore.authenticatedTopDown` with
`AppleTrust.signedByAny`, and `JwsCore.authenticateTopDown`. BouncyCastle's
PKIX engine then checks the same signatures again (`CertPathBuilder` for
receipts, `CertPathValidator` for JWS). `ChainLinkCost` times one link
check, `X509Certificate.verify(issuerKey, provider)` on a fresh
`BouncyCastleProvider`, for each link PKIX repeats, and one whole verify
call for the same input. Library at `1308d83` on `fix/java-bc-followups`,
whose `java/src/main` differs from `main` at `dc3918e` only in
`BouncyCastle`'s Javadoc; the same JDK and machine as above. Links are timed over 20,000 calls after 5,000 of
warm-up, verify calls over 3,000 after 3,000.

| Input | Link | Algorithm | ms per check (3 runs) |
|---|---|---|---|
| `public-receipts/receipt-sandbox-legacy.b64` | leaf ← WWDR | SHA1withRSA | 0.054, 0.061, 0.048 |
| | WWDR ← Apple Inc. Root CA | SHA1withRSA | 0.055, 0.050, 0.049 |
| `generated/transaction.jws` | leaf ← intermediate | SHA256withECDSA | 0.088, 0.089, 0.094 |
| | intermediate ← `jws-root.der` | SHA256withECDSA | 0.091, 0.092, 0.090 |

| Input | Repeated links, ms | Whole verify, ms | Share |
|---|---|---|---|
| legacy receipt, default roots | 0.109, 0.111, 0.097 | 3.40, 3.39, 3.35 | about 3% |
| `transaction.jws`, `jws-root.der` | 0.179, 0.181, 0.184 | 0.95, 0.80, 0.83 | 19 to 23% |

So the duplicate costs about 0.1 ms per receipt and about 0.2 ms per JWS.
The walk itself checks one link more on the legacy receipt than PKIX
repeats: the receipt embeds Apple Inc. Root CA, which the walk checks
against the pinned copy before the leaf. That check is not duplicated.

The alternatives cost more than the 0.1 to 0.2 ms. Dropping the walk
reopens #161. Dropping PKIX means writing RFC 5280 path validation by
hand (validity at the signing instant, basicConstraints, keyUsage,
unknown critical extensions), which shared cases such as
`receipt/reject-intermediate-with-an-unknown-critical-extension` rely on.
Caching authenticated intermediates adds state across calls. The
duplicate is recorded as accepted cost in `AppleTrust`'s class Javadoc.

Limits: the count of two repeated links per input is read from the code
(PKIX checks the leaf and each intermediate against its issuer, never the
anchor); the probe does not count PKIX's own calls. `transaction.jws` is
signed by a synthetic P-256 chain. Apple's real JWS chain under Apple Root
CA - G3 uses P-384, which was not measured and costs more per link.
