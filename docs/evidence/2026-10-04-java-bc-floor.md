# Java: the BouncyCastle floor, the nesting probe and the pre-trust cost

Date: 2026-10-04. Feeds owner decisions Q33 (a), refuse bcprov below 1.86
and a nesting bound below 9 at `Verifier.create`, and Q35 (c), state the
pre-trust cost of a hostile receipt in `java/README.md`. Sources and
commands: [`2026-10-04-java-bc-floor/`](2026-10-04-java-bc-floor/).

## Questions

1. How deep do genuine Apple receipts nest, as BouncyCastle's
   `org.bouncycastle.asn1.max_cons_depth` counts it? Does the 9-deep
   probe at create fail at exactly the bound where they fail?
2. Which bcprov releases does `Verifier.create` refuse, and what does the
   envelope parser of each do with 400,000 nested SEQUENCEs?
3. What does a cap-sized receipt that no pinned root vouches for cost
   before it is refused?

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
