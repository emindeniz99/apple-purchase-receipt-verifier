# Java: the tables BouncyCastle keys by OID before trust

Date: 2026-10-13. Records why Java caps the extensions on a certificate
and the attributes on a SignerInfo (owner Q141 a and Q143), the bound
behind the two caps, and what the caps refuse. It feeds DECISIONS.md
R20, java/README.md's resource bounds and THREAT-MODEL.md §3.7. Nothing
was timed: the cost is a bound read from the sources, not a
measurement, so this note has no folder. The Apple counts came from
`openssl`.

## Question

Can a receipt or a JWS make BouncyCastle build a table keyed by OID in
time quadratic in the input before any chain is trusted, and what
count keeps that cost negligible without refusing anything Apple signs?

## Setup

- bcprov, bcutil and bcpkix 1.86, read with `javap` from the jars the
  build resolves. OpenJDK 21's `java.util.Hashtable`.
- The library on `fix/java-oid-table-caps`, on top of the pre-trust
  shape fixes ([pre-trust shape](2026-10-13-java-pretrust-shape.md)).

## What the sources show

`ASN1ObjectIdentifier.hashCode` is BouncyCastle's own
`org.bouncycastle.util.Arrays.hashCode` over the OID's content octets,
unkeyed and unrandomized, and the OID is the key of a
`java.util.Hashtable` with chained buckets, which unlike `HashMap` never
turns a long chain into a tree. Two tables are built that way:

| Table | Built by | When | Who chooses the OIDs |
|---|---|---|---|
| `Extensions` (`Hashtable extensions`) | `TBSCertificate`, while `Certificate.getInstance` parses | every bag entry (`ReceiptCertificates.decode`) and every x5c entry (`JwsCore.decodeChain`), before any chain is trusted | whoever adds a bag entry or sends an x5c |
| `AttributeTable` (`Hashtable attributes`) | `SignerInformation`, for signed and unsigned attributes | once a SignerInfo is read for verification; a copy of Apple's SignerInfo is vouched for by Apple's chain | anyone relaying a receipt, for unsigned attributes |

When every key lands in one bucket, inserting the Nth compares it with
the N - 1 already there, and each insert scans the bucket twice:
`Extensions` calls `containsKey` then `put`, and
`AttributeTable.addAttribute` calls `get` then `put`. Building the table
therefore costs about N^2 OID comparisons. The Q141 review estimated
that about 10^5 extensions fit under the 3 MiB receipt cap, about 10^10
comparisons. Distinct OIDs
that share a hash are cheap to find for an unkeyed hash; this note did
not build any, and no test does.

## The caps

| Constant | Value | Counted | Over the cap |
|---|---:|---|---|
| `ReceiptCertificates.MAX_CERTIFICATE_EXTENSIONS` | 1,000 | on the raw TBS, every `[3]` field after the version slot, before `Certificate.getInstance` | a bag entry is skipped, as one `AppleTrust.convertible` rejects; an x5c leaf or intermediate is a null link, `UNTRUSTED_CHAIN`, and x5c[2] is never read |
| `ReceiptCore.MAX_SIGNER_INFO_ATTRIBUTES` | 1,000 | signed plus unsigned, on the raw `SignerInfo`, before `CMSSignedData` and `SignerInformation` are built | the SignerInfo is left out; `MALFORMED`, "signer certificate not embedded", when none is left |

At the cap the worst case is about 1,000^2 = 10^6 comparisons per
table, each over a few octets: a few milliseconds, an estimate from
the sources and not timed. A certificate's table is built at least
twice, by `Certificate.getInstance` and again by the CertificateFactory
re-parse in `JcaX509CertificateConverter.getCertificate`. The receipt
cap admits ten certificates and four SignerInfos, so the bound holds
per receipt too.

## What Apple sends

| Input | Count | Source |
|---|---:|---|
| G5 receipt signer | 8 extensions | `fixtures/public-receipts/receipt-sandbox-g5.b64` |
| G5 intermediate | 7 extensions | the same receipt |
| Apple Root CA, as embedded | 5 extensions | the same receipt |
| Apple Root CA - G2, G3 | 3 extensions each | `certs/` |
| Apple's receipt SignerInfo | no attributes | the same receipt |

Counted with `openssl x509 -text` and `openssl pkcs7 -print_certs`.

## Pinned by

- `UnauthenticatedKeyCostTest`: a receipt signer at 1,000 extensions
  verifies and one at 1,001 is passed over; an x5c intermediate at 1,000
  verifies and one at 1,001 is `UNTRUSTED_CHAIN`; a bag stranger at 1,001
  is passed over beside the genuine chain; a `[3]` placed out of order
  still counts; a stranger whose version field is tagged `[3]`, which
  BouncyCastle reads as the version, is not counted and the receipt
  still verifies; a SignerInfo at 1,000 attributes verifies and one at
  1,001 is left out. The OIDs are ordinary distinct arcs under
  1.3.6.1.4.1.99999.
- `receipt/accept-genuine-beside-a-stranger-with-a-thousand-and-one-extensions`:
  Apple's G5 receipt with a 1,001-extension stranger in its bag, ok in
  both implementations (`tools/generate-signer-info-fixtures.mjs`).

## Where this stops holding

- bcprov 1.86. A release that keys these tables differently, or a JDK
  `Hashtable` that treeifies, changes the bound but not the caps.
- The bound assumes the worst case, every OID in one bucket. It was not
  measured, by choice: the inputs that would measure it are not built.
- Apple's own SignerInfo with more than 1,000 unsigned attributes
  appended is refused by Java and accepted by the core, a row in
  DECISIONS.md R20.
- The count runs before the parse, since the parse builds the table, so
  an entry over the cap that would not otherwise decode is passed over
  (a bag stranger leaves the receipt ok; x5c `UNTRUSTED_CHAIN`, or ok
  for x5c[2]) where the core
  answers `MALFORMED` or `INVALID_CERTIFICATE`, another R20 row.
