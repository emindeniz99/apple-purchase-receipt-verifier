# Java: ASN.1 re-encoded and unsigned labels acted on before trust

Date: 2026-10-13. Measures what Java paid before any signer was trusted
for three sender-chosen inputs, and what it pays after the fixes, for
owner decisions Q135 a (the certificate bag and the SignerInfo's
issuer), Q136 a (the md2WithRSAEncryption signature label) and Q137 a
(the RSASSA-PSS label), and the figures in DECISIONS.md R20,
java/README.md and THREAT-MODEL.md §3.7. Sources and commands:
[`2026-10-13-java-pretrust-reencoding/`](2026-10-13-java-pretrust-reencoding/).

The round-4 Java reviews found all three: the bag and issuer shapes
(Q1) and the md2WithRSA label (S1) in one review, the PSS salt (F1) in
the other. `NestedValueProbe` and `SigAlgDigestProbe` are that review's
probes, extended here as noted below.

## Questions

1. BouncyCastle re-encodes some ASN.1 to DER before anything is trusted:
   `ReceiptCertificates.decode` re-encoded every bag entry before parsing
   it as a certificate, and the SignerInfo's issuer name is hashed (in
   `SignerInformationStore`) and compared (`BCStrictStyle.areEqual`) by
   a canonical string that re-encodes every value that is not a string.
   DER sorts every SET by its members' encodings. What does that cost at
   the receipt cap, which call pays it, and what is the smallest guard?
2. A SignerInfo's signatureAlgorithm is unsigned. With signed
   attributes, BouncyCastle hashes them with the digest the label names
   before any signature is checked; md2WithRSAEncryption names MD2, which
   `REFUSED_DIGESTS` refuses only as a digestAlgorithm. What does it cost,
   and is it the only slow label?
3. RSASSA-PSS parameters are unsigned too, and BouncyCastle's `PSSSigner`
   allocates `new byte[saltLength]` while the verifier is built. What
   does a huge saltLength do?

## Setup

- OpenJDK 21.0.10 (Ubuntu build) and 8u504 (Temurin JRE), default
  collectors and heap (3,420 MiB and 3,040 MiB), 4 vCPU, 15 GiB.
  bcprov, bcutil and bcpkix 1.86. The core: rustc 1.98.1, OpenSSL 4.0.3
  built by openssl-src, debug test profile.
- The library at `main` `c3ca8225` for the figures before, and the
  `fix/java-pretrust-reencoding` branch for those after.
- Each probe builds its receipt from the repository's `TestPki`, so the
  signer is a genuine test-PKI leaf that chains to the root passed as the
  only anchor, and calls `ReceiptCore.verifyDer` three or four times in
  one JVM. The first call is cold; the others are warm.
- The shapes, each just under the 3 MiB base64 cap (2.29 to 2.30 MB of
  DER):
  - *flat issuer value*: the SignerInfo's issuer is one CN whose value is a
    SEQUENCE of 768,000 INTEGERs; the bag holds ten certificates with the
    SignerInfo's serial number (`NestedValueProbe plain`);
  - *nested issuer value*: the same with a SEQUENCE of chains of
    two-member SETs nested 30 deep (`NestedValueProbe sid`), also 50 deep;
  - *nested bag entry*: the genuine receipt with one more bag entry, that
    SEQUENCE of nested SETs (`NestedValueProbe cert`, `CertShapeProbe bag`);
  - *string issuer value*, added here: one UTF8String of 2.3 MB
    (`NestedValueProbe string`);
  - *certificate-shaped bag entry*, added here: the genuine receipt with
    one more bag entry shaped as a certificate whose issuer or subject
    holds the nested value as its CN, or whose key or signature
    AlgorithmIdentifier holds it as parameters (`CertShapeProbe issuer`,
    `subject`, `spki`, `sigalg`);
  - *md2WithRSA label*: the genuine SignerInfo with a 2.2 MB attribute
    added to its signed attributes and its signatureAlgorithm relabelled,
    one and four SignerInfos (`SigAlgDigestProbe`);
  - *PSS salt*: the genuine SignerInfo relabelled RSASSA-PSS (SHA-256,
    MGF1 with SHA-256) with a saltLength of 32, 1,000,000,000 and
    2,147,483,647 (`PssSaltProbe`).

## Results

### Which call pays

JFR samples every 10 ms with 2,048-frame stacks (`profile.sh`, grouped by
the first frames outside BouncyCastle's ASN.1 package by `callers.sh`),
one probe run each, before the fix:

- nested issuer value (`results/profile-sid.txt`): the samples split
  between `BCStrictStyle.areEqual` in `ReceiptCertificates.signers`
  (`IETFUtils.canonicalString` → `valueToString`, a DER encoding then a
  hex string, and `canonicalize` → `decodeObject`, which parses that hex
  back), once for each of the ten certificates with the serial, and
  `X500Name.hashCode` for the one-signer `SignerInformationStore` in
  `ReceiptCore.signerInfos`, the same canonical string once. The rest is
  `parseCms`, BouncyCastle's parse of the input.
- nested bag entry (`results/profile-cert.txt`): `getEncoded("DER")` in
  `ReceiptCertificates.decode`, then the parse of the re-encoded bytes,
  then `parseCms`.

### The fix

- The bag entry is read as parsed, `Certificate.getInstance(entry)`, not
  re-encoded and parsed again. Nothing needed the re-encoding: the entry
  comes out of the same parse, and the X.509 object BouncyCastle builds
  makes its own DER where it needs one (the shared cases answer as
  before). A
  SEQUENCE that is not three members long is refused at once.
- A SignerInfo whose issuer holds a value that is not a string
  (`ASN1String`) is left out in `signerInfos`, before its SignerId is
  hashed or compared; when every SignerInfo is left out the receipt is
  `MALFORMED`, "signer certificate not embedded", as before.
- `REFUSED_SIGNATURE_ALGORITHMS`, md2WithRSAEncryption and RSASSA-PSS,
  checked with `REFUSED_DIGESTS` before `signer.verify`:
  `INVALID_SIGNATURE`.

### One call at the cap

`results/before-jdk21.txt`, `after-jdk21.txt`, `before-jdk8.txt`,
`after-jdk8.txt` (`measure.sh`). Each cell: every call of one JVM, cold
first. Verdicts are the same before and after unless noted.

| Shape | JDK 21 before | JDK 21 after | JDK 8 before | JDK 8 after | Verdict |
|---|---:|---:|---:|---:|---|
| flat issuer value | 7,120 / 9,374 / 4,010 ms | 378 / 267 / 248 ms | 3,668 / 2,203 / 1,926 ms | 350 / 1,080 / 219 ms | `MALFORMED`, signer certificate not embedded |
| nested issuer value, 30 deep | 10,732 / 10,624 / 11,746 ms | 792 / 863 / 703 ms | 9,540 / 8,271 / 7,848 ms | 763 / 576 / 643 ms | the same |
| nested issuer value, 50 deep | 19,548 / 16,873 / 17,789 ms | 657 / 649 / 615 ms | | | the same |
| nested bag entry, 30 deep | 3,135 / 3,690 / 3,001 ms | 661 / 407 / 388 ms | 3,051 / 2,921 / 3,131 ms | 767 / 524 / 489 ms | `MALFORMED`, an embedded certificate is not a valid certificate |
| nested bag entry, 50 deep | 5,158 / 6,850 / 6,528 ms | 888 / 662 / 529 ms | | | the same |
| string issuer value, 2.3 MB | 526 / 343 / 327 ms | 675 / 344 / 318 ms | | | `MALFORMED`, not embedded (strings are kept) |
| md2WithRSA label, 1 SignerInfo (best of 7) | 264 ms | 6 ms | 289 ms | 4 ms | `INVALID_SIGNATURE`; after, "signature algorithm 1.2.840.113549.1.1.2 is refused" |
| md2WithRSA label, 4 SignerInfos | 261 ms | 7 ms | 280 ms | 9 ms | the same |
| for scale: rsaEncryption label, 1 and 4 | 26, 28 ms | 24, 33 ms | 25, 28 ms | 24, 30 ms | `INVALID_SIGNATURE` |
| PSS salt 32 | 219 / 26 / 13 ms | 200 / 12 / 11 ms | 248 / 6 / 7 ms | 244 / 5 / 5 ms | `INVALID_SIGNATURE` |
| PSS salt 1,000,000,000, 1 SignerInfo | 21,855 / 2,232 / 5,250 ms, `OutOfMemoryError` | 163 / 7 / 7 ms | 10,483 / 2,875 / 2,282 ms, `OutOfMemoryError` | 222 / 8 / 8 ms | after: `INVALID_SIGNATURE`, "signature algorithm 1.2.840.113549.1.1.10 is refused" |
| PSS salt 1,000,000,000, 4 SignerInfos | 18,180 / 1,985 / 2,519 ms, `OutOfMemoryError` | 214 / 21 / 21 ms | 7,415 / 5,217 / 2,145 ms, `OutOfMemoryError` | 295 / 13 / 10 ms | the same |
| PSS salt 2,147,483,647 | 310 / 18 / 17 ms, `OutOfMemoryError` ("Requested array size exceeds VM limit") | 215 / 15 / 11 ms | 298 / 6 / 6 ms, the same | 284 / 8 / 8 ms | the same |

The `OutOfMemoryError` is an `Error`, so it left `verifyReceipt`, whose
contract is never to throw; one such request also strains the heap of
every other call in the JVM. The round-4 review that found it measured the
same: 22.6 s cold and 2.0 s warm at 1,000,000,000 on JDK 21, immediate at
2,147,483,647.

What the three issuer and bag shapes cost after the fix is
BouncyCastle's parse of the input, `parseCms`
(`results/profile-after-sid.txt`, `profile-after-plain.txt`): 0.25 to
0.9 s at the cap, more with deeper nesting, every byte of which any
receipt that size pays. DECISIONS.md R20 records that cost (Java has no
value budget; the core's is 100,000 values) and the owner accepted it
(Q62). The first figures came from the review's own run:
`plain` 4.5 to 12.5 s, `cert` 3.1 to 3.3 s, `sid` 10.8 to 12.7 s.

### The signature labels

`results/denylist-tables.txt` is `DigestDenylistCostTest`'s two tables
as it now runs them, printed once on JDK 21. Every Signature OID the
provider registers is offered to the CMS verifier for an RSA and an EC
key with SHA-256 as the digest; 20 build for the RSA key and 29 for the
EC key. md2WithRSAEncryption costs 16.2 times rsaEncryption; every other
label at most 2.28 (RSA) and 2.36 (EC). The review's own sweep agrees:
16.2, and 2.40 at most otherwise. GOST and DSTU labels need a key of
their own and fail at `initVerify`, before anything is hashed; RSASSA-PSS
with NULL parameters does not build.

The digest table now offers more than the provider's MessageDigest OIDs:
the keys of the two tables the calculator itself reads
(`MessageDigestUtils`' and `OperatorHelper`'s, by reflection in the test
only) and SHAKE with an output length, at each length the provider
names. 40 digests resolve, where 37 did. The three new ones are fast:
Tiger (1.3.6.1.4.1.11591.12.2) 0.41, SHAKE128-256 0.47 and SHAKE256-512
0.55 times SHA-256.

### What the core answers

`results/core-shapes.txt`: `core_shapes.rs` over the receipts the probes
dumped with `-Ddump`, each under its own test root.

| Shape | Core |
|---|---|
| nested issuer value, nested bag entry, certificate-shaped entries, 30 deep | `MALFORMED`, "nested deeper than 32 constructed values", 40 to 70 ms |
| flat issuer value, flat certificate-shaped entry | `MALFORMED`, "more than 100000 ASN.1 values", 80 to 140 ms |
| md2WithRSA label over padded signed attributes | `INVALID_SIGNATURE` |
| PSS salt 1,000,000,000 | `INVALID_SIGNATURE`, under 1 ms |
| the shared fixture `receipt-signer-rsa-pss`, a genuine PSS signature | ok |

The core's header walk refuses the nested and the flat shapes before
OpenSSL decodes anything, so no new divergence: Java answers `MALFORMED`
for the same receipts. Two do diverge, both in shared cases that allow
both answers: Apple's genuine G5 SignerInfo relabelled
md2WithRSAEncryption (`receipt/reject-a-signer-info-signed-md2-with-rsa`)
is ok in the core, since OpenSSL reads an RSA SignerInfo's
signatureAlgorithm only to choose PKCS#1 v1.5 or PSS and hashes with the
digestAlgorithm, Apple's SHA-256; Java refused it before the fix too,
when MD2 over the content did not match Apple's DigestInfo. And the
genuine PSS signature of `receipt/signer-rsa-pss-does-not-crash`, ok in
the core, is now `INVALID_SIGNATURE` in Java. The same G5 SignerInfo
relabelled PSS with a salt of 1,000,000,000
(`receipt/reject-a-signer-info-labelled-rsa-pss-with-a-huge-salt`) is
`INVALID_SIGNATURE` in both.

### Still open: a certificate-shaped bag entry

Refusing an entry that is not a certificate does not cover one that is
shaped as one. `CertShapeProbe` adds such an entry to the genuine
receipt, so the receipt still verifies. BouncyCastle's X.509 object
DER-encodes the issuer and subject as it is built
(`X509CertificateObject`'s constructor calls `getIssuerX500Principal`),
and the signature parameters, and the path checks encode more
(`results/profile-after-issuer-30.txt`). After the fix:

| Entry, 2.29 MB | JDK 21 before | JDK 21 after | Verdict |
|---|---:|---:|---|
| issuer CN nested 30 deep | 6,768–10,062 ms | 3,826–11,779 ms | ok |
| subject CN nested 30 deep | 7,570–8,256 ms | 4,051–4,684 ms | ok |
| key parameters nested 30 deep | 7,556–7,950 ms | 4,103–4,243 ms | ok |
| signature parameters nested 30 deep | 5,631–7,600 ms | 3,448–3,580 ms | ok |
| issuer CN, flat | 1,081–1,546 ms | 822–1,236 ms | ok |
| issuer CN nested 50 deep | 10,502–11,937 ms | 5,050–7,051 ms | ok |

The fix removed the decode's own re-encoding, about 40% of it; the rest is
inside BouncyCastle's certificate class. The same entry with a broken
signature on the receipt costs the same and is refused, so this is a
cost before trust that the fix does not bound. The core refuses all of
these at its depth bound or value budget. Bounding them in Java needs a
rule of its own: a value budget like the core's, or refusing (or
skipping) a bag certificate whose names hold a value that is not a
string or whose AlgorithmIdentifier parameters nest. Each changes what
Java answers for an Apple-signed receipt carrying such an entry, so the
choice is the owner's. The JWS `x5c` chain builds the same X.509 object
before trust, under the 256 KiB JWS cap; it was not measured.

## Verdict

Read each bag entry as parsed (Q135 a), leave out a SignerInfo whose
issuer holds a value that is not a string before it is hashed or
compared (Q135 a), and refuse md2WithRSAEncryption (Q136 a) and
RSASSA-PSS (Q137 a) as signature labels before anything is hashed or
built. Each shape the review measured now costs what parsing it costs.

None of these refuses an Apple-signed receipt Java accepted. The bag
change reads the same structure without re-encoding it. Every name in
Apple's certificates holds strings (PrintableString and UTF8String), and
BouncyCastle's comparison never matches a value that is not a string with
one that is, so a SignerInfo left out could not have named an Apple
certificate; only a caller's own roots whose names hold other values
could notice. Java already refused the md2WithRSA label, after hashing.
Apple never signs receipts with RSASSA-PSS (owner, 2026-09-27). The
genuine receipts in the shared cases, the G5 and legacy sandbox receipts under
the default roots among them, verify as before.

## Where this stops holding

- One machine, single runs: the figures are an order of magnitude, and
  the cold first call carries class loading and JIT.
- bcprov 1.86. The parse cost after the fix grows with nesting, up to
  BouncyCastle's bound of 64.
- The certificate-shaped bag entry above, and the JWS `x5c` certificates,
  are not bounded by this change.
