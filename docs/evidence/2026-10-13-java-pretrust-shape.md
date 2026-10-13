# Java: certificate shapes, certificate PSS labels and signed attributes before trust

Date: 2026-10-13. Measures what Java paid before any signer was trusted
for the three inputs the pre-trust re-encoding note left open, and what
it pays after the fixes for owner decision Q140 a, and the figures in
DECISIONS.md R20, java/README.md and THREAT-MODEL.md §3.7. Sources and
commands: [`2026-10-13-java-pretrust-shape/`](2026-10-13-java-pretrust-shape/).

## Questions

1. A bag entry shaped as a certificate, or an x5c certificate, whose
   names or algorithm parameters hold a cap-sized value of nested SETs:
   BouncyCastle's X.509 object DER-encodes them, and DER sorts every SET.
   What does it cost, and does a rule that passes over such a
   certificate before converting it bound it?
2. A certificate's own signature label is unsigned. Labelled RSASSA-PSS
   with a huge saltLength and naming an RSA root as its issuer, does it
   reach the allocation #364 closed for SignerInfos?
3. BouncyCastle DER-encodes a SignerInfo's signed attributes before it
   checks the signature. What does a nested attribute cost, what does
   hashing them as sent cost, and which bytes does each implementation
   verify when the attributes are out of DER order?

The Q140 consultation found 2 (its `BagPssProbe` and
`JwsPssRsaProbe`, copied here) and the signed-attribute and `signers()`
gaps (`SidIssuerProbe`).

## Setup

- OpenJDK 21.0.10 (Ubuntu build) and 8u504 (Temurin), default collectors
  and heaps, 4 vCPU. bcprov, bcutil and bcpkix 1.86. The core: rustc
  1.98.1, OpenSSL 4.0.3 built by openssl-src, debug test profile.
- The library at `main` `f309a300` for the figures before, and the
  `fix/java-pretrust-shape` branch for those after.
- Each probe builds its input from the repository's `TestPki`: a genuine
  test-PKI receipt (or JWS) that verifies under the test root passed as
  the only anchor, plus one sender-chosen shape, just under the 3 MiB
  receipt cap (2.29 MB of DER) or the 256 KiB JWS cap. Each call is
  `ReceiptCore.verifyDer` or `JwsCore.verify`, four times in one JVM
  (three for the PSS probes), the first cold.
- The shapes (`ShapeProbe` unless named): a bag entry shaped as a
  certificate the root issued with a SEQUENCE of SET chains 30 (or 50)
  deep as its subject CN, its issuer CN, its key's parameters or its
  outer signature's parameters (`subject`, `issuer`, `spki`, `sigalg`);
  the same value as a directoryName inside a subjectAltName (`san`); a
  subject of one RDN of 100,000 UTF8String values in descending order
  (`widerdn`); the issuer entry carrying the signer's serial, with one
  and four SignerInfos (`SidIssuerProbe`); a JWS whose x5c[2] is the
  `subject` entry (`jws`); a copy of the genuine SignerInfo ahead of it
  with one nested signed attribute (`signedattrs`), or with nested
  signature parameters and a CMSAlgorithmProtection attribute naming the
  same label (`signerparams`); and a 3.5 KB bag entry, or a 2.3 KB
  x5c[1], naming the RSA root as its issuer and labelled RSASSA-PSS with
  a saltLength of 32, 1,000,000,000 or 2,147,483,647 (`BagPssProbe`,
  `JwsPssRsaProbe`).

## The fixes

- `AppleTrust.signedBy`, the one place a certificate's signature is
  checked before trust (the bag walk, the JWS intermediate under a root
  and the JWS leaf under the intermediate), requires the outer
  signatureAlgorithm to equal the TBS's, and passes over an RSASSA-PSS
  label whose saltLength exceeds emLen - hLen - 2 for the issuer's RSA
  key (RFC 8017 9.1.2), or whose issuer key is not RSA, before a
  `Signature` is built. A composite label is checked part by part.
- `AppleTrust.convertible`: every name value is an `ASN1String` and none
  of the three AlgorithmIdentifier parameters holds a SET under
  SEQUENCEs, tagged objects or EXTERNAL. `ReceiptCertificates.decode`
  skips an entry that fails, after the existing decode checks;
  `JwsCore.decodeChain` now reads each entry with
  `Certificate.getInstance` and the same check (a leaf or intermediate
  that fails is `UNTRUSTED_CHAIN`, x5c[2] is left unconverted).
- `ReceiptCore` verifies each SignerInfo through a `SignerInformation`
  subclass whose `getEncodedSignedAttributes` returns the definite-length
  encoding, made at verify time, and leaves out a SignerInfo whose digest
  or signature parameters hold a SET.

## Results

`results/before-jdk21.txt`, `after-jdk21.txt`, `before-jdk8.txt`,
`after-jdk8.txt` (`measure.sh`). Each cell: every call of one JVM, cold
first, in ms. Every receipt verifies before and after unless noted.

| Shape | JDK 21 before | JDK 21 after | JDK 8 before | JDK 8 after |
|---|---:|---:|---:|---:|
| subject, 30 deep | 4,426 / 4,768 / 4,718 / 4,881 | 822 / 590 / 404 / 453 | 4,039 / 3,563 / 5,632 / 3,478 | 1,276 / 843 / 726 / 585 |
| issuer, 30 deep | 4,372 / 4,371 / 4,344 / 4,000 | 838 / 489 / 461 / 500 | 3,881 / 3,828 / 3,547 / 3,475 | 1,066 / 701 / 699 / 776 |
| key parameters, 30 deep | 3,887 / 4,494 / 4,681 / 4,574 | 826 / 510 / 477 / 506 | 4,255 / 3,228 / 3,170 / 3,963 | 1,072 / 622 / 534 / 569 |
| signature parameters, 30 deep | 3,702 / 4,260 / 4,067 / 3,938 | 986 / 543 / 427 / 445 | 3,395 / 2,726 / 2,816 / 2,949 | 1,033 / 688 / 563 / 742 |
| subject, 50 deep | 6,587 / 7,366 / 7,152 / 6,869 | 1,225 / 1,107 / 945 / 1,043 | 5,742 / 7,674 / 6,320 / 5,870 | 1,137 / 909 / 761 / 855 |
| issuer with the signer's serial, 1 SignerInfo | 6,859 / 7,184 / 9,337 / 8,288 | 925 / 622 / 537 / 600 | 6,353 / 6,331 / 5,101 / 4,444 | 1,064 / 657 / 560 / 713 |
| the same, 4 SignerInfos | 9,919 / 9,018 / 16,641 / 9,536 | 860 / 586 / 478 / 533 | 8,507 / 8,412 / 6,601 / 6,450 | 1,072 / 559 / 921 / 453 |
| JWS, x5c[2] subject 30 deep, 256 KiB | 683 / 357 / 201 / 244 | 466 / 73 / 84 / 82 | 705 / 561 / 202 / 197 | 413 / 102 / 71 / 50 |
| subjectAltName, 30 deep (kept) | 307 / 78 / 48 / 49 | 354 / 85 / 49 / 50 | 433 / 62 / 78 / 71 | 452 / 86 / 98 / 70 |
| one RDN of 100,000 values (kept), 1.5 MB | 1,203 / 517 / 560 / 580 | 1,312 / 417 / 511 / 535 | 1,096 / 743 / 434 / 341 | 1,088 / 622 / 395 / 382 |
| signed attribute, 30 deep | 3,155 / 3,357 / 3,462 / 3,292 | 1,203 / 867 / 770 / 820 | 3,368 / 3,454 / 4,850 / 2,802 | 1,163 / 700 / 884 / 519 |
| signature parameters and CMSAlgorithmProtection, 30 deep | 2,505 / 2,556 / 2,195 / 2,409 | 975 / 477 / 474 / 586 | 2,390 / 1,856 / 2,013 / 1,756 | 1,001 / 611 / 699 / 581 |
| PSS bag entry, salt 32 | 192 / 9 / 8 | 221 / 19 / 11 | 324 / 11 / 10 | 297 / 8 / 7 |
| PSS bag entry, salt 1,000,000,000 | 20,277 / 999 / 966 | 195 / 8 / 12 | 12,963 / 6,157 / 13,119 | 406 / 11 / 11 |
| PSS bag entry, salt 2,147,483,647 | 112 / 3 / 3, `OutOfMemoryError` | 189 / 8 / 7 | 210 / 3 / 3, `OutOfMemoryError` | 274 / 8 / 21 |
| PSS x5c[1], salt 1,000,000,000 (`UNTRUSTED_CHAIN`) | 3,306 / 5,931 / 516 | 93 / 2 / 2 | 2,844 / 1,423 / 6,283 | 116 / 2 / 1 |
| PSS x5c[1], salt 2,147,483,647 | 117 / 2 / 1, `OutOfMemoryError` | 95 / 2 / 2, `UNTRUSTED_CHAIN` | 130 / 1 / 1, `OutOfMemoryError` | 135 / 3 / 3, `UNTRUSTED_CHAIN` |

An earlier JDK 21 run before the fix, on the same machine an hour before
(`results/before-jdk21-earlier.txt`, with an older `signerparams` that
had no CMSAlgorithmProtection attribute), measured `subject` at 4.1 to
17.3 s and `sigalg` up to 11.6 s, which is where the wider ranges in R20
come from: the machine was shared with other work.

### Where the remaining time goes

JFR, one run each on the branch (`results/profile-after-*.txt`, the first
frames outside BouncyCastle's ASN.1 package):

- `subject` 30 and 50 deep: almost every sample is in `parseCms`,
  BouncyCastle's parse of the input, which grows with the nesting (the
  pre-trust re-encoding note measured 0.25 to 0.9 s for it). Nothing of
  the certificate's conversion remains.
- `signedattrs`: `parseCms` first, then `SignedAsSent.getEncodedSignedAttributes`
  (the definite-length encoding, linear) and SHA-256 over the 2.3 MB of
  attributes, which any signature over attributes that size costs.
- `widerdn`: the certificate is kept and converted. The time splits
  between `getSubjectX500Principal` in the X.509 object's constructor (a
  DER encoding of the name, whose one SET of 100,000 values BouncyCastle
  1.86 sorts in N log N, then the JDK's parse of it), the TBS's DER
  encoding in `checkSignature`, and `parseCms`. About 0.5 s warm for 1.5
  MB, the same before and after: it was never quadratic.

Every shape after the fix costs at most about twice its parse: 0.4 to 0.9
s warm at 30 deep, up to 1.1 s at 50. The 50-deep figure is BouncyCastle's
parse alone.

### Signed attributes out of DER order

`results/order-java.txt`, `results/core-shapes.txt`
(`SignedAttrsOrderProbe`): a signer certificate the test intermediate
issued, its signed attributes out of DER order in one place, the
signature made over the bytes as sent or over their DER encoding.

| Input | Java before | Java after | Core |
|---|---|---|---|
| the attributes out of order, signed as sent | `INVALID_SIGNATURE` | ok | ok |
| the attributes out of order, signed sorted | ok | `INVALID_SIGNATURE` | `INVALID_SIGNATURE` |
| one attribute's values out of order, signed as sent | `INVALID_SIGNATURE` | ok | `INVALID_SIGNATURE` |
| one attribute's values out of order, signed sorted | ok | `INVALID_SIGNATURE` | ok |

OpenSSL re-encodes the attributes as a SEQUENCE OF, in the order sent
(`CMS_Attributes_Verify`; [substrate follow-up](2026-09-26-substrate-followup.md)), and each
attribute's values as a SET OF, sorted. Java now agrees on the first and
parts on the second. Apple's receipts carry no signed attributes.

### What the core answers

`results/core-shapes.txt`: `core_shapes.rs` over the dumped receipts, each
under its own test root.

| Shape | Core |
|---|---|
| subject, key parameters, signed attribute, signature parameters, 30 deep | `MALFORMED`, "nested deeper than 32 constructed values", 40 to 90 ms |
| one RDN of 100,000 values | `MALFORMED`, "more than 100000 ASN.1 values", 50 to 110 ms |
| subjectAltName, 30 deep | ok, 50 to 70 ms |
| the PSS stranger in Apple's G5 receipt (the shared case) | ok |

So the nested shapes stay a recorded divergence in the direction R20
already has (Java ok, the core `MALFORMED`), and the inputs are over
100 KB, so `UnauthenticatedKeyCostTest` pins them. The PSS stranger fits
in 6.5 KB: `receipt/accept-genuine-beside-a-stranger-labelled-rsa-pss-with-a-huge-salt`
is Apple's G5 receipt with such an entry spliced into its bag, ok in both
(`cargo test --locked`, `conformance`).

### x5c entries read with `Certificate.getInstance`

`results/x5c-trail.txt` (`X5cTrailProbe`): a leaf followed by three zero
octets, or by a second copy of itself, is still ok, since only the first
ASN.1 object of an entry is read, as BouncyCastle's `CertificateFactory`
read it. The leaf as PEM text, which the factory decoded, is now
`INVALID_CERTIFICATE`, as in the core. The header is signed, so no
Apple-signed JWS carries any of these.

### Re-encoding cost

`results/encode-cost.txt` (`EncodeCost`): a parsed 2.3 MB value
re-encoded as DL stays at 0.07 to 0.26 s whatever its nesting; as DER,
SEQUENCE nesting costs at most 0.35 s and SET nesting 1.4 to 1.7 s at 30
deep and 4.4 to 5.1 s at 60. The cost the fixes remove is the SET sort,
and only that.

## Verdict

The three fixes bound each shape to about its parse, and none accepts
anything new. A skipped certificate names no signer and vouches for
nothing, and a bag entry that does not decode is still `MALFORMED`. The
PSS bound and the outer-label check only pass over a certificate before
its signature is checked, and signed attributes are hashed as the signer
sent them.

None refuses an Apple-signed receipt. Apple's names hold
PrintableString and UTF8String, and no signature or key algorithm
defines a SET in its parameters, so no Apple certificate is skipped; a
future Apple CA signed with RSASSA-PSS names a saltLength its own key
holds, or no RSA signer could have made the signature; RFC 5280 requires
the two signature labels to be equal; and Apple's receipts carry no
signed attributes, while a signer's DER attributes encode the same
either way. The two places Java now differs are inputs no conforming
signer produces: a certificate the core also refuses, and attribute
values sent out of DER order.

## Where this stops holding

- One machine shared with other work, single runs: the figures are an
  order of magnitude, and the first call carries class loading and JIT.
- bcprov 1.86. The skip relies on BouncyCastle decoding subjectAltName
  and the other extensions lazily, and sorting an RDN's values in N log
  N; `UnauthenticatedKeyCostTest` fails if a release changes either. The
  parse itself still grows with nesting, up to BouncyCastle's bound of
  64.
