# The core against October's hostile shapes, measured

Date: 2026-10-14 (owner Q176).

**Question.** On 13 and 14 October Java gained pre-trust screens against
BouncyCastle cost paths. They cover these shapes:

- an RSASSA-PSS saltLength;
- the generic composite label;
- md2 labels;
- extension and attribute caps;
- nested-SET names and parameters;
- hash-colliding OIDs.

Only the ten shared cases that carry `maxMillis` re-measured the core
against them. Does the core refuse, or pass over, each shape after work
that is bounded and roughly linear in the input, up to the largest input
the 3 MiB receipt cap lets through? The answer decides whether the core
needs a screen of its own for any of them.

**Answer.** It does not. Every shape costs the core 77 ms or less at the
cap and at most 11 MiB of peak heap, and every one grows linearly in the
input. Two divergences from Java turned up that no R20 row records
(see "Divergences found").

## Versions

- Main at bc34be44, on the branch `docs/core-october-cost-scan`.
- Rust 1.99.0, the toolchain `rust/rust-toolchain.toml` pins, release
  profile (opt-level 3, no LTO).
- OpenSSL 4.0.3, built by `openssl-src` 400.0.2+4.0.3.
- The core's Rust API, natively. Not `aprv.wasm`.
- One Linux x86-64 container: 4 vCPUs (Intel Xeon, 2.1 GHz), 16 GiB, glibc
  malloc.

## Method

The harness is
[`october_cost_scan.rs`](2026-10-14-core-october-cost-scan/october_cost_scan.rs),
run as an example of the core crate (see its README). Every input gets:

1. One warm-up call, which fixes the verdict.
2. One call measured for memory:
   - the peak of live heap above the level before the call, with Rust's
     and OpenSSL's allocations counted together (OpenSSL's through
     `CRYPTO_set_mem_functions`);
   - the bytes allocated;
   - the rise of the process's peak resident set (`VmHWM`), reset through
     `/proc/self/clear_refs` after `malloc_trim(0)`.
3. Nine timed calls. The tables give their median.

All numbers below come from
[`results.tsv`](2026-10-14-core-october-cost-scan/results.tsv).

**Part 1** runs the 21 shared cases named in the brief, from
`fixtures/cases.json`, under each case's own roots.

**Part 2** rebuilds each shape from the Rust tests' test PKI:

- the shared generated receipt (`fixtures/generated-0.7/`) and its pinned
  root, both RSA 2048;
- a stranger certificate that names that root as its issuer, so the
  top-down walk compares names and runs the root's key over the
  stranger;
- or a hand-written SignerInfo that names the trusted signer, so OpenSSL
  reaches the signature check.

Each shape runs from the fixture's size to the largest input that one of
these bounds admits, found by bisection: the base64 cap (3,145,728
characters, 2,359,296 DER octets), the envelope's 100,000-value budget,
or its 32-level depth bound. Where a bigger input exists, the next input
up is measured as a refusal.

The hash-colliding OIDs collide under BouncyCastle's
`ASN1ObjectIdentifier.hashCode`, which is `Arrays.hashCode` over the
content octets, sign-extended, from last to first. They are built with
Joux's multicollision: 15 stages, each a birthday search for two 8-octet
blocks. Four-octet blocks cannot collide, because 257 exceeds an
octet's range, so a short block never wraps 2^32. The result is 32,768
distinct OIDs of 129 octets with one hash, checked in the harness. The
OpenSSL side keeps extensions and attributes in stacks and hashes no
OID, so the collisions cost the core nothing extra. They are there so
that the inputs are the ones that hurt Java.

## Results: the 21 shared cases

| Case | Answer | Median | Peak heap | RSS rise |
|---|---|---:|---:|---:|
| `receipt/expose-unknown-attributes` | ok | 0.32 ms | 25 KiB | 8 KiB |
| `receipt/reject-signer-absent-beside-a-malformed-stranger` | MALFORMED | 0.02 ms | 9 KiB | 4 KiB |
| `receipt/verify-genuine-padded-with-oversized-strangers` | ok | 0.92 ms | 344 KiB | 344 KiB |
| `receipt/signer-rsa-pss-does-not-crash` | ok | 0.24 ms | 23 KiB | 8 KiB |
| `receipt/reject-signer-rsa-pss-tampered` | INVALID_SIGNATURE | 0.24 ms | 23 KiB | 4 KiB |
| `receipt/first-failing-signer-decides-when-the-stranger-comes-first` | UNTRUSTED_CHAIN | 0.27 ms | 29 KiB | 12 KiB |
| `receipt/reject-a-signer-info-signed-md2-with-rsa` | ok (oneOf) | 0.36 ms | 36 KiB | 12 KiB |
| `receipt/reject-a-signer-info-labelled-rsa-pss-with-a-huge-salt` | INVALID_SIGNATURE | 0.54 ms | 36 KiB | 12 KiB |
| `receipt/accept-genuine-beside-a-stranger-labelled-rsa-pss-with-a-huge-salt` | ok | 0.80 ms | 41 KiB | 20 KiB |
| `receipt/accept-genuine-beside-a-stranger-labelled-rsa-pss-with-a-negative-salt` | ok | 0.84 ms | 41 KiB | 20 KiB |
| `receipt/reject-a-signer-info-labelled-with-the-generic-composite-oid` | INVALID_SIGNATURE | 0.57 ms | 36 KiB | 16 KiB |
| `receipt/accept-genuine-beside-a-stranger-labelled-with-the-generic-composite-oid` | ok | 0.96 ms | 62 KiB | 52 KiB |
| `receipt/accept-genuine-beside-a-stranger-with-a-thousand-and-one-extensions` | ok | 3.49 ms | 197 KiB | 248 KiB |
| `receipt/accept-genuine-beside-a-stranger-labelled-md2-with-rsa` | ok | 0.46 ms | 40 KiB | 12 KiB |
| `receipt/verify-with-a-stranger-whose-key-is-unreadable` | ok | 0.45 ms | 33 KiB | 12 KiB |
| `receipt/verify-with-a-stranger-vouched-by-a-same-named-root-listed-first` | ok | 0.58 ms | 35 KiB | 12 KiB |
| `receipt/verify-with-a-stranger-vouched-by-a-same-named-root-listed-second` | ok | 0.53 ms | 35 KiB | 12 KiB |
| `receipt/reject-a-stranger-whose-signature-bit-string-is-unaligned` | MALFORMED | 0.09 ms | 23 KiB | 12 KiB |
| `receipt/printable-string-attributes-are-kept-raw` | ok | 0.27 ms | 22 KiB | 8 KiB |
| `signed-data/reject-a-header-number-of-1001-digits` | ok (oneOf) | 0.60 ms | 18 KiB | 28 KiB |
| `receipt/reject-signed-attributes-with-two-message-digests` | INVALID_SIGNATURE | 0.29 ms | 23 KiB | 8 KiB |

Every answer is within its case's expectation. The slowest case, at
3.5 ms, is about 570 times inside the 2,000 ms `maxMillis` that ten of
them carry.

## Results: the shapes up to the bounds

Two columns need a word:

- **Per unit** is the median time divided by the unit the shape grows
  in: KiB of base64 input, or elements. It is given at two sizes that
  reach OpenSSL.
- **Linear** means that slope stays within a factor of two across at
  least a tenfold range of the input.

The floor is the valid receipt carrying one cap-sized unsigned
OCTET STRING: ok in 2.79 ms, 9.0 MiB peak heap, 11.3 MiB allocated.

| Shape | Largest input | Answer | Median | Peak heap / allocated | Per unit | Bounded, linear |
|---|---|---|---:|---:|---|---|
| PSS saltLength on the trusted SignerInfo | INTEGER of 2,355,852 octets, at the cap | INVALID_SIGNATURE | 6.5 ms | 9.0 / 15.8 MiB | 2.3 µs/KiB at 0.7 MB, 2.1 at the cap | yes, yes |
| PSS saltLength on a stranger (both labels) | 2 × 1,177,549 octets, at the cap | ok | 8.6 ms | 9.0 / 20.3 MiB | 2.9 µs/KiB at 1.4 MB, 2.8 at the cap | yes, yes |
| Generic composite label on the trusted SignerInfo | 33,278 sha256WithRSA parts (value budget) | INVALID_SIGNATURE | 7.4 ms | 1.9 / 3.5 MiB | 0.30 µs per part at 3,000, 0.22 at 33,278 | yes, yes |
| (the same at the cap) | 157,060 parts | MALFORMED, value budget | 8.0 ms | 2.3 / 3.3 MiB | refused by the header walk | yes |
| Generic composite on a stranger, with a SEQUENCE of empty BIT STRINGs as signature | 24,951 parts (value budget) | ok | 11.2 ms | 2.6 / 5.1 MiB | 0.63 µs per part at 3,000, 0.45 at 24,951 | yes, yes |
| (the same at the cap) | 87,239 parts | MALFORMED, value budget | 8.9 ms | 2.3 / 3.0 MiB | refused by the header walk | yes |
| md2WithRSA label on the trusted SignerInfo, content grown to the cap | +2,355,891 octets of payload | INVALID_SIGNATURE | 5.6 ms | 11.3 / 18.1 MiB | one SHA-256 over the content, never MD2 | yes, yes |
| MD2 as the SignerInfo's digestAlgorithm, content at the cap | +2,355,893 octets | INVALID_SIGNATURE | 3.1 ms | 11.3 / 18.1 MiB | refused before any digest (no MD2 in OpenSSL 4) | yes, yes |
| md2WithRSA label on a stranger with a cap-sized TBS | one 2,355,194-octet extension | ok | 5.6 ms | 9.0 / 15.9 MiB | the root's key is not run over the TBS with MD2 | yes, yes |
| Hash-colliding OIDs as unsigned attributes of the trusted SignerInfo | 16,948 OIDs × 129 octets, at the cap | ok | 29.4 ms (38.2 at 16,384) | 9.2 / 17.1 MiB | 1.7 to 2.6 µs per attribute, 1,001 to 16,948 | yes, yes |
| (long OIDs) | 1,024 OIDs × 2,288 octets, at the cap | ok | 10.0 ms | 9.0 / 13.8 MiB | 3.3 µs per KiB | yes, yes |
| A stranger with many extensions (colliding OIDs) | 17,191 extensions, at the cap | ok | 76.4 ms | 11.0 / 27.6 MiB | 4.9 µs per extension at 1,001, 3.7 at 10,000, 4.4 at the cap | yes, yes |
| (short distinct OIDs, at the cap) | 131,762 extensions | MALFORMED, value budget | 11.4 ms | 2.3 / 4.4 MiB | refused by the header walk | yes |
| Signed attributes on a SignerInfo naming the trusted signer (contentType, the right messageDigest, then colliding OIDs) | 2 + 16,949, at the cap | INVALID_SIGNATURE | 25.8 ms | 9.2 / 19.3 MiB | 1.4 to 1.6 µs per attribute, 1,001 to 16,951 | yes, yes |
| Nested SETs as the commonName value of the SignerInfo's issuer | depth 23 (depth bound) × width 4,339 (value budget); leaves to the cap | MALFORMED | 1.1 ms; 2.2 at the cap | 1.2 MiB; 9.0 at the cap | OpenSSL's Name refuses a SET value | yes, yes |
| Nested SETs in a stranger's issuer and subject | depth 23 × width 2,168; leaves to the cap | MALFORMED | 1.0 ms; 2.2 at the cap | 1.2 MiB; 9.0 at the cap | the same | yes, yes |
| (comparison) nested SEQUENCEs in the SignerInfo's issuer | depth 23 × width 4,339 | MALFORMED, signer not embedded | 1.5 ms | 1.8 / 2.4 MiB | 3.8 µs/KiB | yes, yes |
| (comparison) nested SEQUENCEs in a stranger's names | depth 23 × width 2,168 | ok | 2.1 ms | 1.8 / 3.1 MiB | 5.2 µs/KiB | yes, yes |
| (comparison) either of those with leaves grown to the cap | names over 1 MiB | MALFORMED | 2.0 ms | 9.0 MiB | `X509_NAME_MAX` | yes |
| Nested SETs as the trusted SignerInfo's signatureAlgorithm parameters | depth 26 × width 3,838; leaves to the cap | ok | 2.6 ms; 2.8 at the cap | 1.2 MiB; 9.0 at the cap | 6.6 µs/KiB at 400 KB | yes, yes |
| Nested SETs as a stranger's two signature labels' parameters | depth 25 × width 1,995; leaves to the cap | ok | 3.4 ms; 6.8 at the cap | 1.2 MiB; 9.0 at the cap | 8.5 µs/KiB at 400 KB, 2.2 at the cap | yes, yes |

Peak heap stays under 3.7 times the base64 input, which is 5 times the
decoded DER, and the resident set rises by at most 16.6 MiB. That maximum is the
17,191-extension stranger. The `rss_rise_kib` column of `results.tsv`
gives every row.

The most expensive input per byte is the stranger with 17,191
extensions: 25 µs per KiB, about 27 times the floor. Two things make it
expensive:

- each of its OIDs is decoded twice before any key is used: by the
  header walk's hand-off to `d2i_ASN1_TYPE` and by
  `d2i_CMS_ContentInfo`;
- OpenSSL caches its extensions (`ossl_x509v3_cache_extensions`, about a
  dozen linear lookups) when `X509_cmp` and `X509_check_issued` first
  touch it, and the core sorts its OIDs once in
  `Certificate::is_readable`.

Its cost per extension is flat from 1,001 to 17,191 (3.7 to 4.9 µs), so
nothing in that path is quadratic. OpenSSL re-encodes the signed
attributes before it checks the signature, in the order sent and with
each attribute's values in DER order. They cost about 1.5 µs each at
every size measured.

## Why each shape is cheap in the core

- **The labels (PSS, composite, md2) on a SignerInfo.** OpenSSL reads them
  only after a pinned root has vouched for the signer, and it reads an
  RSA SignerInfo's label only to choose PKCS#1 v1.5 or PSS. A PSS
  saltLength that does not fit fails before any allocation sized by the
  salt. The digest always comes from the digestAlgorithm, and MD2 is not
  in OpenSSL 4's default provider.
- **The labels on a stranger.** `X509_verify` refuses before it digests
  anything: the PSS saltLength does not fit, the composite OID is
  unknown, and MD2 is not there.
- **The tables.** OpenSSL keeps extensions and attributes in stacks, so
  the core never builds a hash table keyed by OID, and the collisions
  cost nothing.
- **The bounds.** The header walk's value budget (100,000) and depth
  bound (32) refuse anything larger in about 8 to 11 ms at the cap,
  before the full decode.
- **SETs in names.** OpenSSL's Name grammar refuses a SET as an attribute
  value at any size or depth: `tag2bit` maps tag 17 to 0 in
  `crypto/asn1/tasn_dec.c:84`, outside `ASN1_PRINTABLE`'s mask. It
  accepts a SEQUENCE there, which it keeps as its encoding.

## Divergences found

None of these accepts anything unsigned, and none was in the brief's
cases. Java's side is read from the sources (`PreTrustScreen`), not run.

- **Nested SETs in the parameters of a SignerInfo's signatureAlgorithm,
  within the envelope bounds.** The core verifies: OpenSSL ignores the
  parameters of an RSA PKCS#1 v1.5 label, and here the signature was
  made by the trusted key. Java leaves such a SignerInfo out
  (`appleShaped`, `holdsSet`) and answers MALFORMED, "signer certificate
  not embedded". R20 records the Java screen and, in its Q135 a and
  Q140 a paragraphs, says the core refuses these shapes at its depth
  bound or value budget. That holds only for the cap-sized inputs
  measured on 2026-10-13
  ([pre-trust re-encoding](2026-10-13-java-pretrust-reencoding.md)).
  This is a relabel of unsigned packaging, like the md2 row of R20's
  table. It needs a row of its own, not code.
- **A stranger whose names hold SETs.** The core answers MALFORMED for it
  at any size, because OpenSSL's Name grammar refuses a SET value; the
  smallest measured was 5.7 KB. Java passes such a stranger over
  (`convertible`) and the receipt is ok. R20 puts the core's refusal of
  these shapes down to its bounds, but the cause is OpenSSL's grammar.
  It fails closed on unsigned packaging, the direction R20 records.

## Where this stops holding

- **The build measured.** Native x86-64, release profile, one shared
  4-vCPU container. `aprv.wasm` runs the same code more slowly under
  every runtime, and the debug profile that `cargo test` bounds are set
  for is slower again. The timings here are not those builds'.
- **Noise.** The medians of the largest inputs are noisy. In
  `results.tsv`, 16,384 colliding unsigned attributes took 38 ms and
  16,948 took 29 ms, for inputs 3 % apart. An earlier run of the same
  harness, built with Rust 1.98.1 and not kept, gave other timings, but
  every verdict, size and heap figure was the same.
- **The resident-set figure.** It depends on glibc's `malloc_trim`
  returning freed pages. Another allocator would report less.
- **The library version.** OpenSSL 4.0.3. A release that caches
  extensions differently, decodes a SET in a Name, or adds MD2 to the
  default provider changes the reasons above. Rerun this harness.
- **The inputs.** RSA 2048 keys. Strangers name the pinned root, so
  `X509_check_issued` and `X509_verify` run on them; a stranger that
  names nobody costs less.
- **Sizes not tried.** A stranger with many extensions was measured only
  as the one certificate in the bag besides the shared chain. Seven such
  strangers, which the 10-certificate cap allows, share the same 3 MiB.
  Since the cost per byte is flat, their total should be the same, but
  that was not measured.
