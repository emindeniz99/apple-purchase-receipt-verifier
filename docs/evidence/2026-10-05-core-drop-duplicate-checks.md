# Checks in the core that OpenSSL already makes

**Question.** Five checks on the core's receipt path looked like repeats
of work OpenSSL 4 or the adapter already does. Which of them can go
without changing any answer in `fixtures/cases.json`? The answer decides
what `refactor(rust): drop four duplicate checks from the receipt path`
and the commit after it removed.

**Versions.** OpenSSL 4.0.2, built from source by `openssl-src`
400.0.1+4.0.2 (the crate's `vendored` default); source locations below
are paths in that tarball. Rust 1.98.1. BouncyCastle `bcprov-jdk18on`
1.86 (`bcprov-jdk18on-1.86.jar`, SHA-256
`2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f`) on
OpenJDK 21.0.10. All runs 2026-10-05, on `main` at 68b0b38 and the
commits above it on the branch.

**Method.** Each check was read against the OpenSSL source the core
calls (`CMS_SignerInfo_verify`, `CMS_SignerInfo_verify_content`,
`d2i_CMS_ContentInfo`) and the adapter's own bounds. Each was then
removed, and `cargo test --locked --workspace --all-features` run in
`rust/`, which runs every shared case once. A removal that changed a
shared case was put back.

## Results

| Check | What makes it redundant | Verdict |
|---|---|---|
| `within_member_bounds` (SignerInfo and certificate counts) | The adapter's `SignedData::parse` refuses the same counts on its shallow decode, before the full decode (`within` in `rust/openssl/src/cms.rs`); `envelope_failure` maps both errors to the same messages. | Removed. |
| `signer_digest_known` | `verify_signer` returns false when `signer_md` finds no digest. OpenSSL also refuses one in `CMS_SignerInfo_verify` (`crypto/cms/cms_sd.c:1312-1315`, `CMS_R_UNKNOWN_DIGEST_ALGORITHM`). | Removed. The reason stays `INVALID_SIGNATURE`; only the message changes. |
| `signature_names_digest` | Not redundant: OpenSSL verifies under the `digestAlgorithm` and does not compare it with a hash the `signatureAlgorithm` names. For an EC key `cms_sd_asn1_ctrl` goes to `cms_generic_sign` (`cms_sd.c:273-274`), which returns 1 when verifying without reading the `signatureAlgorithm` (`cms_sd.c:238-266`). For an RSA key `rsa_cms_verify` reads it only to choose PKCS#1 v1.5 or RSASSA-PSS (`crypto/cms/cms_rsa.c:251-274`); a hash is compared only in the PSS parameters (`crypto/rsa/rsa_ameth.c:570`). | Removed by the owner's decision: an RSA PKCS#1 v1.5 DigestInfo binds the hash, so a relabel still fails. An ECDSA signature binds none, so one made over the `digestAlgorithm`'s hash now verifies under any label. The shared case is `oneOf`. |
| The eContent chunk check (`ForeignContentChunk`) | OpenSSL joins the chunks of a constructed string whatever their tag or class: `asn1_d2i_ex_primitive` calls `asn1_collect` with tag `-1` (`crypto/asn1/tasn_dec.c:826`), and `asn1_check_tlen` compares tag and class only when the expected tag is not negative (`tasn_dec.c:1229-1230`). The comment above the call (`tasn_dec.c:821-825`) says the class is checked; it is not, and `rust/tests/envelope_bounds.rs` pins a context-class chunk that verifies. The joined octets are what the signature covers and what the payload is read from. | Removed. A genuine receipt whose eContent is re-chunked with foreign tags now verifies; it was `MALFORMED`. No shared case pins it. |
| Signed-attribute counts and the contentType match | `CMS_SignerInfo_verify` calls `ossl_cms_si_check_attributes` (`cms_sd.c:1291`, defined at `crypto/cms/cms_att.c:254`), whose table (`cms_att.c:44-45`) refuses a missing, repeated or multi-valued `contentType` or `messageDigest`. Nothing on that path compares the `contentType` attribute with the eContentType. The only such comparison in `crypto/cms/` is the ESS receipt check (`cms_ess.c:354`, `CMS_R_CONTENT_TYPE_MISMATCH`), which the core never calls. | Counts removed; the contentType comparison stays. |

**The contentType finding.** With the whole attribute check removed, the
`conformance` target ran 389 passed and 1 failed:
`receipt/reject-a-content-type-attribute-that-differs-from-the-econtent-type`
verified. Applying `without-content-type-match.patch` to the trimmed
code gives the same 389 and 1. With only the counts removed,
`receipt_negative`'s count tests still answer `INVALID_SIGNATURE`
(40 passed).

**Which OpenSSL rule refuses each attribute fault.** The tests in
`rust/tests/receipt_signer_algorithms.rs` build signed attributes under
their own minted signer and sign exactly the bytes OpenSSL verifies, so
a refusal cannot be a signature that does not hold. Appending
`openssl-attribute-diagnostic.rs` to that file runs OpenSSL's own
`CMS_verify` on each and prints its error reasons:

| signedAttrs | OpenSSL's reasons |
|---|---|
| one `contentType`, one `messageDigest` (the control) | none: verifies |
| `contentType` twice | `attribute error` |
| `contentType` with two values | `attribute error` |
| `messageDigest` with two values | `attribute error` |
| empty (`A0 00`) | `error reading messagedigest attribute`, `content verify error` |

`attribute error` is `CMS_R_ATTRIBUTE_ERROR`, raised by
`ossl_cms_si_check_attributes` (`cms_att.c:268`). That function
requires `contentType` and `messageDigest` only when the set has at least
one attribute (`cms_att.c:257`, `cms_check_attribute`'s `have_attrs`), so
the empty set passes it and `CMS_SignerInfo_verify` accepts the signature
over it. The refusal then comes from `CMS_SignerInfo_verify_content`,
which looks for the `messageDigest` whenever the field is present
(`cms_sd.c:1413-1420`).

**BouncyCastle on foreign chunks.** `Probe.java` parses a constructed
`OCTET STRING` holding a `UTF8String`. BouncyCastle 1.86 refuses it:
`ASN1Exception: unknown object encountered in constructed OCTET STRING:
class org.bouncycastle.asn1.DERUTF8String` (definite length), and
`IOException: unknown object encountered` (indefinite). That is the
parser measured, not the Java port: read from its code,
`ReceiptCore.verifySignature` parses the receipt with
`ASN1Primitive.fromByteArray` first and maps that `IOException` to
`MALFORMED`. So the eContent row is a recorded divergence (DECISIONS.md
R20).

**Conformance count.** The `conformance` target runs 390 tests: the 388
cases plus two harness checks. It ran 390 passed on 68b0b38, on
`refactor(rust): drop four duplicate checks from the receipt path`, and
on `refactor(rust): keep only the contentType match of the attribute
check`, and again after the tests above were added.
`git diff --stat main -- fixtures/` is empty throughout.

## Limits

- The source reading holds for OpenSSL 4.0.2. A later OpenSSL that
  starts comparing the `contentType` attribute in
  `CMS_SignerInfo_verify` would make the remaining check redundant too;
  one that stops enforcing the counts would bring back the gap the core
  closed. The shared cases catch both.
- The BouncyCastle probe exercises the parser alone, not a whole receipt
  through the Java port. The port's mapping to `MALFORMED` is read from
  `ReceiptCore.verifySignature`, not run.
- The 1.85.0 floor was checked with `cargo +1.85.0 check --lib` on the
  core and the adapter, not the full floor test leg.
