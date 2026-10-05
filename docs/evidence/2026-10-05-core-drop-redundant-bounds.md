# Bounds and re-checks in the core that OpenSSL already enforces

**Question.** Seven checks on the core's paths (R1 to R7 of the
2026-10-05 simplicity audit) looked dead or repeated: does OpenSSL 4, or
an earlier step of the core, already give each one's answer? The answer
decides what `refactor(rust): drop bounds and re-checks openssl already
makes` removed.

**Versions.** OpenSSL 4.0.2, built from source by `openssl-src`
400.0.1+4.0.2; source locations below are paths in that tarball. Rust
1.98.1, the test profile (unoptimised Rust; OpenSSL as `openssl-src`
builds it for that profile). All runs 2026-10-05 on one Linux x86-64
container, on the branch above `refactor/core-drop-duplicate-checks`.

**Method.** Each check was read against the OpenSSL source the core
calls, then removed, and `cargo test --locked --workspace
--all-features` run in `rust/`, which runs every shared case once
(`conformance`: 390 passed before and after). One shared case moves
within its `oneOf`: `receipt/reject-eleven-embedded-crls` was
`MALFORMED` and now verifies. The CRL cap was also measured (below).

## Results

| # | Check | What already gives its answer | Verdict |
|---|---|---|---|
| R1 | The verify callback's waiver of an expiry reported at the `notAfter` second | `X509_verify_cert` reports `X509_V_ERR_CERT_HAS_EXPIRED` from one place, `ossl_x509_check_cert_time`, and only when `verification_time > notafter_seconds` (`crypto/x509/x509_vfy.c:2288-2290`); the other `CERT_HAS_EXPIRED` site, `X509_check_certificate_times` (`x509_vfy.c:2234-2235`), is not on that path. A report at the `notAfter` second cannot come. `rust/openssl/build.rs` refuses an OpenSSL below 4.0. | Removed. The core's millisecond `notAfter` check stays. |
| R2 | At most ten CRLs | The envelope's 100,000-value budget bounds how many CRLs there are; the 3 MiB receipt cap bounds the work inside them. `crl_cb` on `ASN1_OP_D2I_POST` digests each CRL and decodes its extensions eagerly: the issuing distribution point, the AuthorityKeyIdentifier with its `authorityCertIssuer` GeneralNames, and each entry's `certificateIssuer` (`crypto/x509/x_crl.c:247-316`, `crl_set_issuers` at 80-163). Those values sit inside an `extnValue` OCTET STRING, which the walk counts as one value, so the budget never sees them. One CRL always fit under the cap. | Removed; measured below. |
| R3 | The walk's and the payload's own copy of `ASN1_MAX_STRING_NEST` (`StringTooDeep`, `ChunkError::TooDeep`) | The walk hands every outermost constructed universal string to `d2i_ASN1_TYPE`. Its primitive decoder joins the chunks with `asn1_collect` (`crypto/asn1/tasn_dec.c:826`), which refuses a constructed chunk at depth 5 (`tasn_dec.c:1080`, `1122-1124`): six levels decode, a seventh does not. The walk's depth budget (32) bounds its own recursion and that of the chunk check after it. | Removed. The same inputs fail at the same step with the same reason (`MALFORMED` in the envelope, `UNREADABLE_PAYLOAD` in the payload); only the message changes. |
| R4 | `NotSignedData` after the full decode | The shallow decode reads the same `contentType` of the same bytes and has already refused any type but `signedData` (`rust/openssl/src/envelope.rs`). | Removed. |
| R5 | A null `content` after the shallow decode | `content` is the last field of `APRV_CONTENT_INFO` and not `OPTIONAL`: the template decoder treats the last field as mandatory (`tasn_dec.c:440-441`) and refuses a missing one with `ASN1_R_FIELD_MISSING` (`tasn_dec.c:480-492`). | Removed. |
| R6 | "receipt is empty", "jws is empty" | `decode_receipt_base64` refuses `""` (`rust/src/base64.rs`); a JWS of `""` splits into one segment. Both answer `MALFORMED`. | Removed; the message changes. |
| R7 | The core's ES256 length check | `verify_es256` returns false for any signature that is not 64 bytes (`rust/openssl/src/signature.rs`). Both answer `INVALID_SIGNATURE`. | Removed; the message changes. |

**The CRL cap.** Two probes, each test in a process of its own
(`crl-extension-cost.rs`, outputs in `extension-cost.txt`; peak resident
set from `VmHWM`, before the verification and after it):

| Input | DER bytes | One verification (3 runs) | Peak RSS before, after |
|---|---:|---|---|
| the genuine test receipt | 3,376 | 3.1, 4.5, 3.6 ms | 4, 7 MiB |
| one CRL whose AuthorityKeyIdentifier holds 1,000,000 empty dNSNames (185 values in the envelope) | 2,003,502 | 692, 580, 616 ms | 23, 121 MiB |
| 11,092 minimal CRLs (50 bytes and 9 values each: an AlgorithmIdentifier without parameters, an empty issuer), the most the budget lets through | 557,984 | 100, 116, 132 ms | 9, 17 MiB |
| one bag certificate whose subjectAltName holds 1,000,000 empty dNSNames, issued in name by the pinned root | 2,003,645 | 587, 567, 572 ms | 27, 118 MiB |
| the same certificate naming an issuer nobody pinned | 2,003,632 | 556, 527, 536 ms | 27, 118 MiB |

All five verify, after one full decode. The heavy inputs are single
values: the budget bounds the number of CRLs (and the flood of 11,092 costs
about a tenth of a second and 10 MiB), not the work inside one extension
value, which only the receipt's size cap bounds: about 0.6 s and 100 MiB
for 2 MB of names in the test profile. That cost is not new. At the
branch's base (352f0d1), with the cap in place, the same CRL and the same
certificate cost 527 ms each and the same peak; only the flood was
refused.

The certificate path has the same shape, before any signature is
checked. `X509_cmp`, which the core's `same_as` calls for every embedded
certificate against every anchor in `authenticated_top_down`, runs
`X509_check_purpose` and so `ossl_x509v3_cache_extensions`
(`crypto/x509/x509_cmp.c:152-161`, `crypto/x509/v3_purp.c:91`), which
decodes the subjectAltName (`v3_purp.c:639`); `X509_check_issued` does
the same after a name match (`v3_purp.c:1062-1069`). The certificate
naming nobody costs what the one naming the root costs, so `X509_cmp`
alone reaches the decode. Earlier wording in this note and in R20 said the
work was linear in the CRL's size and bounded by the value budget; the
first half holds per byte, the second does not.

The first measurement, `crl-flood-cost.rs`, used CRLs of 15 values
(6,655 under the budget, 522,474 bytes, 92 to 98 ms) and a flood of
99,831 NULLs (203,063 bytes, 54 to 61 ms); it measured no memory. Before
the value budget existed, 39,121 CRLs cost 319 ms natively (REVIEW-LOG
C-F5); the budget now refuses that flood before the full decode, which
`embedded_crls_are_bounded_by_the_node_budget_alone` pins with 10,000.

**Where this stops holding.** The OpenSSL facts are for 4.0.2; `build.rs`
refuses 3.x, where the `notAfter` second is not counted as valid. The
timings come from the unoptimised test profile on one machine and are
ratios, not budgets.
