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
(`conformance`: 390 passed before and after). The CRL cap was also
measured (below).

## Results

| # | Check | What already gives its answer | Verdict |
|---|---|---|---|
| R1 | The verify callback's waiver of an expiry reported at the `notAfter` second | `X509_verify_cert` reports `X509_V_ERR_CERT_HAS_EXPIRED` from one place, `ossl_x509_check_cert_time`, and only when `verification_time > notafter_seconds` (`crypto/x509/x509_vfy.c:2288-2290`); the other `CERT_HAS_EXPIRED` site, `X509_check_certificate_times` (`x509_vfy.c:2234-2235`), is not on that path. A report at the `notAfter` second cannot come. `rust/openssl/build.rs` refuses an OpenSSL below 4.0. | Removed. The core's millisecond `notAfter` check stays. |
| R2 | At most ten CRLs | The envelope's 100,000-value budget and the 3 MiB size cap. OpenSSL's CRL decode does work linear in the CRL's size: `crl_cb` on `ASN1_OP_D2I_POST` digests it and scans its extensions and revoked entries (`crypto/x509/x_crl.c:247-316`, `crl_set_issuers` at 80). | Removed; measured below. |
| R3 | The walk's and the payload's own copy of `ASN1_MAX_STRING_NEST` (`StringTooDeep`, `ChunkError::TooDeep`) | The walk hands every outermost constructed universal string to `d2i_ASN1_TYPE`. Its primitive decoder joins the chunks with `asn1_collect` (`crypto/asn1/tasn_dec.c:826`), which refuses a constructed chunk at depth 5 (`tasn_dec.c:1080`, `1122-1124`): six levels decode, a seventh does not. The walk's depth budget (32) bounds its own recursion and that of the chunk check after it. | Removed. The same inputs fail at the same step with the same reason (`MALFORMED` in the envelope, `UNREADABLE_PAYLOAD` in the payload); only the message changes. |
| R4 | `NotSignedData` after the full decode | The shallow decode reads the same `contentType` of the same bytes and has already refused any type but `signedData` (`rust/openssl/src/envelope.rs`). | Removed. |
| R5 | A null `content` after the shallow decode | `content` is the last field of `APRV_CONTENT_INFO` and not `OPTIONAL`: the template decoder treats the last field as mandatory (`tasn_dec.c:440-441`) and refuses a missing one with `ASN1_R_FIELD_MISSING` (`tasn_dec.c:480-492`). | Removed. |
| R6 | "receipt is empty", "jws is empty" | `decode_receipt_base64` refuses `""` (`rust/src/base64.rs`); a JWS of `""` splits into one segment. Both answer `MALFORMED`. | Removed; the message changes. |
| R7 | The core's ES256 length check | `verify_es256` returns false for any signature that is not 64 bytes (`rust/openssl/src/signature.rs`). Both answer `INVALID_SIGNATURE`. | Removed; the message changes. |

**The CRL cap.** `crl-flood-cost.rs` builds the largest flood of minimal
CRLs that the value budget lets through and a flood of NULLs that fills
the same budget in an unsigned attribute. Both verify, with one full
decode each. Three runs:

| Input | DER bytes | Per verification (3 runs) |
|---|---:|---|
| the genuine test receipt | 3,376 | 0.97 ms, 1.10 ms, 0.89 ms |
| 6,655 CRLs of 15 values each | 522,474 | 93.9 ms, 97.5 ms, 91.4 ms |
| 99,831 NULLs | 203,063 | 61.4 ms, 54.3 ms, 57.4 ms |

So the worst CRL flood costs about 1.6 times what the value budget
already allows any envelope, the same order. Before the value budget
existed, 39,121 CRLs cost 319 ms natively (REVIEW-LOG C-F5); the budget
now refuses that flood before the full decode, which
`embedded_crls_are_bounded_by_the_node_budget_alone` pins with 10,000.

**Where this stops holding.** The OpenSSL facts are for 4.0.2; `build.rs`
refuses 3.x, where the `notAfter` second is not counted as valid. The
timings come from the unoptimised test profile on one machine and are
ratios, not budgets.
