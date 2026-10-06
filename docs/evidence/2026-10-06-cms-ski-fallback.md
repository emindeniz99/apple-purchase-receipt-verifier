# CMS signer match without a subjectKeyIdentifier

**Question.** A review of PR #280 (owner, Q69) noted that when a certificate
in a receipt's bag has no subjectKeyIdentifier extension, BouncyCastle's
`SignerId.match` (used at `ReceiptCertificates.signers`) falls back to a
computed key id, where OpenSSL's `CMS_SignerInfo_cert_cmp` treats such a
certificate as no match. Does that make the two implementations answer
differently on an Apple-chained receipt? The answer goes into
docs/rust-core/DECISIONS.md R20 as a recorded divergence.

**Date and versions.** 2026-10-06. Java implementation at PR #280 (branch
`fix/java-standard-leniency`) with BouncyCastle 1.86 on OpenJDK 21.0.10;
the core is the `aprv.wasm` pinned in `go/` on the same branch, run through
the Go package (go 1.24.7).

**Method.** [`ProbeSkiFallbackTest.java`](2026-10-06-cms-ski-fallback/ProbeSkiFallbackTest.java)
builds a test PKI from `StandardShapeFixtures` and one receipt per key id
style. The SignerInfo names its signer by a key id. The bag holds, in this
order: a leaf that expired before the creation date and carries that key id
as its subjectKeyIdentifier, a valid renewal on the same key and subject with
no subjectKeyIdentifier extension, and the intermediate.

- `rfc`: the key id is RFC 5280 §4.2.1.2 method 1, a SHA-1 over the
  subjectPublicKey BIT STRING.
- `ms`: the key id is a SHA-1 over the whole SubjectPublicKeyInfo DER,
  which is what BouncyCastle's fallback (`MSOutlookKeyIdCalculator`)
  computes for a certificate without the extension.

[`make-cases.mjs`](2026-10-06-cms-ski-fallback/make-cases.mjs) wraps both in
a `cases.json` that the Go conformance runner reads through
`APRV_FIXTURES_DIR`.

## Results

From the probe's console output and the Go test log:

| Key id | Java | Core |
|---|---|---|
| `rfc` | `INVALID_CERTIFICATE` | `INVALID_CERTIFICATE` (outside its validity window) |
| `ms` | ok | `INVALID_CERTIFICATE` (outside its validity window) |

With a method-1 key id, BouncyCastle's fallback value differs from the
SignerInfo's, so only the expired copy matches in either implementation.
With the SPKI-hash key id, Java also matches the renewal and verifies with
it; the core matches only the expired copy.

**Verdict.** The divergence is real, and narrow: it needs a SignerInfo key
id equal to the SPKI hash and a signer certificate without the extension.
Both certificates chain to the pinned root, so nothing unsigned is accepted.
Recorded in R20.

**Where it stops holding.** BouncyCastle 1.86's `X509CertificateHolderSelector`
and OpenSSL 4 as built into the pinned module. A BouncyCastle that drops the
fallback, or an OpenSSL that computes a missing subjectKeyIdentifier for the
comparison, closes it.
