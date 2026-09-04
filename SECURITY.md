# Security Policy

This library verifies Apple purchase receipts **locally** — its entire job is
security-sensitive parsing of attacker-suppliable input (PKCS#7 blobs, JWS
tokens). Bugs that make it accept a receipt it should reject are the highest
class of issue here.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:
<https://github.com/emindeniz99/apple-purchase-receipt-verifier/security/advisories/new>

Please do not open a public issue for anything exploitable. You can expect an
initial response within a week.

## Supported versions

Only the latest release is supported. Every artifact in a release — npm,
PyPI, Maven Central, SwiftPM, and the registries listed in `BOOTSTRAP.md` as
they come online — is built from the same tag, so a fix ships to all of them
at once.

## What counts

Especially interesting:

- Signature or certificate-chain validation bypasses (forged receipt accepted)
- Trust-anchor confusion (accepting chains not rooted in the pinned Apple roots
  in `certs/`)
- Parser differentials between the nine language implementations — if two
  disagree on the same receipt, one of them is wrong
- ASN.1/JWS parsing crashes on malformed input (DoS in a server context)
