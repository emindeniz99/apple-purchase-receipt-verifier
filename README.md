# apple-purchase-verification

## What it does

Verifies Apple in-app purchases **locally, with zero Apple server calls** —
a replacement for the deprecated `verifyReceipt` endpoint. Cryptographically
proves that purchase data a client presents (StoreKit 2 signed JWS
transactions, or legacy PKCS#7 app receipts) was signed by Apple, by
validating the certificate chain against pinned Apple root CAs. One
implementation per backend language: `java/` (done), `node/` and `python/`
(planned).

Start with [INTENT.md](./INTENT.md) (why + trust model), then
[PLAN.md](./PLAN.md) (algorithms + API shape), then
[ROADMAP.md](./ROADMAP.md) (status).

## How to run

```bash
# Java (requires JDK 17+, Maven)
cd java
mvn test          # full suite incl. generated fake-Apple-PKI fixtures
```

Production trust anchors are the two Apple root certificates in
[`certs/`](./certs) (from [Apple PKI](https://www.apple.com/certificateauthority/)):
`AppleRootCA-G3.cer` for JWS signed data, `AppleIncRootCertificate.cer` for
legacy PKCS#7 receipts. Tests never use them — they generate their own fake
Apple PKI, which also proves anchor pinning rejects foreign chains.

## Notes / learnings

- Apple's official [app-store-server-library](https://github.com/apple/app-store-server-library-java)
  verifies JWS locally but not legacy PKCS#7 receipts; wrappers like
  `node-apple-receipt-verify` just call the deprecated endpoint. Hence this
  project (survey in PLAN.md §1).
- Signature validity ≠ entitlement: replay protection (transaction-id
  bookkeeping) and refund/status tracking are deliberately out of scope —
  see INTENT.md.
- Chain validity is checked at *signing time* (JWS `signedDate` / receipt
  creation date), not "now" — Apple rotates signing certs and old payloads
  must stay verifiable.
