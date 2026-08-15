# apple-purchase-receipt-verifier

[![ci](https://github.com/emindeniz99/apple-purchase-receipt-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/emindeniz99/apple-purchase-receipt-verifier/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/apple-purchase-receipt-verifier?logo=npm)](https://www.npmjs.com/package/apple-purchase-receipt-verifier)
[![PyPI](https://img.shields.io/pypi/v/apple-purchase-receipt-verifier?logo=python&logoColor=white)](https://pypi.org/project/apple-purchase-receipt-verifier/)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.emindeniz99/apple-purchase-receipt-verifier?logo=apachemaven)](https://central.sonatype.com/artifact/io.github.emindeniz99/apple-purchase-receipt-verifier)
[![SwiftPM](https://img.shields.io/github/v/tag/emindeniz99/apple-purchase-receipt-verifier?label=SwiftPM&logo=swift)](https://github.com/emindeniz99/apple-purchase-receipt-verifier/tags)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

## What it does

Verifies Apple in-app purchases **locally, with zero Apple server calls** —
a replacement for the deprecated `verifyReceipt` endpoint. Cryptographically
proves that purchase data a client presents (StoreKit 2 signed JWS
transactions, or legacy PKCS#7 app receipts) was signed by Apple, by
validating the certificate chain against pinned Apple root CAs. Four
implementations, one normative algorithm, one shared fixture set they all
verify byte-for-byte: **Java** (8+), **Node** (20+, zero runtime deps),
**Python** (3.9+), **Swift** (6).

Each implementation also ships **`VerifyReceiptEndpoint`** — a drop-in
local replacement for the deprecated `verifyReceipt` endpoint speaking
Apple's exact request/response/status-code wire contract (incl. local
21007/21008 sandbox routing); see [COMPARISON.md](./COMPARISON.md) for the
field-by-field fidelity account and the gaps only Apple's servers can fill.

Start with [INTENT.md](./INTENT.md) (why + trust model), then
[PLAN.md](./PLAN.md) (algorithms + decisions + API shape), then
[ROADMAP.md](./ROADMAP.md) (what's next).

## Installing

All four implementations publish as **`apple-purchase-receipt-verifier`**,
in lockstep versions cut from this repository's tags.

| Registry | Install | How you import it |
|---|---|---|
| [Maven Central](https://central.sonatype.com/artifact/io.github.emindeniz99/apple-purchase-receipt-verifier) | `io.github.emindeniz99:apple-purchase-receipt-verifier` | `import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;` |
| [npm](https://www.npmjs.com/package/apple-purchase-receipt-verifier) | `npm install apple-purchase-receipt-verifier` | `import { JwsVerifier } from 'apple-purchase-receipt-verifier';` |
| [PyPI](https://pypi.org/project/apple-purchase-receipt-verifier/) | `pip install apple-purchase-receipt-verifier` | `from apple_purchase_receipt_verifier import JwsVerifier` |
| SwiftPM | `.package(url: "https://github.com/emindeniz99/apple-purchase-receipt-verifier.git", from: "0.1.0")` | `import ApplePurchaseReceiptVerifier` |

The import namespace is the registry name in each ecosystem's casing
convention (`applepurchasereceiptverifier` / `apple_purchase_receipt_verifier` /
`ApplePurchaseReceiptVerifier`) — one name everywhere.

## How to run the test suites

```bash
# Java (library targets Java 8; build with any modern JDK + Maven)
cd java && mvn test

# Node (strict TypeScript, zero runtime deps; Node >= 20)
cd node && npm install && npm test    # = tsc && node --test

# Python (>= 3.9; needs: pip install cryptography asn1crypto)
cd python && python3 -m unittest discover -s tests

# Swift (Swift 6; Linux or macOS 13+; manifest lives at the repo root)
swift test
```

All four suites verify the same three shared fixture tiers:

1. `fixtures/generated/` — deterministic cross-language fixtures (fake
   Apple PKI) written by the Java `FixtureGeneratorTest`; regenerate only
   deliberately, then re-run **all four** suites.
2. `fixtures/apple-official/` — Apple's own library test fixtures
   (vendored, MIT): their test-CA-signed JWS mocks verify, their negative
   cases fail with our exact reason codes, and their genuine Xcode
   receipts/payloads are **rejected** against the real pinned Apple roots
   (anchor-pinning proof).
3. `fixtures/public-receipts/` — **genuine Apple-signed**
   sandbox and legacy receipts (vendored, MIT) that must verify against
   the real pinned Apple root, plus an Xcode receipt that must be rejected
   — the strongest tier (real Apple bytes).

Java additionally generates a fresh random PKI per run (`TestPki`) for the
full attack matrix (Java-only, not a shared tier).

Production trust anchors are the two Apple root certificates in
[`certs/`](./certs) (from [Apple PKI](https://www.apple.com/certificateauthority/)):
`AppleRootCA-G3.cer` for JWS signed data, `AppleIncRootCertificate.cer` for
legacy PKCS#7 receipts. Each language bundles its own copy as packaged
resources; verifiers also accept caller-supplied anchors.

## Notes / learnings

- **Both paths are first-class**: StoreKit 2 JWS requires iOS 15+ *and* a
  migrated app — iOS ≤14 devices and unmigrated StoreKit 1 apps still send
  PKCS#7 receipts. Chain validity is checked at *signing time* (JWS
  `signedDate` / receipt creation date), not "now", so old payloads survive
  Apple's certificate rotations.
- **Prior art** (survey in PLAN.md §1, re-verified 2026-08): Apple's
  official libraries verify JWS but only *extract* from legacy receipts
  without validation; the sole server-side legacy validator we found
  (Python `iap-local-receipt`) has been abandoned since ~2016. No
  maintained library does both paths server-side in any of our languages.
- **Signature validity ≠ entitlement**: replay protection (transaction-id
  bookkeeping) and refund/status tracking are deliberately out of scope —
  see INTENT.md. `isActiveAt`/`isActive` helpers + the optional
  max-signed-age policy cover subscription expiry from the signed claims.
