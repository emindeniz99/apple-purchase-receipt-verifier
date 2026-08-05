# Intent — apple-purchase-verification

## Why this project exists

Apple deprecated the [`verifyReceipt`](https://developer.apple.com/documentation/appstorereceipts/verify-receipt)
endpoint. The recommended replacements are:

1. **Verify Apple-signed data locally** — StoreKit 2 gives the app a JWS
   (`Transaction.jwsRepresentation` / `AppTransaction`), and App Store Server
   Notifications V2 deliver the same signed payloads. These are JSON Web
   Signatures whose certificate chain leads to an Apple root CA, so a backend
   can verify them **without any call to Apple**.
2. **Validate the legacy app receipt on-device style** — the PKCS#7 receipt
   from `[NSBundle appStoreReceiptURL]` can be validated with plain PKI
   ([Validating receipts on the device](https://developer.apple.com/documentation/appstorereceipts/validating-receipts-on-the-device)),
   which works identically on a server.

We want our backends to do exactly that: **prove, cryptographically and
offline, that purchase data presented by a client was produced by Apple** —
so we can trust the client enough to unlock purchased products.

## What we are building

A small, self-contained verification library, implemented **per backend
language** (all inside this folder):

| Folder | Language | Status |
|--------|----------|--------|
| [`java/`](./java) | Java 8+ | ✅ done |
| [`node/`](./node) | Node.js 20+ | ✅ done |
| [`python/`](./python) | Python 3.9+ | ✅ done |
| [`swift/`](./swift) | Swift 6+ | ✅ done |

Each implementation provides the same two capabilities:

1. **JWS verification** (`signedTransactionInfo`, `signedRenewalInfo`,
   `AppTransaction`, notification payloads): parse the compact JWS, validate
   the `x5c` certificate chain up to the pinned **Apple Root CA – G3**, check
   Apple's marker OIDs on the leaf and intermediate certificates, verify the
   ES256 signature, then check `bundleId` / `environment` (and `appAppleId`
   in production) against expected values.
2. **Legacy PKCS#7 receipt verification**: verify the CMS/PKCS#7 signature
   and its chain up to the pinned **Apple Inc. Root CA**, parse the ASN.1
   payload (bundle id, app version, opaque value, SHA-1 hash, in-app purchase
   attributes), and optionally check the device-hash binding when the client
   also sends its device GUID (`identifierForVendor`).

Trust is **pinned to the Apple root certificates** stored in
[`certs/`](./certs) (downloaded from [Apple PKI](https://www.apple.com/certificateauthority/)) —
never to the system trust store. That is the PKI model described in
[Everything you should know about certificates and PKI](https://smallstep.com/blog/everything-pki/):
we choose our own trust anchors, and a signature only counts if the chain
terminates at them.

## What verification guarantees — and what it doesn't

Verifying the signature proves **authenticity and integrity**: the payload
was produced by Apple and not modified. It does **not** by itself prove
**entitlement**. Callers still must (outside this library):

- **Prevent replay**: track transaction IDs so one purchase can't unlock
  products on many accounts.
- **Track refunds / current status**: use the transaction ID against the App
  Store Server API and/or subscribe to App Store Server Notifications V2.

Both are deliberately **out of scope** here (they require Apple server
calls / webhooks; our aim is the offline trust primitive).

## Out of scope

- Calling any Apple endpoint (`verifyReceipt`, App Store Server API, OCSP).
- Refund / revocation / subscription-status tracking, webhooks.
- Entitlement storage, replay bookkeeping, fraud scoring.
- Client-side (on-device) validation code.
