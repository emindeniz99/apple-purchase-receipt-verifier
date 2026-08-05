# Plan — apple-purchase-verification

Read [INTENT.md](./INTENT.md) first for the "why". This file records the
research, the verification algorithms every implementation must follow, and
the shared API shape.

## 0. Decisions (design grill, 2026-08-05)

Settled with the project owner; treat as ADRs — changing one needs a reason
recorded here.

- **D1 — Published libraries, not internal-only.** Each implementation will
  be published (Maven Central, npm, PyPI) when the project graduates.
  Consequences: stable API, semver, dependency-light ("vendoring is ok"),
  license required at publish time (MIT assumed — *unconfirmed, ask before
  publishing*).
- **D2 — Enterprise-reality version floors**, not upstream-support floors:
  **Java 8**, **Node ≥20**, **Python ≥3.9**, **Swift 6** (server-side Swift
  has no Java-8-style long tail; Apple's own Swift library requires 6). Java is built `--release 8`
  (no records/`var`/`List.of`; ES256 raw-signature conversion done manually
  since `SHA256withECDSAinP1363Format` is Java 9+). CI should matrix-test
  oldest + current LTS.
- **D3 — Environment routing is an accept-set** (grill Q4, option A): the
  verifier takes a *set* of accepted environments and reports which one
  matched. Rationale: App Review runs production builds against sandbox —
  a single-environment hard fail would reject purchases during review
  (the old `verifyReceipt` 21007 retry-on-sandbox problem, solved locally).
- **D4 — Device-hash check stays optional, off by default.**
  `identifierForVendor` differs per device but each device carries its own
  receipt with its own GUID, so the check is sound — still, requiring it
  would force client changes. Replay defense = server-side transaction-id
  bookkeeping (owner confirmed the server can keep them).
- **D5 — Subscriptions supported**: payloads expose `expiresDate` /
  `revocationDate` with an `isActiveAt(now)` helper, and the JWS verifier
  takes an optional max-signed-age (staleness) policy. Refund/renewal
  *state* still requires Apple's server API — out of scope (INTENT.md).
- **D6 — Real receipt corpus pending**: owner will supply real production +
  sandbox receipts as fixtures later; until then generated fake-Apple-PKI
  fixtures carry the tests (tracked in ROADMAP.md).

## 1. Existing solutions (research, 2026-08)

| Solution | Local verify? | Notes |
|----------|--------------|-------|
| [apple/app-store-server-library-java](https://github.com/apple/app-store-server-library-java) (also [-node](https://github.com/apple/app-store-server-library-node), [-python](https://github.com/apple/app-store-server-library-python), [-swift](https://github.com/apple/app-store-server-library-swift)) | **Yes** (JWS only) | Official. `SignedDataVerifier` validates JWS `x5c` chains against caller-supplied Apple roots, offline by default (optional OCSP "online checks"). Does **not** validate legacy PKCS#7 receipts — `ReceiptUtility` only *extracts* a transaction ID from a receipt, unverified. Heavy: bundles the full App Store Server API client. |
| `node-apple-receipt-verify`, `itunes-iap`, `django-receipt-validator`, … | No | All wrappers around the deprecated `verifyReceipt` endpoint — the thing we're replacing. |
| [SilentCircle/iap-local-receipt](https://github.com/SilentCircle/iap-local-receipt) (Python) | Yes (PKCS#7 only) | The one prior server-side local validator we found. Abandoned (~2016, pyOpenSSL, Python 2 era), no JWS, no device-hash binding. Proves demand; not usable today. |
| [tikhop/TPInAppReceipt](https://github.com/tikhop/TPInAppReceipt) (Swift), [SwiftyLocalReceiptValidator](https://github.com/andrewcbancroft/SwiftyLocalReceiptValidator) | Yes (PKCS#7, on-device) | Client-side focus (`identifierForVendor`, bundle receipt URL); TPInAppReceipt is maintained. Same crypto, different deployment target. |
| objc.io ["Receipt Validation"](https://www.objc.io/issues/17-security/receipt-validation/), [Kodeco tutorial](https://www.kodeco.com/9257-in-app-purchases-receipt-validation-tutorial), [nick.zoic.org PKCS#7 notes](https://nick.zoic.org/art/apple-signed-receipt-verification-pkcs7/) | Yes (on-device, C/Swift/OpenSSL) | Document the PKCS#7 + ASN.1 receipt format we port to server-side. |

**Conclusion** (re-verified 2026-08): no maintained library covers both
paths (JWS + legacy PKCS#7) server-side in any language, let alone across
our four. Server-side legacy validation appears to simply not exist for
Java and Node; the only Python attempt is a decade stale. The official
libraries are the reference for the JWS algorithm (we mirror their checks,
and verify their exact test fixtures); the PKCS#7 path we implement from
Apple's on-device validation spec. Building it ourselves also keeps each
implementation dependency-light and auditable — appropriate for
security-critical code we must be able to reason about.

## 2. Verification algorithms (normative for every language)

### 2.1 JWS signed data (StoreKit 2 / Server Notifications V2)

Input: compact JWS string, expected `bundleId`, expected `environment`,
optional `appAppleId` (required when environment = Production), trusted
roots (Apple Root CA – G3).

1. Split `header.payload.signature`; base64url-decode the header JSON.
2. Require `alg == "ES256"` and an `x5c` array of **exactly 3** certificates
   (leaf, intermediate, root).
3. Marker OIDs (rejects any non-App-Store Apple-issued cert):
   - leaf must carry extension OID `1.2.840.113635.100.6.11.1`
     (Apple in-app-purchase / receipt signing marker);
   - intermediate must carry OID `1.2.840.113635.100.6.2.1`
     (Apple WWDR CA marker) and `CA: true`.
4. Path-validate leaf → intermediate → pinned root (standard PKIX: signatures,
   issuer/subject chaining, basic constraints, validity window), **revocation
   disabled** (no OCSP — offline by design; the x5c root must byte-match a
   pinned trust anchor).
   - Validity is checked at the payload's `signedDate` (fall back to
     `receiptCreationDate`, else current time), so historical payloads
     signed with since-rotated certs still verify — same model as Apple's
     official libraries in offline mode.
5. Verify the ES256 signature over `ASCII(header + "." + payload)` with the
   leaf public key (P-256, SHA-256, raw r‖s per RFC 7515 → DER for JCA-style APIs).
6. Decode the payload JSON and enforce: `bundleId` matches, `environment`
   matches, and in Production `appAppleId` matches.
7. Return the decoded, typed payload. Any failed step throws/raises a
   `VerificationException` with a machine-readable reason code — never a
   partially-verified result.

### 2.2 Legacy PKCS#7 app receipt

Input: receipt bytes (DER PKCS#7/CMS, or its base64 — the exact blob apps
send to `verifyReceipt`), expected `bundleId`, trusted roots (Apple Inc.
Root CA), optional device GUID.

1. Parse as CMS `SignedData`; require signed content present (the payload).
2. Extract the embedded certificate chain; identify the signer cert; build
   and PKIX-validate signer → WWDR CA → pinned Apple Inc. Root CA,
   revocation disabled.
   - Validity is checked at the receipt's **creation date** (attribute 12) —
     Apple's receipt-signing certs expire and rotate; a receipt is valid if
     its chain was valid when Apple signed it. (Requires parsing the payload
     before trusting it — parse defensively, trust only after step 3.)
3. Verify the CMS signature over the content with the signer's public key
   (Apple signs receipts with SHA-1/RSA or SHA-256/RSA — accept what the CMS
   `SignerInfo` declares, but only after the chain anchored at our pinned root).
4. Parse the payload: `SET OF ReceiptAttribute ::= SEQUENCE { type INTEGER,
   version INTEGER, value OCTET STRING }`. App-level attributes:
   | type | field | value encoding |
   |------|-------|----------------|
   | 2 | bundle id | UTF8String (keep raw bytes too — needed for hash) |
   | 3 | app version | UTF8String |
   | 4 | opaque value | raw bytes |
   | 5 | SHA-1 hash | raw bytes |
   | 12 | receipt creation date | IA5String, RFC 3339 |
   | 17 | in-app purchase | nested `SET OF ReceiptAttribute` (repeats) |
   | 19 | original app version | UTF8String |
   | 21 | expiration date | IA5String |
   In-app attributes: 1701 quantity, 1702 product id, 1703 transaction id,
   1704 purchase date, 1705 original transaction id, 1706 original purchase
   date, 1708 subscription expiration date, 1711 web order line item id,
   1712 cancellation date, 1719 is-in-intro-offer-period.
5. Enforce `bundleId` matches. If the caller supplies the device GUID:
   check `SHA1(guid ‖ opaqueValue ‖ bundleIdRawBytes) == attribute 5`
   (device binding — optional because servers don't always have the GUID).
6. Return the typed receipt (app fields + list of in-app purchases); throw
   on any failure, as in 2.1.

### 2.3 Threat model notes

- **Pinned anchors, not system trust store** — a cert chain to any public CA
  must fail; only `certs/*.cer` count.
- **Marker OIDs** stop "valid Apple-issued cert, wrong purpose" attacks on
  the JWS path.
- **No revocation checking** is the accepted trade-off for offline
  verification (Apple's official offline mode does the same). Compromised
  signing certs are handled by Apple rotating them; consumers concerned
  about revocation can layer OCSP later (roadmap).
- **Replay / refunds are not detectable by signature** — see INTENT.md;
  callers must track transaction IDs and purchase status themselves.
- Parse untrusted bytes defensively: bounded sizes, no recursion on
  attacker-controlled depth, reject trailing garbage.

## 3. Shared API shape (adapt idiomatically per language)

```
Environment = { PRODUCTION, SANDBOX, XCODE, LOCAL_TESTING }

JwsVerifier(trustedRoots, bundleId, acceptedEnvironments, appAppleId?, maxSignedAge?)
  .verifyTransaction(jws)      -> TransactionPayload   (decoded fields + isActiveAt helper)
  .verifyAppTransaction(jws)   -> AppTransactionPayload
  .verifyRaw(jws)              -> claims map — signature/chain only, caller checks
                                  claims (covers renewal-info / notification JWS)

ReceiptVerifier(trustedRoots, bundleId)
  .verify(receiptBytes|base64) -> AppReceipt { bundleId, appVersion, opaqueValue,
                                   sha1Hash, creationDate, originalAppVersion,
                                   expirationDate, inAppPurchases[] }
  .verifyWithDeviceGuid(receipt, guid)  // adds the device-hash check

VerificationException { reason: INVALID_JWS_FORMAT | INVALID_CHAIN |
  INVALID_SIGNATURE | INVALID_CERTIFICATE_PURPOSE | WRONG_BUNDLE_ID |
  WRONG_ENVIRONMENT | WRONG_APP_APPLE_ID | INVALID_RECEIPT_FORMAT |
  DEVICE_HASH_MISMATCH | ... }
```

Apple root certs are **not** hard-wired: constructors take trust anchors,
with a helper that loads the bundled `certs/*.cer`. Tests inject a
generated fake "Apple" PKI (root → intermediate-with-OID → leaf-with-OID)
and sign fixtures with it — the same technique Apple's own libraries use —
so tests need no real Apple secrets and prove the anchor pinning works.

## 4. Milestones

1. **Docs** — this folder: INTENT / PLAN / ROADMAP / README. ✅
2. **Java** (`java/`, Maven, Java 8+, BouncyCastle + Jackson):
   JWS verifier + PKCS#7 receipt verifier + test PKI + full test suite. ✅
3. **Node** (`node/`, Node ≥20, ESM, zero runtime deps — hand-rolled
   bounded DER/BER parser + `node:crypto`). ✅
4. **Python** (`python/`, ≥3.9, `cryptography` + `asn1crypto`). ✅
5. **Swift** (`swift/`, SwiftPM, Swift 6, swift-certificates +
   swift-crypto + swift-asn1 only). ✅
6. **Cross-language fixture parity**: one shared fixture set
   (`fixtures/generated/` + the vendored Apple-official set in
   `fixtures/apple-official/`) verified byte-identically by all four
   suites. ✅
7. CI workflow per language (mirror existing `.github/workflows/*` style).
