# Plan — apple-purchase-receipt-verifier

Read [INTENT.md](./INTENT.md) first for the "why". This file records the
research, the verification algorithms every implementation must follow, and
the shared API shape.

## 0. Decisions (design grill, 2026-08-05)

Settled with the project owner; treat as ADRs — changing one needs a reason
recorded here.

- **D1 — Published libraries, not internal-only.** Each implementation will
  be published (Maven Central, npm, PyPI) when the project graduates.
  Consequences: stable API, semver, dependency-light ("vendoring is ok"),
  license: **MIT, confirmed by the owner 2026-08-05** (LICENSE at the
  project root).
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
- **D7 — Full type safety** (2026-08-05): Node is strict TypeScript
  (compiled to `dist/` with declarations; still zero runtime deps), Python
  ships annotations + `py.typed`, Java and Swift are typed by language.
- **D8 — Dependencies stay minimal, hand-rolled parsers stay** (2026-08-05):
  evaluated replacing the Node DER/BER parser with `pkijs`/`node-forge` and
  the JWS handling with `jose` — rejected. `jose` cannot do x5c chain
  validation to a custom pinned root (the security-critical part stays
  manual either way), `node-forge` is effectively unmaintained, and `pkijs`
  pulls a large dependency surface into a security library to replace ~300
  audited lines that Apple's own fixture bytes exercise. Java (BouncyCastle),
  Python (`cryptography`+`asn1crypto`) and Swift (apple/swift-*) already sit
  on the strongest maintained options for their ecosystems.
- **D11 — Observability is the caller's job** (owner decision,
  2026-08-05): this is a library; it exposes machine-readable reason codes
  and nothing else — no logging, no metrics, no callbacks. Integrators wire
  `VerificationException`/`VerificationError` reasons into their own
  telemetry and decide reject/alert policy.
- **D12 — Trust anchors are NEVER fetched at runtime** (owner question,
  2026-08-05): periodic runtime download of Apple's roots was considered
  and rejected — it would convert pinned trust into trust-the-network (a
  MITM on the fetch could inject a root), couple verification availability
  to apple.com, and Apple's PKI page is not an API. Policy instead:
  (1) roots ship pinned with each release (current roots are valid to
  2035/2039 — rotation is a once-a-decade event announced years ahead);
  (2) the scheduled `apple-root-watch` CI workflow diffs Apple's published
  certs weekly and fails loudly on change → cut a release; (3) constructors
  accept caller-supplied anchors, so an integrator who wants their own
  rotation pipeline can inject roots from config — at their own risk.
- **D10 — Forward-compatible ("dynamic") receipt parsing** (2026-08-05):
  attribute types the library does not model are exposed raw on
  `unknownAttributes` (type → verified-but-undecoded value bytes) in every
  language, so fields Apple adds later remain accessible without a library
  update. The JWS side was already dynamic (`verifyRaw` returns all claims).
  Endpoint environment routing fails closed: only `Production` /
  `ProductionVPP` receipt types count as production; sandbox variants
  (incl. `ProductionVPPSandbox`), `Xcode`, and a missing attribute route
  as non-production — a VPP-sandbox misroute found by the adversarial
  review drove this tightening.
- **D13 — Receipt signer-purpose OID is mandatory** (adversarial review,
  2026-08-06): the legacy PKCS#7 path now requires OID
  `1.2.840.113635.100.6.11.1` on the signer leaf (all four languages),
  checked after chain validation. Verified against genuine production +
  sandbox + legacy receipts (all carry it) and a no-OID negative fixture
  (rejected). This closed a CRITICAL forgery hole: chain-to-pinned-root
  alone let any developer certificate sign an accepted receipt. Also
  hardened the same review's findings: Swift CMS parsing is now
  bounds-checked (was an uncatchable out-of-bounds trap → DoS), and the
  cross-language anti-forgery test matrix (marker-OID rejection, Production
  appAppleId binding, receipt signing-time validity) is now covered in all
  four languages, not just Java.
- **D9 — verifyReceipt wire-compat endpoint** (2026-08-05): each language
  ships `VerifyReceiptEndpoint` speaking Apple's exact request/response/
  status-code contract, with 21007/21008 routing reproduced locally from
  the receipt's `receipt_type` attribute. Fidelity and unavoidable gaps:
  [COMPARISON.md](./COMPARISON.md).
- **D14 — Published as `apple-purchase-receipt-verifier`** (owner decision,
  2026-08-11): one registry name on all four registries, replacing the
  working name `apple-purchase-verifier`. Two constraints settled it.
  Maven Central indexes only groupId and artifactId, matching whole tokens
  with AND, so a developer searching "apple receipt" finds this library
  only if both words sit in the coordinates. And a store-neutral name
  (covering Google Play as well) would over-promise, because Play's
  offline verification cannot express expiry or revocation, so nothing
  here generalizes past Apple.
  - Coordinates: `io.github.emindeniz99:apple-purchase-receipt-verifier`
    (Maven Central), `apple-purchase-receipt-verifier` (npm, PyPI), and a
    SwiftPM repository of the same name shipping the
    `ApplePurchaseReceiptVerifier` product.
  - Import namespaces drop the trailing `verifier`: Java package
    `io.github.emindeniz99.applepurchasereceiptverifier`, Python import package
    `apple_purchase_receipt_verifier`, Swift module `ApplePurchaseReceiptVerifier`. The
    types inside already say `JwsVerifier` and `ReceiptVerifier`, and
    Python callers would otherwise type 31 characters per import.
  - Version is `0.1.0` in all four manifests. The pom said
    `0.1.0-SNAPSHOT`; no release automation exists yet that needs a
    SNAPSHOT cycle, and the other three manifests already declared 0.1.0.
    Whoever wires up the Maven release flow decides then whether to move
    the working version back to SNAPSHOT between releases.
- **D15 — All three published Apple roots are pinned, superseding the
  two-root choice inside D12** (owner decision, 2026-08-16, after a
  primary-source research pass): both `jwsRoots`/`receiptRoots` sets now
  contain Apple Inc. Root, Apple Root CA - G2, and Apple Root CA - G3.
  What forced the change: Apple deliberately does not commit to a
  specific root for either verification path, and G2 is already
  published — if Apple ever issued a WWDR intermediate under it, the
  `apple-root-watch` workflow would see no change on the PKI page and
  our fail-closed verifiers would start rejecting genuine receipts with
  zero warning. Evidence:
  - JWS: the `JWSDecodedHeader` doc specifies the intermediate by OID but
    calls the third element only "An Apple root certificate"
    (<https://developer.apple.com/documentation/appstoreserverapi/jwsdecodedheader>),
    and an App Store Commerce Engineer answered the "always G3?" question
    directly with "use all Apple Root CAs"
    (<https://developer.apple.com/forums/thread/742525>). WWDC23 session
    10143 uses the same set-membership framing ("one of the certificates
    you stored as an Apple Root Certificate Authority").
  - Legacy receipts: Apple's Dec 2022 signing-certificate notice names the
    Apple Inc. Root and warns against hardcoding the *intermediate*
    (<https://developer.apple.com/news/?id=ytb7qj0x>). Real Mac App Store
    receipts verify against it (and fail against G2/G3).
  - Today's chains: no published WWDR intermediate is signed by G2 — the
    ones checked chain to Apple Inc. Root (WWDR G3/G4/G5/G7/G8 and the
    expired original) or to Apple Root CA - G3 (WWDR "- G2" and "- G6";
    the WWDR names do not track their root's name). So G2 anchors nothing
    *currently* — pinning it is insurance against re-anchoring, at zero
    trust cost since it sits at the same assurance level on the same page.
  - Contrast that shows the omission is deliberate: where Apple wants a
    single-root guarantee it writes one — the Apple Pay payment-token doc
    says "Ensure that the root CA is the Apple Root CA - G3". No such
    sentence exists for App Store JWS or receipts.
  What still holds from D12: anchors ship pinned (never fetched at
  runtime), the weekly watch diffs both the pinned bytes and the PKI
  page's root listing, and callers can inject their own anchors.

## 1. Existing solutions (research, 2026-08)

| Solution | Local verify? | Notes |
|----------|--------------|-------|
| [apple/app-store-server-library-java](https://github.com/apple/app-store-server-library-java) (also [-node](https://github.com/apple/app-store-server-library-node), [-python](https://github.com/apple/app-store-server-library-python), [-swift](https://github.com/apple/app-store-server-library-swift)) | **Yes** (JWS only) | Official. `SignedDataVerifier` validates JWS `x5c` chains against caller-supplied Apple roots, offline by default (optional OCSP "online checks"). Does **not** validate legacy PKCS#7 receipts — `ReceiptUtility` only *extracts* a transaction ID from a receipt, unverified. Heavy: bundles the full App Store Server API client. |
| `node-apple-receipt-verify`, `itunes-iap`, `django-receipt-validator`, … | No | All wrappers around the deprecated `verifyReceipt` endpoint — the thing we're replacing. |
| [SilentCircle/iap-local-receipt](https://github.com/SilentCircle/iap-local-receipt) (Python) | Yes (PKCS#7 only) | The one prior server-side local validator we found. Abandoned (~2016, Python 2 era; relies on the PKCS7 API modern pyOpenSSL removed), no JWS; does offer the optional GUID device-hash check. Proves demand; not usable today. |
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
4. Path-validate leaf → intermediate → **our pinned root** (standard PKIX:
   signatures, issuer/subject chaining, basic constraints, validity window),
   **revocation disabled** (no OCSP — offline by design). The chain must
   terminate at a pinned trust anchor; the x5c-supplied root (`x5c[2]`) is
   **not** trusted or byte-compared — only the intermediate being signed by
   one of our pinned anchors counts, so an attacker swapping in their own
   `x5c[2]` changes nothing.
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
3. **Signer purpose check (critical):** require the signer leaf to carry
   extension OID `1.2.840.113635.100.6.11.1` (the Apple receipt-signing
   marker, present on the genuine "Mac App Store and iTunes Store Receipt
   Signing" leaf, absent on developer certs). Without this, any certificate
   chaining to the pinned Apple root — including any Apple developer's own
   "Apple Distribution"/"Apple Development" leaf, which chains through the
   same WWDR intermediate — could sign a fully forged receipt. This mirrors
   the JWS leaf marker check (§2.1 step 3). Checked **after** chain validation
   so a foreign chain still reports `INVALID_CHAIN` first.
4. Verify the CMS signature over the content with the signer's public key
   (Apple signs receipts with SHA-1/RSA or SHA-256/RSA — accept what the CMS
   `SignerInfo` declares, but only after the chain anchored at our pinned root
   and the signer-purpose check). Require the signer key to be RSA.
5. Parse the payload: `SET OF ReceiptAttribute ::= SEQUENCE { type INTEGER,
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
6. Enforce `bundleId` matches. If the caller supplies the device GUID:
   check `SHA1(guid ‖ opaqueValue ‖ bundleIdRawBytes) == attribute 5`
   (device binding — optional because servers don't always have the GUID).
7. Return the typed receipt (app fields + list of in-app purchases); throw
   on any failure, as in 2.1.

### 2.3 Threat model notes

- **Pinned anchors, not system trust store** — a cert chain to any public CA
  must fail; only `certs/*.cer` count.
- **Marker OIDs** stop "valid Apple-issued cert, wrong purpose" attacks on
  **both** paths: the JWS leaf must carry `…6.11.1` and the intermediate
  `…6.2.1`; the receipt signer leaf must carry `…6.11.1`. Without the receipt
  check, any developer cert chaining to the pinned root could sign a forged
  receipt (a real hole found by adversarial review, 2026-08-06, now closed).
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
