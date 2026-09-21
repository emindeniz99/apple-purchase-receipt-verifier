# Legacy receipt attribute types

Reference for the ASN.1 attribute types found in legacy PKCS#7 app receipts:
which ones Apple documents, which ones only the community has named, which
ones the genuine receipts in `fixtures/` actually carry, and which ones this
library decodes.

Apple documents 8 app-level types and 10 in-app types. The genuine receipts
in this repository carry 22 app-level types and 20 in-app types. Everything
this library does not decode stays reachable as raw bytes through
`unknownAttributes()`, so the table below is a map of what those raw bytes
are, not a list of gaps.

All Apple pages were read on **2026-09-21**. The archived Receipt Fields
chapter states "Document Last Revised: December 11, 2017" and has not moved
since.

## The ASN.1 module

Apple's payload grammar, quoted from
[Validating receipts on the device](https://developer.apple.com/documentation/appstorereceipts/validating-receipts-on-the-device):

```
ReceiptModule DEFINITIONS ::=
BEGIN

ReceiptAttribute ::= SEQUENCE {
    type    INTEGER,
    version INTEGER,
    value   OCTET STRING
}

Payload ::= SET OF ReceiptAttribute

END
```

Three things the grammar implies and the tables below depend on:

- The payload is a `SET OF`, so order carries no meaning and a type may
  repeat. Type 17 repeats once per in-app purchase.
- `value` is an OCTET STRING whose contents are themselves DER. The
  per-attribute "value type" columns below say what is inside that OCTET
  STRING, not what the attribute is.
- `version` is in every attribute and Apple never says what it means. Every
  attribute in the fixture corpus is version 1 except app-level type 4
  (opaque value), which is version 2 in both genuine sandbox receipts. This
  library ignores the field (`ReceiptVerifier.java:754-756` reads index 0 and
  index 2 of the SEQUENCE and never index 1).

## App-level attribute types

"Apple" cites the archived
[Receipt Fields](https://developer.apple.com/library/archive/releasenotes/General/ValidateAppStoreReceipt/Chapters/ReceiptFields.html)
chapter. "Seen" is what the fixture measurement below found. "Modelled" names
the accessor on `AppReceipt`; blank means the value is reachable only through
`AppReceipt.unknownAttributes()` (`receipt/AppReceipt.java:122`).

| Type | Name | Value type | Apple | Seen in fixtures | Modelled as | Notes and source |
|---|---|---|---|---|---|---|
| 0 | receipt type / environment | UTF8String | no | all 5 | `receiptType()` (`AppReceipt.java:59`) | `"ProductionSandbox"` in both genuine receipts, `"Xcode"` in all three Xcode ones. Named `environment` by TPInAppReceipt, `FT_STAGE` by SilentCircle. `verifyReceipt` responses carry this as the JSON key `receipt_type`; Apple's reference page for the response body is retired and returns 404, and no Apple page ever gave the ASN.1 number. The 21007/21008 routing in `VerifyReceiptEndpoint.java:199` needs the value, which is why this library decodes it. |
| 1 | app Apple ID (adam id) | INTEGER | no | all 5 | | Always `0` in the corpus, which is what Apple says `adam_id` and `app_item_id` are in the sandbox. Named `appStoreID` by TPInAppReceipt. Value 0 everywhere means the corpus cannot distinguish this from types 11, 15 and 16. |
| 2 | bundle identifier | UTF8String | **yes** | all 5 | `bundleId()` + `bundleIdBytes()` (`AppReceipt.java:68`, `:73`) | Raw bytes kept separately because the type 5 hash is over them, not over the decoded string. |
| 3 | app version | UTF8String | **yes** | all 5 | `appVersion()` (`AppReceipt.java:77`) | Decoded, never compared. See "Apple step 4" below. |
| 4 | opaque value | raw bytes | **yes** | all 5 | `opaqueValue()` (`AppReceipt.java:82`) | 16 bytes in the genuine receipts, 8 in the Xcode ones. The only attribute in the corpus at `version 2`. |
| 5 | SHA-1 hash | 20 raw bytes | **yes** | all 5 | `sha1Hash()` (`AppReceipt.java:87`) | 20 bytes in all five. |
| 6 | unknown | raw bytes, no DER tag | no | genuine only | | 55 bytes (g5) and 71 bytes (legacy), no recognisable structure. TPInAppReceipt: "reserved for future use". Absent from Xcode receipts. |
| 7 | unknown | raw bytes, no DER tag | no | genuine only | | 54 bytes (g5) and 72 bytes (legacy). Same status as 6. |
| 8 | transaction date | IA5String | no | all 5 | | Empty string in all five receipts, so the corpus confirms the type exists and says nothing about its contents. Named `transactionDate` by TPInAppReceipt. |
| 9 | fulfillment tool version | INTEGER | no | genuine only | | The integer's big-endian bytes are ASCII: `0x50333035` = `"P305"` (g5), `0x50323533` = `"P253"` (legacy). That is a version string smuggled through an INTEGER, which corroborates TPInAppReceipt's `fulfillmentToolVersion` and rules out the "app Apple ID" reading that the decimal value (1345531957) invites. |
| 10 | age rating | IA5String | no | genuine only | | `"4+"` in both genuine receipts, which is literally an App Store age rating. Confirms TPInAppReceipt's `ageRating`. |
| 11 | developer id | INTEGER | no | genuine only | | `0` in both. Name from TPInAppReceipt, unverifiable against this corpus. |
| 12 | receipt creation date | IA5String, RFC 3339 | **yes** | all 5 | `creationDate()` (`AppReceipt.java:92`) | The instant the certificate chain is checked at. See the chain-of-trust table. |
| 13 | unknown | INTEGER | no | genuine only | | `180602` (g5, receipt created 2025-12-26) and `130401` (legacy, 2020-05-06). Monotonic with receipt age, so plausibly a build or tool revision. TPInAppReceipt: "reserved for future use". |
| 14 | unknown | INTEGER | no | genuine only | | `229` (g5) and `162` (legacy). Same shape as 13. |
| 15 | download id | INTEGER | no | genuine only | | `0` in both. Name from TPInAppReceipt. |
| 16 | installer version id | INTEGER | no | genuine only | | `0` in both. Name from TPInAppReceipt. |
| 17 | in-app purchase receipt | SET OF ReceiptAttribute | **yes** | 4 of 5 | `inAppPurchases()` (`AppReceipt.java:106`) | Repeats once per purchase: 2 in g5, 187 in legacy, 1 in the Xcode receipts with a transaction, 0 in `xcode-app-receipt-empty`. |
| 18 | original purchase date | IA5String, RFC 3339 | no | genuine only | `originalPurchaseDate()` (`AppReceipt.java:64`) | `"2013-08-01T07:00:00Z"` in both genuine receipts, which is the sandbox placeholder Apple has used for years. `verifyReceipt` responses carry an app-level `original_purchase_date` alongside the in-app one that Apple does number (1706); only the in-app number was ever published. SilentCircle names type 18 `FT_ORIGINAL_PURCHASE_DATE`, TPInAppReceipt `originalAppPurchaseDate`. |
| 19 | original app version | UTF8String | **yes** | genuine only | `originalAppVersion()` (`AppReceipt.java:97`) | `"1.0"` in both genuine receipts. |
| 20 | unknown | UTF8String | no | genuine only | | Empty string in both. TPInAppReceipt: "reserved for future use". |
| 21 | receipt expiration date | IA5String, RFC 3339 | **yes** | Xcode only | `expirationDate()` (`AppReceipt.java:102`) | `"4001-01-01T00:00:00Z"` in the Xcode receipts. Apple says this is for Volume Purchase Program receipts; neither genuine sandbox receipt carries it. |
| 25 | unknown | INTEGER | no | genuine only | | `3` in both. TPInAppReceipt: "reserved for future use". |

Types 22, 23 and 24 appear in no source and in no fixture.

## In-app attribute types (inside type 17)

"Modelled" names the accessor on `InAppPurchase`; blank means the value is
reachable only through `InAppPurchase.unknownAttributes()`
(`receipt/InAppPurchase.java:104`).

| Type | Name | Value type | Apple | Seen in fixtures | Modelled as | Notes and source |
|---|---|---|---|---|---|---|
| 1701 | quantity | INTEGER | **yes** | all | `quantity()` (`InAppPurchase.java:55`) | |
| 1702 | product identifier | UTF8String | **yes** | all | `productId()` (`InAppPurchase.java:59`) | |
| 1703 | transaction identifier | UTF8String | **yes** | all | `transactionId()` (`InAppPurchase.java:63`) | |
| 1704 | purchase date | IA5String, RFC 3339 | **yes** | all | `purchaseDate()` (`InAppPurchase.java:71`) | |
| 1705 | original transaction identifier | UTF8String | **yes** | genuine | `originalTransactionId()` (`InAppPurchase.java:67`) | |
| 1706 | original purchase date | IA5String, RFC 3339 | **yes** | genuine | `originalPurchaseDate()` (`InAppPurchase.java:75`) | |
| 1707 | product type | INTEGER | no | genuine | | `3` on every one of the 189 genuine in-app entries, all of which are auto-renewable subscriptions. Named `productType` by TPInAppReceipt. The corpus contains no non-subscription purchase, so it shows the type exists and pins one value to one product kind, nothing more. |
| 1708 | subscription expiration date | IA5String, RFC 3339 | **yes** | all | `expiresDate()` (`InAppPurchase.java:80`) | |
| 1709 | unknown | UTF8String | no | genuine | | Empty string throughout. |
| 1710 | unknown | INTEGER | no | genuine | | `0` throughout. |
| 1711 | web order line item id | INTEGER | **yes** | genuine | `webOrderLineItemId()` (`InAppPurchase.java:89`) | |
| 1712 | cancellation date | IA5String, RFC 3339 | **yes** | genuine | `cancellationDate()` (`InAppPurchase.java:85`) | Empty string throughout the corpus, which is how an absent date is encoded. `ReceiptVerifier.java:814-818` maps the empty string to null for exactly this. |
| 1713 | is_trial_period | INTEGER | no | genuine | | **The best candidate to model.** Apple's Receipt Fields chapter documents "Subscription Trial Period", JSON key `is_trial_period`, with "ASN.1 Field Type (none)" written out. TPInAppReceipt names 1713 `subscriptionTrialPeriod`. It is present on all 189 genuine in-app entries, value `0`, sitting immediately beside 1712 and 1719 whose numbers Apple does confirm. |
| 1714 | unknown | UTF8String | no | genuine | | Empty string throughout. |
| 1715 | unknown | UTF8String | no | genuine | | Empty string throughout. |
| 1716 | unknown | UTF8String | no | genuine | | Empty string throughout. |
| 1717 | unknown | UTF8String | no | genuine | | Empty string throughout. |
| 1718 | unknown | UTF8String | no | genuine | | Empty string throughout. |
| 1719 | is_in_intro_offer_period | INTEGER | **yes** | all | `isInIntroOfferPeriod()` (`InAppPurchase.java:93`) | `1` in the Xcode receipts, `0` in the genuine ones. |
| 1721 | promotional offer identifier | UTF8String | no | **no** | | Named by TPInAppReceipt. Absent from every fixture, so this repository has no evidence for it either way. The Apple Developer Forums thread asking for the ASN.1 number of `offer_code_ref_name` (thread 730612) went unanswered. |
| 1722 | unknown | INTEGER | no | g5 only | | `0` on both g5 entries, absent from the 2020 legacy receipt, so it is a type Apple added between 2020 and 2025. |

Type 1720 appears in no source and in no fixture. The list of candidate
types this audit was asked to check also included 1720 and 1721 at the in-app
level and nothing above 25 at the app level; 1720 could not be corroborated
anywhere.

## Why 0 and 18 are undocumented

Both are values Apple's own `verifyReceipt` response returned, as
`receipt_type` and an app-level `original_purchase_date`, and neither was
ever given an ASN.1 number. The withholding is deliberate, not an oversight,
and the archived Receipt Fields chapter shows it directly: its tables have an
explicit "ASN.1 Field Type" row, and it prints `(none)` there for several
keys: `App Item ID`, `External Version Identifier` and `Subscription Trial
Period` among them. The last of those is the clearest case, because it
describes a per-transaction flag that has to come from somewhere in the
signed bytes, and the community places it at type 1713. The operational rule
Apple leaves in place is the one the objc.io walkthrough states: "you may
also find unlisted attributes while parsing a receipt, but it's best to
simply ignore them".

So the community numbers were not leaked, they were diffed: run a receipt
through `verifyReceipt`, compare the JSON Apple returns against the ASN.1
types present in the same bytes, and the correspondence falls out. That is
how independent libraries in different languages arrived at the same map.
Two of them agreeing on 0 and 18 is the evidence this library relies on, and
it is why those two are decoded while the rest are left as bytes: the
`verifyReceipt`-compatible endpoint has to emit `receipt_type` and
`original_purchase_date`, and it has to route 21007/21008 on the former.

Apple has published no new receipt attribute type since the 2017-12-11
revision. Everything added to in-app purchasing after that date (offer codes,
promotional offers, win-back offers) arrived in StoreKit 2 JWS payloads
instead, which this repository verifies on the other code path. Type 1722,
present in the 2025 receipt and absent from the 2020 one, is the only sign in
this corpus that the receipt format itself still moves.

## What was measured, and how

Source receipts, all of them genuine Apple-signed or Xcode-signed bytes
already in the repository:

| Fixture | Signer | Receipt created | Chain |
|---|---|---|---|
| `fixtures/public-receipts/receipt-sandbox-g5.b64` | Apple | 2025-12-26 | WWDR G5, SHA-256 |
| `fixtures/public-receipts/receipt-sandbox-legacy.b64` | Apple | 2020-05-06 | WWDR G1, SHA-1 |
| `fixtures/public-receipts/receipt-xcode-with-purchases.b64` | Xcode, local | 2023-10-19 | not Apple's |
| `fixtures/apple-official/xcode/xcode-app-receipt-empty` | Xcode, local | 2023-10-19 | not Apple's |
| `fixtures/apple-official/xcode/xcode-app-receipt-with-transaction` | Xcode, local | 2023-10-19 | not Apple's |

See `fixtures/public-receipts/README.md` and
`fixtures/apple-official/README.md` for provenance and licensing. The three
Xcode receipts are in the corpus to prove that pinning rejects them; their
payloads are still real receipt payloads and are counted here.

Method: base64-decode, pull the encapsulated payload out of the CMS
(`openssl cms -verify -noverify -inform DER` for the two BER
indefinite-length Xcode blobs, direct DER walk for the rest), then parse
`SET OF SEQUENCE { INTEGER type, INTEGER version, OCTET STRING value }` and
print every type with its length and, where the value is itself DER, its
decoded form. No attribute was skipped and no type was inferred from a name.

## Chain of trust: Apple's procedure against this implementation

Apple's five steps are from "Validating the receipt" and "Verify the
certificate chain of trust" on the page quoted above. Line numbers are in
`java/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/`.

| Apple's step | This implementation | Verdict |
|---|---|---|
| 1. Locate and load the receipt from the app bundle | Out of scope: the receipt arrives as an argument. `receipt/ReceiptVerifier.java:211-255` takes base64 or DER, with a size ceiling checked before any decode (`:167`, `:223`, `:283`). | Not applicable server-side |
| 2a. Decode as a PKCS#7 container | `receipt/ReceiptVerifier.java:307` rejects trailing bytes, `:312-321` parses the CMS and requires an encapsulated payload. | Matches, stricter on trailing bytes |
| 2b. Trace the chain to the Apple Inc. Root certificate | `receipt/ReceiptVerifier.java:346-465` PKIX-builds signer to pinned anchor; anchors are the three Apple roots, fingerprint-pinned at `AppleRootCerts.java:48-52`. | Matches |
| 2c. Use the receipt creation date (type 12) for signature validation | `receipt/ReceiptVerifier.java:333` computes `at` from `creationDate()`, `:335` passes it to the chain check, `:448` sets it as the PKIX validity instant. No clock seam exists for it, deliberately (`:174-185`). | Matches |
| 2d. Do not hardcode intermediates | The certificate store handed to the builder is built only from the certificates embedded in the receipt (`receipt/ReceiptVerifier.java:439-446`). There is no intermediate store, bundled or system. | Matches |
| 2e. Support SHA-256 and SHA-1 signing | `receipt/ReceiptVerifier.java:527-532` accepts digest OIDs `1.3.14.3.2.26` (SHA-1) and `2.16.840.1.101.3.4.2.1` (SHA-256), and nothing else. Certificate signature algorithms are the JDK's business; `java/README.md` "One platform caveat worth knowing" records what a JVM policy that bans SHA-1 outright does to genuine legacy receipts. | Matches, stricter (an allow-list of two) |
| 3. Verify the bundle identifier (type 2) against your app's | `receipt/ReceiptVerifier.java:246-250`, against the bundle id the verifier was constructed with. `verifyReceiptCore` (`:273`) deliberately omits it and says so. | Matches |
| 4. Verify the version identifier (type 3) against your app's | **Not performed.** Type 3 is decoded and exposed (`receipt/AppReceipt.java:77`) but never compared, and no constructor takes an expected version. | Deviates, see below |
| 5. Compute SHA-1(device GUID, opaque value, bundle id bytes) and compare with type 5 | `receipt/ReceiptVerifier.java:546-563`, constant-time via `MessageDigest.isEqual`. Optional: omitting `deviceGuid` skips it. | Matches when used, optional by design |
| (beyond Apple) signer purpose | `receipt/ReceiptVerifier.java:336-340` requires the Apple receipt-signing marker OID `1.2.840.113635.100.6.11.1` on the leaf. Apple's procedure does not ask for this; without it any Apple developer certificate chaining through the same WWDR intermediate could sign a forged receipt. | Stricter than Apple |

### Step 4, stated plainly

Apple's step 4 is not implemented in any of the nine ports. On a server the
check is weaker than it is on-device: the server cannot see which binary is
running, so the only version it could compare against is one the client
supplies, which an attacker supplies too. What the check buys on-device, and
what is therefore absent here, is rejection of a receipt harvested from a
different version of the same app, for example one issued to a free or
TestFlight build. The bundle id check (step 3) and, when the caller supplies
a GUID, the device binding (step 5) both still hold, so a receipt is still
bound to this app and optionally to one device.

A caller that needs the check can do it: `AppReceipt.appVersion()` returns
the decoded type 3 value. This is a caller responsibility that no document in
the repository currently names, which is the actual gap.

### The expired-intermediate case, measured

Apple's warning is that "if the receipt was signed with a valid certificate,
but the certificate has since expired, using the device's current date
incorrectly returns an invalid result". Both genuine receipts in this
repository are now in exactly that state:

| Fixture | Leaf validity | Intermediate validity | Receipt creation date |
|---|---|---|---|
| `receipt-sandbox-legacy` | 2015-11-13 to 2023-02-07 | WWDR G1, 2013-02-07 to 2023-02-07 | 2020-05-06 |
| `receipt-sandbox-g5` | 2024-07-24 to 2026-08-23 | WWDR G5, 2020-12-16 to 2030-12-10 | 2025-12-26 |

Every certificate in the legacy chain below the root expired on 2023-02-07,
and the g5 leaf expired on 2026-08-23. Both receipts are expected to verify,
in `fixtures/cases.json` cases `receipt/verify-genuine-legacy-sha1-chain` and
`receipt/verify-genuine-sandbox-g5-against-apple-roots`, and neither case
pins a clock. A port that checked validity at verification time would fail
both. The synthetic pair
`receipt/accept-historical-creation-date-under-expired-chain` and
`receipt/reject-fresh-creation-date-under-expired-chain` covers the same rule
in both directions without depending on wall-clock time.

### Root pinning, verified against Apple

Downloaded from Apple PKI on 2026-09-21 and compared with the bundled
resources under
`java/src/main/resources/io/github/emindeniz99/applepurchasereceiptverifier/certs/`:

| Root | SHA-256 | Bundled file |
|---|---|---|
| Apple Inc. Root | `b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024` | byte-identical |
| Apple Root CA - G2 | `c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050` | byte-identical |
| Apple Root CA - G3 | `63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179` | byte-identical |

All three match the fingerprints pinned in `AppleRootCerts.java:48-52`. Apple
publishes the certificates themselves, not fingerprints, so the comparison is
over the DER.

## Sources

Apple, read 2026-09-21:

- [Validating receipts on the device](https://developer.apple.com/documentation/appstorereceipts/validating-receipts-on-the-device).
  The ASN.1 module, the five validation steps, and the "Verify the
  certificate chain of trust" section. The page is a DocC application; its
  content is served as JSON at
  `https://developer.apple.com/tutorials/data/documentation/appstorereceipts/validating-receipts-on-the-device.json`.
- [Receipt Fields](https://developer.apple.com/library/archive/releasenotes/General/ValidateAppStoreReceipt/Chapters/ReceiptFields.html),
  archived, last revised 2017-12-11. App-level types 2, 3, 4, 5, 12, 17, 19,
  21; in-app types 1701 to 1706, 1708, 1711, 1712, 1719. In-app section
  anchor `TP40010573-CH106-SW12`; the `is_trial_period` entry with its
  explicit "ASN.1 Field Type (none)" is anchor `TP40010573-CH106-SW25`.
- [Apple PKI](https://www.apple.com/certificateauthority/). Root and WWDR
  intermediate certificates.

Community, read 2026-09-21:

- [tikhop/TPInAppReceipt](https://github.com/tikhop/TPInAppReceipt),
  `Sources/Core/AppReceiptField.swift`. The fullest published enumeration:
  app-level 0 to 21 plus 25, in-app 1701 to 1719 plus 1721 and 1722, with
  "reserved for future use" on the ones it will not name. MIT. The same
  project's test assets are where two of this repository's genuine receipts
  come from.
- [SilentCircle/iap-local-receipt](https://github.com/SilentCircle/iap-local-receipt),
  `iap_local_receipt/iap_receipt_parser.py`. Independent Python
  implementation naming type 0 `FT_STAGE` and type 18
  `FT_ORIGINAL_PURCHASE_DATE`, the second source for the two types this
  library decodes beyond Apple's list.
- [Receipt Validation, objc.io](https://www.objc.io/issues/17-security/receipt-validation/).
  Walkthrough covering types 2, 3, 4, 5 and 21, and the source of the
  "ignore unlisted attributes" rule.
- [Poking Around in Mac App Store Receipts](http://magervalp.github.io/2013/03/19/poking-around-in-masreceipts.html),
  2013. Early reverse-engineering of the opaque value.
- [Validating App Store Receipts without verifyReceipt, RevenueCat](https://www.revenuecat.com/blog/engineering/validating-app-store-receipts).
  Covers the documented types only; useful as a check that a widely-read
  write-up adds nothing beyond Apple's list.
- [Verifying Apple's Signed Receipts](https://nick.zoic.org/art/apple-signed-receipt-verification-pkcs7/).
  PKCS#7 mechanics. Consulted for attribute numbers and carries none, so it
  is listed as checked rather than as a source.
- Apple Developer Forums
  [thread 730612](https://developer.apple.com/forums/thread/730612), asking
  for the ASN.1 type of `offer_code_ref_name` and of `receipt_type`.
  Unanswered, which is the state of Apple's position on the undocumented
  numbers.
