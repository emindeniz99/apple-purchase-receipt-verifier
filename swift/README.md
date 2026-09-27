# apple-purchase-receipt-verifier (Swift)

Verify Apple in-app purchases locally: no calls to Apple's servers. Checks a
StoreKit 2 signed JWS or a legacy PKCS#7 app receipt against pinned Apple root
certificates and hands back what Apple signed.

This is a verifier, not business logic. It answers one question: did Apple
sign this data? If so, it returns the data, unfiltered by bundle id,
environment or product. Every policy decision (bundle id, environment,
product id, device binding, refunds, idempotency) is yours; see
[What to check after verification](#what-to-check-after-verification).

```swift
// The manifest lives at the repository root (SwiftPM resolves a package's
// manifest only there); the sources stay under swift/.
.package(url: "https://github.com/emindeniz99/apple-purchase-receipt-verifier.git", from: "0.6.0")
```

Swift **6.1** or newer, macOS 13+ or Linux (`Package.swift` declares
`.macOS(.v13)`). Coming from 0.6? Read
[Upgrading from 0.6](#upgrading-from-06): the API is smaller, synchronous,
and every type name has changed.

## Quick start

```swift
import ApplePurchaseReceiptVerifier

// Build once, at startup, and share it: Verifier is immutable and Sendable.
let verifier = Verifier(config: .defaults())

// A legacy PKCS#7 app receipt, as StoreKit hands it to the app.
let receiptResult = verifier.verifyReceipt(base64: receiptBase64)
if let receipt = receiptResult.payload {
    print(receipt.bundleId ?? "", receipt.inApp.count)
} else if let failure = receiptResult.failure {
    print("\(failure.reason): \(failure.message)")
}

// A StoreKit 2 signed transaction, renewal info, app transaction or notification.
let jwsResult = verifier.verifySignedData(jws: jws)
if let payload = jwsResult.payload {
    let json = payload.json  // parse it yourself, see below
}

// The deprecated verifyReceipt HTTP contract, answered locally.
let responseJson = verifier.verifyReceiptEndpoint(environment: .production, requestJson: requestJson)
```

**No method throws for any input.** An empty `base64` / `jws` / `requestJson`
is input and fails as `Reason.malformed`, the same as a garbled one. An
unexpected error inside the library is reported by where it happened: before
a signature has verified it is `.malformed` (input nobody vouched for must
not be able to raise the internal-error alarm at will), while the signed
receipt content is decoded `.unreadablePayload`, and anywhere else
`.internalError`. Swift has no equivalent of Java's `catch (Throwable)` or
Rust's `catch_unwind`: an out-of-bounds access or a forced unwrap traps and
cannot be recovered from, in this library or any other. This containment
comes from bounds-checked parsing throughout (`throw`, never a force-unwrap
or an array index that can go out of range on unverified input), not from a
runtime safety net that could catch a trap after the fact.

**A custom clock**, for tests or for pinning `request_date`:

```swift
let config = try Config.builder().clock { 1_735_689_600_000 }.build()  // 2025-01-01T00:00:00Z
let verifier = Verifier(config: config)
```

`Config.defaults()` uses Apple's three bundled, pinned roots and the system
clock. The clock is read at most once per call, only when one of exactly two
things needs it, after the input has passed every check that comes before:
the chain-validity instant when the receipt or JWS states no signing date of
its own, and `request_date` in the endpoint response. It never decides
whether a certificate is expired when the input states a date; see
[Trust anchors](#trust-anchors).

`Config.defaults()` cannot report a failure (there is nothing to throw to):
should the bundled roots fail to load or match their pinned SHA-256
fingerprints, it silently hands back an empty root set, and every
`Verifier` call built from it then answers `.internalError`, never a
misleading `.untrustedChain`, rather than crashing at startup. Building a
`Config` explicitly through `Config.builder()...build()` DOES throw
`ConfigError` for an empty root set, since a verifier with no roots would
otherwise answer `.untrustedChain` to everything and nobody would notice
until production.

## Which method to call

| You have | Call |
|---|---|
| `receipt-data` from `SKReceiptRefreshRequest` or the app bundle | `verifyReceipt(base64:)` |
| A StoreKit 2 `Transaction.jwsRepresentation`, `signedTransactionInfo`, `signedRenewalInfo`, `AppTransaction.jwsRepresentation`, or a nested notification JWS | `verifySignedData(jws:)` |
| A `verifyReceipt` HTTP request body, from a client that still POSTs one | `verifyReceiptEndpoint(environment:requestJson:)` |

## What to check after verification

The library verifies; it does not decide. After a call returns a payload,
check, in your own code:

- **Bundle id**: `receipt.bundleId` / the JWS payload's `bundleId` claim
  equals your app's bundle identifier.
- **Environment**: `Environment.fromReceiptType(receipt.receiptType)` or
  `Environment.fromJwsEnvironment(claims["environment"])` is the one you
  expect (a sandbox receipt reaching a production server is not
  automatically wrong, but your policy should say what to do with it).
- **Product id**: the transaction is for a product you sell.
- **Idempotency**: `transactionId` (JWS) or each in-app purchase's
  `transactionId` (receipt) has not been applied before; verifying the same
  receipt twice must not grant the purchase twice.

## The device-hash example

A legacy receipt's attribute 5 (`sha1Hash`) is Apple's device-binding hash:
`SHA1(deviceId ‖ opaqueValue ‖ bundleIdBytes)`. The library takes no device
id parameter; the check is yours to run, in constant time, on the fields it
returns:

```swift
import Crypto

func deviceHashMatches(_ receipt: ReceiptPayload, deviceId: [UInt8]) -> Bool {
    guard let opaque = receipt.opaqueValue, let bundleBytes = receipt.bundleIdBytes,
        let expected = receipt.sha1Hash
    else { return false }
    var input: [UInt8] = deviceId
    input.append(contentsOf: opaque)
    input.append(contentsOf: bundleBytes)
    let computed = Array(Insecure.SHA1.hash(data: input))
    guard computed.count == expected.count else { return false }
    // Constant-time comparison.
    var diff: UInt8 = 0
    for i in 0..<computed.count { diff |= computed[i] ^ expected[i] }
    return diff == 0
}
```

## App Store Server Notifications V2

Apple POSTs `{"signedPayload": "<JWS>"}`. Verify the outer JWS, then each
nested `signedTransactionInfo` and `signedRenewalInfo` it carries:

```swift
struct NotificationEnvelope: Decodable {
    let notificationType: String
    let data: Payload?
    struct Payload: Decodable {
        let signedTransactionInfo: String?
        let signedRenewalInfo: String?
    }
}

let outer = verifier.verifySignedData(jws: signedPayload)
guard let outerPayload = outer.payload,
    let envelope = try? JSONDecoder().decode(NotificationEnvelope.self, from: Data(outerPayload.json.utf8))
else { return }

if let signedTransactionInfo = envelope.data?.signedTransactionInfo {
    let transaction = verifier.verifySignedData(jws: signedTransactionInfo)
    // ...
}
if let signedRenewalInfo = envelope.data?.signedRenewalInfo {
    let renewal = verifier.verifySignedData(jws: signedRenewalInfo)
    // ...
}
// A TEST notification carries neither: envelope.data is absent.
```

## Deserialising a JWS payload

The library ships no typed JWS models: `verifySignedData(jws:)` returns the
verified JSON text unchanged (`JsonPayload.json`), and Apple's claims are
epoch milliseconds already. Declare a `Decodable` struct for the fields you
use:

```swift
struct TransactionInfo: Decodable {
    let bundleId: String?
    let productId: String?
    let transactionId: String?
    let purchaseDate: Int64?
    let expiresDate: Int64?
    let environment: String?
}

let info = try JSONDecoder().decode(TransactionInfo.self, from: Data(payload.json.utf8))
```

## The verifyReceipt-compatible endpoint

`verifyReceiptEndpoint(environment:requestJson:)` answers the response body
Apple's deprecated `verifyReceipt` would, verified offline against the
pinned roots instead of by calling Apple. It never fails: every verdict is
the `status` field inside the body:

| Verification outcome | `status` |
|---|---|
| verified, environment matches | 0 |
| verified, sandbox receipt on `.production` | 21007 |
| verified, production receipt on `.sandbox` | 21008 |
| `.malformed`, `.tooLarge` | 21002 |
| `.invalidSignature`, `.untrustedChain`, `.invalidCertificate`, `.invalidCertificatePurpose` | 21003 |
| `.unreadablePayload`, `.internalError` | 21009 |

Both 21009 cases are deterministic for the same input: alert on 21009,
never retry it. `AppleStatus` names every status code Apple documents, so
callers do not write `21007` by hand.

**Framework request bodies.** If your web framework already parses
`application/x-www-form-urlencoded` or multipart bodies before your handler
runs, `requestJson` must be the RAW JSON body, not a re-serialized form.
Rebuilding the body from parsed fields can reorder or drop bytes the
signature-adjacent JSON reader (member-name length, duplicate-key-wins)
treats as significant. Read the raw body in your route handler and pass it
through unchanged.

`password` and `exclude-old-transactions` are read and ignored, as Apple's
own endpoint behaviour is understood today (see the root README's
COMPARISON.md).

## Decoding a receipt

`ReceiptPayload` fields follow Apple's own verifyReceipt vocabulary
(`bundleId`, `applicationVersion`, `inApp`, …), one struct per receipt, one
`InAppPurchase` per attribute-17 entry. Rules, pinned by the shared
conformance vectors:

- A missing attribute decodes to `nil`. The library invents no values.
- Dates are `Int64` epoch milliseconds, UTC. A receipt date parses only in
  the exact form `YYYY-MM-DDTHH:MM:SSZ`; anything else is `nil` and the raw
  bytes are kept in `unknownAttributes`.
- The trial and intro-offer flags are `Bool`: `0` is `false`, any other
  value `true`.
- `bundleIdBytes`, `opaqueValue` and `sha1Hash` are the attribute value
  octets exactly as they sit in the receipt, the device-hash formula's
  input above.
- A known attribute that appears more than once: the FIRST occurrence wins,
  for the typed field and for the chain-validity date. This holds at the top
  level and inside each in-app purchase.
- Nothing Apple signed is lost: every attribute that does not end up in a
  typed field (an unmodelled type, a later copy of a known attribute, or a
  known attribute whose value does not parse) goes raw into
  `unknownAttributes`, keyed by attribute type.
- `receipt.toJson()` writes the payload with Foundation's
  `JSONSerialization`: `null` for a missing field, 64-bit ids as JSON
  strings (a `downloadId` can run to 18 digits, above `2^53`), bytes as
  padded standard base64. The shared conformance vectors compare its parsed
  value, not its bytes, so key order and escaping are not part of the
  contract.

## Trust anchors

`Config.defaults()` embeds Apple's three published roots (Apple Inc. Root
CA, Apple Root CA - G2, Apple Root CA - G3), each checked against its
published SHA-256 when loaded. No code path in this library reads the
operating system's trust store, a distribution CA bundle, or anything
downloaded. The only anchors are the bundled ones, or the ones a caller
supplies through `Config.builder().roots(...)`.

The chain is walked top-down: from a pinned root outward, a certificate's
signature is checked only once the key that will verify it has already been
vouched for, directly or transitively, by a pinned root. A certificate no
root vouches for, including one carrying a deliberately oversized or
unusable key, is never decoded into a usable key and never has its
signature checked; it is simply excluded from the path. A certificate on the
resulting path is then checked for validity at the chain instant, and last
for Apple's marker OIDs (the receipt-signing / WWDR OIDs on the receipt
path, the same pair on the JWS `x5c` chain).

## Resource bounds

| Bound | Value |
|---|---|
| Receipt base64, UTF-8 bytes | 3,145,728 |
| Endpoint request body, UTF-8 bytes | 3,145,728 |
| JWS, UTF-8 bytes | 262,144 |
| JSON nesting depth | 64 |
| JSON member name, characters | 50,000 |
| JSON number, digits | 1,000 |
| Certificates embedded in a receipt | 10 |
| Chain length (below the anchor) | 6 |
| SignerInfos in a receipt | 4 |
| ASN.1 nesting depth (CMS envelope, signed content) | 32 |

The ASN.1 depth is checked on the encoding by this library before
`swift-asn1` parses it, because `swift-asn1`'s own bound (about 49 values)
is looser. Past 32, the envelope is `MALFORMED` and the signed content
`UNREADABLE_PAYLOAD`. Genuine Apple receipts nest 9 levels deep in the
envelope.

## Measured worst-case CPU

Measured on 2026-09-27 with `bench --worst-case`, which times every shared
case in `fixtures/cases-0.7.json` that carries a time budget: oversized
untrusted keys, a cross-signed certificate mesh, and the encoding oddities
inside certificates. Swift 6.3.3, release build, one thread, on a shared
4-vCPU KVM guest (Intel Xeon Processor @ 2.10GHz); one second of warm-up,
then ten samples of at least 100 ms each.

| Call | Median | Slowest sample |
|---|---:|---:|
| Slowest hostile case: `signed-data/reject-untrusted-oversized-x5c` (a JWS near the 256 KiB cap) | 2.5 ms | 2.5 ms |
| Slowest hostile receipt: `receipt/verify-genuine-padded-with-oversized-strangers` | 0.64 ms | 0.76 ms |
| Every other budgeted case | under 0.41 ms | under 0.55 ms |
| For scale: `verifyReceipt` on the genuine 187-purchase legacy receipt | 7.2 ms | 8.1 ms |
| For scale: `verifyReceiptEndpoint` on the same receipt | 13.4 ms | 14.3 ms |

No hostile input in the shared suite costs more than an ordinary large
receipt: the cost of a call follows the size of the input, which the caps
above bound, not the structure an attacker chooses. The machine was shared
with other work, so treat these as an order of magnitude. Run
`swift run -c release --package-path swift/bench bench --worst-case` for
numbers on your own hardware.

## Thread safety

`Config`, `Verifier`, `ReceiptPayload`, `JsonPayload`, `VerificationResult`
and `Failure` are all `Sendable`. Build one `Verifier` and share it across
every request; nothing about a call mutates shared state.

## Upgrading from 0.6

0.6's `ReceiptVerifier`, `JwsVerifier` and `VerifyReceiptEndpoint` are gone,
replaced by one `Verifier` with three methods. Every method is now
**synchronous** (0.6's were `async throws`, because `swift-certificates`'
built-in chain validator is `async`; 0.7 walks the chain itself). The bundle
id, accepted-environment set, `appAppleId` and device-guid parameters are
gone. The library returns the data, and you compare it yourself (see
[What to check after verification](#what-to-check-after-verification) and
[The device-hash example](#the-device-hash-example)).

| 0.6 | 0.7 |
|---|---|
| `ReceiptVerifier(trustedRoots:bundleId:)` | `Verifier(config:)`, compare `bundleId` yourself |
| `try await receiptVerifier.verify(base64Receipt:deviceGuid:)` | `verifier.verifyReceipt(base64:)` (never throws) |
| `AppReceipt` | `ReceiptPayload` (dates are `Int64` ms, not `Date`) |
| `JwsVerifier(trustedRoots:bundleId:acceptedEnvironments:appAppleId:)` | `Verifier(config:)` |
| `try await jwsVerifier.verifyTransaction(_:)` / `.verifyAppTransaction(_:)` / `.verifyRaw(_:)` | `verifier.verifySignedData(jws:)` for all of them (returns untyped JSON; deserialise it yourself) |
| `VerificationError` (thrown) | `Failure` (returned inside `VerificationResult`, never thrown) |
| `VerifyReceiptEndpoint(trustedRoots:environment:clock:)` | `Verifier(config:)`, pass `environment` per call |
| `.verifyReceiptResult(_:)` / `.verifyReceiptJSON(_:)` | `verifier.verifyReceiptEndpoint(environment:requestJson:)` |
| `appleReceiptRoots()` / `appleJwsRoots()` | `Config.defaults()` (one root set for both) |
| n/a | `Reason.invalidCertificatePurpose` split out from the old `INVALID_CERTIFICATE_PURPOSE`-shaped failures; `Reason.unreadablePayload` split out from `INTERNAL_ERROR` for a payload Apple signed but this library cannot parse |

## Licence

See the repository root.
