# apple-purchase-receipt-verifier (Swift)

Verify Apple in-app purchases locally — no calls to Apple's servers.

Replaces the deprecated `verifyReceipt` endpoint by validating StoreKit 2
signed JWS transactions and legacy PKCS#7 app receipts against pinned Apple
root certificates.

```swift
// v0.3.0 is the newest tag; check the project README's badge for the current one
.package(url: "https://github.com/emindeniz99/apple-purchase-receipt-verifier.git", from: "0.3.0")
```

```swift
import ApplePurchaseReceiptVerifier

// Legacy PKCS#7 app receipt
let receipts = try ReceiptVerifier(trustedRoots: appleReceiptRoots(), bundleId: "com.example.app")
let receipt = try await receipts.verify(base64Receipt: receiptBase64)
print(receipt.receiptType ?? "", receipt.inAppPurchases.count)

// StoreKit 2 signed transaction
let transactions = try JwsVerifier(
    trustedRoots: appleJwsRoots(), bundleId: "com.example.app",
    acceptedEnvironments: [.production, .sandbox])
let transaction = try await transactions.verifyTransaction(jws)
print(transaction.productId ?? "", transaction.expiresDate ?? 0)
```

Swift **6.1** or newer, macOS 13+ or Linux (`Package.swift` declares
`.macOS(.v13)`; CI runs the suite on Swift 6.1, 6.2 and 6.3, each on Linux).
The manifest lives at the repository root — SwiftPM resolves a package's
manifest only there — while the sources themselves stay under `swift/`.

Every type is `Sendable`, and every verification method is `async throws`,
because `swift-certificates`' chain validation is an `async` method. Share
one instance of each verifier across requests; see
[Thread safety](#thread-safety).

## The three JWS entry points

```swift
let verifier = try JwsVerifier(
    trustedRoots: appleJwsRoots(),
    bundleId: "com.example.app",
    acceptedEnvironments: [.production, .sandbox],
    appAppleId: 1_234_567_890,       // required to accept a Production AppTransaction
    maxSignedAgeMillis: 300_000)     // omit, or pass nil, to disable the rule

let transaction = try await verifier.verifyTransaction(jws)     // TransactionPayload
let app = try await verifier.verifyAppTransaction(jws)          // AppTransactionPayload
let claims = try await verifier.verifyRaw(jws)                  // [String: Any]
```

`verifyRaw` checks the chain and the signature, and enforces no *identity*
claim: the caller checks `bundleId`, `environment` and `appAppleId` in the
returned dictionary itself. It is not claim-free, though — it runs the same
signed path as `verifyTransaction`, so a configured `maxSignedAgeMillis`
applies to it too and a payload older than that is `.stalePayload` rather
than a returned dictionary.

Include `.sandbox` in `acceptedEnvironments` on any endpoint App Review can
reach: App Review runs production builds against sandbox.

**Date claims on `TransactionPayload` and `AppTransactionPayload` are
`Int64?` epoch-millisecond fields** — `signedDate`, `purchaseDate`,
`expiresDate`, `revocationDate`, `receiptCreationDate` — exactly as Apple
ships them. That is contractual across every port of this library:
converting them to `Date` would lose the raw claim and put this port out of
step with the other eight. Receipt *attribute* dates are the opposite case
and are `Date?` on `AppReceipt` and `InAppPurchase`.

`TransactionPayload.isActive(at:)` answers the entitlement question from the
signed claims alone: not revoked, and for a subscription not expired at the
given date. A refund or a renewal after signing is invisible to it, since it
reads only what was true when Apple signed the payload.

`JwsVerifier.init` throws `VerificationError`, not only its verification
methods: an empty `trustedRoots`, an empty `bundleId`, or an empty
`acceptedEnvironments` set fails at construction.

## Legacy PKCS#7 app receipts

Every input form is reachable with and without the device GUID:

```swift
let verifier = try ReceiptVerifier(trustedRoots: appleReceiptRoots(), bundleId: "com.example.app")

try await verifier.verify(receipt: receiptDER)
try await verifier.verify(base64Receipt: receiptBase64)
try await verifier.verify(receipt: receiptDER, deviceGuid: deviceGuid)
try await verifier.verify(base64Receipt: receiptBase64, deviceGuid: deviceGuid)
```

`verify(base64Receipt:)` decodes exactly what Apple's verifyReceipt accepts
as `receipt-data` (measured 2026-09-23, see
[`docs/evidence/2026-09-23-verifyreceipt-base64.md`](../docs/evidence/2026-09-23-verifyreceipt-base64.md)):
standard base64 (`+`/`/`) with the canonical `=` padding and nothing else.
Whitespace anywhere, the base64url alphabet, omitted or extra padding,
anything after the padding and an empty string are `.invalidReceiptFormat`
before any bytes reach the CMS parser. Unused low bits in the last data
character are accepted, as Apple accepts them. See `decodeReceiptBase64` in
`ReceiptVerifier.swift`.

Passing `deviceGuid` additionally enforces the device binding:
`SHA1(guid ‖ opaqueValue ‖ bundleIdBytes)` must equal attribute 5, compared in
constant time. The check is optional because a server does not always have
the client's device GUID — the raw bytes of `identifierForVendor` on iOS,
iPadOS, tvOS and watchOS, including an iOS app running on an Apple silicon
Mac, or the primary network interface's MAC address from
`copy_mac_address` on macOS and Mac Catalyst.

Four attribute types are modelled although Apple documents none of them:
`AppReceipt.appItemId` (type 1, which Apple's endpoint echoes under both
`adam_id` and `app_item_id`), `AppReceipt.downloadId` (15),
`AppReceipt.versionExternalIdentifier` (16) and `InAppPurchase.isTrialPeriod`
(1713, an `Int64?` like `isInIntroOfferPeriod`). Their meaning was established
by lining a genuine production receipt's attributes up against the answer
Apple's `verifyReceipt` endpoint gives for the same receipt (measured
2026-09-21). All four are `Int64?` rather than narrower: download ids run past
2^53, so a `Double` would round them.

Attribute types the library does not model are exposed verbatim on
`AppReceipt.unknownAttributes` / `InAppPurchase.unknownAttributes`
(`[Int: [Data]]`), the raw verified-but-undecoded value bytes keyed by
type — so a field Apple adds later stays reachable without a library update.

CMS parsing accepts BER, not only strict DER: genuine Apple and Xcode
receipts use indefinite-length encoding.

`ReceiptVerifier.verifyCore(receipt:)` is the instance-level primitive
**without** the bundle-id check, and `ReceiptVerifier.verifyCore(receipt:
trustedRoots:)` is the same primitive as a static function for a caller with
no single bundle id to check — what the `verifyReceipt`-compatible endpoint
below is built on:

```swift
let receipt = try await ReceiptVerifier.verifyCore(receipt: receiptDER, trustedRoots: appleReceiptRoots())
```

A caller that unlocks a product on the strength of it, without comparing
`receipt.bundleId`, will accept a genuine, correctly signed receipt from a
different app.

## The `verifyReceipt`-compatible endpoint

`VerifyReceiptEndpoint` answers Apple's deprecated `verifyReceipt` request
with the same response body, verified offline. One instance emulates one
environment, `.production` or `.sandbox`.

```swift
let endpoint = try VerifyReceiptEndpoint(trustedRoots: appleReceiptRoots(), environment: .production)

// The request body as a dictionary, or the raw JSON text.
let result = await endpoint.verifyReceiptResult(requestBody)
let response = result.response()  // Apple's body as [String: Any]
let json = result.json()          // Apple's body as JSON

// The same as verifyReceiptResult(rawRequestBody).json().
let body = await endpoint.verifyReceiptJSON(rawRequestBody)
// receipt-data alone, with no request envelope.
let bare = await endpoint.verifyReceiptData(receiptBase64)
```

No endpoint method throws on a request: the Apple status is part of the
result, for every input, including a body that is not JSON
(`{"status":21002}`). The statuses it can produce are
`VerifyReceiptEndpoint.statusOK` (`0`), `.statusMalformed` (`21002`),
`.statusNotAuthenticated` (`21003`), `.statusSandboxReceiptOnProduction`
(`21007`), `.statusProductionReceiptOnSandbox` (`21008`) and
`.statusInternal` (`21009`), and no others, because the rest describe
conditions that only exist on Apple's servers. Local 21007/21008 routing
fails closed: only receipt types `Production` and `ProductionVPP` count as
production.

A `VerifyReceiptResult` is one verification. It is an immutable `Sendable`
struct, and only the endpoint creates one.

- `outcome` is `.verified(AppReceipt)` or
  `.failed(reason: VerificationError.Reason, cause: (any Error)?)`.
- `receipt` is the verified `AppReceipt` whenever the receipt bytes
  verified, 21007 and 21008 included, and `failureReason` says why there is
  none. Exactly one of them is non-nil.
- `isVerified` is true exactly when `receipt` is non-nil. That includes
  21007 and 21008, so it is not the same check as `status == 0`:
  `status == 0` asks whether this endpoint's environment accepts the
  receipt, `isVerified` asks whether the receipt verified at all.
- `failureCause` is what is behind an `.internalError`, for logging: the
  parser's error for signed content that could not be read, or the
  unexpected error the endpoint caught.
- `status` is the answer for the endpoint's own environment.
- `requestDate` is the instant rendered as `request_date`.

The response is rendered when `response()` or `json()` is called, not
before.

```swift
switch result.outcome {
case .verified(let receipt):
    guard receipt.bundleId == "com.example.app" else { return reject() }
    grant(receipt.inAppPurchases)
case .failed(let reason, let cause):
    log(reason.rawValue, cause)
}
```

**Retrying in the other environment costs no second verification.**
`response(for:)` and `json(for:)` render what an endpoint of that
environment would answer, recomputing the status from the receipt's own
type:

| receipt | on `.production` | on `.sandbox` |
|---|---|---|
| `Production`, `ProductionVPP` | 0 | 21008 |
| any other type, or none | 21007 | 0 |
| failed verification | its own status | its own status |

```swift
let result = await production.verifyReceiptResult(requestBody)
if result.status == VerifyReceiptEndpoint.statusSandboxReceiptOnProduction {
    let body = try result.json(for: .sandbox)
}
```

A sandbox receipt never renders as a production 0, whichever endpoint
verified it. `.xcode` and `.localTesting` throw
`VerificationError(.wrongEnvironment, ...)`, as the initializer does.

| `failureReason` | status | when |
|---|---|---|
| `.requestTooLarge` | 21002 | the raw body is over `VerifyReceiptEndpoint.maxRequestBytes` (3,145,728 UTF-8 bytes); Apple answers HTTP 413 here |
| `.malformedRequest` | 21002 | the body is not a JSON object or nests past 64 levels, or `receipt-data` is missing, empty or not a string |
| `.invalidReceiptFormat` | 21002 | `receipt-data` is over `ReceiptVerifier.maxReceiptBytes`, is not base64 or its CMS envelope does not parse |
| `.invalidChain`, `.invalidSignature`, other certificate reasons | 21003 | the receipt did not authenticate |
| `.internalError` | 21009 | not the client's fault: the receipt authenticated but its signed content cannot be read, or an unexpected error; `failureCause` holds what is behind it. Alert and retry or escalate; do not deny the user |

`.malformedRequest` and `.requestTooLarge` only ever appear on a result. No
`VerificationError` is thrown with either. `.internalError` is also thrown
by `ReceiptVerifier`, with the parser's error as `VerificationError.cause`.

**`request_date`.** `verifyReceiptResult` and `verifyReceiptData` take an
optional `now: Date?` that becomes `request_date` in place of the
endpoint's clock. Without it the clock is read once, when the call is made.
`now` reaches `request_date` and nothing else: certificate validity never
sees it.

Like Apple's endpoint, this does **not** check the bundle id: compare
`result.receipt?.bundleId` yourself before granting anything, or use
`ReceiptVerifier`, which checks it for you. `password` and
`exclude-old-transactions` are accepted for wire compatibility and never
read. `json()` and `verifyReceiptJSON` are deterministic: Swift
dictionaries carry no insertion order, so keys are serialized
`.sortedKeys` rather than in declaration order. See
[COMPARISON.md](../COMPARISON.md) for the field-by-field fidelity account.

`init(trustedRoots:environment:clock:)` only accepts `.production` or
`.sandbox` for `environment`. `.xcode` and `.localTesting` throw
`VerificationError(.wrongEnvironment, ...)` at construction, since Apple's
endpoint has no other environment to emulate.

A raw request body and `receipt-data` are both measured before they are
parsed or decoded; see [Resource bounds](#resource-bounds).

Migrating from 0.5: `endpoint.verifyReceipt(body)` is removed; use
`await endpoint.verifyReceiptResult(body).response()`. The deprecated
`init(trustedRoots:production:clock:)` is removed; pass
`environment: .production` for `true` and `.sandbox` for `false`.

## The error vocabulary

Every verification verdict is a `VerificationError`, a `Sendable`,
`CustomStringConvertible` struct carrying a `reason: Reason` and a
`message: String`. Switch on `reason`, never parse `description` or
`message`. The one exception is a malformed trust anchor: a `trustedRoots`
entry that is not a parseable DER certificate makes swift-certificates' own
parsing error come back out, not a `VerificationError`. That is usually a
construction-time failure — `JwsVerifier.init` and `ReceiptVerifier.init`
decode their anchors once — but the static
`ReceiptVerifier.verifyCore(receipt:trustedRoots:)` takes its anchors per
call and decodes them per call, so on that entry point the same error
surfaces at verification time. Either way, treat anchors as configuration to
validate at startup rather than as input to catch per call.

```swift
do {
    let transaction = try await verifier.verifyTransaction(jws)
} catch let error as VerificationError {
    switch error.reason {
    case .wrongEnvironment:
        retryAgainstSandbox()
    case .invalidChain, .invalidSignature:
        alertSecurity()
    default:
        reject(error.reason)
    }
}
```

| `Reason` | Raw value | Raised when |
|---|---|---|
| `.invalidJwsFormat` | `INVALID_JWS_FORMAT` | longer than `JwsVerifier.maxJwsBytes`, a header or payload nesting past 64 levels, not three dot-separated segments, a segment that is not base64url JSON, `alg != "ES256"`, or an `x5c` that is not exactly three entries |
| `.invalidCertificate` | `INVALID_CERTIFICATE` | `x5c[0]` or `x5c[1]` does not parse as a certificate. An entry that is not standard base64 with canonical padding (RFC 7515 §4.1.6) is refused before it is decoded: a junk character, a space or line break, a base64url `-` or `_`, or omitted or extra `=` padding gets this verdict rather than being skipped, as in every port. The one divergence is `x5c[2]`, which this port never decodes and java decodes and parses, so an unparseable third certificate is `INVALID_CERTIFICATE` there and unremarked here (ROADMAP.md records it) |
| `.invalidCertificatePurpose` | `INVALID_CERTIFICATE_PURPOSE` | the leaf or intermediate lacks its Apple marker OID, or the receipt signer lacks its own |
| `.invalidChain` | `INVALID_CHAIN` | the path does not reach a pinned anchor, a certificate was not valid at the signing instant, or a receipt embeds more than ten certificates |
| `.invalidSignature` | `INVALID_SIGNATURE` | the ES256 or CMS signature check failed, or the signer key is not RSA |
| `.wrongBundleId` | `WRONG_BUNDLE_ID` | the verified payload or receipt names another bundle |
| `.wrongEnvironment` | `WRONG_ENVIRONMENT` | the environment is outside the accepted set |
| `.wrongAppAppleId` | `WRONG_APP_APPLE_ID` | a Production `AppTransaction` does not name the configured app Apple id |
| `.invalidReceiptFormat` | `INVALID_RECEIPT_FORMAT` | the receipt is over `ReceiptVerifier.maxReceiptBytes`, the CMS blob does not parse, or it has no signer info |
| `.deviceHashMismatch` | `DEVICE_HASH_MISMATCH` | the device hash does not match attribute 5, or the receipt lacks the attributes the check needs |
| `.stalePayload` | `STALE_PAYLOAD` | the payload was signed longer ago than `maxSignedAgeMillis` |
| `.malformedRequest` | `MALFORMED_REQUEST` | never thrown: reported only on a `VerifyReceiptResult`, for an unusable request envelope |
| `.requestTooLarge` | `REQUEST_TOO_LARGE` | never thrown: reported only on a `VerifyReceiptResult`, for a raw body over `VerifyReceiptEndpoint.maxRequestBytes` (status 21002; Apple answers HTTP 413) |
| `.internalError` | `INTERNAL_ERROR` | the receipt's chain and signature verified, but its payload does not parse (`cause` is the parser's error); also reported on a `VerifyReceiptResult` for an unexpected error. Status 21009. Not the client's fault: alert and retry or escalate, do not deny |

**Order of the receipt checks.** CMS parse → the creation date alone
(attribute 12; nothing else in the payload is decoded yet) → chain at that
date, or at the system clock when the date is missing, empty, unreadable or
stated twice → receipt-signing marker OID → CMS signature → full payload
parse → bundle id → device hash. Nothing is trusted before the chain and
the signature, so reading the date never rejects. The chain comes first so
the attacker's own key is never run before it is trusted. A payload that
fails the full parse was signed by a trusted signer, so it is
`.internalError`, not `.invalidReceiptFormat`.

The vocabulary is **closed** by the cross-port contract, and it doubles as
the misconfiguration channel: an empty `trustedRoots`, an empty `bundleId`,
or an empty `acceptedEnvironments` set throws `VerificationError` from
`init` too, not a separate error type — `Reason` cases like
`.invalidCertificate` and `.invalidJwsFormat` are reused there rather than
introducing a new reason just for construction.

## Integrating: from verified payload to entitlement

The backend flow these calls sit inside is written out once in the
[project README](../README.md#integrating-from-verified-payload-to-entitlement):
verify offline, deny on any failure, check the refund field, refresh a payload
past the freshness window, guard against replay on the transaction id, then
grant. That section also carries the policy table saying what each reason
means and which ones are worth an alert. Here are its two branches in this
port's API.

A StoreKit 2 signed transaction:

```swift
import ApplePurchaseReceiptVerifier

func makeVerifier() throws -> JwsVerifier {
    try JwsVerifier(
        trustedRoots: appleJwsRoots(),
        bundleId: "com.example.app",
        acceptedEnvironments: [.production, .sandbox],
        maxSignedAgeMillis: 300_000)          // the freshness window
}

func redeemTransaction(_ verifier: JwsVerifier, userId: String, jws: String) async -> Verdict {
    let payload: TransactionPayload
    do {
        payload = try await verifier.verifyTransaction(jws)          // step 2
    } catch let error as VerificationError {
        if error.reason == .stalePayload {
            // step 4: ask the client for a fresh jwsRepresentation, or fetch
            // one from the App Store Server API and verify that instead
            return .refresh
        }
        logger.warning("purchase rejected: \(error.reason.rawValue)")
        return .denied
    } catch {
        return .denied
    }

    if payload.revocationDate != nil { return .denied }              // step 3

    guard let id = payload.transactionId else { return .denied }
    if grants.exists(id) { return .denied }                          // step 5
    grants.record(id, payload.originalTransactionId, userId)

    grant(userId, payload.productId)
    return .granted
}
```

The legacy PKCS#7 app receipt is the same policy on the other input, the one
StoreKit 1 apps and older SDKs still send:

```swift
// Same policy keyed on the receipt's own dates. `verify(base64Receipt:)` takes
// the string the client sends; `VerifyReceiptEndpoint` is the alternative,
// answering Apple's `verifyReceipt` JSON shape with a status instead.
func redeemReceipt(
    _ verifier: ReceiptVerifier, userId: String, receiptData: String, productId: String
) async -> Verdict {
    guard let receipt = try? await verifier.verify(base64Receipt: receiptData) else {
        return .denied                                               // step 2
    }
    let now = Date()
    guard let purchase = receipt.inAppPurchases.first(where: { $0.productId == productId }),
        purchase.cancellationDate == nil                             // step 3
    else {
        return .denied
    }
    if let expires = purchase.expiresDate, expires <= now { return .denied }

    // step 4: no maxSignedAgeMillis here, so compare the creation date. Past
    // the window, ask the client to refresh its receipt, or call the App Store
    // Server API by transactionId and verify the JWS it returns.
    guard let created = receipt.creationDate, now.timeIntervalSince(created) <= 300 else {
        return .refresh
    }

    guard let id = purchase.transactionId else { return .denied }
    if grants.exists(id) { return .denied }                          // step 5
    grants.record(id, purchase.originalTransactionId, userId)

    grant(userId, purchase.productId)
    return .granted
}
```

## Trust anchors

`appleJwsRoots()` and `appleReceiptRoots()` are top-level functions, each
returning all three published Apple roots (Apple Inc. Root CA, Apple Root
CA - G2, Apple Root CA - G3) as `[Data]` — DER bytes read from `.cer`
resources bundled in the package (`Bundle.module`). Apple deliberately
documents the JWS chain as ending in "an Apple root certificate" rather than
naming one, so narrowing either set would fail closed, silently, the day
Apple re-anchored a path.

To pin your own anchors instead, pass DER-encoded certificates as `[Data]` to
either initializer's `trustedRoots:` parameter.

Trust reaches this library through exactly that argument, never through
`Security.framework`, `SecTrustEvaluateWithError`, or
`CertificateStore.systemTrustRoots` — the one-word substitution that would
silently switch this library onto the platform trust store on Linux.
`TrustStoreIsolationTests` (below) is what proves that, rather than only
documenting it.

## Environment routing and staleness

`acceptedEnvironments` on `JwsVerifier` is a `Set<AppleEnvironment>` checked
against the payload's `environment` (or `receiptType`, for an
`AppTransaction`) claim; a value outside it is `.wrongEnvironment`.
`VerifyReceiptEndpoint`'s single `environment` drives the 21007/21008 status
routing the same way the other ports do.

`maxSignedAgeMillis` is optional; a payload signed longer ago than that is
`.stalePayload`. A payload that states no signing date at all has no age to
be stale by, so the rule never fires for it.

## The clock

`JwsVerifier.init` and `VerifyReceiptEndpoint.init` both take an optional
`clock: (@Sendable () -> Date)?`; `nil` (the default) reads `Date()`. It is
read in exactly two places:

1. the `.stalePayload` comparison in `JwsVerifier`;
2. the `request_date` / `_ms` / `_pst` triple in `VerifyReceiptEndpoint`,
   once per call and only when the call passes no `now`.

**Certificate validity is never judged by the injected clock.** It is judged
at the payload's own `signedDate` / `receiptCreationDate`, or at the
receipt's attribute-12 creation date; where the input states no date of its
own, the fallback reads `Date()` directly — not the injected clock — so a
caller injecting a clock to test staleness, or to work around skew, cannot
thereby accept an expired chain or expire a live one.

`ReceiptVerifier` therefore takes **no clock at all**: it would have no
consumer, and an option with no consumer is an invitation to wire it into the
one place it must never reach.

The closure type is deliberately `@Sendable () -> Date`, not Swift's `Clock`
protocol (`ContinuousClock`, `SuspendingClock`): those measure elapsed time
from an arbitrary origin and cannot name a wall-clock instant like
2025-01-01, which is exactly what pinning "now" for a test requires.

## Thread safety

`JwsVerifier`, `ReceiptVerifier` and `VerifyReceiptEndpoint` are immutable
structs, meant to be shared: build one of each at startup and hand it to
every request. Each holds only `let` properties (the parsed roots, the
configuration and, where there is one, a `@Sendable` clock) and keeps
per-call state in locals.
Every public type, the results included, is `Sendable`, and the package
builds in Swift 6 language mode, so the compiler rejects a data race on a
shared verifier or a verified payload instead of leaving it to review.

`ConcurrencyTests` is the runtime check: sixteen child tasks in a
`TaskGroup`, fifty iterations each, through one shared `ReceiptVerifier`
(`verify(base64Receipt:)`), `VerifyReceiptEndpoint` (the dictionary and
raw JSON entry points) and `JwsVerifier` (`verifyTransaction`), each answer
compared to the answer a sequential call gets.

**Nothing in the verification path is serialized.** `swift-certificates`'
`Verifier` is a struct, not an actor, and its `validate` is a nonisolated
`async` method, which runs on the global concurrent executor. Each call
builds its own `Verifier` and `CertificateStore`, so concurrent calls share
nothing to wait on, and the library has no actor, lock or global actor of
its own.

## Resource bounds

`ReceiptVerifier.verifyCore` bounds a receipt's embedded certificates at ten,
enforced before any of them is decoded — the same number every other port in
this repository uses, and genuine receipts carry one to three. The chain
walk beneath it is bounded by construction rather than by a separate
counter: each step takes only the certificate that actually signed the
current tip and never revisits a subject, so the walk is never longer than
the embedded certificate bag.

Dates read from a payload or receipt are checked against
`isRepresentableAsCertificateValidationTime` before they reach the
certificate-validation policy — `GeneralizedTime` in `swift-certificates`
holds only years 0001 through 9999, and an unchecked date outside that range
would abort the process rather than fail the verification. An
attacker-supplied year like `999999` is therefore `.invalidChain` (JWS) or
`.invalidReceiptFormat` (receipt attribute), not a crash.

### Input size limits

Base64 decoding and JSON parsing both allocate a multiple of their input
before any signature is checked, so the input is measured first. These are
constants, not initializer options.

The request and receipt caps are Apple's, fixed in every port of this
library. Measured on 2026-09-23 against both of Apple's verifyReceipt
endpoints (production and sandbox), a request body of 3,145,728 bytes is
answered and one of 3,145,729 bytes gets HTTP 413. Apple counts UTF-8
bytes, not characters: 3,145,729 bytes of `é`, only 1,572,874 characters,
also got 413.

- **`VerifyReceiptEndpoint.maxRequestBytes` (3 MiB, 3,145,728 bytes).**
  Applied to a raw JSON body before the depth scan and the parse. A larger
  body answers 21002 with `.requestTooLarge`. A body already decoded to a
  dictionary is not measured.
- **`ReceiptVerifier.maxReceiptBytes` (3 MiB, 3,145,728 bytes).** Applied to
  the base64 string at `verify(base64Receipt:)` and at the endpoint's
  `receipt-data` (every entry point), before decoding, and to the DER at
  every entry point that takes bytes, both `verifyCore` overloads included.
  A larger receipt is `.invalidReceiptFormat` (21002 at the endpoint).
  `fixtures/cases.json` requires every port to accept a receipt of up to
  1 MiB of DER, about 1.38 MB of base64, which fits in a JSON body too; the
  largest genuine receipt in the corpus is 79 KB.
- **`JwsVerifier.maxJwsBytes` (256 KiB, 262,144).** Applied to a compact JWS
  before it is split. A longer one is `.invalidJwsFormat`. Every JWS in the
  corpus is under 2.5 KB.
- **JSON nesting depth 64.** `JSONSerialization` and `JSONDecoder` take no
  depth option, so the depth of a request body, and of a JWS header and
  payload, is counted before either runs. A deeper request body answers
  21002 with `.malformedRequest`; a deeper JWS segment is
  `.invalidJwsFormat`. Brackets inside strings are not counted.

Every string is measured in UTF-8 bytes with `utf8.count`, which copies
nothing and is constant time for a native Swift string (a string bridged
from `NSString` may walk its contents, and the count is still exact).

**Answering 413 like Apple.** `.requestTooLarge` exists so an HTTP layer
can send the status Apple sends. The body is Apple's 21002 either way:

```swift
let result = await endpoint.verifyReceiptResult(rawRequestBody)
let httpStatus = result.failureReason == .requestTooLarge ? 413 : 200
return Response(status: httpStatus, body: result.json())
```

A framework or proxy that caps request bodies itself has to allow at least
3 MiB, or it refuses bodies Apple would answer.

## Testing

```bash
swift test                                  # from the repository root; the manifest lives there
swift test --filter ConformanceCasesTests   # just the shared cross-language vectors
```

`ConformanceCasesTests` runs every case in `fixtures/cases.json`, the
normative cross-language vector file every port of this library answers.

`TrustStoreIsolationTests`
(`swift/Tests/ApplePurchaseReceiptVerifierTests/TrustStoreIsolationTests.swift`)
asserts the trust-pinning rule three ways: structurally, by scanning every
source file for any spelling that could reach `Security.framework`, a
socket, or the network; behaviourally, on chains that are well-formed in
every respect except their anchor; and against this machine's real trust
store, which is loaded and effective in the test process and still moves no
verdict.

Beyond conformance and trust isolation, `PublicApiTests` exercises the
public surface, `VerifierTests` covers hostile and malformed input against a
generated fake Apple PKI, and `PortDivergenceTests` pins the handful of
places this port's behaviour is deliberately allowed to differ from the
others (documented in the root [ROADMAP.md](../ROADMAP.md)).

`swift/fuzz/` holds six libFuzzer targets built with SwiftPM's own
`-sanitize=fuzzer` support — no third-party fuzzing dependency, since the
Swift toolchain already carries libFuzzer. It is a separate package
(`swift/fuzz/Package.swift`, depending on the library by path) so that
`swift build`/`swift test` at the root never builds or knows about it:

```bash
cd swift/fuzz
./run.sh all              # every target, 60 s each
./run.sh receipt-der 600  # one target, ten minutes
```

`swift/fuzz/README.md` lists the six targets and the invariant each asserts
beyond "nothing traps" — Swift's `throws` is untyped and `fatalError`, a
force-unwrap, an out-of-range index, and arithmetic overflow all abort the
process rather than throw, so "only `VerificationError` escapes" has to be
checked, not assumed.

## Why offline

Signature verification cannot fail because a vendor endpoint is down, so a
purchase can be honoured immediately and reconciled against the App Store
Server API afterwards. Refunds and revocations still need that
reconciliation pass — a signature proves what Apple signed, not what
happened since.

This is one of nine implementations (Java, Node, Python, Swift, Go, Ruby,
Rust, PHP, .NET) that share a single fixture suite, including Apple's own
official test fixtures, and are required to agree byte for byte. See the
[project README](../README.md) for the full picture and
[COMPARISON.md](../COMPARISON.md) for how it differs from Apple's official
libraries.

## Licence

MIT — see [LICENSE](../LICENSE).
