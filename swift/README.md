# apple-purchase-receipt-verifier (Swift)

Verify Apple in-app purchases locally — no calls to Apple's servers.

Replaces the deprecated `verifyReceipt` endpoint by validating StoreKit 2
signed JWS transactions and legacy PKCS#7 app receipts against pinned Apple
root certificates.

```swift
.package(url: "https://github.com/emindeniz99/apple-purchase-receipt-verifier.git", from: "0.2.1")
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

Every type is `Sendable`, and every verification method is `async throws`:
`JwsVerifier` and `ReceiptVerifier` call into `swift-certificates`' actor-
isolated `Verifier`, so `await` is structural, not decorative.

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

`verifyRaw` checks the chain and the signature and enforces no claim — the
caller checks `bundleId`, `environment` and `appAppleId` in the returned
dictionary itself.

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

`verify(base64Receipt:)` decodes exactly what Apple's `receipt-data` accepts:
RFC 4648 Base64, the standard (`+`/`/`) or base64url (`-`/`_`) alphabet —
never both in the same string — padding present or omitted, and CR/LF/space/
tab anywhere. A character neither alphabet defines, anything but whitespace
after padding starts, or a `=` count other than zero or the exact count the
data length requires is `.invalidReceiptFormat` before any bytes reach the
CMS parser — see `decodeReceiptBase64` in `ReceiptVerifier.swift`.

Passing `deviceGuid` additionally enforces the device binding:
`SHA1(guid ‖ opaqueValue ‖ bundleIdBytes)` must equal attribute 5, compared in
constant time. The check is optional because a server does not always have
the client's `identifierForVendor`.

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

```swift
let endpoint = try VerifyReceiptEndpoint(trustedRoots: appleReceiptRoots(), environment: .production)

let response = await endpoint.verifyReceipt(requestBody)      // [String: Any] in, out
let json = await endpoint.verifyReceiptJSON(rawRequestBody)   // String in, out
```

Neither method throws: the Apple status code is a field of the returned
dictionary, for every input, including one that is not JSON —
`verifyReceiptJSON` answers `{"status":21002}` for that case. The statuses it
can produce are `VerifyReceiptEndpoint.statusOK` (`0`), `.statusMalformed`
(`21002`), `.statusNotAuthenticated` (`21003`),
`.statusSandboxReceiptOnProduction` (`21007`),
`.statusProductionReceiptOnSandbox` (`21008`) and `.statusInternal`
(`21009`) — and no others, because the rest describe conditions that only
exist on Apple's servers. Local 21007/21008 routing fails closed: only
receipt types `Production` and `ProductionVPP` count as production.

Like Apple's endpoint, this does **not** check the bundle id — compare
`receipt["bundle_id"]` yourself. `password` and `exclude-old-transactions`
are accepted for wire compatibility and never read.
`verifyReceiptJSON`'s output is deterministic: Swift dictionaries carry no
insertion order, so keys are serialized `.sortedKeys` rather than in
declaration order. See [COMPARISON.md](../COMPARISON.md) for the
field-by-field fidelity account.

`init(trustedRoots:environment:clock:)` only accepts `.production` or
`.sandbox` for `environment` — `.xcode` and `.localTesting` throw
`VerificationError(.wrongEnvironment, …)` at construction, since Apple's
endpoint has no other environment to emulate. A deprecated
`init(trustedRoots:production:clock:)` boolean overload exists for callers
written against it.

## The error vocabulary

Every verification verdict is a `VerificationError`, a `Sendable`,
`CustomStringConvertible` struct carrying a `reason: Reason` and a
`message: String`. Switch on `reason`, never parse `description` or
`message`. One exception sits at construction rather than verification: a
`trustedRoots` entry that is not a parseable DER certificate makes the
initializer rethrow swift-certificates' own parsing error, so treat anchors
as configuration to validate at startup, not as input to catch per call.

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
| `.invalidJwsFormat` | `INVALID_JWS_FORMAT` | not three dot-separated segments, a segment that is not base64url JSON, `alg != "ES256"`, or an `x5c` that is not exactly three entries |
| `.invalidCertificate` | `INVALID_CERTIFICATE` | `x5c[0]` or `x5c[1]` does not parse as a certificate. Their base64 is decoded with `ignoreUnknownCharacters`, so a junk character is skipped rather than refused, and `x5c[2]` is never decoded at all; both are recorded in ROADMAP.md as divergences from java, which decodes all three |
| `.invalidCertificatePurpose` | `INVALID_CERTIFICATE_PURPOSE` | the leaf or intermediate lacks its Apple marker OID, or the receipt signer lacks its own |
| `.invalidChain` | `INVALID_CHAIN` | the path does not reach a pinned anchor, a certificate was not valid at the signing instant, or a receipt embeds more than ten certificates |
| `.invalidSignature` | `INVALID_SIGNATURE` | the ES256 or CMS signature check failed, or the signer key is not RSA |
| `.wrongBundleId` | `WRONG_BUNDLE_ID` | the verified payload or receipt names another bundle |
| `.wrongEnvironment` | `WRONG_ENVIRONMENT` | the environment is outside the accepted set |
| `.wrongAppAppleId` | `WRONG_APP_APPLE_ID` | a Production `AppTransaction` does not name the configured app Apple id |
| `.invalidReceiptFormat` | `INVALID_RECEIPT_FORMAT` | the CMS blob does not parse, has no signer info, or an attribute is malformed |
| `.deviceHashMismatch` | `DEVICE_HASH_MISMATCH` | the device hash does not match attribute 5, or the receipt lacks the attributes the check needs |
| `.stalePayload` | `STALE_PAYLOAD` | the payload was signed longer ago than `maxSignedAgeMillis` |

The vocabulary is **closed** by the cross-port contract, and it doubles as
the misconfiguration channel: an empty `trustedRoots`, an empty `bundleId`,
or an empty `acceptedEnvironments` set throws `VerificationError` from
`init` too, not a separate error type — `Reason` cases like
`.invalidCertificate` and `.invalidJwsFormat` are reused there rather than
introducing a twelfth vocabulary just for construction.

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
2. the `request_date` / `_ms` / `_pst` triple in `VerifyReceiptEndpoint`.

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

Unlike the PHP and Rust ports, this library does not expose a configurable
ceiling on decoded receipt size; callers who need one should bound the input
before it reaches `verify`.

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
