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
.package(url: "https://github.com/emindeniz99/apple-purchase-receipt-verifier.git", from: "0.8.0")
```

Swift **6.3** or newer, on macOS 15+, iOS 18+ or Linux (`Package.swift`
declares `.macOS(.v15), .iOS(.v18)`). Those are the floors of
[WasmKit](https://github.com/swiftwasm/WasmKit), which runs the module (see
[How it works](#how-it-works)). The other dependency,
[swift-crypto](https://github.com/apple/swift-crypto), computes the SHA-256
that checks the bundled module against its pin. Any release from 3.0.0 up
to, not including, 6.0.0 will do, so the package resolves next to Apple's
[app-store-server-library-swift](https://github.com/apple/app-store-server-library-swift)
(swift-crypto below 4.0.0) and swift-nio-ssh (below 5.0.0). CI builds and
tests both ends: 5.0.0, which `Package.resolved` pins, and 3.0.0.
Coming from 0.7? Read
[Upgrading from 0.7](#upgrading-from-07): the API is the same except
`Config.roots`, and the floors rose.

## How it works

Every verification runs inside `aprv.wasm`, the one verification module
every port of this repository shares: a Rust core on OpenSSL, compiled to
WebAssembly. The package carries the module as a resource, checks it
against the SHA-256 in `aprv.wasm.sha256` before it is parsed
(swift-crypto's `SHA256`, which is CryptoKit's on Apple platforms), and
runs it on WasmKit, a WebAssembly interpreter written in Swift. Nothing is
compiled to machine code at run time, so no JIT entitlement is needed on
iOS.

The Swift code holds no parser, no cryptography and no trust decision: it
reads the clock, copies the input into the module, and turns the module's
JSON answer into the types below. A hostile receipt meets the module inside
the WebAssembly sandbox, never native code in your process. The module
imports one function from the host, a source of random bytes (from
`SystemRandomNumberGenerator`) that OpenSSL uses for ECDSA blinding; it has
no file, network, clock or environment access.

WasmKit checks the module's memory accesses in software. The package asks
for that mode explicitly: WasmKit's default on Linux and macOS would reserve
guard regions and install a process-wide `SIGSEGV`/`SIGBUS` handler, which a
library has no business doing in its caller's process. Every range the host
itself reads or writes in the module's memory is checked before the access,
because WasmKit stops the process, rather than throwing, when a host access
is out of range.

## Quick start

```swift
import ApplePurchaseReceiptVerifier

// Build once, at startup, and share it: Verifier is immutable and Sendable.
let verifier = try Verifier(config: Config())

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

**Inputs are cut at the length the module states** in its `init` answer
(`max_input_bytes`, 3,145,729 bytes today: one over the largest cap) before
they are copied into the module, which then answers `.tooLarge` (21002 at
the endpoint) exactly as it would for any longer input. The number is the
module's, read from each instance; the package keeps no copy of it.

**No method throws for any input.** An empty `base64` / `jws` / `requestJson`
is input and fails as `Reason.malformed`, the same as a garbled one. The
verdict is the module's. When the machinery itself fails (the module traps,
answers something this package cannot read, or cannot be loaded, or the
clock answers a time before 1970) the call answers `.internalError`, 21009
at the endpoint, with the category in `Failure.cause`. A module instance
that trapped is discarded, and the next call runs on a fresh one.

**A custom clock**, for tests or for pinning `request_date`:

```swift
let config = Config(clock: { 1_735_689_600_000 })  // 2025-01-01T00:00:00Z
let verifier = try Verifier(config: config)
```

`Config(roots:clock:)` is the one way to build a `Config`, and `nil` for
either argument means its default. (Three more arguments, all empty by
default, are described under [Revocation](#revocation).) It never throws:
it stores what it is given, and `Verifier(config:)` checks it. `Config()` uses Apple's three
published roots and the system clock. The roots are compiled into
`aprv.wasm` and pinned there, so `Config().roots` is `nil`: "the module's
built-in roots". `Config(roots: ...)` replaces them with your own
certificates, as DER or PEM bytes (the module tells them apart; a PEM bundle
of several certificates is one entry), which tests use. `Verifier(config:)`
hands the configuration to a fresh module instance at once, so a certificate
the module refuses throws `ConfigError` there, at startup, and never on a
call. That instance then serves the first call. It also throws
`ConfigError` for an empty root set, since a verifier with no roots would
answer `.untrustedChain` to everything and nobody would notice until
production. With the default roots and no revocation settings it throws
only if the module this package carries cannot be loaded.

The clock is read once per call, before the input is looked at, and passed
to the module. The module uses it for exactly three things: the
chain-validity instant when the receipt or JWS states no signing date of its
own, `request_date` in the endpoint response, and whether a revocation list
is still fresh when it holds a `certificateHold` entry for a certificate on
the path. It never decides whether
a certificate is expired when the input states a date; see
[Trust anchors](#trust-anchors). A clock must be safe to call from several
threads.

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
- **Environment**: `receipt.environment` or `payload.environment` (a
  `JsonPayload`) is the one you expect: `.production`, `.sandbox`, or `nil`
  when Apple's value names neither (an `Xcode` receipt, a `LocalTesting`
  JWS). For a JWS the verifier reads the top-level `environment` claim, a
  notification's `data.environment` or a summary notification's
  `summary.environment`, the first that is present. A sandbox receipt
  reaching a production server is not automatically wrong, but your policy
  should say what to do with it.
- **Product id**: the transaction is for a product you sell.
- **Idempotency**: `transactionId` (JWS) or each in-app purchase's
  `transactionId` (receipt) has not been applied before; verifying the same
  receipt twice must not grant the purchase twice.

## The device-hash example

A legacy receipt's attribute 5 (`sha1Hash`) is Apple's device-binding hash:
`SHA1(deviceId ‖ opaqueValue ‖ bundleIdBytes)`. The library takes no device
id parameter; the check is yours to run, in constant time, on the fields it
returns. The example uses swift-crypto's `Crypto`. This package depends on
swift-crypto only to hash its module, so your target lists the `Crypto`
product itself before it imports it:

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
| `.invalidSignature`, `.untrustedChain`, `.invalidCertificate`, `.invalidCertificatePurpose`, `.certificateRevoked` | 21003 |
| `.unreadablePayload`, `.internalError` | 21009 |
| verified, environment matches, but an in-app purchase does not decode | 21009 |

Every 21009 case is deterministic for the same input: alert on 21009,
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
`InAppPurchase` per attribute-17 entry. The module decodes the receipt; this
package reads its JSON into these structs. Rules, pinned by the shared
conformance vectors:

- A missing attribute decodes to `nil`. The library invents no values.
- Dates are `Int64` epoch milliseconds, UTC. A receipt date parses as an
  RFC 3339 `date-time` (a fraction truncated to the millisecond, an offset
  converted to UTC); anything else is `nil` and the raw bytes are kept in
  `unknownAttributes`.
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
  padded standard base64. Cancellation reasons are nullable integers,
  like quantity. The shared conformance vectors compare its parsed value,
  not its bytes, so key order and escaping are not part of the contract.

## Trust anchors

`Config()` trusts Apple's three published roots (Apple Inc. Root
CA, Apple Root CA - G2, Apple Root CA - G3), compiled into `aprv.wasm`. The
module cannot read the operating system's trust store, a distribution CA
bundle, or anything downloaded: it has no file or network access at all. The
only anchors are the built-in ones, or the ones a caller supplies through
`Config(roots: ...)`. The package carries no certificate file of its
own; the repository's `certs/` is the reviewable source of the compiled-in
roots.

The chain is walked top-down: from a pinned root outward, a certificate's
signature is checked only once the key that will verify it has already been
vouched for, directly or transitively, by a pinned root. A certificate no
root vouches for is simply excluded from the path. A certificate on the
resulting path is then checked for validity at the chain instant, and last
for Apple's marker OIDs (the receipt-signing / WWDR OIDs on the receipt
path, the same pair on the JWS `x5c` chain).

## Revocation

A verifier refuses a certificate Apple has revoked, when it knows of the
revocation. It knows from three sources, all checked inside the module with
no network access:

| Source | Who sets it | Default |
|---|---|---|
| the list built into the module | each release of this package | always on; cannot be turned off |
| `distrust` | you | empty |
| Apple's revocation lists (CRLs) | you download them and pass the bytes | none |

A revoked certificate on the path fails the call with
`.certificateRevoked` (21003 at the endpoint), whatever date the payload
states: whoever holds a leaked key chooses that date. A missing or stale
list never fails a call.

```swift
let config = Config(
    revocationLists: [crl],  // CRL files exactly as downloaded (DER)
    revocationIssuers: [ca],  // optional: a CA that signs lists, as DER or PEM, like a root
    distrust: [RevokedCertificate(issuer: issuerId, serial: "7D3920094EBEF3F8EFCA6C10EA8E4303")])
let verifier = try Verifier(config: config)
```

The package downloads nothing and starts no task or timer. Refresh on your
own schedule, with your own HTTP client: download the lists the current
verifier names, build a new verifier, and swap the reference.

The new verifier is built with the settings the current one has: `roots`,
`revocationIssuers`, `distrust` and the clock stay as you set them, and only
the lists change. A URL that fails to download keeps the last bytes that
came from it, so a flaky download never drops a list, and the revocation it
carries.

```swift
// Everything except the lists, as you configure it today.
func makeConfig(revocationLists: [[UInt8]]) -> Config {
    Config(
        // roots: and clock: too, if you set them
        revocationLists: revocationLists,
        revocationIssuers: [ca],
        distrust: [RevokedCertificate(issuer: issuerId, serial: "7D3920094EBEF3F8EFCA6C10EA8E4303")])
}

final class VerifierHolder: @unchecked Sendable {
    private let lock = NSLock()
    private var verifier: Verifier
    init(_ verifier: Verifier) { self.verifier = verifier }
    var current: Verifier { lock.withLock { verifier } }
    func replace(_ next: Verifier) { lock.withLock { verifier = next } }
    var lastGood: [String: [UInt8]] = [:]  // URL -> bytes of the last list that downloaded; one refresh at a time
}

func refreshRevocation(_ holder: VerifierHolder) async throws {
    let urls = holder.current.revocationUrls
    for text in urls {
        guard let url = URL(string: text),
            let (data, response) = try? await URLSession.shared.data(from: url),
            (response as? HTTPURLResponse)?.statusCode == 200, data.count <= 1 << 20
        else { continue }  // keep this URL's last good bytes; revocationValidUntil shows the age
        holder.lastGood[text] = [UInt8](data)
    }
    let lists = urls.compactMap { holder.lastGood[$0] }
    // Throws ConfigError for a list the module refuses: the old verifier keeps serving.
    holder.replace(try Verifier(config: makeConfig(revocationLists: lists)))
}
```

- **Take the URLs from `revocationUrls`, never from Apple's PKI page.** The
  page also links an old copy of Apple Root CA's list and a list signed
  under a retired root name, which `Verifier(config:)` refuses, and a 2.3 MB
  WWDR G1 list over the 1 MiB cap. With Apple's roots the URLs are the lists
  of Apple Root CA, Apple Root CA - G3, WWDR G5 and WWDR G6. They are
  `http://`: the module authenticates each list by its signature, not by
  the transport (an app on Apple platforms needs an App Transport Security
  exception for `crl.apple.com` to fetch them).
- **Monitor `revocationValidUntil`.** It is the earliest `nextUpdate` of the
  lists held. `nil` means some issuer the verifier expects a list from has
  none (none passed, or the list was ignored); a date in the past means a
  list is stale. Alert on both. Apple reissues WWDR G6's list daily.

  ```swift
  if let until = verifier.revocationValidUntil, until > Date() {
      // live revocation is in force
  } else {
      alertOps("live revocation is not in force")
  }
  ```
- **`Verifier(config:)` throws `ConfigError`**, naming the first problem
  and its index, when a list is not a CRL, is over 1 MiB, is signed by no
  issuer the verifier knows, or is older than the list this release was
  built with; when there are more than 16 lists; when a `revocationIssuers`
  certificate does not chain to your roots; or when a `distrust` entry is
  malformed or there are more than 1,000. A genuine list in a form the
  module does not support is ignored instead, and counts as missing. A
  `revocationIssuers` certificate that is itself revoked is set aside with
  its own list, not refused: a path through it fails with
  `.certificateRevoked`.
- **`distrust`** takes `RevokedCertificate(issuer:serial:)` strings:
  `issuer` is the SHA-256, in hex, of the issuing certificate's subject Name
  followed by its subjectPublicKeyInfo, both as encoded in that certificate;
  `serial` is the revoked certificate's serial number in hex. Either letter
  case. The package passes both strings to the module unchanged.
- **With your own roots** `revocationUrls` is empty until you add
  `revocationIssuers`; it then names the lists those issuers may appear on.
  The URL of a list an added issuer signs is written only in the
  certificates it issues, so add it to your downloads by hand.

The full rules are in
[docs/design/revocation.md](../docs/design/revocation.md).

## Resource bounds

| Bound | Value |
|---|---|
| Receipt base64, UTF-8 bytes | 3,145,728 |
| Endpoint request body, UTF-8 bytes | 3,145,728 |
| JWS, UTF-8 bytes | 262,144 |
| Certificates embedded in a receipt | 10 |
| Chain length (below the anchor) | no bound of its own: at most the 10 certificates a receipt embeds; a JWS `x5c` holds exactly 3 |
| SignerInfos in a receipt | 4 |
| ASN.1 nesting depth (CMS envelope, signed content) | 32 |

The module owns every bound; this package adds none and exports none of
the numbers: an input over a size cap is `.tooLarge` (21002 at the
endpoint). JSON has no nesting or length bound of its own: the module
skips a value nobody reads without building it, so only the size caps
bound it (docs/rust-core/DECISIONS.md R40). Past the ASN.1 depth, the
envelope is `MALFORMED` and the signed content `UNREADABLE_PAYLOAD`.
Genuine Apple receipts nest 9 levels deep in the envelope.

## Speed

WasmKit interprets, so this is the slowest host of the nine ports. Measured
on 2026-09-29 with `swift run -c release --package-path swift/bench bench
--threads` on a shared 4-vCPU x86-64 Linux guest (Swift 6.3.3, WasmKit
0.4.1, software bounds checking), with the 0.7 core's `aprv.wasm`, counted
per CPU-second of the process because other work shared the machine:

| Call | Per CPU-second | CPU per call |
|---|---:|---:|
| `verifyReceipt`, a genuine sandbox receipt (G5 chain) | 33 to 42 | 24 to 30 ms |
| `verifySignedData`, the fixture StoreKit 2 transaction | 9 to 10 | 100 to 110 ms |

A JWS costs about 100 ms of CPU here, which is the project's guideline of
about 10 verifications per second per core, with no margin on this machine.
If you verify StoreKit 2 transactions at volume, measure on your own
hardware first. Four threads on one shared `Verifier` scale with the free
cores: each call runs on its own instance, and nothing is locked while the
module runs. Start-up: the first `Verifier` of a process checks and parses
the module in 45 to 170 ms; the first call on an instance then takes 150 to
380 ms, because WasmKit translates each function on first use, and later
receipt calls 25 to 45 ms (the higher figures on a fully busy machine). An
instance's linear memory stays the same size over 500 calls, and the bench
process, with five instances, peaked at about 90 MB resident.

Those figures are WasmKit's direct-threaded interpreter loop, which the
package uses only on Linux x86-64. Everywhere else, macOS and iOS included,
it runs the token-threaded loop (see [Known issues](#known-issues)). On the
same machine that loop verified the G5 receipt at half the rate (24 per
CPU-second against 48) and the StoreKit 2 transaction at about 60 per cent
(6 against 10).

## Thread safety

`Config`, `Verifier`, `ReceiptPayload`, `JsonPayload`, `VerificationResult`
and `Failure` are all `Sendable`. Build one `Verifier` and share it across
every request. It owns a small pool of module instances: a call takes an
idle one or creates one (a few milliseconds, then the roots are parsed once
by `init`), runs on it alone, and gives it back. A trapped instance is
discarded, and so is one whose memory grew past 64 MiB. The parsed module is
shared by every `Verifier` of the process; nothing needs closing.

## Upgrading from 0.7

The answers are 0.7's: every port runs the same module against the same
`fixtures/cases.json`. What changed:

- **Floors**: Swift 6.3, macOS 15, iOS 18 (were 6.1 and macOS 13).
- **`Config.roots`** is `[[UInt8]]?`, DER or PEM bytes, where it was
  `[Certificate]` from swift-certificates: `nil` means Apple's roots built
  into the module. `Config(roots:)` takes DER, and PEM bytes too.
- **One way to build a `Config`**: `Config(roots:clock:)`, both arguments
  defaulted to `nil`, which means Apple's roots and the system clock. It
  never throws. `Config.defaults()` becomes `Config()`, and
  `Config.builder().roots(r).clock(c).build()` becomes
  `Config(roots: r, clock: c)`; `ConfigBuilder` is gone.
- **`Verifier(config:)` throws `ConfigError`** where `ConfigBuilder`'s
  `roots(_:)` and `build()` did: for an empty root set, and for a root the
  module refuses. Write `try Verifier(config: config)`.
- **Dependencies**: swift-certificates and swift-asn1 are gone. WasmKit
  runs the module, and swift-crypto stays, for one SHA-256: the bundled
  module against its pin. 0.7 asked for swift-crypto 4.5.1 or newer, which
  could not resolve next to app-store-server-library-swift; 0.8 takes
  anything from 3.0.0 up to, not including, 6.0.0.
- **The clock is read once per call, always**, before the input is looked
  at; 0.7 read it only when it was needed. The verdicts do not change.
- **`Failure.cause`** is the host's error (a trap, an unusable answer) for
  `.internalError`, and `nil` for the module's own verdicts: the core's
  cause chain stays inside the module.
- **Removed names**: `maxReceiptBytes`, `maxEndpointRequestBytes` and
  `maxJwsBytes` (the caps are 3,145,728, 3,145,728 and 262,144 UTF-8 bytes,
  listed under "Resource bounds"; an input over one is `.tooLarge`), and
  `Environment.appleValue` (use `rawValue`, the same string).
- **The environment is on the payload**: `Environment.fromReceiptType(_:)`
  and `Environment.fromJwsEnvironment(_:)` are gone; read
  `ReceiptPayload.environment` and `JsonPayload.environment`, which the
  verifier states beside the payload. `JsonPayload(json:)` became
  `JsonPayload(json:environment:)`. `toJson()` does not write it.

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
| `appleReceiptRoots()` / `appleJwsRoots()` | `Config.defaults()` (one root set for both; `Config()` in 0.8) |

| 0.6 `VerificationError.Reason` | 0.7 `Reason` |
|---|---|
| `.invalidJwsFormat`, `.invalidReceiptFormat`, `.malformedRequest` | `.malformed` |
| `.requestTooLarge` | `.tooLarge` |
| `.invalidChain` | `.untrustedChain`, or `.invalidCertificate` for a certificate outside its validity window |
| `.invalidCertificate`, `.invalidCertificatePurpose`, `.invalidSignature` | same names |
| `.internalError` for signed content that does not parse | `.unreadablePayload` |
| `.wrongBundleId`, `.wrongEnvironment`, `.wrongAppAppleId`, `.deviceHashMismatch` | gone: the caller's own checks |

## Known issues

- **WasmKit's default interpreter loop crashed on macOS arm64 in a release
  build.** With WasmKit 0.4.1, Swift 6.3.3 and Xcode 26.6, the first guest
  call of a process failed inside WasmKit with an "error" that was really
  an array of WasmKit's `ValueType`, and bridging it to `NSError` raised
  `unrecognized selector` (`-domain`); the process then died. That loop,
  direct threading, is the one part of WasmKit that hands Swift errors
  through C as raw pointers. Linux x86-64 runs it cleanly, including under
  AddressSanitizer. The package therefore picks WasmKit's token-threaded
  loop, which is plain Swift, on every platform but Linux x86-64, at the
  speed cost given under [Speed](#speed).

## Licence

MIT; see the repository root. The code compiled into `aprv.wasm` keeps its
own licences (OpenSSL, wasi-libc with musl, the Rust standard library),
shipped beside it in `Sources/ApplePurchaseReceiptVerifier/Resources/licenses`
and copied into the package's resource bundle.
