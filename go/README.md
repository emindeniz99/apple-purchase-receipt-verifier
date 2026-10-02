# apple-purchase-receipt-verifier

Verify Apple in-app purchases locally, with no calls to Apple's servers.

Replaces the deprecated `verifyReceipt` endpoint by validating StoreKit 2
signed JWS payloads and legacy PKCS#7 app receipts against pinned Apple root
certificates.

```bash
go get github.com/emindeniz99/apple-purchase-receipt-verifier/go
```

```go
import applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"

// Build once, share everywhere: the module is set up once, not per call.
// Verifier is safe for concurrent use by multiple goroutines.
verifier, err := applereceipt.NewVerifier(applereceipt.DefaultConfig())

// A legacy app receipt, as the base64 string the app sends.
receipt, err := verifier.VerifyReceipt(receiptBase64)
fmt.Println(receipt.BundleID, len(receipt.InApp))

// Any Apple-signed JWS: a transaction, renewal info, an app transaction or
// a notification. The payload comes back as the JSON text Apple signed.
payload, err := verifier.VerifySignedData(jws)
fmt.Println(payload.JSON())
```

Go 1.25 or newer, one dependency (wazero, whose only dependency is
`golang.org/x/sys`), no cgo.

`internal/wasm/aprv.wasm` is git-ignored until the real module is committed at integration: copy the file into place (it must match `aprv.wasm.sha256`), because `//go:embed` needs it present to build.

The library answers one question: did Apple sign this? It checks the chain
to a pinned root, Apple's marker OIDs and the signature, and hands back
everything the payload says. Whether the payload is for your app, your
environment, your user and still current is your decision, made on the
fields it returns ([What to check after verification](#what-to-check-after-verification)).

## Runtime and version floor

- **Go 1.25**, declared as `go 1.25.0` in `go.mod` (wazero v1.12.0's own
  floor) and proven by CI: the whole suite, conformance included, runs on
  `go1.25` through `go1.27` with `GOTOOLCHAIN=local`, so the floor is what actually compiles rather than
  what a newer toolchain silently upgrades to.
- **No cgo.** `CGO_ENABLED=0` builds, cross-compiles (Linux, macOS, Windows;
  amd64 and arm64) and runs from a `FROM scratch` image. The one dependency,
  [wazero](https://wazero.io), is a WebAssembly runtime written in Go;
  its one requirement is the Go project's `golang.org/x/sys`.
- **The verification is one WebAssembly module.** `aprv.wasm`, the same file
  every port of this library runs (Node, Python, Java, Swift, Ruby, .NET),
  is embedded with `go:embed` and run by wazero, so a fix in the core reaches
  Go in the next release and Go cannot disagree with the others about a
  verdict. This package holds no verification logic: it reads the clock,
  moves bytes in and JSON out, and turns the answer into Go values. Its
  SHA-256 is checked against `internal/wasm/aprv.wasm.sha256` when the package
  loads, and CI checks that file against the release build.
- **Inputs are cut at one byte over the cap.** No more than 3,145,729 bytes of any input are copied into the module, so the core itself answers `TOO_LARGE` (21002 at the endpoint) and a huge input costs no more memory than a barely oversized one.
- **The module is sandboxed.** It has one import, `random-get`, answered from
  `crypto/rand`; it cannot read a file, the network or the clock. A hostile
  receipt that breaks the parser inside it stays in the module's 256 MiB of
  linear memory, and an instance that traps is discarded.
- **Memory and start-up.** The first `NewVerifier` in a process compiles the
  module, about two seconds on a 4-core machine; later ones take tens of milliseconds. A
  `Verifier` keeps a small pool of instances (one per goroutine that is
  verifying at that moment, at least one kept), each a few MiB, and
  releases them when it is garbage collected. There is nothing to close.
- **No I/O, no goroutines started, no global state beyond the compiled
  module.** `*Verifier` is safe for concurrent use by
  multiple goroutines.

## What it will never do

These are the properties the library exists to hold, and each is asserted by
a test rather than only documented.

- **It never reads the operating system's trust store.** Anchors come from
  the caller's `Config` or from `DefaultConfig()`, which means Apple's three
  published roots, compiled into the module. The module cannot read a file,
  so nothing in the environment can add a root.
- **It never touches the network.** No OCSP, no CRL, no AIA fetch, no root
  download. Revocation checking is disabled by design; an integrator who
  needs it must layer it on top.
- **It never uses a key no pinned root vouched for.** The chain is walked
  from the roots down, so a certificate carrying an attacker's key is never
  used to check anything.
- **It never returns anything partial.** A failure returns a `*Failure` and
  a `nil` payload; a success returns only data that passed every check, in
  fresh slices that do not alias the input.
- **It never logs, meters or calls back into your code** except for the
  clock you give it. `Reason` is the whole observability surface, and a
  failure message never quotes the input.
- **It never turns a broken module into a verdict.** A trap, an answer this
  package cannot read, or a clock that panics is `INTERNAL_ERROR`, never a
  pass and never a guess at what the module meant.

## The API

### `Config`: the roots and the clock

```go
config := applereceipt.DefaultConfig() // Apple's three roots, the system clock

pinned := applereceipt.NewConfig(applereceipt.ConfigOptions{
    Roots: []*x509.Certificate{myRoot}, // replaces the defaults
    Clock: func() int64 { return 1_735_689_600_000 }, // epoch milliseconds
})
verifier, err := applereceipt.NewVerifier(pinned)
```

A nil `*Config`, or one with no trust anchors, is a plain `error` from
`NewVerifier`, never a `*Failure`: a verifier with no roots would reject
everything, and nobody would notice until production, and a caller
switching on `Reason` must never see a misconfiguration. So is a trust anchor
the module refuses (one that is not a certificate). `DefaultConfig()` and
`NewConfig` with no `Roots` send the module an empty list, which means the
three Apple roots compiled into it. The package carries no copy of those
roots, so `DefaultConfig().Roots()` is nil; `Roots()` returns certificates
only when you passed your own. An explicitly empty, non-nil `Roots` slice is
refused by `NewVerifier`.

### `Verifier`: three methods

| Method | Input | Success |
|---|---|---|
| `VerifyReceipt(string)` | the base64 receipt an app sends | `*ReceiptPayload, error` |
| `VerifySignedData(string)` | any Apple-signed compact JWS | `*JSONPayload, error`: the signed JSON text |
| `VerifyReceiptEndpoint(Environment, string)` | a `verifyReceipt` request body | Apple's response body, always, as a `string` |

The first two return `error` as `*Failure` on rejection. The endpoint never
returns an error and never panics: the Apple status code is a field of the
body, for every input.

`applereceipt.Version` is the library version; `AppleStatus`-named
constants (`StatusOK`, `StatusMalformedReceiptData`, ...) hold Apple's
`verifyReceipt` status codes.

### `ReceiptPayload`

Every scalar field is a pointer (`nil` means absent), byte fields are
`[]byte`, ids are `int64`, dates are epoch milliseconds:

```go
receipt.ReceiptType                 // *string: "Production", "ProductionSandbox", ...
receipt.BundleID                    // decoded attribute 2
receipt.BundleIDBytes               // its raw octets: the device-hash input
receipt.ReceiptCreationDateMs       // *int64
receipt.InApp[0].ProductID
receipt.InApp[0].ExpiresDateMs
receipt.UnknownAttributes           // map[int64][][]byte, in receipt order
receipt.ToJSON()                    // JSON with the same value in every port
```

Decoding follows the rules every port shares: the first occurrence of an
attribute wins; every attribute that does not end up in a typed field (a
later copy, or a value that does not decode, whose field is then `nil`) is
kept raw in `UnknownAttributes`, the in-app ones in that purchase's own; an
empty date string means "not set" and is not kept. `ToJSON()` writes
JSON with `encoding/json` whose parsed value is the same in every port; the
bytes may differ.

### `Failure` and `Reason`

`*Failure` implements `error`. `Cause` is nil for a verdict of the module;
it names the machinery when `INTERNAL_ERROR` comes from the wrapper (a trap,
an unreadable answer, the clock). Match on `failure.Reason`; never parse
`failure.Message`.

| `Reason` | Token | Raised when | Endpoint |
|---|---|---|---|
| `ReasonMalformed` | `MALFORMED` | the base64, ASN.1, CMS or JWS structure is broken, or a structural bound is exceeded | 21002 |
| `ReasonTooLarge` | `TOO_LARGE` | the input is over its size cap and was not decoded | 21002 |
| `ReasonInvalidSignature` | `INVALID_SIGNATURE` | the signature did not verify | 21003 |
| `ReasonUntrustedChain` | `UNTRUSTED_CHAIN` | the chain does not reach a pinned root | 21003 |
| `ReasonInvalidCertificate` | `INVALID_CERTIFICATE` | a certificate does not decode, or is outside its validity window at the chain instant | 21003 |
| `ReasonInvalidCertificatePurpose` | `INVALID_CERTIFICATE_PURPOSE` | a certificate lacks Apple's marker OID for its place | 21003 |
| `ReasonUnreadablePayload` | `UNREADABLE_PAYLOAD` | the chain and signature passed, but the signed content does not parse | 21009 |
| `ReasonInternalError` | `INTERNAL_ERROR` | the library failed after the signature held, the module trapped or gave an answer this package cannot read, or the configured clock panicked or answered a time before 1970; no input makes a correct library answer it | 21009 |

`errors.As(err, &failure)` is the canonical read; `errors.Is(err,
applereceipt.ReasonUntrustedChain)` is sugar for the single-reason case, and
`applereceipt.ReasonOf(err)` returns `(Reason, bool)` without an `errors.As`
call. `UNREADABLE_PAYLOAD` and `INTERNAL_ERROR` are not the client's fault:
alert, log the failure with `applereceipt.Version`, and reconcile the
purchase through the App Store Server API rather than deny the user.

## What to check after verification

The library proves Apple signed the payload. Before granting anything, check
what it says:

```go
receipt, err := verifier.VerifyReceipt(receiptBase64)
if err != nil {
    return err
}
if receipt.BundleID == nil || *receipt.BundleID != "com.example.app" {
    return errOtherApp
}
```

For a JWS, read the claims with your own JSON decoder. No typed JWS models
ship with this library; Apple's own `app-store-server-library` publishes
those for languages that have one:

```go
var transaction struct {
    BundleID    string `json:"bundleId"`
    Environment string `json:"environment"`
    ExpiresDate *int64 `json:"expiresDate"`
}
json.Unmarshal([]byte(payload.JSON()), &transaction)
```

`bundleId`, `environment`, `appAppleId` for a Production `AppTransaction`,
`revocationDate`, `expiresDate`, and `signedDate` for freshness. No payload
is rejected for its age, as in Apple's own App Store Server Libraries: the
right limit depends on the endpoint (Apple retries a server notification for
days), so apply one yourself.

**The device hash** is yours too, when you have the device's identifier:
`SHA1(deviceID || OpaqueValue || BundleIDBytes)` must equal `SHA1Hash`.

**Deduplicate on transaction ids, never on the receipt or JWS bytes.** A
legacy receipt is BER, and one correctly signed receipt can be re-chunked
into different byte strings that carry the same signed content.

## The clock

`Config`'s clock is a `func() int64` (epoch milliseconds), read once per
call, before the input is looked at, and handed to the module, which uses it
in two places:

- **the certificate-validity instant, when the input states no usable date
  of its own**: a receipt whose creation date (attribute 12) is missing or
  does not parse, a JWS without a representable `signedDate`. Otherwise the
  chain is judged at the date the input states.
- **`request_date`** in the endpoint's response.

A certificate outside its validity window at that instant is
`INVALID_CERTIFICATE`. A clock that panics, or answers a time before 1970,
is `INTERNAL_ERROR` (21009 at the endpoint) whatever the input is, with a
fixed message that never carries the panic's own text.

## What the checks are, and in what order

The order is observable and is part of the contract: an input that fails an
early check reports that check's reason, not a later one. The core module
makes these checks, and [`docs/design/0.7-api.md`](../docs/design/0.7-api.md)
is where they are written down; the shared cases in `fixtures/cases.json`
pin them, and this package's conformance test runs every one.

**JWS (`VerifySignedData`).** Size cap, three strict base64url segments, the
header (`alg` `ES256`, the `x5c` chain), the chain at `signedDate` (or the
clock), Apple's marker OIDs on the leaf and the intermediate, and last the
signature. A chain that does not reach a pinned root is `UNTRUSTED_CHAIN`
whatever markers it carries. A payload that does not parse is reported only
after the signature, so nothing unsigned decides which reason a caller sees.

**Receipt (`VerifyReceipt`).** Size cap, strict base64, the PKCS#7 structure,
the signer's chain at the receipt's creation date (or the clock), the signer
and WWDR marker OIDs, the signature, and only then the payload's attributes.
A candidate's key is used only once its own chain has passed, so a certificate
that merely claims the genuine signer's identity cannot shadow it. Certificates
in the bag that no pinned root vouches for are ignored, never trusted.

Trust anchors are trusted by fiat, so **an anchor's own expiry is not
checked**, which is what lets a receipt signed years ago under a since-expired
chain verify at its own creation date.

## Defensive parsing

Everything the module parses is attacker-supplied, so its bounds are part of
the design rather than a configuration, and the core owns every one: this
package adds none. ASN.1 nesting depth 32; at most ten embedded
certificates, four `SignerInfo`s, and six certificates below the anchor.
JSON (the JWS header, the JWS payload and the endpoint request body) has no
nesting or length bound of its own: the module skips a value nobody reads
without building it, so only the size caps bound it
(docs/rust-core/DECISIONS.md R40).

Input size is capped before anything is decoded, and the caps are Apple's
own (measured on 2026-09-23 against both `verifyReceipt` endpoints):

- the endpoint request body and the receipt base64 string: 3,145,728 UTF-8
  bytes. Over it is `TOO_LARGE`, 21002 at the endpoint. Apple answers HTTP
  413 there, so check the body's length before the call to do the same.
- the compact JWS: 262,144 bytes, `TOO_LARGE`.

The package exports none of these numbers: the module enforces them, and
its answer says which one an input exceeded.

`receipt-data` is decoded exactly as Apple's `verifyReceipt` accepts it:
standard base64 with canonical `=` padding and nothing else. `x5c` entries
are standard base64, JWS segments unpadded canonical base64url, so one
signed payload has one accepted spelling.

The verify methods never panic for any input. What goes wrong inside the
module is reported by the module: `MALFORMED` before a signature has
verified, as input nobody vouched for must not be able to raise the
internal-error alarm at will, `UNREADABLE_PAYLOAD` while signed content is
read, `INTERNAL_ERROR` (21009 at the endpoint) after that. A module that
traps is `INTERNAL_ERROR` too, its instance is discarded, and the next call
gets a fresh one. A message never carries the trap's own text; the `Cause`
does.

## Speed

Measured with `go test -bench` on a shared 4-vCPU guest (Intel Xeon
Processor @ 2.80GHz, Go 1.24.7, wazero v1.9.0's compiler), one goroutine, on
the 0.7 module (3,005,922 bytes). The machine was busy with other jobs during
every run (load average 8 to 18), so the figures are the best of several runs
and a floor:

| Call | Per second | Time per call |
|---|---:|---:|
| `VerifyReceipt`, the genuine sandbox G5 receipt | about 180 | 5.5 ms |
| `VerifySignedData`, a StoreKit 2 transaction | about 45 | 22 ms |
| `NewVerifier`, after the first (a new instance and its `init`) | | 13 to 20 ms |
| the first `NewVerifier` in a process (compiles the module) | | about 2.3 s |

An instance's linear memory is 2 MiB and does not grow across 2,000 calls; each
instance also costs about 4.3 MB of Go heap. The pool gives each goroutine its
own instance, so throughput grows with cores. The cost of a call follows the
size of the input, which the caps below bound, not the structure an attacker
chooses. For numbers on your own hardware:

```sh
go test -run '^$' -bench . -benchtime 3s -cpu 1,4 .              # through the API
go test -run '^$' -bench . -benchtime 3s ./internal/host         # the module and the ABI alone
```

## The endpoint

```go
body := verifier.VerifyReceiptEndpoint(applereceipt.EnvironmentProduction, rawRequestBody)
```

**Pass the exact bytes the client posted.** `rawRequestBody` must be the
JSON body itself (`application/json`, `{"receipt-data": "..."}`), not a
form re-encoded as `application/x-www-form-urlencoded` by an HTTP
framework or a proxy in front of your handler: this method parses JSON
only, and a form-encoded body simply fails as a malformed request (status
21002) rather than being decoded some other way.

The statuses it produces are `0`, `21002`, `21003`, `21007`, `21008` and
`21009`, and no others, because the rest describe conditions that exist
only on Apple's servers. Local 21007 / 21008 routing fails closed: only
receipt types `Production` and `ProductionVPP` count as production. Like
Apple's endpoint, it does **not** check the bundle id: compare
`receipt.bundle_id` in the response before granting anything. `password`
and `exclude-old-transactions` are accepted for compatibility and never
read.

## Upgrading from 0.6

0.7 replaces the three verifiers with one `Verifier` and takes no policy: no
bundle id, no accepted environments, no app Apple id, no device id, no
`EnvironmentXcode` / `EnvironmentLocalTesting`. The caller checks those on
the returned payload.

| 0.6 | 0.7 |
|---|---|
| `ReceiptVerifier.VerifyBase64` | `Verifier.VerifyReceipt`, then compare `BundleID` |
| `ReceiptVerifier.Verify` (DER) | base64-encode, then `VerifyReceipt` |
| `..._WithDeviceGUID` | compute the device hash from `OpaqueValue` and `BundleIDBytes` |
| `JWSVerifier.VerifyTransaction`, `VerifyAppTransaction`, `VerifyRaw` | `Verifier.VerifySignedData`, then read the claims from `JSON()` |
| `VerifyReceiptEndpoint.VerifyReceiptJSON` | `Verifier.VerifyReceiptEndpoint` |
| `AppleJWSRoots()`, `AppleReceiptRoots()` | `DefaultConfig()` (one pinned set for both paths) |
| a per-verifier `Now func() time.Time` | `ConfigOptions.Clock func() int64` (epoch milliseconds) |
| `VerificationError` | `Failure` |
| `AppReceipt` | `ReceiptPayload` (`*_ms` epoch milliseconds, pointer fields) |

| 0.6 `Reason` | 0.7 `Reason` |
|---|---|
| `ReasonInvalidJWSFormat`, `ReasonInvalidReceiptFormat`, `ReasonMalformedRequest` | `ReasonMalformed` |
| `ReasonRequestTooLarge` | `ReasonTooLarge` |
| `ReasonInvalidChain` | `ReasonUntrustedChain`, or `ReasonInvalidCertificate` for a certificate outside its validity window |
| `ReasonInternalError` for signed content that does not parse | `ReasonUnreadablePayload` |
| `ReasonWrongBundleID`, `ReasonWrongEnvironment`, `ReasonWrongAppAppleID`, a device-hash mismatch | gone: the caller's checks |

## Upgrading from 0.7

0.8 verifies inside `aprv.wasm`, which compiles the three Apple roots in, so
the package no longer carries its own copy of them:

- `AppleRoots()` is gone. `DefaultConfig()` still trusts exactly those three
  roots; nothing else changes for a caller who used them through it.
- `DefaultConfig().Roots()` and the `Roots()` of a `NewConfig` without
  `Roots` return nil instead of three certificates.
- A caller who passed `AppleRoots()` into `ConfigOptions.Roots` next to a
  root of their own now loads Apple's certificates themselves, from
  Apple's PKI page or the repository's `certs/` directory.

0.8 also trims names that duplicated another or only stated the core's
numbers:

| 0.7 | 0.8 |
|---|---|
| `(*ReceiptPayload).String()` | `ToJSON()`, which it returned |
| `(*JSONPayload).String()` | `JSON()`, which it returned |
| `MaxReceiptBytes`, `MaxRequestBytes`, `MaxJWSBytes` | removed: the caps are 3,145,728, 3,145,728 and 262,144 UTF-8 bytes, and an input over one is `TOO_LARGE` (21002 at the endpoint) |
| `MaxJSONNestingDepth`, `MaxJSONMemberNameLength`, `MaxJSONNumberDigits` | removed: the core's JSON bounds (64, 50,000 and 1,000), stated under "Defensive parsing" |

## Vendoring

To build the module from a copy rather than `go get`, copy the `go/`
directory whole. One thing is embedded and must come along:
`internal/wasm/aprv.wasm` and `aprv.wasm.sha256`, the verification module
and its hash. Never replace one without the other; the package refuses to
load when they disagree. The pinned Apple roots are compiled into the
module, so there is no certificate file to carry.

**The tests need the shared fixtures.** They look for `fixtures/` with
`cases.json` above the module directory, or read `APRV_FIXTURES_DIR`
when it is set.

## Testing

```bash
go test ./...
go test -race -count=2 ./...
gofmt -l .          # must print nothing
go vet ./...
```

`conformance_test.go` runs `fixtures/cases.json`, the normative
cross-language vector file every port of this library answers, as one
named test per case, and fails unless every case ran. The adapter carries
no case-specific knowledge: it checks each fixture against the digest the
registry records, builds a `Config` from the case, dispatches on the
operation and evaluates the expected JSON Pointers on the result. 0.7 has no
public base64 decoder, so the `decodeBase64` groups run through
`VerifyReceipt` and through a JWS whose `x5c` carries the text, and check
which side of the base64 rule each text lands on. A case with a `maxMillis`
budget is timed after a warm-up call.

Beyond conformance (this package holds no verification logic to test):

- `facade_test.go` runs the wrapper over `testdata/mirror/mirror.wasm`, a
  test double of the module's ABI that answers with its own input, so a test
  chooses the module's answer: every field of a verified receipt, each of the
  eight reasons, answers that are not the wire (an unknown member, a reason
  outside the eight, an id that is not a decimal integer) which must be
  `INTERNAL_ERROR`, a trap and recovery, the clock read once per call and
  before the input, and the six outcomes of the ABI (verified, failed,
  misuse, ABI mismatch, trap, unreadable answer);
- `concurrency_test.go` answers every case once, then again on several
  goroutines through the same Verifiers, under `-race` in CI;
- `internal/host` runs the ABI tests of the canonical-ABI round (`env` 2, 255
  and 2^32-1 trap; verify before `init` and a second `init` trap; a failing
  `random-get` traps; a trap in one instance leaves another verifying; 2,000
  calls leave memory the same size) and tests the pool: a trapped instance is
  never reused, an abandoned pool releases its instances, a module of another
  ABI version or with an import beyond `random-get` is refused, and a hostile
  module cannot grow past 256 MiB;
- `internal/wasm` refuses a module that differs from its hash file by one
  byte;
- `apisurface_test.go` locks the public API's shape and keeps verification
  packages (`encoding/asn1`, `crypto/ecdsa`, `math/big`, and the rest) out of
  the library;
- two seed-corpus fuzz targets, `FuzzVerifyReceipt` and `FuzzVerifySignedData`,
  run on every `go test` and are run by CI with `-fuzz` for a fixed budget; a
  crasher is written under `testdata/fuzz/` and becomes a permanent
  regression case once committed.

`go run ./internal/corpusrun CALLS.jsonl` runs a calls file through the same
host layer for the corpus parity check (see `CI-NOTES.md`).
