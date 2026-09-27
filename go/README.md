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

// Build once, share everywhere: the roots are parsed once, not per call.
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

Go 1.22 or newer, no third-party dependencies.

The library answers one question: did Apple sign this? It checks the chain
to a pinned root, Apple's marker OIDs and the signature, and hands back
everything the payload says. Whether the payload is for your app, your
environment, your user and still current is your decision, made on the
fields it returns ([What to check after verification](#what-to-check-after-verification)).

## Runtime and version floor

- **Go 1.22**, declared as `go 1.22` in `go.mod` and proven by CI: the whole
  suite, conformance included, runs on `go1.22` through `go1.27` with
  `GOTOOLCHAIN=local`, so the floor is what actually compiles rather than
  what a newer toolchain silently upgrades to.
- **No third-party dependencies.** `go.mod` has no `require` block and no
  `go.sum`. Every byte of attacker-supplied ASN.1 (certificates, CMS,
  receipt payloads) and every byte of JSON (a JWS header and payload, the
  endpoint request body) is read by this module's own bounded readers
  (`internal/der`, `encoding.go`), so no third-party parser decides what a
  key, a signature or a claim is. What is delegated to the standard library
  is arithmetic: `crypto/rsa`, `crypto/ecdsa`, `crypto/x509`.
- **No I/O, no goroutines started, no global state beyond the bundled
  roots.** Every entry point is synchronous, and `*Verifier` is immutable
  after construction and safe for concurrent use by multiple goroutines.

## What it will never do

These are the properties the library exists to hold, and each is asserted by
a test rather than only documented.

- **It never reads the operating system's trust store.** Anchors come from
  the caller's `Config` or from `DefaultConfig()`, which holds `go:embed`-ed
  copies of Apple's three published roots, so they work unchanged in a
  `FROM scratch` container. `internal/chain`'s path builder is hand-written
  precisely so `x509.Certificate.Verify` is never called. With a nil
  `VerifyOptions.Roots` it falls back to the platform verifier.
- **It never touches the network.** No OCSP, no CRL, no AIA fetch, no root
  download. Revocation checking is disabled by design; an integrator who
  needs it must layer it on top.
- **It never uses a key no pinned root vouched for.** Certificate signatures
  are checked from the roots down, so a certificate carrying an attacker's
  key (their choice of size and exponent) is never used to check anything
  ([Stranger certificates](#stranger-certificates)).
- **It never returns anything partial.** A failure returns a `*Failure` and
  a `nil` payload; a success returns only data that passed every check, in
  fresh slices that do not alias the input.
- **It never logs, meters or calls back into your code** except for the
  clock you give it. `Reason` is the whole observability surface, and a
  failure message never quotes the input.

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
switching on `Reason` must never see a misconfiguration.

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

`*Failure` implements `error`, with `Cause` holding the parser's error for
`UNREADABLE_PAYLOAD`. Match on `failure.Reason`; never parse
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
| `ReasonInternalError` | `INTERNAL_ERROR` | the library failed (a contained panic after the signature), or the configured clock panicked; no input makes a correct library answer it | 21009 |

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

`Config`'s clock is a `func() int64` (epoch milliseconds), read at most once
per call, memoised for the rest of that call, and only when one of these
needs it, after the input has passed every check that comes before:

- **the certificate-validity instant, when the input states no usable date
  of its own**: a receipt whose creation date (attribute 12) is missing or
  does not parse, a JWS without a representable `signedDate`. Otherwise the
  chain is judged at the date the input states.
- **`request_date`** in the endpoint's response.

A certificate outside its validity window at that instant is
`INVALID_CERTIFICATE`. A clock that panics is contained as `INTERNAL_ERROR`
(21009 at the endpoint), with a fixed message that never carries the
panic's own text.

## What the checks are, and in what order

The order is observable and is part of the contract: an input that fails an
early check reports that check's reason, not a later one.

**JWS (`VerifySignedData`).** Size cap → three segments, each strict
base64url → header JSON (strict UTF-8, no byte order mark, nothing but
whitespace after the object) → `alg` `ES256` and exactly three `x5c`
entries → the certificates decode → the chain at `signedDate` (or the
clock), the intermediate checked against the pinned roots **before** the
leaf is checked against the intermediate → **leaf marker OID**
`1.2.840.113635.100.6.11.1` → **intermediate marker OID**
`1.2.840.113635.100.6.2.1` → ES256 signature. A chain that does not reach a
pinned root is `UNTRUSTED_CHAIN` whatever markers it carries. The marker
checks run only once the chain is trusted. The payload is read before the
chain, for `signedDate`, but a payload that does not parse (trailing
content included) is reported only after the signature:
`UNREADABLE_PAYLOAD` if the signature holds, `INVALID_SIGNATURE` if not, so
nothing unsigned decides which a caller sees.

**Receipt (`VerifyReceipt`).** Size cap → strict base64 → CMS parse,
including the shape of every `SignerInfo`'s `signedAttrs`, whatever its
position → at most four `SignerInfo`s and ten embedded certificates → any
certificate that parses but whose signature is not canonically encoded is
fatal, wherever it sits → the creation date alone (nothing else in the
payload is read yet) → for each `SignerInfo`, every embedded certificate
matching its issuer and serial number, tried in bag order: the chain,
top-down from the pinned roots, at the creation date or the clock →
**signer marker OID** → **WWDR marker OID on the intermediate** → the CMS
signature. A candidate's key is used only once its own chain has passed, so
a stranger certificate that merely claims the genuine signer's identity
cannot shadow it. One candidate of one `SignerInfo` passing is enough; when
none does, the first failure is the verdict. Then the full payload parse,
where any failure is `UNREADABLE_PAYLOAD`.

The receipt signer may use any algorithm `crypto/rsa` and `crypto/ecdsa`
verify: RSA PKCS#1 v1.5 or ECDSA, over MD5 (via `crypto/rsa.VerifyPKCS1v15`
directly, since `crypto/x509` refuses to check an MD5 signature at all),
SHA-1 or the SHA-2 family, and RSA-PSS. A signer that chains to a pinned
root and carries Apple's marker is trusted whatever it signs with. There is
no certificate signature-algorithm allowlist beyond what `crypto/x509`
itself verifies under a pinned chain, so a change on Apple's side does not
reject genuine receipts. A `signatureAlgorithm` that names a hash
(`sha256WithRSAEncryption`, `ecdsa-with-SHA384`, the RSA-PSS parameters)
must name the `SignerInfo`'s `digestAlgorithm`, or the signature is
`INVALID_SIGNATURE`; `rsaEncryption` and `id-ecPublicKey` name none and take
the digest.

The bundled roots are checked against their published SHA-256 fingerprints
when they load, all three or none; a mismatch panics inside `AppleRoots()`
(and so inside `DefaultConfig()`) rather than silently answering
`UNTRUSTED_CHAIN` for everything.

`x5c[2]` is never compared to an anchor and never trusted, and neither is a
receipt's embedded copy of its root: the chain terminates at an anchor the
caller pinned. Trust anchors are trusted by fiat, so **an anchor's own
expiry is not checked**, which is what lets a receipt signed years ago
under a since-expired chain verify at its own creation date.

A certificate on the path (not the anchor) that marks critical an
extension `crypto/x509` does not itself process (`Certificate
.UnhandledCriticalExtensions`) makes the path `UNTRUSTED_CHAIN`, per RFC
5280 §4.2. In `signedAttrs`, `contentType` or `messageDigest` twice, or a
`contentType` that differs from the `eContentType`, is `INVALID_SIGNATURE`
(RFC 5652 §5.3, §11.1).

### Stranger certificates

A receipt's certificate bag is not signed, so anyone can add to it.

- A certificate that genuinely fails to parse, and whose raw bytes do not
  name the `SignerInfo`'s own signer, is exactly the kind of stranger no
  pinned root ever vouches for: it is simply excluded from the top-down
  walk, the same as a certificate that parses fine but names nobody real.
  A genuine receipt padded with such certificates still verifies.
- A certificate that DOES parse, but whose signature is not canonically
  encoded, is fatal wherever it sits, signer or stranger:
  `crypto/x509.ParseCertificate` parses it anyway, silently
  reinterpreting the signature bytes as something other than what was
  actually signed, which is exactly the platform-parser leniency this
  library refuses to trust.
- An unreadable entry whose raw bytes DO name the signer is
  `INVALID_CERTIFICATE`, the same as an unreadable `x5c` entry on the JWS
  path.

The walk starts at the roots, so the cost of a stranger is a name
comparison, however large or broken its key: an 8,192-bit RSA modulus cap
is checked before any modulus is handed to `crypto/rsa`, so an
attacker-chosen oversized key is never the thing that gets slow. The shared
denial-of-service cases pin this with a time budget, and the tests assert
it directly through a seam that records every key used.

## Defensive parsing

Everything this module parses is attacker-supplied, so the bounds are part
of the design rather than a configuration. ASN.1 (`internal/der`): nesting
depth 32 constructed values, a 100,000-node budget per parse, indefinite
(BER) lengths only on constructed values, trailing bytes refused. JSON:
nesting depth 64, numbers of at most 1,000 digits, member names of at most
50,000 characters, applied to the JWS header, the JWS payload and the
endpoint request body alike. Chains: at most six certificates below the
anchor. RSA keys: at most 8,192 bits, refused before any arithmetic.

Input size is capped before anything is decoded, and the caps are Apple's
own (measured on 2026-09-23 against both `verifyReceipt` endpoints):

- the endpoint request body and the receipt base64 string:
  `applereceipt.MaxReceiptBytes` / `MaxRequestBytes`, 3,145,728 UTF-8 bytes.
  Over it is `TOO_LARGE`, 21002 at the endpoint. Apple answers HTTP 413
  there, so check the body's length before the call to do the same.
- the compact JWS: `applereceipt.MaxJWSBytes`, 262,144 bytes, `TOO_LARGE`.

`receipt-data` is decoded exactly as Apple's `verifyReceipt` accepts it:
standard base64 with canonical `=` padding and nothing else. `x5c` entries
are standard base64, JWS segments unpadded canonical base64url, so one
signed payload has one accepted spelling.

Every verify method contains its own panics: before a signature has
verified it is `MALFORMED` (21002), as input nobody vouched for must not be
able to raise the internal-error alarm at will; while the signed receipt
payload is decoded it is `UNREADABLE_PAYLOAD`; after that it is
`INTERNAL_ERROR` (21009). The fixed message never carries the panic's own
text.

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
| `AppleJWSRoots()`, `AppleReceiptRoots()` | `AppleRoots()` (one pinned set for both paths) |
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

## Vendoring

To build the module from a copy rather than `go get`, copy the `go/`
directory whole: `certs/` (the repository's canonical root certificates)
and `roots/certs/` (`go generate`'s copy of them, embedded with
`go:embed`). An embed pattern cannot reach outside its module directory,
so the copy exists precisely so `go build` needs nothing outside `go/`.

**Rotating or adding a root** touches, together:

- the `.cer` file in the repository's `certs/` (and `go/roots/certs/`,
  regenerated with `go generate ./...` and checked byte for byte by a
  test and by CI's `go-generate-check` job);
- the fingerprint in `roots.go`'s `appleRootFingerprints`, the SHA-256
  Apple publishes for the file (check it with `sha256sum` on the DER);
- the fingerprint and count tests in `roots_test.go`.

The roots load all together or not at all, so a file that does not match
its fingerprint panics inside `AppleRoots()` / `DefaultConfig()` at
startup, loudly, rather than leaving every call to answer
`UNTRUSTED_CHAIN`.

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
operation and evaluates the expected JSON Pointers on the result. The
`decodeBase64` cases call the two base64 decoders directly through
test-only exported hooks (`export_test.go`), and a case with a `maxMillis`
budget is timed after a warm-up call, with the SPKI of every key a
certificate-signature check used recorded through
`internal/chain.KeysUsedDuring` and checked against the DoS budget
directly, not only against a clock.

The native suite beyond conformance covers hostile and malformed input, the
resource bounds above, the public API's shape (`apisurface_test.go`), the
module's forbidden-import and forbidden-identifier gates, the trust-pinning
rule from three directions (`systemtrust_test.go` plants a root in the OS
trust store in a subprocess and proves it is still never consulted), the
SHA-1 `CheckSignature`/`CheckSignatureFrom` asymmetry the legacy path
depends on (`sha1_canary_test.go`), stranger certificates and their key
cost, every signer and certificate algorithm, US-Pacific date rendering,
FIPS-140-only mode not crashing the caller (`fips_test.go`), and a
mutation pass over the genuine receipts (`mutation_test.go`). The mutation
pass asserts the invariant that matters: a mutated receipt is either
rejected or produces an identical result.

Two seed-corpus fuzz targets, `FuzzVerifyReceipt` and `FuzzVerifySignedData`
(plus `internal/der`'s own `FuzzParseDER`), run on every `go test` and are
additionally run by CI with `-fuzz` for a fixed budget on every push; a
crasher it finds is written under `testdata/fuzz/` and becomes a permanent
regression case once committed.
