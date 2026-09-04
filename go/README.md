# apple-purchase-receipt-verifier (Go)

Verify Apple in-app purchases locally — no calls to Apple's servers.

Replaces the deprecated `verifyReceipt` endpoint by validating StoreKit 2
signed JWS transactions and legacy PKCS#7 app receipts against pinned Apple
root certificates. No third-party dependencies: `go.mod` has no `require`
block, and a test fails the build if one appears.

```bash
go get github.com/emindeniz99/apple-purchase-receipt-verifier/go
```

```go
import applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"
```

The import path ends in `/go` because that is the module's directory in the
repository; the package it declares is `applereceipt`, since `go` is a
keyword.

## Legacy PKCS#7 app receipt

```go
verifier, err := applereceipt.NewReceiptVerifier(applereceipt.ReceiptVerifierOptions{
	TrustedRoots: applereceipt.AppleReceiptRoots(),
	BundleID:     "com.example.app",
})
if err != nil {
	return err // a configuration mistake, not a verdict about a receipt
}

receipt, err := verifier.VerifyBase64(receiptFromTheClient)
if err != nil {
	return err // a *VerificationError; see "Errors" below
}
for _, purchase := range receipt.InAppPurchases {
	grant(purchase.ProductID)
}
```

Four entry points, so every input form is reachable with and without the
optional device binding:

| | DER bytes | base64 |
|---|---|---|
| without the device GUID | `Verify` | `VerifyBase64` |
| with the device GUID | `VerifyWithDeviceGUID` | `VerifyBase64WithDeviceGUID` |

The device check computes `SHA1(guid ‖ opaqueValue ‖ bundleIdBytes)` and
compares it, in constant time, with attribute 5. It is optional because a
server does not always hold the device's `identifierForVendor`.

`VerifyReceiptCore(der, roots)` is the same verification **without** the
bundle-id check — the primitive the endpoint below is built on. If you unlock
products with its result, compare `receipt.BundleID` yourself.

## StoreKit 2 / App Store Server JWS

```go
verifier, err := applereceipt.NewJWSVerifier(applereceipt.JWSVerifierOptions{
	TrustedRoots: applereceipt.AppleJWSRoots(),
	BundleID:     "com.example.app",
	// Include Sandbox on any endpoint App Review can reach: review runs
	// production builds against sandbox, and a Production-only accept set
	// rejects purchases during review.
	AcceptedEnvironments: []applereceipt.Environment{
		applereceipt.EnvironmentProduction,
		applereceipt.EnvironmentSandbox,
	},
	AppAppleID:   &appAppleID,   // required to accept a Production AppTransaction
	MaxSignedAge: 5 * time.Minute, // optional staleness policy; zero disables it
})

payload, err := verifier.VerifyTransaction(jws)          // JWSTransactionDecodedPayload
appTxn, err := verifier.VerifyAppTransaction(jws)        // AppTransaction
claims, err := verifier.VerifyRaw(jws)                   // renewal info, notifications
```

`VerifyTransaction` and `VerifyAppTransaction` return typed payloads whose
`Claims` field carries every claim, including ones the struct does not model.
`VerifyRaw` verifies the chain and the signature and enforces no claim at all;
the caller checks `bundleId`, `environment` and `appAppleId` itself.

**Date claims are epoch milliseconds, as `*int64`, exactly as Apple ships
them.** That is contractual across all ports: converting to `time.Time` loses
the raw claim and invites a timezone bug. Only legacy receipt attributes
(`AppReceipt`, `InAppPurchase`) use `time.Time`.

`(*TransactionPayload).IsActiveAt(t)` answers the entitlement question from
the signed claims: not revoked, and not expired if it is a subscription.

## The verifyReceipt-compatible endpoint

A drop-in for a POST to Apple's deprecated endpoint: the same request body,
the same response body, the same status codes — answered locally.

```go
endpoint, err := applereceipt.NewVerifyReceiptEndpoint(
	applereceipt.VerifyReceiptEndpointOptions{
		TrustedRoots: applereceipt.AppleReceiptRoots(),
		Environment:  applereceipt.EnvironmentProduction, // drives 21007/21008
	})

body := endpoint.VerifyReceiptJSON(requestBody)          // JSON in, JSON out
response := endpoint.VerifyReceipt(applereceipt.VerifyReceiptRequest{
	ReceiptData: base64Receipt,
})                                                       // typed in, typed out
```

It never returns an error and never panics: every failure is a status code in
the answer. Like Apple's endpoint it does **not** check the bundle id — the
caller compares `receipt.bundle_id`.

Statuses this produces: `0`, `21002`, `21003`, `21007`, `21008`, `21009`.
`21000`, `21004`, `21005`, `21006`, `21010`, the `21100`–`21199` range and
`is_retryable` are out of scope and never appear
([COMPARISON.md](../COMPARISON.md)). `password` and
`exclude-old-transactions` are accepted and never read.

**No `http.Handler` ships with this package, deliberately.** COMPARISON.md
places status `21000` out of scope on the grounds that this is a body-level
API with no HTTP layer, and a handler would have to answer questions — which
methods, which content types, what body cap, what HTTP status accompanies
21002 — that no other port answered. Wire `VerifyReceiptJSON` into your own
mux in three lines.

The `_pst` fields need the IANA time zone database. A `FROM scratch` or
distroless image has none, and a compiled Go binary does not carry
`$GOROOT/lib/time/zoneinfo.zip` either, so `NewVerifyReceiptEndpoint` returns
an error naming the remedy — add `import _ "time/tzdata"` to your main
package — rather than rendering a wrong instant. `PacificLocation` in the
options takes a `*time.Location` if you would rather supply one. The library
itself does not embed `time/tzdata`: it is ~450 KB in every consumer binary,
including the majority that never touch this endpoint.

## Errors

Every failed verification returns a `*VerificationError` carrying one of
eleven `Reason` values, and nothing else — no logging, no metrics, no
callbacks. The `Detail` string is safe to log: it never contains receipt
bytes, claim values or key material.

```go
var verr *applereceipt.VerificationError
if errors.As(err, &verr) {
	switch verr.Reason {
	case applereceipt.ReasonWrongEnvironment:
		retryAgainstSandbox()
	case applereceipt.ReasonInvalidChain, applereceipt.ReasonInvalidSignature:
		alertSecurity()
	}
}
```

`errors.Is(err, applereceipt.ReasonStalePayload)` also works, as sugar;
`errors.As` is canonical because it also carries the detail and any wrapped
cause. `ReasonOf(err)` is the one-line form.

| Reason | Raised when |
|---|---|
| `INVALID_JWS_FORMAT` | not three segments, header not base64url JSON, `alg` is not ES256, `x5c` is absent or not exactly three entries |
| `INVALID_CERTIFICATE` | an `x5c` entry does not parse as a certificate |
| `INVALID_CERTIFICATE_PURPOSE` | a marker OID is missing: `1.2.840.113635.100.6.11.1` on the JWS leaf and on the receipt signer, `1.2.840.113635.100.6.2.1` on the JWS intermediate |
| `INVALID_CHAIN` | validity window at signing time, name mismatch, issuer signature, disallowed signature algorithm, not a CA, no path to a pinned anchor, path too long, more than ten embedded certificates |
| `INVALID_SIGNATURE` | ES256 signature not 64 bytes or not verifying, leaf key not EC, receipt signer key not RSA, CMS signature or `messageDigest` mismatch |
| `WRONG_BUNDLE_ID` | the payload's bundle id is not the configured one |
| `WRONG_ENVIRONMENT` | the environment (or `receiptType`) claim is outside the accept set |
| `WRONG_APP_APPLE_ID` | a Production `AppTransaction` whose app Apple id is unset or does not match |
| `INVALID_RECEIPT_FORMAT` | unparseable CMS, trailing bytes after the blob, no encapsulated content, no `SignerInfo`, an embedded certificate that does not decode, signer not embedded, unsupported digest OID, bad attribute shape, decoded receipt over `MaxReceiptBytes` |
| `DEVICE_HASH_MISMATCH` | the device-hash check was requested and failed, or the receipt lacks the attributes it needs |
| `STALE_PAYLOAD` | `MaxSignedAge` is set and the payload's own signing date is older than it |

Misconfiguration — no trust anchors, an empty bundle id, an environment other
than Production or Sandbox on the endpoint — is a **plain error from the
`New…` constructor**, never a `*VerificationError`. A caller switching on
`Reason` should never have to consider a programming bug.

## Trust model

- **Pinned anchors only.** Trust comes from the `TrustedRoots` you pass.
  `AppleJWSRoots()` and `AppleReceiptRoots()` return the three published Apple
  roots (Apple Root CA, Apple Root CA - G2, Apple Root CA - G3), compiled into
  the binary with `go:embed`, and both sets are the same three (PLAN.md D15).
  The operating system trust store is never read: `x509.Certificate.Verify`,
  `x509.SystemCertPool` and `x509.CertPool` appear nowhere in the module, the
  path builder is hand-written, and a test enforces all of that by parsing the
  library's own source.
- **No network, ever.** No OCSP, no CRL, no AIA fetch, no runtime root
  download. `net` and `net/http` are not imported, and the same source test
  keeps it that way.
- **Marker OIDs are mandatory.** Without them any Apple developer's own
  certificate — which chains through the same WWDR intermediate to the same
  pinned root — could sign a fully forged receipt. On the JWS path they are
  checked before the chain; on the receipt path after it, so a foreign chain
  reports `INVALID_CHAIN` rather than `INVALID_CERTIFICATE_PURPOSE`.
- **Validity is judged at signing time**, not now: `signedDate`, else
  `receiptCreationDate`, else the receipt's attribute-12 creation date, else
  the system clock. That is what lets a historical payload signed with a
  since-rotated certificate keep verifying.
- **The injected clock cannot move a certificate verdict.** `Now` exists on
  `JWSVerifier` (for the `MaxSignedAge` rule) and on `VerifyReceiptEndpoint`
  (for `request_date`). It reaches nothing else, and `ReceiptVerifier` takes
  no clock at all: a caller injecting one to test staleness, or to work around
  skew, must not thereby be able to accept a receipt signed under an expired
  chain.
- **Defensive parsing.** The BER/DER reader bounds nesting depth (32), node
  count (100,000 — the genuine 79 KB legacy receipt parses to 271 nodes),
  long-form lengths, and rejects trailing bytes after the outermost value.
  It is zero-copy: nesting an indefinite-length value does not multiply the
  bytes a parse materializes, so depth is not an amplification lever.
  Receipts are capped at 1 MiB by default and at ten embedded certificates,
  the latter enforced *before* any certificate is decoded.
- **`MaxReceiptBytes` bounds the decode, not only the parse.** It is a
  ceiling on the DECODED size, and the base64 entry points — including the
  endpoint, which is the untrusted-network surface — stop decoding one byte
  past it. A 300 MB request body against a 1 MiB ceiling allocates about a
  megabyte and answers `21002`. Characters the decoder skips (PEM line
  breaks, whitespace) do not count against the ceiling.
- **An embedded certificate that does not decode is fatal.** The CMS
  certificate bag is the one region of a receipt the `SignerInfo` signature
  does not cover, so it is where a genuine receipt can be rewritten for
  free. An entry `crypto/x509` cannot parse rejects the receipt rather than
  being skipped: a verified result must never describe bytes the library
  could not read.
- **Byte fields are copies.** Everything on a returned `AppReceipt` is
  freshly allocated, so a caller reusing its receipt buffer cannot mutate an
  already-verified receipt, and holding a result does not pin the input's
  backing array.
- **Only `*VerificationError` escapes.** Containment is categorical, including
  panics: under `GODEBUG=fips140=only`, `crypto/sha1` panics rather than
  erroring, and every genuine legacy Apple receipt is SHA-1 signed. Measured
  in a child process, that panic comes back as `INVALID_RECEIPT_FORMAT`
  instead of taking the caller's process down; SHA-256 receipts still verify.

What signatures cannot tell you: a refund, a revocation or a renewal after
signing is invisible offline, and so is a replayed receipt. Track transaction
ids server-side and reconcile against Apple's App Store Server API
([INTENT.md](../INTENT.md)).

## Runtime and version floor

`go 1.22`, following PLAN.md D2's "enterprise reality" rule rather than Go's
own two-release support window: 1.22 is the toolchain in Ubuntu 24.04 LTS's
`golang-go` and in RHEL 9's `go-toolset`. The suite is run on every line from
the floor to current, with `GOTOOLCHAIN=local`, so the floor is a tested fact
and not a claim. Nothing in the design needs anything newer.

No build tags, no cgo, no platform-specific code.

Every verifier is immutable after construction and safe for concurrent use by
multiple goroutines; a `-race` test drives all three from 64 goroutines and
requires identical answers.

## Two Go-specific behaviours worth knowing

**SHA-1 certificate signatures.** `Certificate.CheckSignatureFrom` refuses
them and the `GODEBUG=x509sha1=1` escape hatch was removed in Go 1.24, but
the exported three-argument `Certificate.CheckSignature` still accepts them.
Apple's legacy receipt chain is `sha1WithRSAEncryption` from the leaf up, so
the whole legacy path rests on that asymmetry. It is public API but not a
documented guarantee, so a canary test asserts it on every supported
toolchain; if a future Go closes it, the documented replacement is
`rsa.VerifyPKCS1v15(pub, crypto.SHA1, sha1(tbs), sig)`, which that test also
exercises.

**Base64 strictness.** Receipt and `x5c` base64 is decoded leniently, matching
Java's MIME decoder and Node's `Buffer.from`: whitespace, PEM line breaks and
padding are skipped. Compact-JWS segments are decoded **strictly** — a
character outside the base64url alphabet, a wrong length, or non-zero bits in
the final quantum is `INVALID_JWS_FORMAT`. That is stricter than the other
ports in one observable place: appending junk to a JWS, or flipping the unused
bits of a segment's last character, leaves their answer unchanged and makes
this one reject. Strictness there can only turn an accept into a reject, and
it means every byte of a JWS this port accepts is a byte the signature covers.

## Tests

`go test ./...` runs everything, including the shared cross-language
conformance vectors in `fixtures/cases.json` — the same file the Java, Node,
Python and Swift suites read, with every fixture's `contentSha256` re-checked
against its decoded bytes before any case runs.

Beyond conformance the suite covers hostile and malformed input at every
layer, the certificate-flood and nesting bounds, the unsigned certificate
bag, result aliasing, allocation ceilings measured as a ratio to the input
so they hold on any machine, the OS trust store (a CA is installed into the process's trust store
and the library still rejects a chain under it), FIPS-140-only mode, the
concurrency claim under `-race`, deterministic mutation passes over the
genuine receipts, and three fuzz targets whose seed corpora run on every
build.

## Licence

MIT — see [LICENSE](./LICENSE).

This is one of several implementations that share a single fixture suite,
including Apple's own official test fixtures, and are required to agree byte
for byte. See the [project README](../README.md) for the full picture and
[COMPARISON.md](../COMPARISON.md) for how it differs from Apple's official
libraries.
