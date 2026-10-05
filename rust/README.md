# apple-purchase-receipt-verifier

Verify Apple in-app purchases locally, with no calls to Apple's servers.

Replaces the deprecated `verifyReceipt` endpoint by validating StoreKit 2
signed JWS payloads and legacy PKCS#7 app receipts against pinned Apple root
certificates.

```bash
cargo add apple-purchase-receipt-verifier
```

```rust
use apple_purchase_receipt_verifier::{Config, Verifier};

// Build once, share everywhere: the roots are parsed once, not per call.
let verifier = Verifier::new(Config::default());

// A legacy app receipt, as the base64 string the app sends.
let receipt = verifier.verify_receipt(receipt_base64)?;
println!("{:?} {}", receipt.bundle_id, receipt.in_app.len());

// Any Apple-signed JWS: a transaction, renewal info, an app transaction or
// a notification. The payload comes back as the JSON text Apple signed.
let payload = verifier.verify_signed_data(jws)?;
println!("{}", payload.json());
```

Synchronous, `#![forbid(unsafe_code)]`, Rust 1.85 or newer.

The library answers one question: did Apple sign this? It checks the chain
to a pinned root, Apple's marker OIDs and the signature, and hands back
everything the payload says. Whether the payload is for your app, your
environment, your user and still current is your decision, made on the
fields it returns ([What to check after verification](#what-to-check-after-verification)).

## Runtime and version floor

- **Rust 1.85.0**, declared as `rust-version` and proven by CI: the whole
  suite, conformance included, runs on a real 1.85.0 toolchain against
  `Cargo.lock`, which is committed and resolved for that floor. Edition 2021.
- **Four direct dependencies**: `aprv-openssl` (`openssl/`, published
  beside this crate), `base64` for `receipt-data` and `x5c` entries,
  `jiff` for the calendar and the US Pacific time of the `_pst` dates
  (one zone, `America/Los_Angeles`, compiled in; no time-zone file is
  read at run time), and `serde_json`, which only writes `to_json()` and
  the endpoint response and never reads input. Every byte of
  attacker-supplied ASN.1 (certificates, CMS, receipt payloads, keys,
  signatures) is parsed by OpenSSL 4 through
  that adapter, which also does the path building and the signature
  arithmetic; this crate keeps the policy (roots, markers, the chain
  instant, the bounds, the reasons and their order) and holds
  `#![forbid(unsafe_code)]`. Every byte of JSON (a JWS header and payload,
  the endpoint request body) is read by `serde_json`, each document as a
  map of raw member values so that nothing the core does not read is
  built (docs/rust-core/DECISIONS.md R40).
- **OpenSSL 4.0 or later.** By default the adapter builds OpenSSL 4.0.2
  from source (openssl-src). That needs this repository's workspace patch
  of openssl-sys; a crates.io build of this crate links a prebuilt
  OpenSSL 4 instead (`OPENSSL_NO_VENDOR=1 OPENSSL_DIR=...`). See
  [`openssl/README.md`](openssl/README.md).
- **No `no_std`, no async.** Nothing here does I/O, every entry point is
  synchronous, and `Verifier` is `Send + Sync + Clone`, so one can be shared
  across threads or dropped into `spawn_blocking`.
- Verifying the largest genuine receipt in the shared corpus (79 KB, 187
  in-app purchases) takes about 1.5 ms in a release build.

## What it will never do

These are the properties the library exists to hold, and each is asserted by
a test rather than only documented.

- **It never reads the operating system's trust store.** Anchors come from
  the caller's `Config` or from `Config::default()`, which holds
  `include_bytes!`-embedded copies of Apple's three published roots, so they
  work unchanged in a `FROM scratch` container. There is no code path to a
  system store, so there is no switch to get wrong. The OpenSSL adapter
  initialises OpenSSL without its configuration file and never gives a
  store default paths, and `openssl/tests/isolation.rs` proves a planted
  `SSL_CERT_FILE`, `SSL_CERT_DIR` and `OPENSSL_CONF` are ignored.
  `deny.toml` refuses, at build time, every crate that could carry one.
- **It never touches the network.** No OCSP, no CRL, no AIA fetch, no root
  download. Revocation checking is disabled by design; an integrator who
  needs it must layer it on top.
- **It never uses a key no pinned root vouched for.** Certificate signatures
  are checked from the roots down, so a certificate carrying an attacker's
  key (their choice of size and exponent) is never used to check anything
  ([Stranger certificates](#stranger-certificates)).
- **It never returns anything partial.** A failure returns a `Failure` and
  nothing else; a success returns only data that passed every check, in
  owned buffers that do not alias the input.
- **It never logs, meters or calls back into your code** except for the
  clock you give it. `Reason` is the whole observability surface, and a
  failure message never quotes the input.

## The API

### `Config`: the roots and the clock

```rust
use apple_purchase_receipt_verifier::{Config, TrustAnchor};

let config = Config::default(); // Apple's three roots, the system clock

let pinned = Config::builder()
    .roots([TrustAnchor::from_der(&root_der)?]) // replaces the defaults
    .clock(|| 1_735_689_600_000)                  // epoch milliseconds
    .build()?;
```

An empty root set is a `ConfigError` from `build()`, never a verdict: a
verifier with no roots would reject everything, and nobody would notice
until production. So is a `TrustAnchor` whose bytes are not a certificate.
`TrustAnchor::from_der_or_pem(&bytes)` reads bytes in either encoding,
told apart by the bytes, and returns every certificate a PEM bundle holds;
it is how the module's `init` reads each root. PEM goes through OpenSSL's
reader, as does `TrustAnchor::from_pem`.

At startup, prefer `Config::builder().build()?` to `Config::default()`,
even with nothing to set: it reports bundled roots that did not load as a
`ConfigError` where the process can stop, while `Config::default()` cannot
fail and leaves every call answering `INTERNAL_ERROR` instead.

The defaults have one spelling, the `Default` trait. 0.7's
`Config::defaults()` is `Config::default()` from 0.8.

### `Verifier`: three methods

| Method | Input | Success |
|---|---|---|
| `verify_receipt(&str)` | the base64 receipt an app sends | `ReceiptPayload` |
| `verify_signed_data(&str)` | any Apple-signed compact JWS | `JsonPayload`: the signed JSON text |
| `verify_receipt_endpoint(Environment, &str)` | a `verifyReceipt` request body | Apple's response body, always |

The first two return `Result<_, Failure>`. The endpoint never fails: the
Apple status code is a field of the body, for every input.

`VERSION` is the library version; `AppleStatus` holds Apple's `verifyReceipt`
status codes as constants.

### `ReceiptPayload`

Every field is an `Option` (or a `Vec`) with public fields, so a test can
build one by hand. Dates are epoch milliseconds (`*_ms`, `i64`), ids are
`i64`, bytes are `Vec<u8>`:

```rust
receipt.receipt_type;                 // Some("Production"), Some("ProductionSandbox"), ...
receipt.bundle_id;                    // decoded attribute 2
receipt.bundle_id_bytes;              // its raw octets: the device-hash input
receipt.receipt_creation_date_ms;
receipt.in_app[0].product_id;
receipt.in_app[0].expires_date_ms;
receipt.unknown_attributes;           // type -> raw values, in receipt order
receipt.to_json();                    // JSON with the same value in every port
```

Decoding follows the rules every port shares: the first occurrence of an
attribute wins; every attribute that does not end up in a typed field (a
later copy, or a value that does not decode, whose field is then `None`) is
kept raw in `unknown_attributes`, the in-app ones in that purchase's own; an
empty date string means "not set" and is not kept. `to_json()` writes
JSON whose parsed value is the same in every port; the bytes may differ.

### `Failure` and `Reason`

`Failure` implements `std::error::Error`, with `source()` holding the
parser's error for `UNREADABLE_PAYLOAD`. Match on `failure.reason()`; never
parse `failure.message()`.

| `Reason` | Token | Raised when | Endpoint |
|---|---|---|---|
| `Malformed` | `MALFORMED` | the base64, ASN.1, CMS or JWS structure is broken, or a structural bound is exceeded | 21002 |
| `TooLarge` | `TOO_LARGE` | the input is over its size cap and was not decoded | 21002 |
| `InvalidSignature` | `INVALID_SIGNATURE` | the signature did not verify | 21003 |
| `UntrustedChain` | `UNTRUSTED_CHAIN` | the chain does not reach a pinned root | 21003 |
| `InvalidCertificate` | `INVALID_CERTIFICATE` | a certificate does not decode, or is outside its validity window at the chain instant | 21003 |
| `InvalidCertificatePurpose` | `INVALID_CERTIFICATE_PURPOSE` | a certificate lacks Apple's marker OID for its place | 21003 |
| `UnreadablePayload` | `UNREADABLE_PAYLOAD` | the chain and signature passed, but the signed content does not parse | 21009 |
| `InternalError` | `INTERNAL_ERROR` | the library failed (a contained panic after the signature), or the configured clock panicked; no input makes a correct library answer it | 21009 |

`UNREADABLE_PAYLOAD` and `INTERNAL_ERROR` are not the client's fault: alert,
log the failure with `VERSION`, and reconcile the purchase through the App
Store Server API rather than deny the user.

## What to check after verification

The library proves Apple signed the payload. Before granting anything, check
what it says:

```rust
let receipt = verifier.verify_receipt(receipt_base64)?;
if receipt.bundle_id.as_deref() != Some("com.example.app") {
    return Err(Rejected::OtherApp);
}
// Production, Sandbox, or None for a receipt_type naming neither (Xcode).
let environment = receipt.environment();
```

Both payloads state the environment Apple's value names:
`ReceiptPayload::environment()` reads `receipt_type`, and
`JsonPayload::environment()` the first of the top-level `environment`, a
notification's `data.environment` and a summary notification's
`summary.environment` that is present. Whether to accept Sandbox is
yours to decide.

For a JWS, read the other claims with your own JSON parser:
`bundleId`, `appAppleId` for a Production `AppTransaction`,
`revocationDate`, `expiresDate`, and `signedDate` for freshness. No payload
is rejected for its age, as in Apple's own App Store Server Libraries: the
right limit depends on the endpoint (Apple retries a server notification for
days), so apply one yourself.

**The device hash** is yours too, when you have the device's identifier:
`SHA1(device_id || opaque_value || bundle_id_bytes)` must equal `sha1_hash`.

**Deduplicate on transaction ids, never on the receipt or JWS bytes.** A
legacy receipt is BER, and one correctly signed receipt can be re-chunked
into different byte strings that carry the same signed content.

## The clock

`Config`'s clock is read at most once per call, and only when one of these
needs it, after the input has passed every check that comes before:

- **the certificate-validity instant, when the input states no usable date
  of its own**: a receipt whose creation date (attribute 12) is missing or
  does not parse, a JWS without a representable `signedDate`. Otherwise the
  chain is judged at the date the input states.
- **`request_date`** in the endpoint's response.

A certificate outside its validity window at that instant is
`INVALID_CERTIFICATE`. A clock that panics is contained as `INTERNAL_ERROR`
(21009 at the endpoint), with a fixed message.

## What the checks are, and in what order

The order is observable and is part of the contract: an input that fails an
early check reports that check's reason, not a later one.

**JWS.** Size cap → three segments, each strict base64url → header JSON
(strict UTF-8, no byte order mark, nothing but whitespace after the object),
`alg` ES256 and exactly three `x5c` entries → the certificates decode →
the chain at `signedDate` (or the clock), the intermediate checked against
the pinned roots **before** the leaf is checked against the intermediate →
**leaf marker OID** `1.2.840.113635.100.6.11.1` → **intermediate marker
OID** `1.2.840.113635.100.6.2.1` → ES256 signature. As on the receipt path,
a chain that does not reach a pinned root is `UNTRUSTED_CHAIN` whatever
markers it carries. A key OpenSSL cannot use is
`INVALID_CERTIFICATE`, judged only once it has been vouched for and is
about to be used. The payload is read before the chain, for `signedDate`, but a
payload that does not parse (text after the object included) is
reported only after the signature: `UNREADABLE_PAYLOAD` if the signature
holds, `INVALID_SIGNATURE` if not, so nothing unsigned decides which a
caller sees.

**Receipt.** Size cap → strict base64 → CMS parse, including the syntax of
every `SignerInfo`'s `signedAttrs`, whatever its position → at most four
`SignerInfo`s and ten embedded certificates → the creation date alone
(nothing else in the payload is read yet) → for each `SignerInfo`: the
signer's certificate → the chain, top-down from the pinned roots, at the
creation date or the clock → **signer marker OID** → **WWDR marker OID on the
intermediate** → the signer's key, which OpenSSL must be able to use → the
CMS signature. One `SignerInfo` passing is enough; when
none does, the first one's failure is the verdict. Then the full payload
parse, where any failure is `UNREADABLE_PAYLOAD`.

The receipt signer may use any algorithm OpenSSL's default provider
verifies: RSA PKCS#1 v1.5, RSA-PSS or ECDSA on its named curves (P-256,
P-384 and P-521 included), over MD5, SHA-1, the SHA-2 family or SHA-3. A signer that chains to a pinned root and carries Apple's
marker is trusted whatever it signs with, so a change on Apple's side does
not reject genuine receipts. The same goes for certificate signatures in the
chain. The signature is checked under the `SignerInfo`'s
`digestAlgorithm`, as OpenSSL checks it, and a hash the
`signatureAlgorithm` names (`sha256WithRSAEncryption`,
`ecdsa-with-SHA384`) is not compared with it. For an RSA signer OpenSSL
reads the `signatureAlgorithm` only to choose PKCS#1 v1.5 or RSA-PSS and
checks a hash only in the PSS parameters; an RSA PKCS#1 v1.5 signature
binds its hash anyway. For an ECDSA signer it does not read the
`signatureAlgorithm` at all.

The bundled roots are checked against their published SHA-256 fingerprints
when they load, all three or none; `Config::builder().build()` refuses an
empty set, and a `Verifier` from `Config::default()` without them answers
`INTERNAL_ERROR`.

`x5c[2]` is never compared to an anchor and never trusted, and neither is a
receipt's embedded copy of its root: the chain terminates at an anchor the
caller pinned. Trust anchors are trusted by fiat, so **an anchor's own expiry
is not checked**, which is what lets a receipt signed years ago under a
since-expired chain verify at its own creation date.

A certificate on the path (not the anchor) that marks critical an
extension OpenSSL's path validation does not process makes the path
`UNTRUSTED_CHAIN`, as it does for a PKIX validator. Accepted when
critical are the extensions OpenSSL 4 lists as supported: keyUsage,
extKeyUsage, basicConstraints, subjectAltName, certificatePolicies,
policyMappings, policyConstraints, inhibitAnyPolicy, nameConstraints,
cRLDistributionPoints, nsCertType, proxyCertInfo, the OCSP noCheck
extension and the two RFC 3779 extensions. Accepted is not evaluated: no
policy check and no purpose is asked for, so certificate policies and
extKeyUsage are not judged, on the leaf or on an intermediate, and
cRLDistributionPoints, OCSP noCheck and nsCertType are not acted on.
Nothing unsigned depends on them: only a certificate a pinned root vouched
for is on the path. Names chain by
their RFC 5280 canonical form (case, whitespace and string type do not
matter), as in Java. A certificate decodes only as
exactly three elements, and a BOOLEAN only with exactly one content octet.
In signedAttrs, `contentType` or `messageDigest` twice, or a `contentType`
that differs from the eContentType, is `INVALID_SIGNATURE`.

An embedded certificate whose structure does not decode is fatal. One
OpenSSL's decoder refuses makes the whole envelope `MALFORMED`. One it
decodes but the 0.7 structure rules refuse (a version above 3, a signature
with unused bits, a repeated extension, an undecodable basicConstraints or
keyUsage) is `INVALID_CERTIFICATE` when it is the **signer** and
`MALFORMED` for any other entry, because the certificate bag is unsigned. A
key the library cannot use is not a structural failure: a certificate's key
is used only once a pinned root vouches for it, so a stranger carrying a
key on an unimplemented curve is ignored and the receipt verifies (shared
case `receipt/verify-with-a-stranger-whose-key-is-unreadable`).

### Stranger certificates

A receipt's certificate bag is not signed, so anyone can add to it. A
certificate there that no pinned root vouches for, directly or through a
certificate it vouched for, is ignored: it never reaches the path builder
and its key is never used, so a genuine receipt padded with such
certificates still verifies. The walk starts at the roots, so a stranger
costs its decoding and a name comparison, however large or broken its key. The shared
denial-of-service cases pin this with a time budget, and the tests assert it
directly through a seam that records every key used.

## Defensive parsing

Everything this crate parses is attacker-supplied, so the bounds are part of
the design rather than a configuration. ASN.1 is decoded by OpenSSL's
template decoder, with its own limits (30 levels of nested templates, six
constructed levels of a string, indefinite (BER) lengths only on
constructed values). Before it, a walk over the headers alone
(`ASN1_get_object`) bounds each value parsed on its own, the CMS envelope
and each attribute SET: at most 32 nested constructed values of any class,
counted as BouncyCastle counts them, and at most 100,000 values; the
primitive values OpenSSL would keep whole are handed to its own decoder.
In the payload, the chunks of a constructed `OCTET STRING` (an attribute
value, the Xcode wrap) must be `OCTET STRING`s, and a tag in
high-tag-number form and a length of more than four octets are refused,
as 0.7's reader refused them. Trailing bytes are
refused. At most 10 embedded certificates, 10 CRLs and 4 SignerInfos,
counted on a shallow decode after the envelope's header walk and before
any certificate is decoded. JSON: strict RFC 8259 grammar, read by
`serde_json` with no nesting or length bound of its own; a value nobody
reads is skipped, not built, so the size caps bound the work (R40).
Chains: at most six certificates, built by OpenSSL from the
certificates a pinned root vouched for. RSA keys: OpenSSL's cap of 16,384
bits, on keys a pinned root vouched for.

Input size is capped before anything is decoded, and the caps are Apple's
own (measured on 2026-09-23 against both `verifyReceipt` endpoints; see
[`docs/evidence/2026-09-23-verifyreceipt-base64.md`](../docs/evidence/2026-09-23-verifyreceipt-base64.md)):

- the endpoint request body and the receipt base64 string: 3,145,728 UTF-8
  bytes. Over it is `TOO_LARGE`, 21002 at the endpoint. Apple answers
  HTTP 413 there, so check the body's length before the call to do the same.
- the compact JWS: 256 KiB, `TOO_LARGE`.

`receipt-data` is decoded exactly as Apple's `verifyReceipt` accepts it:
standard base64 with canonical `=` padding and nothing else. `x5c` entries
are standard base64, JWS segments unpadded canonical base64url, so one
signed payload has one accepted spelling.

The library target additionally denies `unwrap`, `expect`, slice indexing
and `panic!` at compile time, and every public method contains a panic by
where it happened, with a fixed message that never carries the panic's text:
before a signature has verified it is `MALFORMED` (21002), as input nobody
vouched for must not be able to raise the internal-error alarm at will;
while the signed receipt payload is decoded it is `UNREADABLE_PAYLOAD`;
after that it is `INTERNAL_ERROR` (21009). Containment needs unwinding: a
binary built with `panic = "abort"` ends the process on a panic instead.

## Measured worst-case CPU

Measured on 2026-09-27 with `examples/bench.rs --worst-case`, which times
every shared case in `fixtures/cases.json` that carries a time budget:
oversized untrusted keys, a cross-signed certificate mesh, and the encoding
oddities inside certificates. Rust 1.94.1, release build, one thread, on a
shared 4-vCPU KVM guest (Intel Xeon Processor @ 2.10GHz); one second of
warm-up, then ten samples of at least 100 ms each.

| Call | Median | Slowest sample |
|---|---:|---:|
| Slowest hostile case: `receipt/verify-genuine-padded-with-oversized-strangers` (a valid receipt carrying oversized certificates it does not need) | 2.7 ms | 3.3 ms |
| Next: `receipt/reject-untrusted-oversized-intermediates` | 1.4 ms | 1.5 ms |
| Slowest hostile JWS: `signed-data/intermediate-with-a-ca-boolean-of-01-does-not-crash` | 0.84 ms | 1.1 ms |
| Every other budgeted case | under 0.70 ms | under 0.85 ms |
| For scale: `verify_receipt` on the genuine 187-purchase legacy receipt | 1.3 ms | 1.5 ms |
| For scale: `verify_receipt_endpoint` on the same receipt | 3.1 ms | 4.2 ms |

The slowest hostile case costs about twice what `verify_receipt` spends on
the largest genuine receipt, and less than the endpoint spends on it: the
cost of a call follows the size of the input, which the caps above bound,
not the structure an attacker chooses. The machine was shared with other
work, so treat these as an order of magnitude. Run
`cargo run --release --locked --example bench -- --worst-case` for the
hostile cases on your own hardware, and the same command without
`--worst-case` for the genuine receipts.

## The endpoint

```rust
use apple_purchase_receipt_verifier::{AppleStatus, Environment};

let body = verifier.verify_receipt_endpoint(Environment::Production, raw_request_body);
```

The statuses it produces are `0`, `21002`, `21003`, `21007`, `21008` and
`21009`, and no others, because the rest describe conditions that exist only
on Apple's servers. Local 21007 / 21008 routing fails closed: only receipt
types `Production` and `ProductionVPP` count as production. Like Apple's
endpoint, it does **not** check the bundle id: compare `receipt.bundle_id` in
the response before granting anything. `password` and
`exclude-old-transactions` are accepted for compatibility and never read.
See [COMPARISON.md](../COMPARISON.md) for the field-by-field fidelity
account.

## The C ABI: `ffi/`

`ffi/` is a second crate that exposes this library through a C ABI, so C, C++
and any FFI-capable runtime (Elixir NIFs, Lua, ctypes, P/Invoke, Java FFM)
can call it without a reimplementation. It is a `cdylib`/`staticlib` plus a
cbindgen-generated header, and a thin wrapper: every verification decision,
parser and trust rule is this crate's, unchanged.

The shape mirrors this API: one opaque `AprvVerifier` built from roots (DER, or PEM read as `init` reads it)
and an optional fixed clock, `aprv_verify_receipt`, `aprv_verify_signed_data`
and `aprv_verify_receipt_endpoint`, and one
`AprvResult { int32_t status; char *json; }` whose `json` is exactly
`ReceiptPayload::to_json()` or the signed JWS text. `ffi/README.md` has the
ABI rules (ownership, thread safety, the status bands). Prebuilt binaries
are not published yet.

## Upgrading from 0.6

0.7 replaces the three verifiers with one `Verifier` and takes no policy:
no bundle id, no accepted environments, no app Apple id, no device id. The
caller checks those on the returned payload.

| 0.6 | 0.7 |
|---|---|
| `ReceiptVerifier::verify_base64` | `Verifier::verify_receipt`, then compare `bundle_id` |
| `ReceiptVerifier::verify` (DER) | base64-encode, then `verify_receipt` |
| `..._with_device_guid` | compute the device hash from `opaque_value` and `bundle_id_bytes` |
| `JwsVerifier::verify_transaction`, `verify_app_transaction`, `verify_raw` | `Verifier::verify_signed_data`, then read the claims from `json()` |
| `VerifyReceiptEndpoint::verify_receipt_json` | `Verifier::verify_receipt_endpoint` |
| `apple_jws_roots()`, `apple_receipt_roots()` | `Config::default()` |
| `Clock`, `FixedClock` | `Config::builder().clock(\|\| millis)` |
| `VerificationError` | `Failure` |
| `AppReceipt` (`SystemTime` dates) | `ReceiptPayload` (`*_ms` epoch milliseconds) |

| 0.6 `Reason` | 0.7 `Reason` |
|---|---|
| `InvalidJwsFormat`, `InvalidReceiptFormat`, `MalformedRequest` | `Malformed` |
| `RequestTooLarge` | `TooLarge` |
| `InvalidChain` | `UntrustedChain`, or `InvalidCertificate` for a certificate outside its validity window |
| `InternalError` for signed content that does not parse | `UnreadablePayload` |
| `WrongBundleId`, `WrongEnvironment`, `WrongAppAppleId`, `DeviceHashMismatch` | gone: the caller's checks |

The `endpoint` feature is gone: the endpoint is always there, and
`serde_json` is an unconditional dependency that only writes JSON.

## Vendoring

To build the crate from a copy rather than from crates.io, copy `src/`,
`certs/`, `Cargo.toml` and `Cargo.lock`. The three root certificates are
compiled in with `include_bytes!("../certs/...")` from `src/roots.rs`, so
`certs/` must sit next to `src/`. Nothing is read at run time.

**Rotating or adding a root** touches, together:

- the `.cer` file in `certs/` (and the repository's own `certs/`, which a
  test compares byte for byte);
- `APPLE_ROOT_DER` and `APPLE_ROOT_SHA256` in `src/roots.rs`, the second
  being the SHA-256 Apple publishes for the file (check it with
  `sha256sum` on the DER);
- the fingerprint and count tests in `src/roots.rs` and the bundled-roots
  tests in `tests/trust_pinning.rs`.

The roots load all together or not at all, so a file that does not match
its fingerprint leaves `Config::default()` without anchors, and every call
answers `INTERNAL_ERROR`.

**The tests need the shared fixtures.** They look for `fixtures/` with
`cases.json` above the crate directory, or read `APRV_FIXTURES_DIR`
when it is set (`tests/conformance.rs` has its own lookup, above the crate
directory only). A few tests read the build itself: the dependency-set
test reads `Cargo.toml`, the `certs/` drift test reads the repository's
`certs/` next to `fixtures/`, and the date tests read
`tests/data/pacific-transitions.txt`.

**The C ABI** in `ffi/` depends on the crate by path and takes its version
from the crate's `VERSION`, so it vendors along with it; `ffi/include/` is
generated by cbindgen and checked in.

## Testing

```bash
cargo test --locked
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --check
cargo deny check
```

`Cargo.lock` is committed, which is unusual for a library and deliberate here:
CI runs every leg with `--locked` so a hijacked release cannot reach a runner
before the seven-day dependabot cooldown has looked at it. The file has to
stay resolvable on the 1.85.0 floor, so regenerate it with a modern cargo and
the MSRV-aware resolver rather than with `cargo update`:

```bash
CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback cargo +stable generate-lockfile
```

A consumer's build ignores this file; it constrains only this repository.

`tests/conformance.rs` runs `fixtures/cases.json`, the normative
cross-language vector file every port of this library answers, as one named
test per case, and fails unless every case ran. The adapter carries no
case-specific knowledge: it checks each fixture against the digest the
registry records, builds a `Config` from the case, dispatches on the
operation and evaluates the expected JSON Pointers on the result. The
`decodeBase64` cases call the two base64 decoders directly, and a case with
a `maxMillis` budget is timed after a warm-up call.

The native suite beyond conformance covers hostile and malformed input, the
resource bounds above, the public API's shape, the trust-pinning rule from
three directions, OpenSSL's isolation from its environment
(`openssl/tests/isolation.rs`), stranger certificates and their key cost,
every signer and certificate algorithm, US-Pacific date rendering against
vectors generated from the IANA database, and a mutation pass over the
genuine receipts. The
mutation pass asserts the invariant that matters: a mutated receipt is
either rejected or produces an identical result.

`fuzz/` holds six `cargo fuzz` targets (the verifier's three methods, the
DER receipt path, the C ABI's exports, and `aprv.wasm` through its canonical
ABI; OpenSSL's own decoders are fuzzed upstream by OSS-Fuzz) seeded from the
shared fixtures and run by CI for a fixed budget on every push. `fuzz/README.md` lists them and the invariant each asserts
beyond "no panic".

`tests/data/pacific-transitions.txt` carries every `America/Los_Angeles`
offset transition from 1900 to 2100, taken from the IANA database via
Python's `zoneinfo`, and the suite checks the rendering rules at the second
before and the second of each of the 308 of them. The offsets come from
`jiff`, which compiles that one zone in from its own copy of the database,
local mean time before 1883-11-18 included. `tests/datetime.rs` also holds
them, and the renderings, to the hand-written rules this crate carried
until 2026-10-01: every minute from 1883-11-18 to 2100 and every hour to
the end of 9999 in an ignored test (`cargo test --release --test datetime
-- --ignored`), and a sample on every run. Dates render from the year
-9999 to 9999-12-31T23:59:59Z, the receipt grammar's last second; the
endpoint answers a clock outside that range as a broken clock, with
status 21009.
