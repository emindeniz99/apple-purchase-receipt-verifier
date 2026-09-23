# apple-purchase-receipt-verifier

Verify Apple in-app purchases locally — no calls to Apple's servers.

Replaces the deprecated `verifyReceipt` endpoint by validating StoreKit 2
signed JWS transactions and legacy PKCS#7 app receipts against pinned Apple
root certificates.

```bash
cargo add apple-purchase-receipt-verifier
```

```rust
use apple_purchase_receipt_verifier::{
    apple_jws_roots, apple_receipt_roots, Environment, JwsVerifier, ReceiptVerifier,
};

// Legacy PKCS#7 app receipt
let receipts = ReceiptVerifier::builder()
    .trusted_roots(apple_receipt_roots().iter().cloned())
    .bundle_id("com.example.app")
    .build()?;
let receipt = receipts.verify_base64(receipt_b64)?;
println!("{:?} {}", receipt.receipt_type, receipt.in_app_purchases.len());

// StoreKit 2 signed transaction
let transactions = JwsVerifier::builder()
    .trusted_roots(apple_jws_roots().iter().cloned())
    .bundle_id("com.example.app")
    .accepted_environments([Environment::Production, Environment::Sandbox])
    .build()?;
let transaction = transactions.verify_transaction(jws)?;
println!("{:?} {:?}", transaction.product_id, transaction.expires_date);
```

Synchronous, `#![forbid(unsafe_code)]`, Rust 1.85 or newer.

## Runtime and version floor

- **Rust 1.85.0**, declared as `rust-version` and proven by CI: the whole
  suite, conformance included, runs on a real 1.85.0 toolchain against
  `Cargo.lock`, which is committed and resolved for that floor. Edition 2021.
- **Nine direct dependencies**, all of them primitives: `rsa`, `p256`,
  `p384`, `sha1`, `sha2`, `digest` and `subtle` for the arithmetic,
  `serde_json` for the JWS payloads, which are JSON, and `base64` for
  `receipt-data` and `x5c` entries. Every byte of
  attacker-supplied ASN.1 — certificates, CMS,
  receipt payloads, keys, signatures — is parsed by this crate's own bounded
  reader, so no third-party parser decides what a key or a signature is.
  What is delegated is arithmetic.
- **No `no_std`, no async.** Nothing here does I/O, every entry point is
  synchronous, and the verifiers are `Send + Sync + 'static`, so one can be
  shared across threads or dropped into `spawn_blocking`.
- Verifying the largest genuine receipt in the shared corpus — 79 KB with
  187 in-app purchases — is sub-millisecond in a release build.

## What it will never do

These are the properties the library exists to hold, and each is asserted by
a test rather than only documented.

- **It never reads the operating system's trust store.** Anchors come from
  the caller's argument or from `apple_jws_roots()` / `apple_receipt_roots()`,
  which are `include_bytes!`-embedded copies of Apple's three published
  roots — so they work unchanged in a `FROM scratch` container. There is no
  code path to a system store, so there is no switch to get wrong.
  `deny.toml` refuses, at build time, every crate that could carry one.
- **It never touches the network.** No OCSP, no CRL, no AIA fetch, no root
  download. Revocation checking is disabled by design; an integrator who
  needs it must layer it on top.
- **It never judges a certificate at a clock the caller controls.** See
  [The clock](#the-clock).
- **It never returns anything partial.** A failure returns a
  `VerificationError` and nothing else; a success returns only data that
  passed every check, in owned buffers that do not alias the input.
- **It never logs, meters or calls back.** `Reason` is the whole
  observability surface, and a detail string never contains receipt bytes,
  claims or key material.

## The three entry points

### `JwsVerifier` — StoreKit 2 and Server Notifications V2

```rust
let verifier = JwsVerifier::builder()
    .trusted_roots(apple_jws_roots().iter().cloned())
    .bundle_id("com.example.app")
    .accepted_environments([Environment::Production, Environment::Sandbox])
    .app_apple_id(1_234_567_890)          // required for Production AppTransactions
    .max_signed_age(Duration::from_secs(300))
    .build()?;

let transaction = verifier.verify_transaction(jws)?;   // JWSTransactionDecodedPayload
let app = verifier.verify_app_transaction(jws)?;       // AppTransaction
let claims = verifier.verify_raw(jws)?;                // renewal info, notifications
```

`verify_raw` checks the chain and the signature and **enforces no claim** —
the caller checks bundle id, environment and app Apple id in the returned
claims itself.

Include `Environment::Sandbox` on any endpoint App Review can reach: App
Review runs production builds against sandbox.

**Apple's date claims stay epoch-millisecond integers** — `signed_date`,
`purchase_date`, `expires_date`, `revocation_date`,
`receipt_creation_date` — exactly as Apple ships them. That is contractual
across every port of this library, and it is not an oversight to be
"improved" into a date type: converting loses the raw claim and makes two
ports disagree about what the same payload says. Only *receipt attribute*
dates become `SystemTime`.

Every claim, modelled or not, is on `payload.claims`.
`payload.is_active_at(now)` answers the entitlement question from the signed
claims alone — a refund or a renewal after signing is invisible to it.

### `ReceiptVerifier` — legacy PKCS#7 app receipts

```rust
let verifier = ReceiptVerifier::builder()
    .trusted_roots(apple_receipt_roots().iter().cloned())
    .bundle_id("com.example.app")
    .build()?;

verifier.verify(der)?;
verifier.verify_base64(text)?;
verifier.verify_with_device_guid(der, guid)?;
verifier.verify_base64_with_device_guid(text, guid)?;
```

`verify_base64` and `verify_base64_with_device_guid` decode exactly what
Apple's verifyReceipt accepts as `receipt-data` (measured 2026-09-23, see
[`docs/evidence/2026-09-23-verifyreceipt-base64.md`](../docs/evidence/2026-09-23-verifyreceipt-base64.md)):
standard base64 (`+`/`/`) with the canonical `=` padding and nothing else.
Whitespace anywhere, the base64url alphabet, omitted or extra padding,
anything after the padding and an empty string are `INVALID_RECEIPT_FORMAT`
(`21002` at the endpoint) before any bytes reach the CMS parser. Unused low
bits in the last data character are accepted, as Apple accepts them. See
`decode_receipt_base64` in `base64.rs`.

Every input form is reachable with and without the device GUID. Passing one
additionally enforces the device binding:
`SHA1(guid ‖ opaqueValue ‖ bundleIdBytes)` must equal attribute 5, compared
in constant time. The check is optional by design — a server does not always
have the GUID.

Attribute types the library does not model are exposed verbatim on
`unknown_attributes`, type → the raw verified-but-undecoded values, so a
field Apple adds later stays reachable without a library update.

`verify_receipt_core(der, anchors)` is the same chain-and-signature
verification **without** the bundle-id check — the primitive the endpoint is
built on. It is public because the alternative is a wildcard bundle id
inside a security library, and it is documented the way it has to be: a
caller that unlocks a product on the strength of it, without comparing
`bundle_id`, will accept a genuine, correctly signed receipt from a
different app.

It is the one entry point that takes its anchors as a plain argument rather
than through a builder, so it is the one that can still be called wrong. Its
error is `CoreError`, not `VerificationError`: an empty anchor set is
`CoreError::Config` and *not a verdict*, because reporting it as
`INVALID_CHAIN` would make an anchor-loading bug — a typo'd path, an empty
environment variable, a `Vec` filtered to nothing — look exactly like a
forged receipt. `error.reason()` is `Option<Reason>` for the same reason:
`None` means no check ran.

### `VerifyReceiptEndpoint` — Apple's wire contract, locally

```rust
let endpoint = VerifyReceiptEndpoint::builder()
    .trusted_roots(apple_receipt_roots().iter().cloned())
    .environment(Environment::Production)
    .build()?;

let result = endpoint.verify_receipt_result(&VerifyReceiptRequest::new(receipt_b64));
let result = endpoint.verify_receipt_result_from_json(raw_request_body);
let result = endpoint.verify_receipt_data(receipt_b64);   // receipt-data alone, no envelope

let response: VerifyReceiptResponse = result.to_response(); // Apple's body, typed
let json: String = result.to_json();                         // Apple's body as JSON

let json = endpoint.verify_receipt_json(raw_request_body);   // same as ..._from_json(body).to_json()
```

No endpoint method returns an error or panics. The Apple status code is a
field of the body, for every input, including one that is not JSON
(`{"status":21002}`). The statuses it can produce are `0`, `21002`, `21003`,
`21007`, `21008` and `21009`, and no others, because the rest describe
conditions that only exist on Apple's servers. Local 21007 / 21008 routing
fails closed: only receipt types `Production` and `ProductionVPP` count as
production.

A `VerifyReceiptResult` holds one verification. `status()` is the answer for
the endpoint's own environment. `outcome()` is a `VerifyReceiptOutcome`:
`Verified(AppReceipt)` whenever the receipt bytes verified, 21007 and 21008
included, or `Failed { reason, cause }`. `verified()`, `receipt()`,
`failure_reason()` and `failure_cause()` read the same thing without a
`match`. The response is rendered only when you call `to_response()` or
`to_json()`. Only the endpoint can create a result, and it is immutable.

```rust
match result.outcome() {
    VerifyReceiptOutcome::Verified(receipt) => { /* compare receipt.bundle_id, unlock */ }
    VerifyReceiptOutcome::Failed { reason, .. } => { /* reject; log reason.as_str() */ }
}
```

**Retrying in the other environment costs no second verification.**
`to_response_in(environment)` and `to_json_in(environment)` render what an
endpoint of that environment would answer, recomputing the status from the
receipt's own type each time:

| receipt | on `Production` | on `Sandbox` |
|---|---|---|
| `Production`, `ProductionVPP` | 0 | 21008 |
| any other type, or none | 21007 | 0 |
| failed verification | its own status | its own status |

`Xcode` and `LocalTesting` return the same `ConfigError` the builder returns
for them. A sandbox receipt never renders as a production 0, whichever
endpoint verified it. 21007 and 21008 bodies carry the status alone, as
Apple's do.

**Failure reasons.** `failure_reason()` is a `Reason`:

| `failure_reason()` | status | when |
|---|---|---|
| `RequestTooLarge` | 21002 | the raw body is over `MAX_REQUEST_BYTES` (3,145,728 UTF-8 bytes); Apple answers HTTP 413 here, see [Defensive parsing](#defensive-parsing) |
| `MalformedRequest` | 21002 | the body is not a JSON object or nests deeper than 64, or `receipt-data` is missing, empty or not a string |
| `InvalidReceiptFormat` | 21002 | `receipt-data` is not receipt base64, is over `MAX_RECEIPT_BYTES`, or its CMS envelope does not parse |
| `InvalidChain`, `InvalidSignature`, other certificate reasons | 21003 | the receipt did not authenticate |
| `InternalError` | 21009 | not the client's fault: the receipt authenticated but this crate cannot read its signed content (`failure_cause()` holds the parser's detail), or a panic inside the endpoint was contained (`failure_cause()` holds its message). Alert and retry or escalate; do not deny the user |

**`request_date`.** Each entry point has an `_at` variant that takes a
`SystemTime` for `request_date` in place of the endpoint's clock. Without
one, the endpoint reads its clock once per call and `request_date()` returns
that instant. The instant reaches `request_date` and nothing else:
certificate validity never sees it (see [The clock](#the-clock)).

Like Apple's endpoint, this does **not** check the bundle id: compare
`receipt.bundle_id` yourself before granting anything, or use
`ReceiptVerifier`, which checks it for you. `password` and
`exclude-old-transactions` are accepted for compatibility and never read.
See [COMPARISON.md](../COMPARISON.md) for the field-by-field fidelity
account.

## The error vocabulary

Verification returns `Result<_, VerificationError>`. Match on
`error.reason()`; never parse the message. `Reason::as_str()` yields the
canonical token, identical in every port of this library.

| `Reason` | Token | Raised when |
|---|---|---|
| `InvalidJwsFormat` | `INVALID_JWS_FORMAT` | not three segments, a segment that is not base64url JSON, `alg != ES256`, or an `x5c` that is not exactly three entries |
| `InvalidCertificate` | `INVALID_CERTIFICATE` | an `x5c` entry is not a parseable certificate |
| `InvalidCertificatePurpose` | `INVALID_CERTIFICATE_PURPOSE` | a certificate lacks the Apple marker OID for its role |
| `InvalidChain` | `INVALID_CHAIN` | the path does not reach a pinned anchor, or a certificate was not valid at the signing instant |
| `InvalidSignature` | `INVALID_SIGNATURE` | the payload or receipt signature did not verify |
| `WrongBundleId` | `WRONG_BUNDLE_ID` | the verified payload names another bundle |
| `WrongEnvironment` | `WRONG_ENVIRONMENT` | the environment is outside the accepted set |
| `WrongAppAppleId` | `WRONG_APP_APPLE_ID` | a Production `AppTransaction` does not name the configured app Apple id |
| `InvalidReceiptFormat` | `INVALID_RECEIPT_FORMAT` | the PKCS#7/CMS envelope could not be parsed |
| `DeviceHashMismatch` | `DEVICE_HASH_MISMATCH` | the device hash does not match attribute 5 |
| `StalePayload` | `STALE_PAYLOAD` | the payload was signed longer ago than `max_signed_age` |
| `InternalError` | `INTERNAL_ERROR` | the receipt's chain and signature verified, but its signed content cannot be read: not the client's fault, so alert and retry or escalate rather than deny |

The vocabulary is **closed** by the cross-port contract: a thirteenth reason
would be a change to the shared vector file and to every port at once.
`Reason` is nevertheless `#[non_exhaustive]`, so that if that ever happens a
caller with a `_ => reject` arm keeps compiling and keeps failing closed.
That arm is a safety net, not an extension point.

`Reason` also has `MalformedRequest` (`MALFORMED_REQUEST`) and
`RequestTooLarge` (`REQUEST_TOO_LARGE`), but only as a `VerifyReceiptResult`
failure reason. No verifier returns either, and `Reason::all()` lists only
the twelve above. `InternalError` joined that list last, so every earlier C
ABI reason code kept its number and `INTERNAL_ERROR` is 12.

**Misconfiguration is a different type.** Empty trust anchors, an empty
bundle id, an empty accepted-environment set, an unparseable anchor and an
endpoint environment other than Production or Sandbox all return
`ConfigError` from `build()`. A programming mistake must not be catchable as
a verification verdict. The free `verify_receipt_core` has no `build()` to
fail in, so it returns `CoreError::Config` instead — see above.

## Integrating: from verified payload to entitlement

The backend flow these calls sit inside is written out once in the
[project README](../README.md#integrating-from-verified-payload-to-entitlement):
verify offline, deny on any failure, check the refund field, refresh a payload
past the freshness window, guard against replay on the transaction id, then
grant. That section also carries the policy table saying what each reason
means and which ones are worth an alert. Here are its two branches in this
port's API.

A StoreKit 2 signed transaction:

```rust
use std::time::Duration;

use apple_purchase_receipt_verifier::{
    apple_jws_roots, ConfigError, Environment, JwsVerifier, Reason,
};

fn build_verifier() -> Result<JwsVerifier, ConfigError> {
    JwsVerifier::builder()
        .trusted_roots(apple_jws_roots().iter().cloned())
        .bundle_id("com.example.app")
        .accepted_environments([Environment::Production, Environment::Sandbox])
        .max_signed_age(Duration::from_secs(300)) // the freshness window
        .build()
}

fn redeem_transaction(verifier: &JwsVerifier, user_id: &str, jws: &str) -> Verdict {
    let payload = match verifier.verify_transaction(jws) {
        // step 2
        Ok(payload) => payload,
        Err(e) if e.reason() == Reason::StalePayload => {
            // step 4: ask the client for a fresh jwsRepresentation, or fetch
            // one from the App Store Server API and verify that instead
            return Verdict::Refresh;
        }
        Err(e) => {
            tracing::warn!(reason = e.reason().as_str(), "purchase rejected");
            return Verdict::Denied;
        }
    };

    if payload.revocation_date.is_some() {
        // step 3
        return Verdict::Denied;
    }

    let Some(id) = payload.transaction_id.as_deref() else {
        return Verdict::Denied;
    };
    if grants::exists(id) {
        // step 5
        return Verdict::Denied;
    }
    grants::record(id, payload.original_transaction_id.as_deref(), user_id);

    grant(user_id, payload.product_id.as_deref());
    Verdict::Granted
}
```

The legacy PKCS#7 app receipt is the same policy on the other input, the one
StoreKit 1 apps and older SDKs still send:

```rust
use std::time::{Duration, SystemTime};

use apple_purchase_receipt_verifier::{apple_receipt_roots, ConfigError, ReceiptVerifier};

fn build_receipt_verifier() -> Result<ReceiptVerifier, ConfigError> {
    ReceiptVerifier::builder()
        .trusted_roots(apple_receipt_roots().iter().cloned())
        .bundle_id("com.example.app")
        .build()
}

// Same policy keyed on the receipt's own dates. `verify_base64` takes the
// string the client sends; `VerifyReceiptEndpoint` is the alternative,
// answering Apple's `verifyReceipt` JSON shape with a status instead.
fn redeem_receipt(
    verifier: &ReceiptVerifier,
    user_id: &str,
    receipt_data: &str,
    product_id: &str,
) -> Verdict {
    let Ok(receipt) = verifier.verify_base64(receipt_data) else {
        return Verdict::Denied; // step 2
    };
    let now = SystemTime::now();
    let Some(purchase) = receipt
        .in_app_purchases
        .iter()
        .find(|p| p.product_id.as_deref() == Some(product_id))
    else {
        return Verdict::Denied;
    };

    if purchase.cancellation_date.is_some() {
        // step 3
        return Verdict::Denied;
    }
    if purchase.expires_date.is_some_and(|at| at <= now) {
        return Verdict::Denied;
    }

    // step 4: no max_signed_age here, so compare the creation date. Past the
    // window, ask the client to refresh its receipt, or call the App Store
    // Server API by transaction_id and verify the JWS it returns.
    let fresh = receipt
        .creation_date
        .and_then(|at| now.duration_since(at).ok())
        .is_some_and(|age| age <= Duration::from_secs(300));
    if !fresh {
        return Verdict::Refresh;
    }

    let Some(id) = purchase.transaction_id.as_deref() else {
        return Verdict::Denied;
    };
    if grants::exists(id) {
        // step 5
        return Verdict::Denied;
    }
    grants::record(id, purchase.original_transaction_id.as_deref(), user_id);

    grant(user_id, purchase.product_id.as_deref());
    Verdict::Granted
}
```

## The clock

The injected `Clock` is read in exactly two places and nowhere else:

1. the `STALE_PAYLOAD` comparison in `JwsVerifier`;
2. the `request_date` / `_ms` / `_pst` triple in `VerifyReceiptEndpoint`.

**Certificate validity is never judged at it.** Validity is judged at the
payload's `signedDate` / `receiptCreationDate`, or at the receipt's
attribute-12 creation date; where the input states no date of its own, the
fallback reads the system clock directly. A caller injecting a clock — to
test staleness, or to work around skew — must not thereby be able to accept
an expired chain or expire a live one.

`ReceiptVerifier` therefore takes **no clock at all**: it would have no
consumer, and an option with no consumer is an invitation to wire it into
the one place it must never reach.

## What the checks are, and in what order

The order is observable and is part of the contract: a payload that fails an
early check reports that check's reason, not a later one.

**JWS.** Segment shape → header JSON → `alg` → `x5c` → certificates parse →
**leaf marker OID** `1.2.840.113635.100.6.11.1` → **intermediate marker
OID** `1.2.840.113635.100.6.2.1` → payload JSON → chain at the signing
instant → ES256 signature → staleness → bundle id → environment → app Apple
id.

**Receipt.** Base64 → CMS parse (trailing bytes after the blob are refused)
→ **the creation date alone** (attribute 12; nothing else in the payload is
decoded yet) → **at most ten embedded certificates**, checked before any is
decoded → signer is among them → **the signer is a certificate this crate
can read** → chain at the creation date, or at the system clock when that
date is missing, empty, unreadable or stated twice → **signer marker OID** →
RSA key, SHA-1 or SHA-256 digest → CMS signature → **full payload parse**,
where any failure is `INTERNAL_ERROR` → bundle id → device hash.

Nothing is trusted before the chain and the signature, so reading the
creation date never rejects a receipt. The chain comes before the signature
so the attacker's own key (their RSA size and exponent) is never run before
it is trusted. A payload the crate cannot read after that is content a
trusted signer signed, so it is `INTERNAL_ERROR` (21009): reporting it as
`INVALID_RECEIPT_FORMAT` (21002) would tell an app server to deny a user
who may well have paid.

Two orderings are load-bearing and deliberately opposite. On the JWS path
the marker OIDs are checked **before** the chain; on the receipt path the
marker OID is checked **after** it, so a receipt signed under a foreign
chain reports `INVALID_CHAIN` rather than a purpose error.

`x5c[2]` is never compared to an anchor and never trusted, and neither is a
receipt's embedded copy of its root. Swapping either for another PKI's root
changes nothing, because the chain terminates at an anchor the caller
pinned. Being untrusted is not the same as being unread: all three `x5c`
entries are parsed, and an entry that is not a certificate is
`INVALID_CERTIFICATE` at whichever index it sits.

Trust anchors are trusted by fiat: **an anchor's own expiry is not
checked**. That is standard PKIX trust-anchor semantics, and it is what lets
a receipt signed years ago under a since-expired chain verify at its own
creation date.

## A verified blob is not an identifier

**Do not dedupe on the receipt or JWS bytes.** Deduplicate on
`transaction_id` / `original_transaction_id` (JWS) or on the in-app
purchases' transaction ids (receipt), which is what `PLAN.md` D4 means by
"replay defence is transaction-id bookkeeping".

The reason is not laziness, it is the formats. A legacy receipt is BER, and
genuine Xcode and BouncyCastle receipts really do use its constructed,
indefinite-length forms, so the CMS `eContent` of one correctly signed
receipt can be re-chunked into different byte strings whose concatenated
content octets — the bytes the RSA signature covers — are identical. This
crate refuses the sharper version of that (a constructed `OCTET STRING`
whose children are not `OCTET STRING`s is a malformed receipt, not a payload
to be joined), but legal re-chunking remains, and it always will: rejecting
BER would reject Apple's own Xcode receipts.

The JWS side is closed instead of merely documented. The three segments are
decoded as unpadded canonical base64url (RFC 7515 §2), so one signed payload
has exactly one accepted spelling; a segment that is not that exact spelling
is `INVALID_JWS_FORMAT`, decided before any cryptography runs, the same class
as a header that is not base64url JSON. An `x5c` entry is a certificate,
not a segment, and RFC 7515 §4.1.6 makes it standard base64: a character
outside that alphabet, a line break, a base64url `-` or `_`, or omitted or
extra `=` padding is `INVALID_CERTIFICATE`, refused rather than skipped, as in
every port. It follows the `receipt-data` rule above, which differs from the
segment rule in one way: the unused low bits of the last data character are
not checked, because Apple does not check them.

The receipt path draws one line worth stating: an embedded certificate that
will not decode is fatal, but the reason depends on which one it is. A
stranger the receipt merely carries is `INVALID_RECEIPT_FORMAT` — the bag is
unsigned, so bytes that cannot be read are a defect of the receipt. The
**signer** being unreadable is `INVALID_CERTIFICATE`, the same verdict an
unreadable `x5c` entry gets, because the defect is in a certificate rather
than in the CMS around it. `receipt/reject-signer-*` pins the four ways a
signer can be unreadable: an unknown X.509 version, a repeated extension, an
extension value that stops decoding, and a public key on a curve this crate
does not implement.

## Defensive parsing

Everything this crate parses is attacker-supplied, so the bounds are part of
the design rather than a configuration: nesting depth capped at 32, a
100,000-node budget per parse, multi-byte tags refused, at most four length
octets, indefinite (BER) lengths only on constructed values, trailing bytes
after the outer value refused, negative and out-of-range attribute integers
refused, at most ten embedded certificates enforced before decoding, a path
length of at most six with each candidate issuer tried once per hop.

Input size is capped before anything is decoded or parsed, because all of
that work happens before a signature is checked. Each cap is a fixed public
constant, the same in every port of this library, not a builder option.

The request and receipt caps are Apple's own limit. Measured on 2026-09-23
against both of Apple's verifyReceipt endpoints (production and sandbox), a
request body of 3,145,728 bytes is answered normally and one of 3,145,729
bytes gets HTTP 413. Apple counts UTF-8 bytes, not characters: 3,145,729
bytes of `é`, only 1,572,874 characters, also got 413. `fixtures/cases.json`
holds every port to these numbers from both sides.

- `MAX_REQUEST_BYTES` (3 MiB, 3,145,728 bytes): the endpoint's raw JSON
  request body, checked before the depth scan and before `serde_json` runs.
  Over it is 21002 with `REQUEST_TOO_LARGE`.
- `MAX_RECEIPT_BYTES` (3 MiB, 3,145,728 bytes): the receipt base64 string,
  checked before it is decoded (the endpoint's `receipt-data` included), and
  the receipt DER, checked before the CMS parse. No receipt Apple accepts can
  be larger than the request that carries it. Over it is
  `INVALID_RECEIPT_FORMAT`, and 21002 at the endpoint.
- `MAX_JWS_BYTES` (256 KiB): the compact JWS, checked before it is split.
  Over it is `INVALID_JWS_FORMAT`.
- `MAX_JSON_NESTING_DEPTH` (64): the request body and the JWS header and
  payload. `serde_json`'s own limit is fixed at 128, so the depth is counted
  in one pass before the parser runs. Deeper is 21002 with
  `MALFORMED_REQUEST` at the endpoint and `INVALID_JWS_FORMAT` on a JWS.

String lengths are UTF-8 bytes (`str::len`), Apple's unit. A `&str` is
UTF-8, so the count costs nothing and copies nothing. For base64 and a
compact JWS it is the same count as characters.

**Answering 413 like Apple.** `REQUEST_TOO_LARGE` exists so an HTTP layer can
send the status Apple sends. The body is Apple's 21002 either way:

```rust
let result = endpoint.verify_receipt_result_from_json(&raw_request_body);
let http_status = if result.failure_reason() == Some(Reason::RequestTooLarge) { 413 } else { 200 };
(http_status, result.to_json())
```

A framework that caps request bodies itself has to allow at least 3 MiB, or
it refuses bodies Apple would answer.

An attribute type above `2^31 − 1` is a malformed receipt, not an attribute
filed under a sentinel: fail closed, never clamp.

The library target additionally denies `unwrap`, `expect`, slice indexing
and `panic!` at compile time. The probe that preceded this port found a real
out-of-bounds panic in a CMS walk by mutating a genuine receipt; those lints
are the mechanical form of not shipping the next one.

## The C ABI — `ffi/`

`ffi/` is a second crate that exposes this library through a C ABI, so C, C++
and any FFI-capable runtime (Elixir NIFs, Lua, ctypes, P/Invoke, Java FFM)
can call it without a reimplementation. It is a `cdylib`/`staticlib` plus a
cbindgen-generated header, and it is a thin wrapper: every verification
decision, parser and trust rule is this crate's, unchanged.

```bash
cargo build --locked --manifest-path ffi/Cargo.toml
```

The shape, in one paragraph: three opaque handles (`AprvJwsVerifier`,
`AprvReceiptVerifier`, `AprvReceiptEndpoint`), seven verification calls, and
one `AprvResult { int32_t status; char *json; }`. JSON is the interchange
because a claim set is open-ended and modelling it as C structs would make
every field Apple adds a breaking ABI change. `status` is `0`, one of the
twelve canonical [`Reason`] codes in declaration order (stable and
append-only), or a `100`+ code meaning the *call* was malformed and nothing
was checked. Every exported function runs its body inside `catch_unwind`, so
no panic ever crosses the boundary.

It is a separate crate rather than a feature of this one for the same reason
`fuzz/` is: a `cdylib` is a different artifact with a different lifecycle, and
`exclude` keeps it out of the published tarball. It carries its own
`Cargo.lock`, resolved for the same 1.85.0 floor.

**Prebuilt binaries are not published yet** — building from source is the
only supported path today. See `ffi/README.md` for the ABI rules (ownership,
thread safety, the status bands) and `ROADMAP.md` for what phase 2 would be.

## Testing

```bash
cargo test                      # default features
cargo test --all-features
cargo test --no-default-features
cargo clippy --all-targets --all-features -- -D warnings
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
test per case. The adapter carries no case-specific knowledge: it resolves a
fixture id to bytes, checks the digest the registry records for them, builds
a verifier from the generic config, dispatches on the operation, normalises
the result and reads the reason off a failure. A case it cannot map is a
hard harness failure, never a skip.

The native suite beyond conformance covers hostile and malformed input, the
resource bounds above, the public API's shape, the trust-pinning rule from
three directions, US-Pacific date rendering against vectors generated from
the IANA database, and a mutation pass over the genuine receipts. The
mutation pass asserts the invariant that matters: a mutated receipt is
either rejected or produces a byte-identical result — anything that changes
what the caller is told must be refused.

The C ABI in `ffi/` has three test layers of its own — its own unit tests
for null, non-UTF-8 and refused configurations; `fixtures/cases.json` driven
through the ABI from C++17; and the same vectors again from Python over
ctypes, which checks the nested field paths a dependency-free C++ program
cannot reach. Both conformance harnesses run every case in `cases.json` and
skip none: the cases that pin a clock go through the ABI's `_and_clock` constructors, which
take the instant as epoch milliseconds rather than a callback.
`ffi/README.md` says what that clock can and cannot move.

`fuzz/` holds seven `cargo fuzz` targets — the ASN.1, X.509 and CMS readers
on their own, the three verifiers, and the endpoint body — seeded from the
shared fixtures and run by CI for a fixed budget on every push. `fuzz/README.md`
lists them and the invariant each asserts beyond "no panic".

`tests/data/pacific-transitions.txt` carries every `America/Los_Angeles`
offset transition from 1900 to 2100, taken from the IANA database via
Python's `zoneinfo`, and the suite checks the rendering rules at the second
before and the second of each of the 308 of them. The other ports get
this from a full time-zone database; this crate has no such dependency, so
the whole rule set — including wartime daylight time, the 1950-1966 01:00
switches and the two Emergency Daylight Saving Time Act years — is written
out and checked against theirs. `request_date_pst` is rendered at a
caller-supplied clock with no lower bound, so "no Apple date reaches that
branch" was never a reason to leave it wrong.
