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

Synchronous, `#![forbid(unsafe_code)]`, Rust 1.74 or newer.

## Runtime and version floor

- **Rust 1.74.0**, declared as `rust-version` and proven by CI: the whole
  suite, conformance included, runs on a real 1.74.0 toolchain against a
  lockfile resolved for that floor. Edition 2021.
- **Eight direct dependencies**, all of them primitives: `rsa`, `p256`,
  `p384`, `sha1`, `sha2`, `digest` and `subtle` for the arithmetic, and
  `serde_json` for the JWS payloads, which are JSON. Every byte of
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
Apple's `receipt-data` accepts: Base64 as RFC 4648 defines it, the way
Foundation's `base64EncodedString(options:)` can emit it — the standard
alphabet or base64url, padded or not, with `CR`/`LF` line breaks at 64 or 76
columns. Concretely: `+`/`/` or `-`/`_` (never both in the same string),
padding present or omitted, and `\r`, `\n`, ` ` or `\t` anywhere. A character
neither alphabet defines, both alphabets in one string, anything but
whitespace once padding has started, an empty or whitespace-only string, or a
`=` count other than zero or the exact count the data length requires (no
over- or under-padding) is `INVALID_RECEIPT_FORMAT` (`21002` at the endpoint)
before any bytes reach the CMS parser — see `decode_receipt_base64` in
`base64.rs`.

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

let response = endpoint.verify_receipt(&VerifyReceiptRequest::new(receipt_b64));
let json: String = endpoint.verify_receipt_json(raw_request_body);
```

It never fails: the Apple status code is a field of the body it answers, for
every input, including one that is not JSON. The statuses it can produce are
`0`, `21002`, `21003`, `21007`, `21008` and `21009` — and no others, because
the rest describe conditions that only exist on Apple's servers. Local
21007 / 21008 routing fails closed: only receipt types `Production` and
`ProductionVPP` count as production.

`password` and `exclude-old-transactions` are accepted for compatibility and
never read. See [COMPARISON.md](../COMPARISON.md) for the field-by-field
fidelity account.

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
| `InvalidReceiptFormat` | `INVALID_RECEIPT_FORMAT` | the PKCS#7 receipt could not be parsed |
| `DeviceHashMismatch` | `DEVICE_HASH_MISMATCH` | the device hash does not match attribute 5 |
| `StalePayload` | `STALE_PAYLOAD` | the payload was signed longer ago than `max_signed_age` |

The vocabulary is **closed** by the cross-port contract: a twelfth reason
would be a change to the shared vector file and to every port at once.
`Reason` is nevertheless `#[non_exhaustive]`, so that if that ever happens a
caller with a `_ => reject` arm keeps compiling and keeps failing closed.
That arm is a safety net, not an extension point.

**Misconfiguration is a different type.** Empty trust anchors, an empty
bundle id, an empty accepted-environment set, an unparseable anchor and an
endpoint environment other than Production or Sandbox all return
`ConfigError` from `build()`. A programming mistake must not be catchable as
a verification verdict. The free `verify_receipt_core` has no `build()` to
fail in, so it returns `CoreError::Config` instead — see above.

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
→ payload parse → **at most ten embedded certificates**, checked before any
is decoded → signer is among them → chain at the creation date → **signer
marker OID** → RSA key, SHA-1 or SHA-256 digest → CMS signature → bundle id
→ device hash.

Two orderings are load-bearing and deliberately opposite. On the JWS path
the marker OIDs are checked **before** the chain; on the receipt path the
marker OID is checked **after** it, so a receipt signed under a foreign
chain reports `INVALID_CHAIN` rather than a purpose error.

`x5c[2]` is never parsed, never compared to an anchor and never trusted;
neither is a receipt's embedded copy of its root. Swapping either changes
nothing, because the chain terminates at an anchor the caller pinned.

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
as a header that is not base64url JSON. An `x5c` entry is a certificate
container, not a segment, and stays leniently decoded — every character
outside both alphabets silently skipped, the same input Java hands to its
MIME decoder — so a padded or wrapped `x5c` entry keeps its own reason
codes.

`receipt-data` sits between those two: not blanket-lenient like `x5c` (an
unrecognised character is a hard `INVALID_RECEIPT_FORMAT`, not something
skipped), and not closed to one spelling like a JWS segment either — see the
`verify_base64` rule above.

One further deliberate difference, recorded because no shared vector covers
it: `x5c[2]` is never decoded or parsed here. Node, Python and Swift agree;
Java alone parses it, so a JWS whose third entry is unparseable is
`INVALID_CERTIFICATE` in Java and reaches the signature check everywhere
else. It is untrusted by design in all five, so no verdict about a
well-formed JWS moves.

## Defensive parsing

Everything this crate parses is attacker-supplied, so the bounds are part of
the design rather than a configuration: nesting depth capped at 32, a
100,000-node budget per parse, multi-byte tags refused, at most four length
octets, indefinite (BER) lengths only on constructed values, trailing bytes
after the outer value refused, negative and out-of-range attribute integers
refused, at most ten embedded certificates enforced before decoding, a path
length of at most six with each candidate issuer tried once per hop, and an
8 MiB ceiling on a receipt.

An attribute type above `2^31 − 1` is a malformed receipt, not an attribute
filed under a sentinel: fail closed, never clamp.

The library target additionally denies `unwrap`, `expect`, slice indexing
and `panic!` at compile time. The probe that preceded this port found a real
out-of-bounds panic in a CMS walk by mutating a genuine receipt; those lints
are the mechanical form of not shipping the next one.

## Testing

```bash
cargo test                      # default features
cargo test --all-features
cargo test --no-default-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
cargo deny check
```

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
