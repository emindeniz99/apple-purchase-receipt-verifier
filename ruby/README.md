# apple-purchase-receipt-verifier (Ruby)

Verify Apple App Store purchase receipts on your own servers, without calling
Apple.

Two verification paths, the same two every other implementation in this
repository ships:

- **StoreKit 2 / App Store Server JWS** — `jwsRepresentation`,
  `signedTransactionInfo`, `signedRenewalInfo`, Server Notifications V2.
- **Legacy PKCS#7 app receipts** — the exact blob an app used to send to
  Apple's now-deprecated `verifyReceipt` endpoint.

Plus a local, drop-in replacement for that endpoint, so a Rails or Sinatra
service can delete its `Net::HTTP.post` to Apple and keep the same response
shape.

Zero runtime dependencies: `openssl` and `json` are default gems.

**This is 0.7.** It is a verifier, not business logic: no bundle id,
environment, product id or device-binding parameter exists anywhere in this
API. Every verify call returns Apple's own signed data and nothing tells you
whether to trust it beyond the fact that it verified. See
[Post-verification checklist](#post-verification-checklist) for what to do
with that. Upgrading from 0.6: see [Upgrading from 0.6](#upgrading-from-06).

## Install

```ruby
gem "apple-purchase-receipt-verifier"
```

```ruby
require "apple_purchase_receipt_verifier"   # canonical
require "apple-purchase-receipt-verifier"   # the gem name also works
```

Ruby **3.3 or newer**. The floor moved from 3.1 in 0.6 because the 0.7 data
types are built on `Data.define`, a Ruby 3.2 feature that needs 3.3 for
keyword-only construction with defaults to behave the way this library
depends on.

## Quick start

Three methods on one `Verifier`, immutable and thread-safe once created:

```ruby
APRV = ApplePurchaseReceiptVerifier

verifier = APRV::Verifier.create(APRV::Config.defaults)

# 1. A legacy PKCS#7 app receipt, the base64 string a client sends.
result = verifier.verify_receipt(receipt_data)

# 2. Any Apple-signed compact JWS: a StoreKit 2 transaction, renewal info,
#    an app transaction, or an App Store Server Notifications V2 envelope.
result = verifier.verify_signed_data(jws)

# 3. A local stand-in for Apple's deprecated verifyReceipt endpoint: same
#    request body, same response body, same status codes.
response_json = verifier.verify_receipt_endpoint(APRV::Environment::SANDBOX, request_body)
```

`verify_receipt` and `verify_signed_data` never raise for any input. Every
outcome is a `VerificationResult`:

```ruby
if result.verified?
  result.payload          # ReceiptPayload or JsonPayload
else
  result.failure.reason    # a Reason Symbol, e.g. :UNTRUSTED_CHAIN
  result.failure.message   # safe to log, not meant to be parsed
  result.failure.cause     # the inner exception behind UNREADABLE_PAYLOAD/INTERNAL_ERROR, else nil
end
```

`verify_receipt_endpoint` never returns a failure either: every verdict,
including a rejected receipt, comes back as the `status` field inside the
JSON body, exactly as Apple's endpoint reports it. See
[The verifyReceipt-compatible endpoint](#the-verifyreceipt-compatible-endpoint).

Custom roots or a custom clock:

```ruby
config = APRV::Config.new(
  roots: [my_pem_or_der_string],           # defaults to Apple's three pinned roots
  clock: -> { (Time.now.to_r * 1000).to_i } # defaults to the system clock, epoch milliseconds
)
verifier = APRV::Verifier.create(config)
```

`Config.builder.roots(...).clock(...).build` is the same thing spelled as a
builder, if you prefer setting parts one at a time.

## Post-verification checklist

Verification answers one question: did Apple sign this, under a pinned Apple
root? Everything else is your decision, on the data the payload carries:

- **Bundle id.** `result.payload.bundle_id` for a receipt;
  `JSON.parse(result.payload.json)["bundleId"]` for a JWS. Compare it against
  the app you expect — the library checks nothing here.
- **Environment.** `APRV::Environment.from_receipt_type(result.payload.receipt_type)`
  for a receipt; `APRV::Environment.from_jws_environment(claims["environment"])`
  for a JWS. Both map Apple's string to `PRODUCTION`, `SANDBOX` or `nil` and
  decide nothing themselves — reject or route on the result yourself. Accept
  `SANDBOX` on any endpoint App Review can reach: App Review runs production
  builds against sandbox, and a single-environment hard fail rejects real
  purchases during review.
- **Product id / app Apple id.** Read `product_id` (receipt) or `productId` /
  `appAppleId` (JWS claims) and match against what you sold.
- **Idempotency.** Key off `transaction_id` (receipt) or `transactionId`
  (JWS): a purchase notification, an App Store Server Notification retry and
  a client resending the same receipt must not grant twice.
- **Freshness is your call.** No payload is rejected for its age. The right
  limit depends on the endpoint (Apple retries a server notification for
  days; a device may present an old but genuine receipt), so apply one
  yourself, e.g. `(Time.now.to_f * 1000) - transaction["signedDate"] > 300_000`.
- **Refunds and revocation.** Check `revocationDate` (JWS) or
  `cancellation_date_ms` (in-app purchase) before granting anything.

The [project README](https://github.com/emindeniz99/apple-purchase-receipt-verifier#integrating-from-verified-payload-to-entitlement)
writes this flow out once, with the policy table saying what each `Reason`
means and which ones are worth an alert. Below are its two branches in this
port's 0.7 API.

A StoreKit 2 signed transaction:

```ruby
APRV = ApplePurchaseReceiptVerifier
VERIFIER = APRV::Verifier.create(APRV::Config.defaults)

def redeem_transaction(user_id, jws)
  result = VERIFIER.verify_signed_data(jws) # step 2
  unless result.verified?
    logger.warn("purchase rejected: #{result.failure.reason}")
    return :denied
  end

  claims = JSON.parse(result.payload.json)
  return :denied if claims["bundleId"] != "com.example.app"
  return :denied unless [APRV::Environment::PRODUCTION, APRV::Environment::SANDBOX]
                         .include?(APRV::Environment.from_jws_environment(claims["environment"]))
  return :denied if claims["revocationDate"] # step 3

  # step 4, your call: past the window, ask the client for a fresh
  # jwsRepresentation, or fetch one from the App Store Server API and verify
  # that instead
  return :refresh if (Time.now.to_f * 1000) - claims["signedDate"].to_i > 300_000

  transaction_id = claims["transactionId"] # step 5
  return :denied if Grants.exists?(transaction_id)

  Grants.record(transaction_id, claims["originalTransactionId"], user_id)
  grant(user_id, claims["productId"])
  :granted
end
```

The legacy PKCS#7 app receipt is the same policy on the other input:

```ruby
RECEIPTS = APRV::Verifier.create(APRV::Config.defaults)

def redeem_receipt(user_id, receipt_data, product_id)
  result = RECEIPTS.verify_receipt(receipt_data) # step 2
  return :denied unless result.verified?

  receipt = result.payload
  return :denied if receipt.bundle_id != "com.example.app"

  now = Time.now.utc
  purchase = receipt.in_app.find { |p| p.product_id == product_id }
  return :denied if purchase.nil? || purchase.cancellation_date_ms # step 3
  return :denied if purchase.expires_date_ms && purchase.expires_date_ms <= now.to_i * 1000

  # step 4: the same caller-side check, on the creation date. Past
  # the window, ask the client to refresh its receipt, or call the App Store
  # Server API by transaction id and verify the JWS it returns.
  created = receipt.receipt_creation_date_ms
  return :refresh if created.nil? || (now.to_i * 1000) - created > 300_000

  return :denied if Grants.exists?(purchase.transaction_id) # step 5

  Grants.record(purchase.transaction_id, purchase.original_transaction_id, user_id)
  grant(user_id, purchase.product_id)
  :granted
end
```

## Device hash

There is no `device_guid` parameter anywhere in 0.7. A verified legacy
receipt carries the three raw attribute values Apple's device-hash formula
hashes together — `opaque_value`, `sha1_hash` and `bundle_id_bytes` — so
compute and compare it yourself:

```ruby
require "digest"

# device_id_bytes: the raw bytes of identifierForVendor on iOS, iPadOS,
# tvOS and watchOS (including an iOS app on an Apple silicon Mac), or the
# primary network interface's MAC address from copy_mac_address on macOS
# and Mac Catalyst.
def device_hash_matches?(receipt, device_id_bytes)
  return false if receipt.opaque_value.nil? || receipt.bundle_id_bytes.nil? || receipt.sha1_hash.nil?

  Digest::SHA1.digest(device_id_bytes + receipt.opaque_value + receipt.bundle_id_bytes) == receipt.sha1_hash
end
```

Binding to one device is optional, because a server does not always have the
device's GUID; only do this check when your endpoint has one.

## Verifying a legacy app receipt

```ruby
result = verifier.verify_receipt(params[:receipt_data])
raise "rejected: #{result.failure.reason}" unless result.verified?

receipt = result.payload
receipt.bundle_id                  # => "com.example.app"
receipt.receipt_creation_date_ms   # => 1722945600000  (epoch milliseconds)
receipt.in_app.first.product_id
receipt.unknown_attributes         # => { 9999 => ["\x01\x02\x03"] }
```

`verify_receipt` takes only base64 text — the string a client actually sends.
There is no separate DER entry point in 0.7; a caller holding raw DER bytes
encodes them first: `verifier.verify_receipt([der].pack("m0"))`.

### Decode rules

- Field names are Apple's own words from the verifyReceipt response
  (`application_version`, `in_app`), each spelled in Ruby's `snake_case`.
- A missing attribute decodes to `nil`. The library invents no values.
- Dates are epoch milliseconds, UTC, with an `_ms` suffix. Receipt dates carry
  whole seconds, so the last three digits are always `000`.
- The trial and intro flags (`is_trial_period`, `is_in_intro_offer_period`)
  are booleans: `0` is `false`, any other value is `true`.
- `bundle_id_bytes`, `opaque_value` and `sha1_hash` are the attribute value
  octets exactly as they sit in the receipt — see [Device hash](#device-hash).
- A known attribute repeated: the first occurrence in receipt order wins, for
  the typed field and for the chain date. Holds for top-level and in-app
  attributes alike.
- Nothing Apple signed is lost. Every attribute that does not end up in a
  typed field goes raw into `unknown_attributes`: an attribute type the
  library does not model, the second and later copies of a known attribute,
  and a known attribute whose value does not parse (whose typed field is then
  `nil`).
- A date attribute parses only in the exact form `YYYY-MM-DDTHH:MM:SSZ` — a
  real calendar date, no fraction, no offset. An empty date string means "not
  set" (the field is `nil`, nothing kept raw); any other non-empty string
  that does not parse is `nil` and kept raw in `unknown_attributes`. A
  creation-date attribute that does not parse leaves the chain instant to the
  clock.
- `receipt.to_json` renders the canonical JSON every port produces byte for
  byte: 64-bit ids (`app_item_id`, `download_id`,
  `version_external_identifier`, `web_order_line_item_id`) as JSON strings
  since genuine receipts carry 18-digit values above `2**53`; every other
  field as its natural JSON type; `unknown_attributes` keys in ascending
  numeric order.

**Several SignerInfos.** A receipt verifies when at least one of its (up to
four) CMS signers verifies under a pinned chain, since all signers sign the
same content. A fifth SignerInfo fails as `MALFORMED` before any signature is
checked.

## Verifying a StoreKit 2 transaction

```ruby
result = verifier.verify_signed_data(jws)
raise "rejected: #{result.failure.reason}" unless result.verified?

claims = JSON.parse(result.payload.json)
claims["productId"]      # => "com.example.app.pro"
claims["transactionId"]  # => "2000000000000001"
claims["signedDate"]     # => 1722945600000  (epoch milliseconds)
```

**Entitlement is your rule.** There is no "is active" helper, as in Apple's
own libraries:

```ruby
now_millis = (Time.now.to_r * 1000).to_i
expires = claims["expiresDate"]
entitled = claims["revocationDate"].nil? && (expires.nil? || expires > now_millis)
```

That is only what the payload said when it was signed. A billing grace
period (it lives in the renewal info), an upgrade (`isUpgraded`) and a refund
after signing are yours to handle; App Store Server Notifications V2 or the
App Store Server API give the live status.

`verify_signed_data` covers every Apple JWS: transactions, renewal info, app
transactions and App Store Server Notifications V2 — one method, unlike 0.6's
three. It enforces **no claim**: check `bundleId`, `environment` and
`appAppleId` yourself, exactly as shown in
[Post-verification checklist](#post-verification-checklist). The library
ships no typed JWS models and no parse helper; declare a struct for the
claims you use, or, following Apple's own `app-store-server-library`
conventions, deserialize `claims` into your own value objects.

### App Store Server Notifications V2

A notification nests more JWS inside its payload: verify the outer envelope,
then each nested `signedTransactionInfo` and `signedRenewalInfo` the same way.

```ruby
def handle_notification(verifier, signed_payload)
  outer = verifier.verify_signed_data(signed_payload)
  return :denied unless outer.verified?

  envelope = JSON.parse(outer.payload.json)
  data = envelope["data"] || {}

  [data["signedTransactionInfo"], data["signedRenewalInfo"]].compact.each do |nested_jws|
    inner = verifier.verify_signed_data(nested_jws)
    return :denied unless inner.verified?

    process(envelope["notificationType"], JSON.parse(inner.payload.json))
  end

  :ok
end
```

A `TEST` notification carries neither `signedTransactionInfo` nor
`signedRenewalInfo`, so the loop above naturally does nothing for one beyond
verifying the envelope.

## The verifyReceipt-compatible endpoint

Same request body, same response body, same status codes as Apple's deprecated
endpoint, answered locally.

```ruby
VERIFIER = APRV::Verifier.create(APRV::Config.defaults)

# Rails
def create
  render json: VERIFIER.verify_receipt_endpoint(APRV::Environment::PRODUCTION, request.body.read)
end
```

**A raw request body is form-encoded, not JSON, on the wire clients actually
use.** Apple's own client libraries POST
`application/x-www-form-urlencoded` bodies to some integrations; if yours
does, extract the JSON payload (or build `{"receipt-data": "..."}` yourself)
before calling `verify_receipt_endpoint` — passing the raw form body through
unchanged answers `21002` (`MALFORMED_RECEIPT_DATA`), not a verified receipt.

One method takes the whole request and returns the whole response, both as
JSON text — unlike 0.6's `VerifyReceiptResult`, there is no typed result
object and no separate `receipt-data`-only entry point:

```ruby
response_json = VERIFIER.verify_receipt_endpoint(APRV::Environment::SANDBOX, request_json)
response = JSON.parse(response_json)
response["status"]   # 0, 21002, 21003, 21007, 21008 or 21009
response["receipt"]  # present only when status is 0
```

A 21007 keeps nothing to reuse: call again with `Environment::SANDBOX`, as
Apple's own client does — the second call is offline, since it only re-walks
the same trusted chain.

Status codes it can produce:

| Verification outcome | Status |
|---|---|
| verified, environment matches | 0 |
| verified, sandbox receipt on `PRODUCTION` | 21007 |
| verified, production receipt on `SANDBOX` | 21008 |
| `MALFORMED`, `TOO_LARGE` | 21002 |
| `INVALID_SIGNATURE`, `UNTRUSTED_CHAIN`, `INVALID_CERTIFICATE`, `INVALID_CERTIFICATE_PURPOSE` | 21003 |
| `UNREADABLE_PAYLOAD`, `INTERNAL_ERROR` | 21009 |

Both 21009 cases are deterministic for the same input: alert and escalate,
never retry. Apple's 21005 and 21100-21199 mean Apple's own servers failed
and invite a retry; this local endpoint never returns them, since it never
calls Apple. `APRV::AppleStatus` names every status Apple documents, so a
caller matching on the response does not write `21007` by hand.

Like the real endpoint, it does **not** check the bundle id — read
`response["receipt"]["bundle_id"]` yourself before granting anything.

Status codes outside the table above depend on Apple's subscription database
and are out of scope; `COMPARISON.md` at the repository root has the
field-by-field fidelity table, including what `latest_receipt_info` and
`pending_renewal_info` would need.

## Time

Certificate validity is judged at the instant Apple signed, not now — so a
payload signed with a since-rotated certificate keeps verifying. The instant
is the receipt's creation-date attribute (legacy path) or the JWS
`signedDate` claim, and, when that is missing or is not a representable
instant (such as `1e300`), the **configured clock** stands in.

`clock:` on `Config` is read in exactly two places: the chain-validity
fallback described above, and the endpoint's `request_date` / `_ms` / `_pst`
triple, once per `verify_receipt_endpoint` call. It never otherwise decides
whether a payload verifies: injecting a clock to control `request_date`, or
to work around skew, must not let you authenticate an expired chain, and
cannot. No payload is rejected for its age — how old one may be is your
decision, per [Post-verification checklist](#post-verification-checklist).

Anything responding to `#call` and returning an Integer epoch-millisecond
value works:

```ruby
APRV::Config.new(clock: -> { (Time.now.to_r * 1000).to_i })
```

Do not reach for `Timecop` or `ActiveSupport::Testing::TimeHelpers` to test
this library's behaviour: hand `Config.new` a clock instead.

Receipt dates parse only in the exact form `YYYY-MM-DDTHH:MM:SSZ` — see
[Decode rules](#decode-rules). JWS `signedDate` and other epoch-millisecond
claims are read as sent, JSON number and all: a fractional one still drives
the chain instant. `claims` is the payload's own JSON, unmodelled, so a claim
of the wrong type is exactly what Apple signed — nothing here substitutes or
rejects it.

## Input limits

Base64 decoding, the CMS parse and JSON parsing all allocate in proportion to
their input before any signature is checked, so the input is measured first.
The size limits are Apple's, fixed constants in every port of this library,
not `Config` options.

| Bound | Value | Failure |
|---|---|---|
| Receipt base64, UTF-8 bytes | 3,145,728 | `TOO_LARGE` |
| Endpoint request body, UTF-8 bytes | 3,145,728 | `TOO_LARGE` (status 21002) |
| JWS, UTF-8 bytes | 262,144 | `TOO_LARGE` |
| JSON nesting depth | 64 | `MALFORMED` |
| ASN.1 nesting depth | 32 | `MALFORMED` in the envelope, `UNREADABLE_PAYLOAD` in signed content |
| Certificates embedded in a receipt | 10 | `MALFORMED` |
| Chain length below the anchor | 6 certificates | `UNTRUSTED_CHAIN` |
| SignerInfos in a receipt | 4 | `MALFORMED` |

Measured against both of Apple's verifyReceipt endpoints, a request body of
3,145,728 bytes is answered normally and one of 3,145,729 bytes gets HTTP
413; Apple counts UTF-8 bytes, not characters. `verify_receipt_endpoint`
answers status 21002 in place of the 413 an HTTP layer would send — route it
yourself if you need Apple's exact status code:

```ruby
response = JSON.parse(VERIFIER.verify_receipt_endpoint(env, request.body.read))
status = response["status"] == 21_002 && request.body.read.bytesize > 3_145_728 ? 413 : 200
```

A framework or proxy that caps request bodies itself has to allow at least
3 MiB, or it refuses bodies Apple would answer.

## Reasons

One outcome type carrying one machine-readable Symbol:

```ruby
case result.failure.reason
when APRV::Reason::UNTRUSTED_CHAIN then reject_and_alert(result.failure.reason)
else                                    reject(result.failure.reason)
end
```

`reason.to_s` is the canonical cross-language token, with no mapping table
anywhere. The vocabulary is closed by the cross-port contract: eight reasons
in `Reason::ALL`, and a ninth would be a change to every implementation in
one pull request.

| Reason | When |
|---|---|
| `MALFORMED` | base64, ASN.1, CMS or JWS structure is broken, or input is over a size bound |
| `TOO_LARGE` | input is over a fixed cap — see [Input limits](#input-limits) |
| `INVALID_SIGNATURE` | the signature does not match the content |
| `UNTRUSTED_CHAIN` | the chain does not reach a pinned root |
| `INVALID_CERTIFICATE` | an `x5c`/embedded certificate does not decode, or a certificate on the chain is outside its validity window at the signing instant |
| `INVALID_CERTIFICATE_PURPOSE` | a certificate on the chain is missing its Apple marker OID |
| `UNREADABLE_PAYLOAD` | the chain and signature verified, but the signed content does not parse (`failure.cause` is the parser's error) |
| `INTERNAL_ERROR` | the library failed before it could decide — not the client's fault: alert and escalate, never retry |

**Order of the checks**, the same for both paths: base64/JWS structure →
the creation date or `signedDate` alone, to pick the chain instant → the
chain, walked top-down to a pinned root, with certificate validity judged at
that instant → Apple's marker OIDs on both the leaf and the intermediate →
the signature → the full payload parse. Nothing is trusted before the chain
and the signature, so reading the date never rejects; validity is part of
the chain check, so an expired chain that also lacks a marker, or has a
broken signature, is `INVALID_CERTIFICATE`. A payload that fails the full
parse was signed by a trusted signer, so it is `UNREADABLE_PAYLOAD`, not
`MALFORMED`.

**Misconfiguration is not a verification verdict.** `Verifier.create` raises
`ArgumentError` for an empty root set; `Config.new` raises it for a `clock:`
that does not respond to `#call` or a `roots:` entry that is neither a
certificate nor a DER/PEM String; `verify_receipt_endpoint` raises it for an
`environment` that is not `Environment::PRODUCTION` or `Environment::SANDBOX`.
You cannot catch a typo as though a receipt were forged.

Nothing else escapes `verify_receipt` or `verify_signed_data`. Containment is
categorical and explicitly covers `SystemStackError`, which is not a
`StandardError` and would otherwise walk through your `rescue` and take the
request with it.

## Security model

- **Pinned anchors only.** Trust anchors come from `Config#roots`, or from
  the three bundled Apple roots. The operating system's trust store is never
  consulted on any code path — there is no `OpenSSL::X509::Store` holding
  certificates anywhere in the gem, `set_default_paths` appears nowhere, and
  a test proves that a chain the platform's own default store accepts is
  still rejected.
- **No network.** No OCSP, no CRL, no AIA fetch, no root download. Revocation
  is disabled by design, the same trade-off Apple's official libraries make
  in offline mode.
- **Top-down chain walk.** Each certificate's signature is checked only with
  a key already vouched for by a pinned anchor, so an attacker's own key is
  never asked to validate anything before it is trusted.
- **Marker OIDs are mandatory.** The JWS leaf must carry
  `1.2.840.113635.100.6.11.1` and the intermediate `1.2.840.113635.100.6.2.1`;
  the receipt signer must carry `1.2.840.113635.100.6.11.1` and its
  intermediate the same `1.2.840.113635.100.6.2.1`. Without the intermediate
  check, any Apple developer's own distribution certificate — which chains
  through the same intermediate to the same root — could sign a forged
  receipt.
- **Unknown critical extensions reject the chain** (RFC 5280): a certificate
  on the path marking an extension critical that this library does not
  process makes that path `UNTRUSTED_CHAIN`.
- **Signed-attribute integrity** (RFC 5652 §5.3): a CMS SignerInfo whose
  signed attributes carry `messageDigest` twice, or whose `contentType`
  differs from the content's own type, is `INVALID_SIGNATURE`.
- **Reject rather than repair.** An input the grammar cannot represent
  fails; it is never substituted with a sentinel.
- **Bounded parsing.** Attacker-supplied bytes go through an iterative,
  explicit-stack scanner before anything else sees them — see
  [Input limits](#input-limits). The budgets count structural elements, so
  the cost *inside* one element is bounded separately where it can grow. The
  CMS structure and the creation date are read before any cryptographic
  check, because the creation date is what the chain's validity is judged
  at, so these ceilings are what an unsigned blob can spend; the rest of the
  payload is parsed only after the signature.
- **No logging, no metrics, no callbacks.** `failure.reason` is the entire
  observability surface, and messages carry no receipt bytes, claims or key
  material.

### One platform caveat worth knowing

**Known issue: genuine legacy receipts fail on RHEL 9.** The legacy Apple
receipt chain and its CMS signature are SHA-1, and RHEL 9's DEFAULT crypto
policy (also Alma, Rocky, and Fedora with `rh-allow-sha1-signatures = no`)
makes the system OpenSSL refuse SHA-1 signatures. This port uses the system
OpenSSL, so every genuine legacy receipt there is `UNTRUSTED_CHAIN`. Observed
on AlmaLinux 9.8 on 2026-09-24. Newer receipts (SHA-256 chains) and every JWS
are unaffected. FIPS mode is untested.

Until the fix ships, allow SHA-1 signatures on that host with
`update-crypto-policies --set DEFAULT:SHA1`. The planned fix checks SHA-1
signatures on Apple's pinned legacy chain only, with OpenSSL's RSA
`verify_recover` and an exact byte comparison, and adds an AlmaLinux 9 CI job
(ROADMAP.md).

## Trust anchors

`APRV::Config.defaults.roots` returns all three published Apple roots — Apple
Inc. Root, Apple Root CA - G2 and Apple Root CA - G3 — used for both the
legacy receipt path and the JWS path; Apple deliberately documents the JWS
chain as ending in "an Apple root certificate" rather than a specific one, so
narrowing either set would fail closed, silently, the day Apple re-anchored a
path.

The bytes are compiled into the gem rather than read from disk when a config
is built, so it works from a read-only or bundled deployment.

To pin your own anchors, pass them: `Config.new(roots:)` accepts
`OpenSSL::X509::Certificate` objects or DER/PEM strings.

## Performance

Measured with `bench/bench.rb` (`ruby -Ilib bench/bench.rb`) on this host,
under load shared with other work, so treat these as an order of magnitude
rather than a guarantee: a synthetic 2-in-app-purchase receipt verifies
(`verify_receipt`) at a median of ~2.1 ms; a genuine 187-in-app-purchase
receipt — the largest fixture in the shared corpus, and the port's practical
worst case — at a median of ~27 ms and up to ~28 ms across ten samples.
Rendering that same large receipt through `verify_receipt_endpoint` costs
more (median ~65 ms, up to ~71 ms), since it also walks and JSON-encodes
every in-app purchase into Apple's response shape. Memory, not CPU, is
usually the limit for a server handling many concurrent calls; do not rely on
CPU headroom alone.

## Upgrading from 0.6

0.7 removes the 0.6 API outright — there is no deprecation period, and no
bundle id, environment, app Apple id or device GUID parameter survives
anywhere in this library. Read every reason through
[Post-verification checklist](#post-verification-checklist) before upgrading.

| 0.6 | 0.7 |
|---|---|
| `ApplePurchaseReceiptVerifier.apple_jws_roots` / `.apple_receipt_roots` | `Config.defaults.roots` (one shared set for both paths) |
| `ReceiptVerifier.new(trusted_roots:, bundle_id:)` | `Verifier.create(Config.new(roots:))`; compare `result.payload.bundle_id` yourself |
| `verifier.verify_der(bytes)` / `#verify_base64(text)` / `#verify(either)` | `verifier.verify_receipt(base64)`; DER callers encode first: `[der].pack("m0")` |
| `verifier.verify_base64(text, device_guid:)` | `verifier.verify_receipt(base64)`, then compare the device hash yourself — see [Device hash](#device-hash) |
| `ApplePurchaseReceiptVerifier.verify_receipt_core(der, trusted_roots:)` | `verifier.verify_receipt(base64)` — no separate "core"/DER entry point |
| `JwsVerifier.new(trusted_roots:, bundle_id:, accepted_environments:, app_apple_id:)` | `Verifier.create(Config.new(roots:))` |
| `verifier.verify_transaction(jws)` / `#verify_app_transaction(jws)` / `#verify_raw(jws)` | `verifier.verify_signed_data(jws)` — one method; parse `result.payload.json` and check `bundleId`/`environment`/`appAppleId` yourself |
| `VerifyReceiptEndpoint.new(trusted_roots:, environment:)` | `Verifier.create(Config.new(roots:))`; pass `environment` per call to `verify_receipt_endpoint` |
| `endpoint.verify_receipt_result(request)` / `#verify_receipt_data(receipt_data)` / `#verify_receipt_json(body)` | `verifier.verify_receipt_endpoint(environment, request_json)` — one method, JSON text in, JSON text out; no `VerifyReceiptResult` object |
| `result.to_response(other_environment)` / `#to_json(other_environment)` | call `verify_receipt_endpoint` again with the other `Environment` value — the second call is offline |
| raises `ApplePurchaseReceiptVerifier::VerificationError` | returns a `VerificationResult`; `verify_receipt`/`verify_signed_data` no longer raise for input |
| `Reason::INVALID_CHAIN` | `Reason::UNTRUSTED_CHAIN`, or `INVALID_CERTIFICATE` when the chain is outside its validity window |
| `Reason::INVALID_RECEIPT_FORMAT` / `INVALID_JWS_FORMAT` / `MALFORMED_REQUEST` | `Reason::MALFORMED` |
| `Reason::REQUEST_TOO_LARGE` | `Reason::TOO_LARGE` |
| `Reason::WRONG_BUNDLE_ID` / `WRONG_ENVIRONMENT` / `WRONG_APP_APPLE_ID` / `DEVICE_HASH_MISMATCH` | gone — the payload verifies and you read the field yourself |
| `active_at?` | gone — read `expiresDate`/`revocationDate` yourself, as in [Verifying a StoreKit 2 transaction](#verifying-a-storekit-2-transaction) |

## Development

```sh
bundle exec rake test                  # conformance + native suites
APRV_PACKAGING=1 bundle exec rake test # also builds and installs the gem
ruby script/gen_roots.rb               # regenerate the inlined anchors
```

`rake test` on its own works too, and that is what CI's Ruby matrix runs: the
library has no runtime dependencies and the suite uses only gems that ship
with Ruby.

`Gemfile` lists minitest and rake directly instead of calling `gemspec`. A
`gemspec` line puts this library into `Gemfile.lock` as a path gem carrying
its own version, and a release commit that bumps only `version.rb` would then
break every frozen install. `Gemfile.lock` and the two files under
`gemfiles/` are committed, and CI installs them with `BUNDLE_FROZEN=true`.

`test/conformance_test.rb` runs `fixtures/cases-0.7.json`, the normative
cross-language vectors every implementation in this repository answers. It
carries no per-case knowledge and no skip list.

`fuzz/` holds six coverage-guided [ruzzy](https://github.com/trailofbits/ruzzy)
targets — the ASN.1 scanner and the CMS walk on their own, the receipt and
JWS verifiers, and the endpoint body — seeded from the shared fixtures and
run by CI for a fixed budget on every push. `fuzz/README.md` lists them and
the invariant each asserts beyond "nothing escapes". Its one dependency lives
in `gemfiles/fuzz.gemfile`, out of the gemspec and out of the test Gemfile:
ruzzy needs clang and a libFuzzer runtime, and a tool the library does not
need must not be able to fail the Ruby 3.3 leg.

## License

MIT. See `LICENSE`.
