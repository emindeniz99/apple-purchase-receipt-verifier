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

## Install

```ruby
gem "apple-purchase-receipt-verifier"
```

```ruby
require "apple_purchase_receipt_verifier"   # canonical
require "apple-purchase-receipt-verifier"   # the gem name also works
```

Ruby **3.1 or newer**. That floor is enterprise reality rather than upstream
support: 3.1 is Debian 12's system Ruby and is exercised by the whole test
suite on every push, exactly as this project does for Java 8, Node 20 and
Python 3.10.

## Verifying a StoreKit 2 transaction

```ruby
APRV = ApplePurchaseReceiptVerifier

verifier = APRV::JwsVerifier.new(
  trusted_roots: APRV.apple_jws_roots,
  bundle_id: "com.example.app",
  accepted_environments: [APRV::Environment::PRODUCTION, APRV::Environment::SANDBOX],
  app_apple_id: 123_456_789,
  max_signed_age_seconds: 300
)

transaction = verifier.verify_transaction(jws)
transaction.product_id          # => "com.example.app.pro"
transaction.transaction_id      # => "2000000000000001"
transaction.signed_date         # => 1722945600000  (epoch milliseconds)
transaction.active_at?(Time.now)
transaction.claims              # every claim, as Apple sent it
```

Three operations:

| Method | What it enforces |
|---|---|
| `verify_transaction(jws)` | chain, signature, `bundleId`, `environment` |
| `verify_app_transaction(jws)` | the above, plus `appAppleId` in Production |
| `verify_raw(jws)` | chain and signature only — every claim is returned and none is checked |

`verify_raw` is for payload types this library does not model (renewal info,
notification envelopes). **It enforces no claim**: check `bundleId` and
`environment` yourself.

Include `Sandbox` in `accepted_environments` on any endpoint App Review can
reach — App Review runs production builds against sandbox, and a
single-environment hard fail rejects real purchases during review.

`max_signed_age_seconds` is optional. The unit is in the name because a bare
`300` at a call site otherwise says nothing.

## Verifying a legacy app receipt

```ruby
verifier = APRV::ReceiptVerifier.new(
  trusted_roots: APRV.apple_receipt_roots,
  bundle_id: "com.example.app"
)

receipt = verifier.verify_base64(params[:receipt_data])
receipt.bundle_id                  # => "com.example.app"
receipt.creation_date              # => 2024-08-06 12:00:00 UTC (a Time)
receipt.in_app_purchases.first.product_id
receipt.unknown_attributes         # => { 9999 => ["\x01\x02\x03"] }
```

Every input form is reachable with and without the device GUID:

```ruby
verifier.verify_der(bytes)
verifier.verify_base64(text)
verifier.verify(either)                              # 0x30 means DER, else base64
verifier.verify_der(bytes, device_guid: guid_bytes)  # adds the device-hash check
verifier.verify_base64(text, device_guid: guid_bytes)
```

The device-hash check (`SHA1(guid + opaqueValue + bundleIdBytes)` equals
attribute 5) is optional, because servers do not always have the device's
GUID — the raw bytes of `identifierForVendor` on iOS, iPadOS, tvOS and
watchOS, including an iOS app running on an Apple silicon Mac, or the
primary network interface's MAC address from `copy_mac_address` on macOS
and Mac Catalyst. Supplying it binds the receipt to one device.

`ReceiptVerifier` takes **no clock**, and must never grow one: no receipt
verdict depends on the current time. See "Time" below.

### The chain-and-signature primitive

```ruby
receipt = ApplePurchaseReceiptVerifier.verify_receipt_core(der, trusted_roots: roots)
```

This is what both `ReceiptVerifier` and the endpoint are built on. It **skips
the bundle-id check** — if you unlock products from its result, compare
`receipt.bundle_id` yourself, or use `ReceiptVerifier`, which does it for you.

## The verifyReceipt-compatible endpoint

Same request body, same response body, same status codes as Apple's deprecated
endpoint, answered locally.

```ruby
ENDPOINT = APRV::VerifyReceiptEndpoint.new(
  trusted_roots: APRV.apple_receipt_roots,
  environment: APRV::Environment::PRODUCTION   # drives 21007/21008 routing
)

# Rails
def create
  render json: ENDPOINT.verify_receipt_result(params.permit!.to_h).to_response
end

# Or pipe the raw body straight through
ENDPOINT.verify_receipt_json(request.body.read)   # String in, String out
```

Every entry point returns a `VerifyReceiptResult`, except `verify_receipt_json`,
which returns its JSON:

| Method | Takes |
|---|---|
| `verify_receipt_result(request, now: nil)` | a request Hash, or its raw JSON text |
| `verify_receipt_data(receipt_data, now: nil)` | the bare base64 `receipt-data` value, no envelope |
| `verify_receipt_json(body)` | raw JSON text; the same as `verify_receipt_result(body).to_json` |

```ruby
result = ENDPOINT.verify_receipt_data(receipt_data)

result.status          # 0, 21002, 21003, 21007, 21008 or 21009, for this endpoint's environment
result.verified?       # true when the receipt verified, 21007 and 21008 included
result.receipt         # the AppReceipt when verified?, else nil
result.failure_reason  # a Reason Symbol when not verified?, else nil
result.failure_cause   # the error behind INTERNAL_ERROR, else nil
result.request_date    # the Time rendered as request_date, read once per call

result.to_response     # the response body as a new Hash
result.to_json         # the same, as JSON text

# A 21007 keeps the receipt, so the sandbox answer needs no second verification.
result.to_json(APRV::Environment::SANDBOX) if result.status == 21_007
```

`verified?` is not `status.zero?`. A 21007 or 21008 means the receipt verified
and belongs to the other environment. `to_response(environment)` and
`to_json(environment)` answer what an endpoint of that environment would, with
the status recomputed from the receipt's own `receipt_type`: a production
receipt answers 0 on Production and 21008 on Sandbox, any other receipt 21007
on Production and 0 on Sandbox, and a failed result keeps its status on both.
An environment other than Production or Sandbox raises `ArgumentError`.

`now:` takes a `Time` and renders it as `request_date` in place of the clock.
It reaches `request_date` and nothing else; certificate validity never sees it.
Anything other than `nil` or a `Time` raises `ArgumentError`.

A result is frozen, and `VerifyReceiptResult.new` is private: only the endpoint
creates one, so no caller can build a status 0. Passing a result to
`JSON.generate` or to Rails' `render json:` embeds its own response.

No request input makes the endpoint raise: failures come back as a result with
a status, exactly as the real endpoint reports them. Two reasons exist only on
a result, never on a `VerificationError`:

| Reason | Status | When |
|---|---|---|
| `MALFORMED_REQUEST` | 21002 | the body is not a JSON object, is over `MAX_REQUEST_BYTES` or nests past 64 levels, or `receipt-data` is missing, empty or not a String |
| `INTERNAL_ERROR` | 21009 | an unexpected error inside the endpoint, including a clock that raises or returns something other than a `Time`; `failure_cause` holds it |

Like the real endpoint, it does **not** check the bundle id. Compare
`result.receipt.bundle_id` yourself.

Status codes it can produce: `0`, `21002`, `21003`, `21007`, `21008`, `21009`.
Everything else in Apple's list depends on Apple's subscription database and is
out of scope; `COMPARISON.md` at the repository root has the field-by-field
fidelity table, including what `latest_receipt_info` and `pending_renewal_info`
would need.

### Migrating from `verify_receipt`

`verify_receipt(body)` is gone. `verify_receipt_result(body).to_response`
returns the same Hash.

## Input limits

Base64 decoding, the CMS parse and JSON parsing all allocate in proportion to
their input before any signature is checked, so the input is measured first.
These are constants, not constructor options, and they match the Java, PHP
and Python ports.

- **`ReceiptVerifier::MAX_RECEIPT_BYTES` (2 MiB).** Applied to base64 text in
  characters, before decoding: at `ReceiptVerifier#verify`, `#verify_base64`
  and the endpoint's `receipt-data`. Applied to DER in bytes, before parsing:
  at `#verify_der` and `verify_receipt_core`. A larger receipt is
  `INVALID_RECEIPT_FORMAT` (21002 at the endpoint). `fixtures/cases.json`
  requires every port to accept a receipt of up to 1 MiB of DER, about
  1.38 MB of base64; the largest genuine receipt in the corpus is 79 KB.
- **`VerifyReceiptEndpoint::MAX_REQUEST_BYTES` (1 MiB).** Applied to a raw
  JSON body in bytes, before it is parsed. A larger body answers 21002 with
  `MALFORMED_REQUEST`. It sits below the receipt cap on purpose: the JSON
  path parses the body as well as decoding the receipt. So a receipt at the
  1 MiB DER floor verifies through `verify_receipt_data` or a Hash request,
  and answers 21002 inside a JSON body. A request already decoded to a Hash
  is not measured; its `receipt-data` still is.
- **JSON nesting depth 64.** Applies to the request body and to the JWS
  header and payload. A deeper body answers 21002 with `MALFORMED_REQUEST`; a
  deeper JWS segment is `INVALID_JWS_FORMAT`. The depth is enforced by the
  parser's `max_nesting` and then counted over the result, because newer json
  gems do not count an empty innermost array or object.
- **`JwsVerifier::MAX_JWS_BYTES` (256 KiB).** Applied to the compact JWS in
  characters, before it is split or decoded. A longer one is
  `INVALID_JWS_FORMAT`. Every JWS in the shared corpus is under 2.5 KB.

## Errors

One exception class carrying one machine-readable Symbol:

```ruby
begin
  transaction = verifier.verify_transaction(jws)
rescue ApplePurchaseReceiptVerifier::VerificationError => e
  case e.reason
  when APRV::Reason::WRONG_ENVIRONMENT then retry_against_sandbox
  when APRV::Reason::STALE_PAYLOAD     then ask_the_client_to_refresh
  else                                      reject_and_alert(e.reason)
  end
end
```

`e.reason.to_s` is the canonical cross-language token, with no mapping table
anywhere. The vocabulary is closed by the cross-port contract: eleven reasons
in `Reason::ALL`, and a twelfth would be a change to every implementation in
one pull request. (The endpoint's `MALFORMED_REQUEST` and `INTERNAL_ERROR` are
outside it; no verifier raises them.)

| Reason | Raised when |
|---|---|
| `INVALID_JWS_FORMAT` | over `MAX_JWS_BYTES`, not three segments, not base64url, not JSON (or nested past 64 levels), `alg` is not ES256, `x5c` is not three certificates |
| `INVALID_CERTIFICATE` | an `x5c` entry does not decode as a certificate |
| `INVALID_CERTIFICATE_PURPOSE` | a certificate lacks its Apple marker OID |
| `INVALID_CHAIN` | the chain does not reach a pinned anchor, or was not valid at signing time |
| `INVALID_SIGNATURE` | the signature does not check out, or the key is the wrong type |
| `WRONG_BUNDLE_ID` | the payload names a different app |
| `WRONG_ENVIRONMENT` | the environment is outside the accepted set |
| `WRONG_APP_APPLE_ID` | a Production AppTransaction names a different app Apple id |
| `INVALID_RECEIPT_FORMAT` | the receipt is over `MAX_RECEIPT_BYTES`, or is not a well-formed CMS blob or attribute set |
| `DEVICE_HASH_MISMATCH` | the receipt is not bound to the device GUID supplied |
| `STALE_PAYLOAD` | the payload was signed longer ago than `max_signed_age_seconds` |

**Misconfiguration is not a verification verdict.** An empty `trusted_roots`,
a nil `bundle_id`, an empty accepted-environment set, an endpoint environment
that is not Production or Sandbox — all raise `ArgumentError`. You cannot
catch a typo as though a receipt were forged.

Nothing else escapes an entry point. Containment is categorical, and it
explicitly covers `SystemStackError`, which is not a `StandardError` and would
otherwise walk through your `rescue` and take the request with it.

## Integrating: from verified payload to entitlement

The backend flow these calls sit inside is written out once in the
[project README](https://github.com/emindeniz99/apple-purchase-receipt-verifier#integrating-from-verified-payload-to-entitlement):
verify offline, deny on any failure, check the refund field, refresh a payload
past the freshness window, guard against replay on the transaction id, then
grant. That section also carries the policy table saying what each reason
means and which ones are worth an alert. Here are its two branches in this
port's API.

A StoreKit 2 signed transaction:

```ruby
APRV = ApplePurchaseReceiptVerifier

VERIFIER = APRV::JwsVerifier.new(
  trusted_roots: APRV.apple_jws_roots,
  bundle_id: "com.example.app",
  accepted_environments: [APRV::Environment::PRODUCTION, APRV::Environment::SANDBOX],
  max_signed_age_seconds: 300 # the freshness window
)

def redeem_transaction(user_id, jws)
  begin
    payload = VERIFIER.verify_transaction(jws) # step 2
  rescue APRV::VerificationError => e
    # step 4: ask the client for a fresh jwsRepresentation, or fetch one from
    # the App Store Server API and verify that instead
    return :refresh if e.reason == APRV::Reason::STALE_PAYLOAD

    logger.warn("purchase rejected: #{e.reason}")
    return :denied
  end

  return :denied if payload.revocation_date # step 3

  transaction_id = payload.transaction_id # step 5
  return :denied if Grants.exists?(transaction_id)

  Grants.record(transaction_id, payload.original_transaction_id, user_id)
  grant(user_id, payload.product_id)
  :granted
end
```

The legacy PKCS#7 app receipt is the same policy on the other input, the one
StoreKit 1 apps and older SDKs still send:

```ruby
RECEIPTS = APRV::ReceiptVerifier.new(
  trusted_roots: APRV.apple_receipt_roots,
  bundle_id: "com.example.app"
)

# Same policy keyed on the receipt's own dates. `verify` takes the base64 the
# client sends or the DER bytes; VerifyReceiptEndpoint is the alternative,
# answering Apple's `verifyReceipt` JSON shape with a `status` instead.
def redeem_receipt(user_id, receipt_data, product_id)
  receipt = RECEIPTS.verify_base64(receipt_data) # step 2
  now = Time.now.utc
  purchase = receipt.in_app_purchases.find { |p| p.product_id == product_id }

  return :denied if purchase.nil? || purchase.cancellation_date # step 3
  return :denied if purchase.expires_date && purchase.expires_date <= now

  # step 4: no max_signed_age_seconds here, so compare the creation date. Past
  # the window, ask the client to refresh its receipt, or call the App Store
  # Server API by transaction_id and verify the JWS it returns.
  return :refresh if receipt.creation_date.nil? || now - receipt.creation_date > 300

  return :denied if Grants.exists?(purchase.transaction_id) # step 5

  Grants.record(purchase.transaction_id, purchase.original_transaction_id, user_id)
  grant(user_id, purchase.product_id)
  :granted
end
```

## Time

Certificate validity is judged at the instant Apple signed, not now — so a
payload signed with a since-rotated certificate keeps verifying. The instant is
the payload's `signedDate`, else its `receiptCreationDate`, else the receipt's
creation-date attribute, and failing all of those, the **system** clock.

`clock:` is available on `JwsVerifier` and `VerifyReceiptEndpoint` and is read
in exactly two places:

1. the `STALE_PAYLOAD` comparison;
2. the endpoint's `request_date` / `_ms` / `_pst` triple, once per call, and
   not at all when the call passes `now:`.

It never reaches a certificate-validity decision. Injecting a clock to test
staleness, or to work around skew, must not let you authenticate an expired
chain — and cannot. That is also why `ReceiptVerifier` has no `clock:` at all.

Anything that responds to `#call` and returns a `Time` works:

```ruby
APRV::JwsVerifier.new(..., max_signed_age_seconds: 300, clock: -> { Time.now.utc })
```

Do not reach for `Timecop` or `ActiveSupport::Testing::TimeHelpers` to test
this library's behaviour: hand the verifier a clock instead.

Receipt dates are RFC 3339 with a mandatory timezone designator — a naive date
would be read as the server's local time, and the same receipt would then
verify on one host and fail on another. The offset must be a real one
(`±00:00` … `±23:59`) and a leap second is refused, because both feed the
instant the chain is judged at. Fractional seconds are kept to the nanosecond;
further digits are dropped, which is the finest precision any port in this
family represents.

JWS signing dates (`signedDate`, `receiptCreationDate`) are read as sent, JSON
number and all — a fractional one drives the chain instant and the staleness
rule exactly like an integer. The payload readers still model Apple's wire
contract, where those claims are integer epoch milliseconds, so
`payload.signed_date` reads `nil` for a value of an unexpected JSON type;
`payload["signedDate"]` always has the raw claim.

## Security model

- **Pinned anchors only.** Trust anchors come from the argument you pass, or
  from the three bundled Apple roots. The operating system's trust store is
  never consulted on any code path — there is no `OpenSSL::X509::Store` holding
  certificates anywhere in the gem, `set_default_paths` appears nowhere, and a
  test proves that a chain the platform's own default store accepts is still
  rejected.
- **No network.** No OCSP, no CRL, no AIA fetch, no root download. Revocation
  is disabled by design, the same trade-off Apple's official libraries make in
  offline mode.
- **Marker OIDs are mandatory.** The JWS leaf must carry
  `1.2.840.113635.100.6.11.1` and the intermediate `1.2.840.113635.100.6.2.1`;
  the receipt signer must carry `1.2.840.113635.100.6.11.1`. Without the last
  one, any Apple developer's own distribution certificate — which chains
  through the same intermediate to the same root — could sign a forged receipt.
- **Reject rather than repair.** An input the grammar cannot represent fails;
  it is never substituted with a sentinel.
- **Bounded parsing.** Attacker-supplied bytes go through an iterative,
  explicit-stack scanner before anything else sees them: full consumption
  (trailing bytes are refused), depth ≤ 32, a node budget, no multi-byte tags,
  length fields of at most four octets, and at most ten embedded certificates —
  bounded before any certificate is decoded. The budgets count structural
  elements, so the cost *inside* one element is bounded separately where it can
  grow: a date's fractional seconds are read to the nanosecond and no further.
  Structural parsing runs before any cryptographic check in every port, because
  the receipt's creation date is what the chain's validity is judged at, so
  these ceilings are what an unsigned blob can spend.
- **No logging, no metrics, no callbacks.** The reason code is the entire
  observability surface, and messages carry no receipt bytes, claims or key
  material.

### One platform caveat worth knowing

The genuine legacy Apple receipt chain is SHA-1 end to end. A distribution that
disables SHA-1 signatures at the OpenSSL policy layer — RHEL 9 and Fedora with
`rh-allow-sha1-signatures = no`, or a FIPS build — will therefore fail genuine
legacy receipts with `INVALID_CHAIN` or `INVALID_SIGNATURE`. The library will
not silently downgrade around it. The escape hatch is the platform's own:
`update-crypto-policies --set LEGACY`. Newer receipts (SHA-256 chains) are
unaffected. Python and PHP share this exposure; the ports that hand-roll their
own RSA verification do not.

## Trust anchors

`ApplePurchaseReceiptVerifier.apple_jws_roots` and `.apple_receipt_roots` both
return all three published Apple roots — Apple Inc. Root, Apple Root CA - G2
and Apple Root CA - G3 — as fresh objects each call. Apple deliberately
documents the JWS chain as ending in "an Apple root certificate" rather than a
specific one, so narrowing either set would fail closed, silently, the day
Apple re-anchored a path.

The bytes are compiled into the gem rather than read from disk when a verifier
is built, so it works from a read-only or bundled deployment.

To pin your own anchors, pass them: `trusted_roots:` accepts
`OpenSSL::X509::Certificate` objects or DER/PEM strings.

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

`test/conformance_test.rb` runs `fixtures/cases.json`, the normative
cross-language vectors every implementation in this repository answers. It
carries no per-case knowledge and no skip list.

`fuzz/` holds six coverage-guided [ruzzy](https://github.com/trailofbits/ruzzy)
targets — the ASN.1 scanner and the CMS walk on their own, the receipt and
JWS verifiers, and the endpoint body — seeded from the shared fixtures and
run by CI for a fixed budget on every push. `fuzz/README.md` lists them and
the invariant each asserts beyond "nothing escapes". Its one dependency lives
in `gemfiles/fuzz.gemfile`, out of the gemspec and out of the test Gemfile:
ruzzy needs clang and a libFuzzer runtime, and a tool the library does not
need must not be able to fail the Ruby 3.1 leg.

## License

MIT. See `LICENSE`.
