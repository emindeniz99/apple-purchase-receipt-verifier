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
Python 3.9.

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
`identifierForVendor`. Supplying it binds the receipt to one device.

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
endpoint — answered locally.

```ruby
ENDPOINT = APRV::VerifyReceiptEndpoint.new(
  trusted_roots: APRV.apple_receipt_roots,
  environment: APRV::Environment::PRODUCTION   # drives 21007/21008 routing
)

# Rails
def create
  render json: ENDPOINT.verify_receipt(params.permit!.to_h)
end

# Or pipe the raw body straight through
ENDPOINT.verify_receipt_json(request.body.read)   # String in, String out
```

It never raises: failures are reported through `status`, exactly as the real
endpoint does. Like the real endpoint, it does **not** check the bundle id —
compare `response["receipt"]["bundle_id"]` yourself.

Status codes it can produce: `0`, `21002`, `21003`, `21007`, `21008`, `21009`.
Everything else in Apple's list depends on Apple's subscription database and is
out of scope; `COMPARISON.md` at the repository root has the field-by-field
fidelity table, including what `latest_receipt_info` and `pending_renewal_info`
would need.

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
anywhere. The vocabulary is closed by the cross-port contract — eleven reasons,
and a twelfth would be a change to every implementation in one pull request:

| Reason | Raised when |
|---|---|
| `INVALID_JWS_FORMAT` | not three segments, not base64url, not JSON, `alg` is not ES256, `x5c` is not three certificates |
| `INVALID_CERTIFICATE` | an `x5c` entry does not decode as a certificate |
| `INVALID_CERTIFICATE_PURPOSE` | a certificate lacks its Apple marker OID |
| `INVALID_CHAIN` | the chain does not reach a pinned anchor, or was not valid at signing time |
| `INVALID_SIGNATURE` | the signature does not check out, or the key is the wrong type |
| `WRONG_BUNDLE_ID` | the payload names a different app |
| `WRONG_ENVIRONMENT` | the environment is outside the accepted set |
| `WRONG_APP_APPLE_ID` | a Production AppTransaction names a different app Apple id |
| `INVALID_RECEIPT_FORMAT` | the receipt is not a well-formed CMS blob or attribute set |
| `DEVICE_HASH_MISMATCH` | the receipt is not bound to the device GUID supplied |
| `STALE_PAYLOAD` | the payload was signed longer ago than `max_signed_age_seconds` |

**Misconfiguration is not a verification verdict.** An empty `trusted_roots`,
a nil `bundle_id`, an empty accepted-environment set, an endpoint environment
that is not Production or Sandbox — all raise `ArgumentError`. You cannot
catch a typo as though a receipt were forged.

Nothing else escapes an entry point. Containment is categorical, and it
explicitly covers `SystemStackError`, which is not a `StandardError` and would
otherwise walk through your `rescue` and take the request with it.

## Time

Certificate validity is judged at the instant Apple signed, not now — so a
payload signed with a since-rotated certificate keeps verifying. The instant is
the payload's `signedDate`, else its `receiptCreationDate`, else the receipt's
creation-date attribute, and failing all of those, the **system** clock.

`clock:` is available on `JwsVerifier` and `VerifyReceiptEndpoint` and is read
in exactly two places:

1. the `STALE_PAYLOAD` comparison;
2. the endpoint's `request_date` / `_ms` / `_pst` triple.

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
