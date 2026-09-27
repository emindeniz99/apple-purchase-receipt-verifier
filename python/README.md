# apple-purchase-receipt-verifier

Verify Apple in-app purchases locally — no calls to Apple's servers.

Replaces the deprecated `verifyReceipt` endpoint by validating StoreKit 2
signed JWS transactions and legacy PKCS#7 receipts against pinned Apple
root certificates.

```bash
pip install apple-purchase-receipt-verifier
```

The import package is `apple_purchase_receipt_verifier`; the distribution is
`apple-purchase-receipt-verifier`. Requires Python 3.10+.

## Quick start

One `Verifier`, built from a `Config`, exposes the three entry points. It is
immutable and thread-safe once constructed, and none of its `verify_*`
methods raise: each returns a `VerificationResult` (or, for the endpoint, a
JSON string) that reports failure instead of throwing.

```python
from apple_purchase_receipt_verifier import Config, Environment, Verifier

verifier = Verifier(Config.defaults())  # Apple's three pinned roots, system clock
```

**StoreKit 2 signed transaction or renewal info (compact JWS):**

```python
result = verifier.verify_signed_data(jws)
if not result.verified:
    raise ValueError(f"{result.failure.reason}: {result.failure.message}")
payload = json.loads(result.payload.json)  # the verified claims, as a dict
```

**Legacy PKCS#7 app receipt (base64):**

```python
result = verifier.verify_receipt(receipt_b64)
if not result.verified:
    raise ValueError(f"{result.failure.reason}: {result.failure.message}")
receipt = result.payload  # a ReceiptPayload
print(receipt.bundle_id, len(receipt.in_app))
```

**A `verifyReceipt`-shaped request body, verified offline:**

```python
response_json = verifier.verify_receipt_endpoint(Environment.PRODUCTION, request_body)
```

`request_body` is the raw JSON body Apple's endpoint would have received
(`{"receipt-data": "...", "password": "..."}`); `response_json` is the JSON
string Apple's endpoint would have answered, `status` field included. See
"The verifyReceipt-compatible endpoint" below for the raw-body caveat and the
status table.

## Integrating: from verified payload to entitlement

Verification proves Apple signed the bytes. It does not prove the presenter
owns them, and it says nothing about what happened after the signature. The
[project README](../README.md#integrating-from-verified-payload-to-entitlement)
lays out the full flow once, with a reason-to-next-step table; here are its
two branches in this port's 0.7 API.

Both branches now follow the same shape: verify, deny on any failure, then
run the post-verification checklist above yourself: 0.7 has no
constructor-supplied bundle id or environment allowlist to do it for you.

```python
# Branch A: StoreKit 2 signed transaction
result = verifier.verify_signed_data(jws)
if not result.verified:
    log(result.failure.reason)  # deny; nothing partial is returned
    return
payload = json.loads(result.payload.json)
if payload.get("bundleId") != "com.example.app":
    return  # step 1 of the checklist above
environment = Environment.from_jws_environment(payload.get("environment"))
if payload.get("revocationDate") is not None:
    return  # refunded or revoked as of signing time
expires = payload.get("expiresDate")
if expires is not None and expires <= now_ms:
    return  # subscription term had ended
grant(payload["productId"], environment, payload["transactionId"])  # idempotent on transactionId

# Branch B: legacy PKCS#7 app receipt
result = verifier.verify_receipt(receipt_b64)
if not result.verified:
    log(result.failure.reason)
    return
receipt = result.payload
if receipt.bundle_id != "com.example.app":
    return
environment = Environment.from_receipt_type(receipt.receipt_type)
for purchase in receipt.in_app:
    if purchase.cancellation_date_ms is not None:
        continue
    if purchase.expires_date_ms is not None and purchase.expires_date_ms <= now_ms:
        continue
    grant(purchase.product_id, environment, purchase.transaction_id)
```

**Freshness is your call.** Neither method rejects a payload for its age;
the signing instant (`signedDate` / the receipt's creation date) only
decides what certificate-validity window the chain is judged against. The
right freshness limit depends on the endpoint (Apple retries a server
notification for days, and a device may legitimately present an old but
genuine receipt), so apply one yourself where it fits.

## Post-verification checklist

A verified payload is only proof of what Apple signed. Nothing here checks
whether it applies to *your* app or has already been used. Every caller does
these four things with the signed fields before granting anything:

1. **Bundle id.** Compare it against your app's bundle id yourself.
   Legacy: `receipt.bundle_id`. JWS: `payload["bundleId"]`.
2. **Environment.** `Environment.from_receipt_type(receipt.receipt_type)` for
   a legacy receipt, `Environment.from_jws_environment(payload.get("environment"))`
   for a JWS payload. Decide whether you accept `SANDBOX` here; both return
   `None` for a receipt type or environment claim you don't recognise, which
   fails closed if you require a specific `Environment`.
3. **Product id.** Compare `product_id` / `payload["productId"]` against
   the catalogue of products you actually sell: a signature proves Apple
   signed it, not that it's a product your server still grants.
4. **Idempotency.** Key your own bookkeeping on the transaction id
   (`transaction_id` / `payload["transactionId"]`) so a replayed or retried
   JWS/receipt is not granted twice.

None of this is checked by `verify_receipt`, `verify_signed_data` or
`verify_receipt_endpoint` themselves: 0.7 dropped constructor-supplied
policy (bundle id, allowed environments) entirely; every check above is read
off the returned payload by the caller, every time.

## Device hash

Legacy receipts carry a device-binding hash (attribute 5,
`ReceiptPayload.sha1_hash`) that Apple's on-device code computes as
`SHA-1(device_id + opaque_value + bundle_id_bytes)`. The library does not
call this check itself: the design (0.7) treats it as a caller decision,
since `device_id` is something only the caller has (the app supplies its own
device identifier bytes; there is no single canonical source across
platforms). `device_hash` computes the formula for you:

```python
from apple_purchase_receipt_verifier.receipt import device_hash

expected = device_hash(device_id_bytes, receipt.opaque_value, receipt.bundle_id_bytes)
if expected != receipt.sha1_hash:
    raise ValueError("receipt was not issued for this device")
```

`opaque_value` and `bundle_id_bytes` are the raw attribute value octets, not
the decoded strings, because the hash is defined over the DER bytes Apple
signed.

## App Store Server Notifications V2

A V2 notification body is itself a compact JWS whose decoded payload carries
further compact JWS strings nested inside it (`data.signedTransactionInfo`,
`data.signedRenewalInfo`). Verify the outer envelope, then verify each
nested one the same way:

```python
import json

outer = verifier.verify_signed_data(request_body)
if not outer.verified:
    raise ValueError(f"{outer.failure.reason}: {outer.failure.message}")
notification = json.loads(outer.payload.json)

data = notification.get("data", {})
for key in ("signedTransactionInfo", "signedRenewalInfo"):
    nested_jws = data.get(key)
    if nested_jws is None:
        continue
    nested = verifier.verify_signed_data(nested_jws)
    if not nested.verified:
        raise ValueError(f"{key}: {nested.failure.reason}: {nested.failure.message}")
    # json.loads(nested.payload.json) is the transaction or renewal info:
    # run the post-verification checklist above on it before acting.
```

Each nested JWS is checked against the same pinned roots as the outer one;
there is nothing notification-specific about `verify_signed_data` itself.

## The verifyReceipt-compatible endpoint

`verify_receipt_endpoint` is a stateless, one-shot replacement for Apple's
deprecated endpoint: same request body, same response body, same status
codes, verified offline against the pinned roots instead of by calling
Apple. It never raises. Fields that only Apple's own server-side database
can supply (`latest_receipt_info`, `pending_renewal_info`) are not produced.
Like Apple's own endpoint, it checks no bundle id: compare
`json.loads(response)["receipt"]["bundle_id"]` yourself.

| status | meaning |
|---|---|
| 0 | Valid. `environment` and `receipt` are present in the response. |
| 21002 | `receipt-data` is missing, not a string, too large, or the body isn't valid JSON. |
| 21003 | The receipt failed to authenticate (bad signature, untrusted chain, expired or wrong-purpose certificate). |
| 21007 | A sandbox receipt was sent to `Environment.PRODUCTION`. |
| 21008 | A production receipt was sent to `Environment.SANDBOX`. |
| 21009 | Internal data access error (the library's own code faulted); alert, don't retry. |

No other `verifyReceipt` status (21000, 21001, 21004, 21005, 21006, 21010,
21100-21199) is ever returned: those describe HTTP-method, shared-secret and
Apple-server-side conditions this offline replacement cannot produce. See
`apple_status` for the named constants behind each code.

**Read the raw body.** A web framework that parses
`application/x-www-form-urlencoded` bodies rebuilds the request from parsed
fields, which is not byte-for-byte the JSON Apple's endpoint contract
expects. Read the raw request body and pass it straight through:

```python
@app.post("/verifyReceipt")
async def handle_verify_receipt(request: Request) -> Response:
    raw_body = (await request.body()).decode("utf-8")
    response_json = verifier.verify_receipt_endpoint(Environment.PRODUCTION, raw_body)
    return Response(response_json, media_type="application/json")
```

## Decode rules

Reading a legacy receipt's attributes follows a few fixed rules, the same in
every port:

- **First occurrence wins.** If Apple's payload repeats an attribute type
  (it shouldn't, but the parser doesn't assume that), the first occurrence
  decides the field; later ones are ignored. This applies to the receipt
  creation date too, since it anchors the certificate-validity check.
- **Dates** are `YYYY-MM-DDTHH:MM:SSZ` exactly (RFC 3339, UTC, no fractional
  seconds); anything else leaves the field `None` rather than raising.
  Decoded dates are epoch milliseconds (always ending in `000`, since
  receipts carry whole seconds).
- **Strings** are `UTF8String` or `IA5String` only; `IA5String` bytes ≥ 0x80
  fail to decode (7-bit ASCII, by definition). A string that fails to decode
  leaves the field `None` (or, for `bundle_id`, only `bundle_id_bytes` is
  set, see below) rather than raising.
- **`unknown_attributes`** holds the raw value octets of every attribute
  type the payload doesn't model as a named field, keyed by attribute type,
  in receipt order, so a field Apple adds later is never silently dropped.
  `bundle_id` (attribute 2) is the one exception: a decode failure there
  does not also appear in `unknown_attributes`, because `bundle_id_bytes`
  already carries the raw value unconditionally.
- **64-bit ids** (`app_item_id`, `download_id`, `version_external_identifier`,
  `web_order_line_item_id`) are plain Python `int`; `ReceiptPayload.to_json()`
  renders them as JSON strings (JSON numbers lose precision above 2^53) and
  everything else as JSON numbers, matching every other port's canonical
  form byte for byte.

## Upgrading from 0.6

0.7 is a breaking change: the two verifier classes are gone, policy checks
(bundle id, allowed environments) are no longer constructor arguments, and
every failure is a `VerificationResult`/`Failure` instead of a raised
`VerificationError`.

| 0.6 | 0.7 |
|---|---|
| `ReceiptVerifier(roots, bundle_id).verify(b64)` | `Verifier(Config.create(roots=roots)).verify_receipt(b64)`, then compare `result.payload.bundle_id` yourself |
| `JwsVerifier(roots, bundle_id, environments).verify_transaction(jws)` | `Verifier(Config.create(roots=roots)).verify_signed_data(jws)`, then compare `payload["bundleId"]` / `payload["environment"]` yourself |
| `apple_receipt_roots()` / `apple_jws_roots()` | `default_roots()` (one function, one pinned set, for both paths) |
| raised `VerificationError` with `.reason` | `VerificationResult.failure` (`Failure.reason`, `.message`, `.cause`); nothing raises |
| `Reason.INVALID_RECEIPT_FORMAT`, `.INVALID_JWS_FORMAT` | `Reason.MALFORMED` |
| `Reason.REQUEST_TOO_LARGE` | `Reason.TOO_LARGE` |
| `Reason.INVALID_CHAIN` | `Reason.UNTRUSTED_CHAIN` |
| `endpoint.verify_receipt_result(body).to_response()` | `Verifier(...).verify_receipt_endpoint(environment, body)` (returns the JSON string directly; no `VerifyReceiptResult`, no environment re-render without re-verifying) |
| `VerifyReceiptEndpoint.MAX_REQUEST_BYTES` | `apple_purchase_receipt_verifier.endpoint.MAX_REQUEST_BYTES` |
| `ReceiptVerifier.MAX_RECEIPT_BYTES` | `apple_purchase_receipt_verifier.receipt.MAX_RECEIPT_BYTES` |
| `JwsVerifier.MAX_JWS_BYTES` | `apple_purchase_receipt_verifier.jws.MAX_JWS_BYTES` |
| transaction's `expires_date` / `.revocation_date` attributes | read the same keys straight off `json.loads(payload.json)` (there is no longer a typed JWS model, only the verified JSON text) |
| device-hash check built into `ReceiptVerifier` | `apple_purchase_receipt_verifier.receipt.device_hash(...)`, called by you (see "Device hash" above) |

## Measured worst-case CPU

One call to `verify_receipt` on the larger of the two cross-port sandbox
fixtures (187 in-app purchases) takes a median of about 18 ms and a worst
observed sample of about 22 ms on the machine `bench/bench.py` ran on
(warm, GC on, ten samples of at least 100 ms each, see the script for the
exact method). `verify_receipt_endpoint` adds the JSON request/response
rendering on top, at about 29 ms median for the same fixture. The smaller
fixture (2 in-app purchases) and `verify_signed_data` are both well under a
millisecond. Run `uv run --locked python bench/bench.py` for current numbers
on your own hardware; `../BENCHMARKS.md` compares all nine ports.

## Debugging a receipt by hand

See the [project README](../README.md#debugging-a-receipt-by-hand) for the
`openssl` commands that open a receipt or a JWS payload without verifying
it (useful when a verification fails and you want to see what arrived).

## Input limits

Base64 decoding and JSON parsing both allocate a multiple of their input
before any signature is checked, so the input is measured first. The byte
limits are Apple's, fixed constants in every port of this library, not
`Config` options.

- **`receipt.MAX_RECEIPT_BYTES`** (3 MiB, 3,145,728 bytes): the base64 text
  given to `verify_receipt`, in UTF-8 bytes, before decoding. A larger
  receipt is `Reason.TOO_LARGE`.
- **`endpoint.MAX_REQUEST_BYTES`** (3 MiB, 3,145,728 bytes): the request
  body given to `verify_receipt_endpoint`, before it is parsed. A larger
  body is `Reason.TOO_LARGE` (status 21002).
- **`jws.MAX_JWS_BYTES`** (256 KiB, 262,144 bytes): the compact JWS text
  given to `verify_signed_data`, before it is split into segments. A larger
  JWS is `Reason.TOO_LARGE`.
- **JSON nesting depth 64**: checked before any JSON is parsed, in the
  request body, the JWS header and the JWS payload alike. Deeper input is
  `Reason.MALFORMED`.
- **ASN.1 nesting depth 32**: checked before any certificate is decoded.
  Deeper input is `Reason.MALFORMED`.

`fixtures/cases-0.7.json` holds every port to these same numbers, from both
sides of each boundary.

## Known issue: legacy receipts on RHEL 9

The legacy Apple receipt chain and its CMS signature are SHA-1. The
`cryptography` wheel from PyPI bundles its own OpenSSL and is not affected.
The distro package (`python3-cryptography` on RHEL 9, Alma or Rocky) uses the
system OpenSSL, which the DEFAULT crypto policy stops from verifying SHA-1
signatures, so with it a genuine legacy receipt is `Reason.UNTRUSTED_CHAIN`.
Observed on AlmaLinux 9.8 on 2026-09-24. Newer receipts (SHA-256 chains) and
every JWS are unaffected; FIPS mode is untested.

Until the fix ships, install `cryptography` from PyPI, or run
`update-crypto-policies --set DEFAULT:SHA1` on that host. The planned fix
checks SHA-1 signatures on Apple's pinned legacy chain with `cryptography`'s
`recover_data_from_signature` and an exact byte comparison, and adds an
AlmaLinux 9 CI job (ROADMAP.md).

## Why offline

Signature verification cannot fail because a vendor endpoint is down, so a
purchase can be honoured immediately and reconciled against the App Store
Server API afterwards. Refunds and revocations still need that reconciliation
pass — a signature proves what Apple signed, not what happened since.

This is one of nine implementations (Java, Node, Python, Swift, Go, Ruby,
Rust, PHP, .NET) that share a single fixture suite, including Apple's own official test fixtures, and are
required to agree byte for byte. See the
[project README](../README.md) for the full picture and
[COMPARISON.md](../COMPARISON.md) for how it differs from Apple's official
libraries.

## Licence

MIT — see [LICENSE](../LICENSE).
