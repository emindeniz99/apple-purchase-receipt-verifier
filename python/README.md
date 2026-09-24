# apple-purchase-receipt-verifier

Verify Apple in-app purchases locally — no calls to Apple's servers.

Replaces the deprecated `verifyReceipt` endpoint by validating StoreKit 2
signed JWS transactions and legacy PKCS#7 receipts against pinned Apple
root certificates.

```bash
pip install apple-purchase-receipt-verifier
```

```python
from apple_purchase_receipt_verifier import (
    JwsVerifier,
    ReceiptVerifier,
    apple_jws_roots,
    apple_receipt_roots,
)

# Legacy PKCS#7 app receipt
receipt = ReceiptVerifier(apple_receipt_roots(), "com.example.app").verify(receipt_b64)
print(receipt.receipt_type, len(receipt.in_app_purchases))

# StoreKit 2 signed transaction
transaction = JwsVerifier(
    apple_jws_roots(), "com.example.app", ["Production", "Sandbox"]
).verify_transaction(jws)
print(transaction.product_id, transaction.expires_date)
```

The import package is `apple_purchase_receipt_verifier`; the distribution is
`apple-purchase-receipt-verifier`. Requires Python 3.10+.

## Integrating: from verified payload to entitlement

The backend flow these calls sit inside is written out once in the
[project README](../README.md#integrating-from-verified-payload-to-entitlement):
verify offline, deny on any failure, check the refund field, refresh a payload
past the freshness window, guard against replay on the transaction id, then
grant. That section also carries the policy table saying what each reason
means and which ones are worth an alert. Here are its two branches in this
port's API.

**Freshness is your call.** `JwsVerifier` rejects no payload for its age, as
in Apple's own App Store Server Libraries: `signedDate` only decides the
instant the chain is judged at. The right limit depends on the endpoint
(Apple retries a server notification for days, and a device may present an
old but genuine payload), so apply one yourself where it fits:
`if time.time() * 1000 - payload["signedDate"] > 5 * 60 * 1000: ...`.

A StoreKit 2 signed transaction:

```python
import time

from apple_purchase_receipt_verifier import (
    JwsVerifier,
    VerificationError,
    apple_jws_roots,
)

verifier = JwsVerifier(apple_jws_roots(), "com.example.app", ["Production", "Sandbox"])


def redeem_transaction(user_id: str, jws: str) -> str:
    try:
        payload = verifier.verify_transaction(jws)  # step 2
    except VerificationError as error:
        log.warning("purchase rejected: %s", error.reason)
        return "denied"

    if payload.get("revocationDate") is not None:  # step 3
        return "denied"

    # step 4, your call: past the window, ask the client for a fresh
    # jwsRepresentation, or fetch one from the App Store Server API and
    # verify that instead
    if time.time() * 1000 - (payload.get("signedDate") or 0) > 5 * 60 * 1000:
        return "refresh"

    transaction_id = payload["transactionId"]  # step 5
    if grants.exists(transaction_id):
        return "denied"
    grants.record(transaction_id, payload.get("originalTransactionId"), user_id)

    grant(user_id, payload["productId"])
    return "granted"
```

The legacy PKCS#7 app receipt is the same policy on the other input, the one
StoreKit 1 apps and older SDKs still send:

```python
from datetime import datetime, timedelta, timezone

from apple_purchase_receipt_verifier import ReceiptVerifier, apple_receipt_roots

receipts = ReceiptVerifier(apple_receipt_roots(), "com.example.app")


# Same policy keyed on the receipt's own dates. `verify` takes the base64 the
# client sends or the DER bytes; VerifyReceiptEndpoint is the alternative,
# answering Apple's `verifyReceipt` JSON shape with a `status` instead.
def redeem_receipt(user_id: str, receipt_data: str, product_id: str) -> str:
    receipt = receipts.verify(receipt_data)  # step 2
    now = datetime.now(timezone.utc)
    purchase = next((p for p in receipt.in_app_purchases if p.product_id == product_id), None)
    if purchase is None or purchase.cancellation_date is not None:  # step 3
        return "denied"
    if purchase.expires_date is not None and purchase.expires_date <= now:
        return "denied"

    # step 4: the same caller-side check, on the creation date. Past
    # the window, ask the client to refresh its receipt, or call the App Store
    # Server API by purchase.transaction_id and verify the JWS it returns.
    if now - receipt.creation_date > timedelta(minutes=5):
        return "refresh"

    if grants.exists(purchase.transaction_id):  # step 5
        return "denied"
    grants.record(purchase.transaction_id, purchase.original_transaction_id, user_id)

    grant(user_id, purchase.product_id)
    return "granted"
```

## The verifyReceipt-compatible endpoint

`VerifyReceiptEndpoint` answers Apple's deprecated `verifyReceipt` request
with the same response body, verified offline. One instance emulates one
environment, `"Production"` or `"Sandbox"`.

```python
from apple_purchase_receipt_verifier import VerifyReceiptEndpoint, apple_receipt_roots

endpoint = VerifyReceiptEndpoint(apple_receipt_roots(), "Production")

# The request body as a dict, or the raw JSON text.
result = endpoint.verify_receipt_result(request_body)
response = result.to_response()  # Apple's body as a dict
json_body = result.to_json()  # Apple's body as JSON

# The same as verify_receipt_result(raw_body).to_json().
json_body = endpoint.verify_receipt_json(raw_body)
# receipt-data alone, with no request envelope.
bare = endpoint.verify_receipt_data(receipt_b64)
```

No endpoint method raises on a request: the Apple status is part of the
result, for every input, including a body that is not JSON
(`{"status":21002}`). The statuses it can produce are 0, 21002, 21003,
21007, 21008 and 21009, and no others, because the rest describe conditions
that only exist on Apple's servers. Local 21007/21008 routing fails closed:
only receipt types `Production` and `ProductionVPP` count as production.

A `VerifyReceiptResult` is one verification:

- `status` is the answer for the endpoint's own environment.
- `receipt` is the verified `AppReceipt` whenever the receipt bytes
  verified, 21007 and 21008 included.
- `failure_reason` is a `Reason` value saying why there is no receipt.
  Exactly one of `receipt` and `failure_reason` is set.
- `verified` is `True` exactly when `receipt` is set. That includes 21007
  and 21008, so it is not the same check as `status == 0`: `status == 0`
  asks whether this endpoint's environment accepts the receipt, `verified`
  asks whether the receipt verified at all.
- `failure_cause` is what is behind an `INTERNAL_ERROR`, for logging: the
  parser's exception for signed content that could not be read, or the
  unexpected exception the endpoint caught.
- `request_date` is the UTC `datetime` rendered as `request_date`.

The result is immutable and only the endpoint creates one. Each response is
rendered the first time it is asked for and reused after that.

**Retrying in the other environment costs no second verification.**
`to_response(environment)` and `to_json(environment)` render what an endpoint
of that environment would answer, recomputing the status from the receipt's
own type:

| receipt | on `"Production"` | on `"Sandbox"` |
|---|---|---|
| `Production`, `ProductionVPP` | 0 | 21008 |
| any other type, or none | 21007 | 0 |
| failed verification | its own status | its own status |

```python
result = production.verify_receipt_result(request_body)
if result.status == 21007:
    json_body = result.to_json("Sandbox")
```

A sandbox receipt never renders as a production 0, whichever endpoint
verified it. Any environment other than `"Production"` or `"Sandbox"` raises
`ValueError`, as the constructor does.

| `failure_reason` | status | when |
|---|---|---|
| `REQUEST_TOO_LARGE` | 21002 | the raw body is over `MAX_REQUEST_BYTES` (3,145,728 UTF-8 bytes); Apple answers HTTP 413 here, see [Input limits](#input-limits) |
| `MALFORMED_REQUEST` | 21002 | the body is not a JSON object or nests past 64 levels, or `receipt-data` is missing, empty or not a string |
| `INVALID_RECEIPT_FORMAT` | 21002 | `receipt-data` is over `MAX_RECEIPT_BYTES`, is not canonical standard base64 (whitespace, base64url and omitted or extra padding all count, as at Apple) or its CMS envelope does not parse |
| `INVALID_CHAIN`, `INVALID_SIGNATURE`, other certificate reasons | 21003 | the receipt did not authenticate |
| `INTERNAL_ERROR` | 21009 | not the client's fault: the receipt authenticated but its signed content cannot be read, or an unexpected exception inside the endpoint; `failure_cause` holds what is behind it. Alert and retry or escalate; do not deny the user |

`MALFORMED_REQUEST` and `REQUEST_TOO_LARGE` only ever appear on a result. No
`VerificationError` is raised with either. `INTERNAL_ERROR` is also raised
by `ReceiptVerifier` and `verify_receipt_core`, with the parser's exception
as its `__cause__`.

**Order of the receipt checks.** CMS parse → the creation date alone
(attribute 12; nothing else in the payload is decoded yet) → chain at that
date, or at the system clock when the date is missing, empty, unreadable or
stated twice → receipt-signing marker OID → CMS signature → full payload
parse → bundle id → device hash. Nothing is trusted before the chain and
the signature, so reading the date never rejects. The chain comes first so
the attacker's own key is never run before it is trusted. A payload that
fails the full parse was signed by a trusted signer, so it is
`INTERNAL_ERROR`, not `INVALID_RECEIPT_FORMAT`.

**`request_date`.** `verify_receipt_result` and `verify_receipt_data` take
a keyword-only `now`, a timezone-aware `datetime` that becomes
`request_date` in place of the endpoint's clock. Without it the clock is
read once, when the call is made.
`now` reaches `request_date` and nothing else: certificate validity never
sees it. A naive `datetime` raises `ValueError`.

Like Apple's endpoint, this does **not** check the bundle id: compare
`result.receipt.bundle_id` yourself before granting anything, or use
`ReceiptVerifier`, which checks it for you.

Migrating from 0.5: `endpoint.verify_receipt(body)` is removed; use
`endpoint.verify_receipt_result(body).to_response()`.

## Input limits

Base64 decoding and JSON parsing both allocate a multiple of their input
before any signature is checked, so the input is measured first. The byte
limits are Apple's, fixed constants in every port of this library, not
constructor options. Measured on 2026-09-23 against both of Apple's
verifyReceipt endpoints (production and sandbox), a request body of
3,145,728 bytes is answered normally and one of 3,145,729 bytes gets HTTP
413. Apple counts UTF-8 bytes, not characters: 3,145,729 bytes of `é`, only
1,572,874 characters, also got 413. `fixtures/cases.json` holds every port
to these numbers from both sides.

- **`VerifyReceiptEndpoint.MAX_REQUEST_BYTES` (3 MiB, 3,145,728 bytes).**
  Applied to a raw JSON body before it is parsed: a `str` in UTF-8 bytes, a
  `bytes` body by its length. A larger body answers 21002 with
  `REQUEST_TOO_LARGE`, before the parse and the depth check. A body already
  decoded to a dict is not measured.
- **`ReceiptVerifier.MAX_RECEIPT_BYTES` (3 MiB, 3,145,728 bytes).** Applied
  to the base64 string at `ReceiptVerifier.verify` and at the endpoint's
  `receipt-data`, in UTF-8 bytes, before decoding, and to the DER at every
  entry point that takes bytes, `verify_receipt_core` included. No receipt
  Apple accepts can be larger than the request that carries it. A larger
  receipt is `INVALID_RECEIPT_FORMAT`.
- **JSON nesting depth 64.** `json.loads` has no depth option and recurses
  once per level, so the depth is counted before it runs. A deeper body
  answers 21002 with `MALFORMED_REQUEST`. A verifyReceipt body is a flat
  object of strings.
- **`JwsVerifier.MAX_JWS_BYTES` (256 KiB).** Applied to the compact JWS
  string in characters, before it is split into segments or any segment is
  decoded. A larger JWS is `INVALID_JWS_FORMAT`. The header and payload JSON
  are also capped at nesting depth 64, checked before `json.loads` runs, for
  the same reason as the request body above. Apple's JWS payloads are a few
  KB at most.

A `str` holds code points, one to four UTF-8 bytes each, so its length
decides most checks without encoding it: more code points than the limit is
over it, four times the code points within the limit is within it, and an
ASCII string is exactly its length. Only a non-ASCII string between those
bounds is encoded to be counted, a copy of at most four times the limit. A
lone surrogate counts as three bytes.

**Answering 413 like Apple.** `REQUEST_TOO_LARGE` exists so an HTTP layer can
send the status Apple sends. The body is Apple's 21002 either way:

```python
result = endpoint.verify_receipt_result(raw_request_body)
http_status = 413 if result.failure_reason == Reason.REQUEST_TOO_LARGE else 200
return Response(result.to_json(), status=http_status, media_type="application/json")
```

A framework that caps request bodies itself has to allow at least 3 MiB, or
it refuses bodies Apple would answer.

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
