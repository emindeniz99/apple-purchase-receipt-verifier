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
`apple-purchase-receipt-verifier`. Requires Python 3.9+.

## Integrating: from verified payload to entitlement

The backend flow these calls sit inside is written out once in the
[project README](../README.md#integrating-from-verified-payload-to-entitlement):
verify offline, deny on any failure, check the refund field, refresh a payload
past the freshness window, guard against replay on the transaction id, then
grant. That section also carries the policy table saying what each reason
means and which ones are worth an alert. Here are its two branches in this
port's API.

A StoreKit 2 signed transaction:

```python
from apple_purchase_receipt_verifier import (
    JwsVerifier,
    Reason,
    VerificationError,
    apple_jws_roots,
)

verifier = JwsVerifier(
    apple_jws_roots(),
    "com.example.app",
    ["Production", "Sandbox"],
    max_signed_age_millis=5 * 60 * 1000,        # the freshness window
)


def redeem_transaction(user_id: str, jws: str) -> str:
    try:
        payload = verifier.verify_transaction(jws)                  # step 2
    except VerificationError as error:
        if error.reason == Reason.STALE_PAYLOAD:
            # step 4: ask the client for a fresh jwsRepresentation, or fetch
            # one from the App Store Server API and verify that instead
            return "refresh"
        log.warning("purchase rejected: %s", error.reason)
        return "denied"

    if payload.get("revocationDate") is not None:                   # step 3
        return "denied"

    transaction_id = payload["transactionId"]                       # step 5
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
    receipt = receipts.verify(receipt_data)                         # step 2
    now = datetime.now(timezone.utc)
    purchase = next(
        (p for p in receipt.in_app_purchases if p.product_id == product_id), None
    )
    if purchase is None or purchase.cancellation_date is not None:  # step 3
        return "denied"
    if purchase.expires_date is not None and purchase.expires_date <= now:
        return "denied"

    # step 4: no max_signed_age_millis here, so compare the creation date. Past
    # the window, ask the client to refresh its receipt, or call the App Store
    # Server API by purchase.transaction_id and verify the JWS it returns.
    if now - receipt.creation_date > timedelta(minutes=5):
        return "refresh"

    if grants.exists(purchase.transaction_id):                      # step 5
        return "denied"
    grants.record(purchase.transaction_id, purchase.original_transaction_id, user_id)

    grant(user_id, purchase.product_id)
    return "granted"
```

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
