# apple-purchase-receipt-verifier

Verify Apple in-app purchases locally — no calls to Apple's servers.

Replaces the deprecated `verifyReceipt` endpoint by validating StoreKit 2
signed JWS transactions and legacy PKCS#7 receipts against pinned Apple
root certificates.

```bash
pip install apple-purchase-receipt-verifier
```

```python
from apple_purchase_receipt_verifier import ReceiptVerifier, JwsVerifier, apple_receipt_roots

# Legacy PKCS#7 app receipt
receipt = ReceiptVerifier(apple_receipt_roots(), "com.example.app").verify(receipt_b64)
print(receipt.receipt_type, len(receipt.in_app_purchases))

# StoreKit 2 signed transaction
transaction = JwsVerifier(apple_jws_roots(), "com.example.app").verify_transaction(jws)
print(transaction.product_id, transaction.expires_date)
```

The import package is `apple_purchase_receipt_verifier`; the distribution is
`apple-purchase-receipt-verifier`. Requires Python 3.9+.

## Why offline

Signature verification cannot fail because a vendor endpoint is down, so a
purchase can be honoured immediately and reconciled against the App Store
Server API afterwards. Refunds and revocations still need that reconciliation
pass — a signature proves what Apple signed, not what happened since.

This is one of four implementations (Java, Node, Python, Swift) that share a
single fixture suite, including Apple's own official test fixtures, and are
required to agree byte for byte. See the
[project README](../README.md) for the full picture and
[COMPARISON.md](../COMPARISON.md) for how it differs from Apple's official
libraries.

## Licence

MIT — see [LICENSE](../LICENSE).
