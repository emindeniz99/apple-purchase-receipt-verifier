# apple-purchase-receipt-verifier

Verify Apple in-app purchases locally — no calls to Apple's servers.

Replaces the deprecated `verifyReceipt` endpoint by validating StoreKit 2
signed JWS transactions and legacy PKCS#7 receipts against pinned Apple
root certificates. Zero runtime dependencies.

```bash
npm install apple-purchase-receipt-verifier
```

```js
import {
  ReceiptVerifier, JwsVerifier, appleReceiptRoots, appleJwsRoots,
} from 'apple-purchase-receipt-verifier';

// Legacy PKCS#7 app receipt
const receipt = new ReceiptVerifier({
  trustedRoots: appleReceiptRoots(),
  bundleId: 'com.example.app',
}).verify(receiptB64);
console.log(receipt.receiptType, receipt.inAppPurchases.length);

// StoreKit 2 signed transaction
const txn = new JwsVerifier({
  trustedRoots: appleJwsRoots(),
  bundleId: 'com.example.app',
}).verifyTransaction(jws);
console.log(txn.productId, txn.expiresDate);
```

ESM, Node 20+.

## Why offline

Signature verification cannot fail because a vendor endpoint is down, so a
purchase can be honoured immediately and reconciled against the App Store
Server API afterwards. Refunds and revocations still need that reconciliation
pass — a signature proves what Apple signed, not what happened since.

This is one of four implementations (Java, Node, Python, Swift) that share a
single fixture suite, including Apple's own official test fixtures, and are
required to agree byte for byte. See the
[project README](https://github.com/emindeniz99/apple-purchase-receipt-verifier#readme)
for the full picture and
[COMPARISON.md](https://github.com/emindeniz99/apple-purchase-receipt-verifier/blob/main/COMPARISON.md)
for how it differs from Apple's official libraries.

## Changelog

One version across all four languages —
[CHANGELOG.md](https://github.com/emindeniz99/apple-purchase-receipt-verifier/blob/main/CHANGELOG.md)
/ [releases](https://github.com/emindeniz99/apple-purchase-receipt-verifier/releases).

## Licence

MIT — see [LICENSE](./LICENSE).
