# Genuine Apple receipts (vendored, public)

Base64 receipts copied from the MIT-licensed
[tikhop/TPInAppReceipt](https://github.com/tikhop/TPInAppReceipt)
test assets (commit `a5d9f39681bdab635f9bd119d418bc878d979de5`), Copyright (c) 2016-Present Pavel Tikhonenko.
These are **real Apple-signed bytes** — the strongest fixture tier:

| File | What it proves |
|---|---|
| `receipt-production.b64` | A genuine App Store production receipt verifies against the pinned Apple Inc. Root CA (real SHA-1/RSA WWDR chain, 7-byte integers, undocumented attrs 1/9/11/13/14/15/16/25 + 1707/1710/1713/1722) |
| `receipt-sandbox-g5.b64` | Genuine sandbox receipt (newer G5 signing chain) verifies |
| `receipt-sandbox-legacy.b64` | Genuine legacy receipt with a full SHA-1 chain and **187 in-app purchases** verifies (stress test; exposed a Python SHA-1 chain-helper gap now fixed) |
| `receipt-xcode-with-purchases.b64` | Xcode-signed receipt is REJECTED (INVALID_CHAIN) against real Apple roots |
