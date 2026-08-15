# Genuine Apple receipts (vendored, public)

Base64 receipts copied from the MIT-licensed
[tikhop/TPInAppReceipt](https://github.com/tikhop/TPInAppReceipt)
test assets (commit `a5d9f39681bdab635f9bd119d418bc878d979de5`), Copyright (c) 2016-Present Pavel Tikhonenko.
These are **real Apple-signed bytes** — the strongest fixture tier:

| File | What it proves |
|---|---|
| `receipt-sandbox-g5.b64` | Genuine sandbox receipt (newer G5 signing chain) verifies |
| `receipt-sandbox-legacy.b64` | Genuine legacy receipt with a full SHA-1 chain and **187 in-app purchases** verifies (stress test; exposed a Python SHA-1 chain-helper gap now fixed) |
| `receipt-xcode-with-purchases.b64` | Xcode-signed receipt is REJECTED (INVALID_CHAIN) against real Apple roots |

## Why there is no production receipt here

There was one (`receipt-production.b64`, a consumer dating app's receipt).
It was removed before this project became public.

A genuine *production* receipt necessarily contains one real end user's
purchase history — that file carried four transaction ids and dated
subscription records keyed to a stable `original_transaction_id`, for a
consumer app. Being MIT-licensed upstream settles copyright, not data
protection, and republishing it in immutable registry artifacts under a
different name is a fresh act rather than an inherited one.

Apple reached the same conclusion: their official libraries' test data
(vendored under `../apple-official/`) is entirely synthetic — a
self-signed `testCA` chain and `mock_signed_data`, with no production
receipt anywhere.

**What this costs us, measured rather than assumed:** nothing in the
certificate path. All three remaining genuine receipts chain to the same
real Apple Root CA and the same Apple Worldwide Developer Relations
intermediate, so the pinned-root verification is still exercised against
real Apple-signed bytes. What is no longer covered is the
`receiptType == "Production"` field value and production-only attribute
combinations; the sandbox receipts assert `"ProductionSandbox"` instead.

Restoring that coverage means generating a production receipt from an app
we control, not borrowing another one.
