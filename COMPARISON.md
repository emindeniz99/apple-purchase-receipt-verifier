# Apple `verifyReceipt` vs. our local `VerifyReceiptEndpoint`

Every implementation ships a `VerifyReceiptEndpoint` that speaks the exact
wire contract of Apple's deprecated
[`verifyReceipt`](https://developer.apple.com/documentation/appstorereceipts/verify-receipt)
endpoint — same [request body](https://developer.apple.com/documentation/appstorereceipts/requestbody),
same [response body](https://developer.apple.com/documentation/appstorereceipts/responsebody)
shape, same [status codes](https://developer.apple.com/documentation/appstorereceipts/error) —
verified offline instead of by calling Apple. Each one takes either a
parsed request body or the raw JSON body as a string (`verifyReceipt(String)`
in Java, `verifyReceiptJson` in Node, `verify_receipt_json` in Python,
`verifyReceiptJSON` in Swift), answering in the same form it was given. This
file is the honest field-by-field account of what is identical, what differs,
and what is **impossible** to produce locally.

The principle behind the gaps: the PKCS#7 receipt the client sends contains
everything Apple *signed into it* — app identity, versions, dates, and every
in-app purchase at signing time. What it does **not** contain is Apple's
**server-side subscription database state** (later renewals, refunds,
auto-renew intent). Apple's endpoint merges both; we can only ever produce
the first part — cryptographically verified.

## Request body

| Field | Apple | Ours |
|---|---|---|
| `receipt-data` | required, base64 receipt | ✅ identical |
| `password` (shared secret) | required for auto-renewable subs; wrong value → 21004 | ⚠️ accepted, **ignored** — the shared secret is verified against Apple's account database, which doesn't exist locally. We never return 21004. |
| `exclude-old-transactions` | trims `latest_receipt_info` | ⚠️ accepted, no effect — we never produce `latest_receipt_info` (below). |

## Status codes

| Code | Apple meaning | Ours |
|---|---|---|
| 0 | valid | ✅ same semantics (chain + signature to pinned Apple root) |
| 21000 / 21002 | malformed request / receipt-data | ✅ we return 21002 for both malformed cases |
| 21003 | receipt could not be authenticated | ✅ chain or signature failure |
| 21004 | shared secret mismatch | ❌ never produced (see `password`) |
| 21005 / is-retryable | Apple server unavailable | ❌ never produced — there is no server to be unavailable; this is a *benefit* |
| 21006 | valid but subscription expired (iOS 6 style only) | ❌ never produced (legacy iOS 6 transaction receipts unsupported) |
| 21007 / 21008 | sandbox↔production routing | ✅ reproduced locally from the receipt's `receipt_type` attribute — the classic "try production, retry sandbox on 21007" dance still works unchanged. Fails closed: only `Production`/`ProductionVPP` count as production; sandbox variants, `Xcode`, and a missing attribute are treated as sandbox |
| 21009 / 21010 | internal error / account not found | 21009 on unexpected internal errors; 21010 never (no account database) |

## Response body

### Produced with full fidelity (from the verified receipt)

`environment`; `receipt.receipt_type`, `bundle_id`, `application_version`,
`original_application_version`, `receipt_creation_date` (+`_ms`, `_pst`),
`request_date` (+`_ms`, `_pst`), `original_purchase_date` (+`_ms`, `_pst`),
`expiration_date` (VPP receipts), and per-purchase `in_app` entries:
`quantity`, `product_id`, `transaction_id`, `original_transaction_id`,
`purchase_date` / `original_purchase_date` / `expires_date` /
`cancellation_date` (each +`_ms`, `_pst`), `web_order_line_item_id`,
`is_in_intro_offer_period`. Number-as-string and date-triplet formatting
match Apple's (`"1"`, `"2024-08-06 12:00:00 Etc/GMT"`).

### Not produced — receipt attributes Apple documents in the response but that are absent or undocumented in the ASN.1 receipt

`adam_id` / `app_item_id`, `download_id`, `version_external_identifier`,
`preorder_date`, `is_trial_period` (attribute exists but its type id is not
reliably documented — needs the real-receipt corpus, ROADMAP), promotional
offer ids introduced after the receipt format froze.

### Impossible locally — Apple server-side database state

| Field | Why it cannot exist locally |
|---|---|
| `latest_receipt` / `latest_receipt_info` | Apple returns the *latest* subscription transactions, including renewals that happened **after** this receipt was signed. Only Apple's database knows them. Replacement: App Store Server API `Get Transaction History` by transaction id, or Server Notifications V2. |
| `pending_renewal_info` (`auto_renew_status`, `expiration_intent`, …) | Renewal *intent* is live account state, never part of the signed receipt. Same replacements. |
| refund/revocation after signing | A receipt signed before a refund verifies forever — by design of signatures. Track transaction ids server-side (INTENT.md). |

**Bottom line**: for one-time purchases (consumables, non-consumables) the
local endpoint is a faithful, complete replacement. For auto-renewable
subscriptions it faithfully reports what the presented receipt proves — the
subscription state *as of signing* — and the "what happened since"
questions must go to the App Store Server API / Notifications V2, exactly
as Apple's own migration guidance says.
