# Apple `verifyReceipt` vs. our local `VerifyReceiptEndpoint`

Every implementation ships a `VerifyReceiptEndpoint` that speaks the exact
wire contract of Apple's deprecated
[`verifyReceipt`](https://developer.apple.com/documentation/appstorereceipts/verify-receipt)
endpoint — same [request body](https://developer.apple.com/documentation/appstorereceipts/requestbody),
same [response body](https://developer.apple.com/documentation/appstorereceipts/responsebody)
shape, same [status codes](https://developer.apple.com/documentation/appstorereceipts/status) —
verified offline instead of by calling Apple. Each one takes either a
parsed request body or the raw JSON body as a string — `verifyReceiptJson`
in Java, Node and PHP, `verify_receipt_json` in Python, Ruby and Rust,
`verifyReceiptJSON` in Swift, `VerifyReceiptJSON` in Go and
`VerifyReceiptJson` in .NET — answering in the same form it was given. This
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
| `password` (shared secret) | required for auto-renewable subs; wrong value → 21004 | ⚠️ **never read** — a shared secret can only be validated against Apple's account database, which doesn't exist locally. We never return 21004. |
| `exclude-old-transactions` | trims `latest_receipt_info` | ⚠️ **never read** — there is nothing to trim, since we never produce `latest_receipt_info` (below). |

### Size limit

We match Apple. On 2026-09-23 we measured both of Apple's endpoints,
`buy.itunes.apple.com/verifyReceipt` and the sandbox one: Apple answers a
request body of 3,145,728 bytes and returns HTTP 413 for 3,145,729 bytes.
Apple counts UTF-8 bytes, not characters. A body of 3,145,729 bytes of `é`
(1,572,874 characters) also got 413, and 3,145,727 bytes of it got 200.

Every port refuses a raw body over 3,145,728 UTF-8 bytes before parsing it.
The answer is status 21002 with the result-only reason `REQUEST_TOO_LARGE`,
so your HTTP layer can send 413 as Apple does. A `receipt-data` over
3,145,728 bytes, or DER over that size, is `INVALID_RECEIPT_FORMAT` (21002).
The limits are fixed constants, and `fixtures/cases.json` holds every port
to them from both sides.

## Status codes

| Code | Apple meaning | Ours |
|---|---|---|
| 0 | valid | ✅ same semantics (chain + signature to pinned Apple root) |
| 21000 | the request didn't use HTTP POST | ❌ out of scope — this is a body-level API with no HTTP layer, so there is no request method to get wrong. Your framework decides what a non-POST gets |
| 21001 | "The App Store no longer sends this status code." | ❌ never produced; Apple retired it |
| 21002 | receipt-data malformed or missing | ✅ returned when `receipt-data` is absent, empty, not a string, not base64, or its CMS envelope does not parse. Payload content that a trusted signer signed and the library cannot read is 21009, not 21002 |
| 21003 | receipt could not be authenticated | ✅ chain or signature failure |
| 21004 | shared secret mismatch | ❌ never produced (see `password`) |
| 21005 | Apple's receipt server is unavailable | ❌ never produced — there is no server to be unavailable; this is a *benefit* |
| 21006 | valid but subscription expired (iOS 6 style only) | ❌ never produced (legacy iOS 6 transaction receipts unsupported) |
| 21007 / 21008 | sandbox↔production routing | ✅ reproduced locally from the receipt's `receipt_type` attribute — the classic "try production, retry sandbox on 21007" dance still works unchanged. Fails closed: only `Production`/`ProductionVPP` count as production; sandbox variants and a missing attribute are treated as sandbox. `Xcode` is in that fail-closed set for completeness only — an Xcode-generated receipt is not Apple-signed, so it stops at 21003 before routing is reached |
| 21009 / 21010 | internal error / account not found | 21009 (`INTERNAL_ERROR`) when the receipt authenticates (trusted chain, valid signature) but its signed content cannot be read, when the runtime lacks an algorithm the check needs, and on unexpected internal errors. Not the client's fault, and deterministic: the same receipt gives 21009 again, so retrying does not help. Log the cause with the library version, alert, and settle the purchase through the App Store Server API by transaction id. 21010 never (no account database) |
| 21100–21199 (+ `is_retryable`) | Apple internal data access error; `is_retryable` says whether retrying may help | ❌ never produced, and we never emit an `is_retryable` field either — these codes report the state of Apple's own datastore, and there is no remote call here to retry |

A tampered receipt shows 21002 and 21003 diverging in practice. Altering one
byte of a well-formed payload while keeping the DER structurally valid
(2026-09-22, not committed) gets 21003 from this endpoint and 21002 from
Apple's own. Apple's reference defines 21003 as "The receipt could not be
authenticated" and 21002 as malformed data or a temporary issue on Apple's
server; this endpoint follows the documented meaning and reports 21003 for
the case that description names, while Apple's own endpoint collapses both
into 21002. A caller migrating from Apple's endpoint should not read a
21002 response from Apple as covering every rejection this endpoint reports
as 21003.

Apple's answer was 21002 for every rejection measured, not only that one.
Ten input classes went to `buy.itunes.apple.com/verifyReceipt` on
2026-09-22: a genuine receipt (0), the same receipt with one byte changed in
the payload, in the signature, and in a certificate, a receipt truncated in
half, valid DER that is not a receipt, random bytes, a string that is not
base64, the empty string, and an Xcode-signed receipt that is well formed
but not signed by Apple. Every rejection came back 21002. This endpoint
answers 21002 for the four that never become a receipt and 21003 for the
four that do and then fail to authenticate. So 21003 is a code Apple
documents and does not appear to emit.

## Response body

### Produced with full fidelity (from the verified receipt)

`receipt.receipt_type`, `bundle_id`, `application_version`,
`original_application_version`, `receipt_creation_date` (+`_ms`, `_pst`),
`request_date` (+`_ms`, `_pst`), `original_purchase_date` (+`_ms`, `_pst`),
`expiration_date` (VPP receipts), `adam_id` / `app_item_id`, `download_id`,
`version_external_identifier` (all three JSON numbers, the first two
echoing the same value under both keys), and per-purchase `in_app` entries:
`quantity`, `product_id`, `transaction_id`, `original_transaction_id`,
`purchase_date` / `original_purchase_date` / `expires_date` /
`cancellation_date` (each +`_ms`, `_pst`), `web_order_line_item_id`,
`is_in_intro_offer_period`, `is_trial_period` (JSON string `"true"`/`"false"`,
like `is_in_intro_offer_period`). Number-as-string and date-triplet
formatting match Apple's (`"1"`, `"2024-08-06 12:00:00 Etc/GMT"`).

`environment` is the one response field not read from the receipt: it echoes
the environment this endpoint instance was configured to emulate. On a
status-0 response the two agree by construction — a receipt that disagrees
with the configured environment is what 21007/21008 report instead, and
those responses carry no `environment` at all.

### Not produced — receipt attributes Apple documents in the response but that are absent, undocumented, or unavailable locally

`preorder_date`, promotional offer ids introduced after the receipt format
froze, and `in_app_ownership_type` — family-sharing state that no receipt,
sandbox or production, carries, so it cannot be derived locally.

Measured against a genuine production receipt (not committed) and Apple's
own `verifyReceipt` answer for it, 2026-09-21: the endpoint now matches
Apple on 30 of the 31 fields Apple returned for that receipt, the lone gap
being `in_app_ownership_type`. Key order inside `receipt` matches Apple's
except that Apple places `original_application_version` immediately before
`in_app`, which is not part of the JSON contract.

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
