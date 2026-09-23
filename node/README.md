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

## WebCrypto-only runtimes

`apple-purchase-receipt-verifier/web` is a second entry point that verifies
the same things using nothing but `crypto.subtle`, `TextDecoder` and
`Uint8Array`. Same class names, same option names, same `VerificationError`
reasons; every verify method returns a Promise, because `crypto.subtle` is
async. Porting between the two is adding or removing `await`.

```js
import {
  ReceiptVerifier, JwsVerifier, appleReceiptRoots, appleJwsRoots,
} from 'apple-purchase-receipt-verifier/web';

const receipt = await new ReceiptVerifier({
  trustedRoots: appleReceiptRoots(),
  bundleId: 'com.example.app',
}).verify(receiptB64);

const txn = await new JwsVerifier({
  trustedRoots: appleJwsRoots(),
  bundleId: 'com.example.app',
  acceptedEnvironments: ['Production'],
}).verifyTransaction(jws);
```

Which entry point a runtime needs:

| Runtime | Entry point |
|---|---|
| Node 20+, Bun, Deno | either |
| Cloudflare Workers with `nodejs_compat` (compatibility date 2024-09-23 or later, or `nodejs_compat_v2` on an older one) | either |
| Cloudflare Workers with no compatibility flags | `/web` |
| Vercel Edge runtime, Next.js edge middleware | `/web` |
| Fastly Compute, Akamai EdgeWorkers | `/web` |

Two differences beyond `await`:

- Byte-valued fields are `Uint8Array`, not `Buffer`: `opaqueValue`,
  `sha1Hash`, `bundleIdBytes`, the values in `unknownAttributes`, and the
  `deviceGuid` argument.
- Trust roots go in as DER `Uint8Array` or PEM strings. There is no
  `X509Certificate` to pass, and `appleReceiptRoots()` / `appleJwsRoots()`
  return DER bytes here.

`VerifyReceiptEndpoint` is in both entry points. On `/web` its three methods
return Promises that never reject, and the response bytes are the same.

Everything else is shared source, including the DER reader, the receipt
attribute grammar, the JWS claim checks and the `Reason` vocabulary, so the
two builds cannot drift apart on what a receipt says. The test suite runs
every shared fixture, both genuine public receipts and a corpus of over a
thousand mutated ones, through both builds and requires the same verdict.

`npm run test:runtimes:web` runs the web build on Node, on the Vercel Edge
runtime (`@edge-runtime/vm`) and on Cloudflare workerd configured with no
compatibility flags at all. `npm run test:runtimes:fastly` adds Fastly
Compute: `js-compute-runtime` builds the smoke to wasm and Fastly's own
local runtime, viceroy, serves it. viceroy is a Rust binary rather than an
npm package, so it is a separate script; install it with
`cargo install viceroy --locked` and the runner says so if it is missing.

Akamai EdgeWorkers is expected to work — it implements the same WebCrypto
API — but is untested: it has no local runtime to run it in, so the claim
for it rests on what the build asks of a runtime rather than on a passing
run. That list is short:
`crypto.subtle.digest` (SHA-1, SHA-256), `crypto.subtle.importKey` in
`'jwk'` format, `crypto.subtle.verify` for RSASSA-PKCS1-v1_5 (SHA-1 and
SHA-256) and for ECDSA (P-256 and P-384, SHA-256 and SHA-384), plus
`TextDecoder`. **SHA-1 with RSASSA-PKCS1-v1_5 is not optional**: Apple's
legacy receipt chain is signed `sha1WithRSAEncryption` from the leaf up, so
a runtime that refuses SHA-1 even for verification cannot verify a legacy
app receipt at all. Node, workerd and the Vercel Edge runtime all accept it;
a test in `runtime-smoke/web-smoke.mjs` verifies a genuine 187-purchase
legacy receipt on each of them, which is where that support gets proved.

A test also reads the emitted module graph and fails if anything reachable
from the web entry point imports a `node:` module, imports anything
non-relative, or so much as mentions `Buffer` or `process`.

## Integrating: from verified payload to entitlement

The backend flow these calls sit inside is written out once in the
[project README](https://github.com/emindeniz99/apple-purchase-receipt-verifier#integrating-from-verified-payload-to-entitlement):
verify offline, deny on any failure, check the refund field, refresh a payload
past the freshness window, guard against replay on the transaction id, then
grant. That section also carries the policy table saying what each reason
means and which ones are worth an alert. Here are its two branches in this
port's API.

A StoreKit 2 signed transaction:

```js
import {
  JwsVerifier, Reason, VerificationError, appleJwsRoots,
} from 'apple-purchase-receipt-verifier';

const verifier = new JwsVerifier({
  trustedRoots: appleJwsRoots(),
  bundleId: 'com.example.app',
  acceptedEnvironments: ['Production', 'Sandbox'],
  maxSignedAgeMillis: 5 * 60 * 1000,        // the freshness window
});

export function redeemTransaction(userId, jws) {
  let payload;
  try {
    payload = verifier.verifyTransaction(jws);                    // step 2
  } catch (error) {
    if (!(error instanceof VerificationError)) throw error;
    if (error.reason === Reason.STALE_PAYLOAD) {
      // step 4: ask the client for a fresh jwsRepresentation, or fetch one
      // from the App Store Server API and verifyTransaction that instead
      return 'refresh';
    }
    log.warn({ reason: error.reason }, 'purchase rejected');
    return 'denied';
  }

  if (payload.revocationDate !== undefined) return 'denied';      // step 3

  const id = payload.transactionId;                               // step 5
  if (grants.exists(id)) return 'denied';
  grants.record(id, payload.originalTransactionId, userId);

  grant(userId, payload.productId);
  return 'granted';
}
```

The legacy PKCS#7 app receipt is the same policy on the other input, the one
StoreKit 1 apps and older SDKs still send:

```js
import { ReceiptVerifier, appleReceiptRoots } from 'apple-purchase-receipt-verifier';

const receipts = new ReceiptVerifier({
  trustedRoots: appleReceiptRoots(),
  bundleId: 'com.example.app',
});

// Same policy keyed on the receipt's own dates. `verify` takes the base64 the
// client sends or the DER bytes; VerifyReceiptEndpoint is the alternative,
// answering Apple's `verifyReceipt` JSON shape with a `status` instead.
export function redeemReceipt(userId, receiptData, productId) {
  const receipt = receipts.verify(receiptData);                     // step 2
  const purchase = receipt.inAppPurchases.find((p) => p.productId === productId);
  if (purchase === undefined) return 'denied';
  if (purchase.cancellationDate !== null) return 'denied';          // step 3
  if (purchase.expiresDate !== null && purchase.expiresDate <= new Date()) return 'denied';

  // step 4: no maxSignedAge here, so compare the receipt's creation date. Past
  // the window, ask the client to refresh its receipt, or call the App Store
  // Server API by purchase.transactionId and verify the JWS it returns.
  if (Date.now() - receipt.creationDate.getTime() > 5 * 60 * 1000) return 'refresh';

  if (grants.exists(purchase.transactionId)) return 'denied';       // step 5
  grants.record(purchase.transactionId, purchase.originalTransactionId, userId);
  grant(userId, purchase.productId);
  return 'granted';
}
```

## The verifyReceipt-compatible endpoint

`VerifyReceiptEndpoint` answers Apple's deprecated `verifyReceipt` request
with Apple's response body, verified offline. Each call returns a
`VerifyReceiptResult`; the body is rendered only when you ask for it.

```js
import { VerifyReceiptEndpoint, appleReceiptRoots } from 'apple-purchase-receipt-verifier';

const endpoint = new VerifyReceiptEndpoint({
  trustedRoots: appleReceiptRoots(),
  environment: 'Production',
});

const result = endpoint.verifyReceiptResult(requestBody); // an object, or the raw JSON string
result.toResponse();                                     // Apple's body as an object
result.toJson();                                         // Apple's body as JSON text

endpoint.verifyReceiptJson(rawBody);           // same as verifyReceiptResult(rawBody).toJson()
endpoint.verifyReceiptData(receiptBase64);     // receipt-data alone, no envelope
```

No method throws. The statuses it can produce are `Status.OK` (0),
`MALFORMED` (21002), `NOT_AUTHENTICATED` (21003),
`SANDBOX_RECEIPT_ON_PRODUCTION` (21007), `PRODUCTION_RECEIPT_ON_SANDBOX`
(21008) and `INTERNAL` (21009), and no others, because the rest describe
conditions that only exist on Apple's servers. Routing fails closed: only
receipt types `Production` and `ProductionVPP` count as production.

A result is a union on `verified`:

```js
if (result.verified) {
  result.receipt.bundleId;     // the verified AppReceipt; compare the bundle id yourself
} else {
  result.failureReason;        // a Reason, e.g. 'INVALID_CHAIN' or 'MALFORMED_REQUEST'
  result.failureCause;         // what is behind INTERNAL_ERROR only; otherwise null
}
result.status;                 // the status for the endpoint's own environment
result.requestDate;            // the instant rendered as request_date
```

`verified` is not `status === 0`. A receipt that verified but belongs to the
other environment answers 21007 or 21008 and still carries its `receipt`.
Exactly one of `receipt` and `failureReason` is set. The result is frozen,
and only the endpoint creates one.

Like Apple's endpoint, this does **not** check the bundle id: compare
`result.receipt.bundleId` yourself before granting anything, or use
`ReceiptVerifier`, which checks it for you.

**Retrying in the other environment costs no second verification.**
`toResponse(environment)` and `toJson(environment)` render what an endpoint
of that environment would answer, recomputing the status from the receipt's
own type:

| receipt | on `'Production'` | on `'Sandbox'` |
|---|---|---|
| `Production`, `ProductionVPP` | 0 | 21008 |
| any other type, or none | 21007 | 0 |
| failed verification | its own status | its own status |

```js
const json = result.status === Status.SANDBOX_RECEIPT_ON_PRODUCTION
  ? result.toJson('Sandbox')
  : result.toJson();
```

A sandbox receipt never renders as a production 0, whichever endpoint
verified it. Any environment other than `'Production'` or `'Sandbox'` is a
`TypeError`, as it is for the constructor.

**Failure reasons:**

| `failureReason` | status | when |
|---|---|---|
| `REQUEST_TOO_LARGE` | 21002 | the raw body is over `MAX_REQUEST_BYTES` (3,145,728 UTF-8 bytes); Apple answers HTTP 413 here, see [Input limits](#input-limits) |
| `MALFORMED_REQUEST` | 21002 | the request is not an object, the string is not a JSON object or nests past 64 levels, or `receipt-data` is missing, empty or not a string |
| `INVALID_RECEIPT_FORMAT` | 21002 | `receipt-data` is over `MAX_RECEIPT_BYTES`, is not canonical standard base64 (whitespace, base64url and omitted or extra padding all count, as at Apple) or its CMS envelope does not parse |
| `INVALID_CHAIN`, `INVALID_SIGNATURE`, other certificate reasons | 21003 | the receipt did not authenticate |
| `INTERNAL_ERROR` | 21009 | not the client's fault: the receipt authenticated but its signed content cannot be read (`failureCause` is the parser's error), or an unexpected error inside the endpoint (`failureCause` holds it). Alert and retry or escalate; do not deny the user |

`MALFORMED_REQUEST` and `REQUEST_TOO_LARGE` appear only on a result. No
`VerificationError` is ever thrown with either. `INTERNAL_ERROR` is also
thrown by `ReceiptVerifier` and `verifyReceiptCore`, with the parser's error
as its `cause`.

**Order of the receipt checks.** CMS parse → the creation date alone
(attribute 12; nothing else in the payload is decoded yet) → chain at that
date, or at the system clock when the date is missing, empty, unreadable or
stated twice → receipt-signing marker OID → CMS signature → full payload
parse → bundle id → device hash. Nothing is trusted before the chain and
the signature, so reading the date never rejects. The chain comes first so
the attacker's own key is never run before it is trusted. A payload that
fails the full parse was signed by a trusted signer, so it is
`INTERNAL_ERROR`, not `INVALID_RECEIPT_FORMAT`.

**`request_date`.** Every method takes an optional `Date` as its second
argument, which becomes `request_date` in place of the endpoint's `clock`.
Without one, the clock is read once, when the call is made. That instant
reaches `request_date` and nothing else: receipt chain validity is judged at
the receipt's own creation date.

`password` and `exclude-old-transactions` are accepted for wire
compatibility and never read. See
[COMPARISON.md](https://github.com/emindeniz99/apple-purchase-receipt-verifier/blob/main/COMPARISON.md)
for the field-by-field account.

## Input limits

Base64 decoding, ASN.1 parsing and JSON parsing all allocate in proportion to
their input, and all of them run before any signature is checked. So each
input is measured first. The caps are static constants on the classes, the
same in the default and the `/web` build and in every port of this library.
They are not options.

The receipt and request caps are Apple's own limit. Measured on 2026-09-23
against both of Apple's verifyReceipt endpoints (production and sandbox), a
request body of 3,145,728 bytes is answered normally and one of 3,145,729
bytes gets HTTP 413. Apple counts UTF-8 bytes, not characters: 3,145,729
bytes of `é`, only 1,572,874 characters, also got 413. `fixtures/cases.json`
holds every port to these numbers from both sides.

- **`VerifyReceiptEndpoint.MAX_REQUEST_BYTES` (3 MiB, 3145728).** Applied to
  a raw JSON body, in UTF-8 bytes, before anything else looks at it. A larger
  body answers 21002 with `REQUEST_TOO_LARGE`. A body passed as an object is
  not measured.
- **`ReceiptVerifier.MAX_RECEIPT_BYTES` (3 MiB, 3145728).** Applied to a
  base64 receipt string, in UTF-8 bytes, before it is decoded (at
  `ReceiptVerifier.verify` and at the endpoint's `receipt-data`), and to the
  DER, in bytes, before it is parsed (at every entry point, `verifyReceiptCore`
  included). No receipt Apple accepts can be larger than the request that
  carries it. A larger receipt is `INVALID_RECEIPT_FORMAT`, 21002 at the
  endpoint.
- **JSON nesting depth 64.** `JSON.parse` has no depth option, so brackets
  outside strings are counted before it runs. A deeper request body answers
  21002 with `MALFORMED_REQUEST`; a deeper JWS header or payload is
  `INVALID_JWS_FORMAT`. A verifyReceipt body is a flat object of strings.
- **`JwsVerifier.MAX_JWS_BYTES` (256 KiB, 262144).** Applied to the compact
  JWS, in characters, before it is split or decoded. A longer one is
  `INVALID_JWS_FORMAT`. Apple's JWS payloads are a few kilobytes.

A JavaScript string holds UTF-16 units, so strings are measured in UTF-8
bytes without being encoded: more units than the cap is over it, three times
the units within the cap is within it, and only a string between the two is
walked, stopping at the first byte past the cap.

**Answering 413 like Apple.** `REQUEST_TOO_LARGE` exists so an HTTP layer can
send the status Apple sends. The body is Apple's 21002 either way:

```js
const result = endpoint.verifyReceiptResult(rawRequestBody);
const httpStatus = result.failureReason === Reason.REQUEST_TOO_LARGE ? 413 : 200;
res.status(httpStatus).type('application/json').send(result.toJson());
```

A framework that caps request bodies itself (Express's `express.json()` and
`express.text()` default to 100 KB) has to allow at least 3 MiB, or it
refuses bodies Apple would answer.

## Receipt ids are bigints

Three App Store ids come off a receipt as `bigint`: `appItemId` (attribute 1),
`downloadId` (15) and `versionExternalIdentifier` (16). Apple's download ids
are eighteen digits, so a JavaScript number would round the id it exists to
identify a download by. In-app purchases carry `isTrialPeriod` (1713) as the
integer it is, like `isInIntroOfferPeriod`.

`VerifyReceiptEndpoint` echoes them under Apple's own keys — attribute 1 twice,
as `adam_id` and `app_item_id`, because Apple does — as JSON numbers rather
than the strings the in-app integers use, and 1713 as `is_trial_period`,
`"true"` or `"false"`.

```js
const { receipt } = endpoint.verifyReceiptResult(body).toResponse();
receipt.download_id;                  // 9223372036854775807n
JSON.stringify(receipt);              // "download_id":9223372036854775808 — rounded
endpoint.verifyReceiptJson(rawBody);  // "download_id":9223372036854775807 — every digit
```

`JSON.stringify` on the response does not throw on those bigints: the receipt
renders itself with the ids as JSON numbers, which is what `JSON.parse` of
Apple's own answer yields in JavaScript anyway. `verifyReceiptJson` is the one
path that writes every digit, because it serializes the ids itself — Node 20,
the floor this package supports, has no `JSON.rawJSON` to do it with. Read
exact values off the object as bigints, or hand a consumer outside JavaScript
the `verifyReceiptJson` text.

An attribute the receipt does not carry reads `null` on the object, and its
key is left out of the endpoint's answer rather than sent as JSON null.

## Why offline

Signature verification cannot fail because a vendor endpoint is down, so a
purchase can be honoured immediately and reconciled against the App Store
Server API afterwards. Refunds and revocations still need that reconciliation
pass — a signature proves what Apple signed, not what happened since.

This is one of nine implementations (Java, Node, Python, Swift, Go, Ruby,
Rust, PHP, .NET) that share a single fixture suite, including Apple's own official test fixtures, and are
required to agree byte for byte. See the
[project README](https://github.com/emindeniz99/apple-purchase-receipt-verifier#readme)
for the full picture and
[COMPARISON.md](https://github.com/emindeniz99/apple-purchase-receipt-verifier/blob/main/COMPARISON.md)
for how it differs from Apple's official libraries.

## Changelog

One version across every language —
[CHANGELOG.md](https://github.com/emindeniz99/apple-purchase-receipt-verifier/blob/main/CHANGELOG.md)
/ [releases](https://github.com/emindeniz99/apple-purchase-receipt-verifier/releases).

## Licence

MIT — see [LICENSE](./LICENSE).
