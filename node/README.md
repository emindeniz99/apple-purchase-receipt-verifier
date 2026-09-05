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

Three differences beyond `await`:

- Byte-valued fields are `Uint8Array`, not `Buffer`: `opaqueValue`,
  `sha1Hash`, `bundleIdBytes`, the values in `unknownAttributes`, and the
  `deviceGuid` argument.
- Trust roots go in as DER `Uint8Array` or PEM strings. There is no
  `X509Certificate` to pass, and `appleReceiptRoots()` / `appleJwsRoots()`
  return DER bytes here.
- `VerifyReceiptEndpoint`, the drop-in for Apple's deprecated endpoint, is
  only in the default entry point.

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

Akamai EdgeWorkers has no local runtime to run it in, so the claim for it
rests on what the build asks of a runtime rather than on a passing run.
That list is short:
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
