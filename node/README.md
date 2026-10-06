# apple-purchase-receipt-verifier

Verify Apple in-app purchases locally, with no calls to Apple's servers.

Replaces the deprecated `verifyReceipt` endpoint by validating StoreKit 2
signed JWS payloads and legacy PKCS#7 app receipts against pinned Apple root
certificates.

```bash
npm install apple-purchase-receipt-verifier
```

```js
import { createConfig, createVerifier } from 'apple-purchase-receipt-verifier';

// Build once, share everywhere: the module and its roots load once, not per call.
const verifier = createVerifier(createConfig());

// A legacy app receipt, as the base64 string the app sends.
const receiptResult = verifier.verifyReceipt(receiptBase64);
if (receiptResult.verified) {
  console.log(receiptResult.payload.receiptType, receiptResult.payload.inApp.length);
}

// Any Apple-signed JWS: a transaction, renewal info, an app transaction or
// a notification. The payload comes back as the JSON text Apple signed.
const jwsResult = verifier.verifySignedData(jws);
if (jwsResult.verified) {
  console.log(jwsResult.payload.json);
}
```

ESM, Node 20+, zero runtime dependencies. No verify method throws for input
you do not control: every call returns a result object.

The library answers one question: did Apple sign this? It checks the chain
to a pinned root, Apple's marker OIDs and the signature, and hands back
everything the payload says. You decide whether the payload is for your
app, your environment, your user and still current, from the fields it
returns ([What to check after verification](#what-to-check-after-verification)).

## The module

The verification runs in `aprv.wasm`, one WebAssembly module built from the
library's Rust core on OpenSSL. The same file runs under the Python, Go,
Swift, Ruby and .NET packages. This package holds no parser, no crypto and
no trust decision of its own. It carries the module, the JavaScript bindings
[jco](https://github.com/bytecodealliance/jco) generates for it, and a
façade that:

- reads your clock once per call and passes the time in;
- passes the input in as its UTF-8 bytes;
- reads the module's answer into the types below;
- gives each `Verifier` one instance of the module, set up with that
  `Verifier`'s roots.

The module imports one function, a source of random bytes, which the
package answers from `crypto.getRandomValues`. It reads no file, no
environment variable, no clock and no network.

If a call fails inside the module, the result is `INTERNAL_ERROR` (21009 at
the endpoint), the package discards that instance, and your next call runs
on a fresh one.

The tarball carries the licences of the code compiled into the module
(OpenSSL, wasi-libc with musl, the Rust standard library) under `licenses/`.

## Runtimes

The package loads the module the way each runtime allows, chosen by
`package.json` conditions. The default entry point is synchronous
everywhere; `apple-purchase-receipt-verifier/web` returns Promises from the
same functions, for code written against 0.7's `/web` entry point.

| Runtime | How the module loads | Tested |
|---|---|---|
| Node 20+ | read from the package directory, compiled on first use | the full suite; the runtime smoke |
| Bun | as Node | the runtime smoke |
| Deno | as Node; run with `--allow-read --allow-env=JCO_DEBUG` | the runtime smoke |
| Cloudflare Workers (workerd) | static `.wasm` imports, compiled at upload; no compatibility flag needed | the runtime smoke on workerd, no compatibility flags |
| Browsers, through a bundler | fetched next to the package and compiled at load (top-level `await`) | the runtime smoke in headless Chromium, with an import map in place of a bundler; Firefox and WebKit untested here |
| Vercel Edge (`edge-light`) | static `.wasm?module` imports for Vercel's bundler | the facade and the module inside `@edge-runtime/vm`; the `?module` import itself is untested |

**Deno** needs `--allow-env=JCO_DEBUG` because jco's generated glue reads
`process.env.JCO_DEBUG` on every call, and jco has no option to leave the
read out. Without the grant, `createVerifier` throws `NotCapable`.

**Workers** refuse to compile WebAssembly from bytes at run time, so the
package imports its three core modules statically under the `workerd`
condition. Bundle with that condition and keep the `.wasm` imports as
Wasm modules, as wrangler does.

[`examples/cloudflare-worker/`](examples/cloudflare-worker/) is a Worker
you can deploy: it installs this package from the registry and serves
[aprv-server's routes](../rust/server/README.md#the-wire-contract) with
wrangler's defaults, rate limited per client address.

**Browsers** without a bundler must map the package's internal import
`#aprv-load` to `dist/load/fetch.js` in an import map, the way
`runtime-smoke/browser.mjs` does.

Fastly Compute and Akamai EdgeWorkers are not supported: neither runs
WebAssembly.

## What it will never do

- **Read the operating system's trust store.** The anchors are the roots
  you pass to `createConfig`, or Apple's three published roots, which
  `createConfig()` selects when you pass none and which are compiled into
  the module.
- **Touch the network.** No OCSP, no CRL, no AIA fetch, no root download.
  Revocation checking is out of scope.
- **Return anything partial.** A failed result carries a `failure` and no
  `payload`; a verified one carries a `payload` and no `failure`.
- **Log, meter or call back into your code** except for the clock you give
  it. `Reason` is the whole observability surface.

`test/no-logic.test.js` holds the package to the first two: it fails if the
package source imports anything but its own files, the bindings and, for the
Node loader, `node:fs`, or names a crypto, TLS or network API.

## The API

### `createConfig`: the roots and the clock

```js
import { createConfig } from 'apple-purchase-receipt-verifier';

const config = createConfig(); // Apple's three roots, the system clock

const pinned = createConfig({
  roots: [rootBytes],            // DER or PEM as a Uint8Array; replaces the defaults
  clock: () => 1_735_689_600_000, // epoch milliseconds; replaces Date.now
});
```

`createConfig` is the one way to build a config, and an option left out
takes its default.

A root is the certificate's bytes, DER or PEM, as a `Uint8Array` (a `Buffer`
is one). The module reads both and tells them apart by the bytes, so a file
is a root as it stands: `readFileSync('AppleRootCA-G3.cer')` (Apple's PKI page
publishes DER `.cer` files) or `readFileSync('roots.pem')`. A PEM file holding
several certificates is one root entry, and every certificate in it is
trusted. A string is a `TypeError` that points here: pass PEM text as its
bytes, `new TextEncoder().encode(pem)`, which works in every runtime. Both
entry points take the same roots.

`config.roots` is the bytes of each root you passed, or `null` for Apple's
roots, which are compiled into the module: the package ships no certificate
files of its own. An empty `roots` array is a `TypeError`, from `createConfig` or
`createVerifier`: a verifier with no roots would reject everything, and
nobody would notice until production. A root the module cannot read as a
certificate is a `TypeError` from `createVerifier`.

### `createVerifier`: three methods

| Method | Input | Result |
|---|---|---|
| `verifyReceipt(base64)` | the base64 receipt an app sends | `VerificationResult<ReceiptPayload>` |
| `verifySignedData(jws)` | any Apple-signed compact JWS | `VerificationResult<JsonPayload>`: `{ json, environment }`, the signed JSON text and the environment it names |
| `verifyReceiptEndpoint(environment, requestJson)` | a `verifyReceipt` request body | Apple's response body, as a JSON string, always |

`VerificationResult<T>` is `{ verified: true, payload: T } | { verified:
false, failure: Failure }`: check `result.verified` before touching either
field. The endpoint always answers: the Apple status code is a field of the
body, for every input. `environment` must be `Environment.PRODUCTION` or
`Environment.SANDBOX`; anything else is a `TypeError`.

`createVerifier` throws an `Error` naming the module's exports if the
module is not the one this package was built for.

### `ReceiptPayload`

Every field is `null` when the attribute is absent or does not decode, so a
test can build one by hand with `createReceiptPayload`. Dates are epoch
milliseconds (`*Ms`, `number`); 64-bit ids (`appItemId`, `downloadId`,
`versionExternalIdentifier`, an in-app purchase's `webOrderLineItemId`) are
decimal **strings**, because a JavaScript `number` cannot hold an
eighteen-digit id without rounding it:

```js
payload.receiptType;               // 'Production', 'ProductionSandbox', ...
payload.bundleId;                  // decoded attribute 2
payload.bundleIdBytes;             // its raw octets: the device-hash input
payload.receiptCreationDateMs;
payload.inApp[0].productId;
payload.inApp[0].expiresDateMs;
payload.unknownAttributes;         // Map<number, Uint8Array[]>, by attribute type
payload.environment;               // Environment.PRODUCTION, Environment.SANDBOX or null
payload.toJson();                  // JSON with the same value in every port
```

`environment` is the environment `receiptType` names, as the module states
it: `Production` and `ProductionVPP` are `Environment.PRODUCTION`,
`ProductionSandbox` and `ProductionVPPSandbox` `Environment.SANDBOX`, and
anything else (`Xcode`, a missing value) `null`. A JWS payload's
`environment` comes from the first of the top-level `environment` claim, a
notification's `data.environment` and a summary notification's
`summary.environment` that is present: `Production`, `Sandbox`, or `null`
for anything else (`Xcode`, `LocalTesting`) or none. It is not part of
`toJson()`. `createReceiptPayload` and `createJsonPayload(json,
environment)` take it as given, `null` when left out.

The first occurrence of an attribute wins. Every attribute that does not
end up in a typed field (a later copy, or a value that does not decode,
whose field is then `null`) stays raw in `unknownAttributes`, keyed by type
in ascending order with each type's values in receipt order; in-app ones
stay in that purchase's own map. `toJson()` writes JSON whose parsed value
is the same in every port; the bytes may differ.

### `Failure` and `Reason`

`Failure` is `{ reason, message, cause? }`. Match on `failure.reason`; never
parse `failure.message`, which never quotes the input. `cause` is present
when the package itself hit the failure: a clock that threw, or an error
inside the module.

| `Reason` | Raised when | Endpoint status |
|---|---|---|
| `MALFORMED` | the base64, ASN.1, CMS or JWS structure is broken, or a structural bound is exceeded | 21002 |
| `TOO_LARGE` | the input is over its size cap and was not decoded | 21002 |
| `INVALID_SIGNATURE` | the signature did not verify | 21003 |
| `UNTRUSTED_CHAIN` | the chain does not reach a pinned root | 21003 |
| `INVALID_CERTIFICATE` | a certificate does not decode, or is outside its validity window at the chain instant | 21003 |
| `INVALID_CERTIFICATE_PURPOSE` | a certificate lacks Apple's marker OID for its place | 21003 |
| `UNREADABLE_PAYLOAD` | the chain and signature passed, but the signed content does not parse | 21009 |
| `INTERNAL_ERROR` | the library failed, or the configured clock threw or answered no epoch milliseconds | 21009 |

`UNREADABLE_PAYLOAD` and `INTERNAL_ERROR` are not the client's fault: alert,
log the failure, and reconcile the purchase through the App Store Server API
rather than deny the user.

## What to check after verification

The library proves Apple signed the payload. Before granting anything, check
what it says:

```js
const result = verifier.verifyReceipt(receiptBase64);
if (!result.verified) {
  return denied(result.failure.reason);
}
if (result.payload.bundleId !== 'com.example.app') {
  return denied('OTHER_APP');
}
```

**The environment** is `result.payload.environment` for a receipt and a JWS
alike. Decide whether to accept `Environment.SANDBOX` at all, and scope what
you grant from it: TestFlight, including public-link installs, buys in
sandbox for free, and App Review runs production builds against sandbox.

For a JWS, read the other claims off `JSON.parse(result.payload.json)`:
`bundleId`, `appAppleId` for a Production `AppTransaction`,
`revocationDate`, `expiresDate`, and `signedDate` for freshness. Apple's own
[`app-store-server-library`](https://github.com/apple/app-store-server-library-node)
publishes typed decoder classes for the transaction, renewal and
notification shapes, if you want them instead of reading the object by hand.
The library rejects no payload for its age, as Apple's own libraries do
not: the right limit depends on the endpoint (Apple retries a server
notification for days), so apply one yourself:

```js
if (Date.now() - (payload.signedDate ?? 0) > 5 * 60 * 1000) { /* too old here */ }
```

**The device hash** is yours too, when you have the device's identifier:

```js
import { createHash, timingSafeEqual } from 'node:crypto';

const expected = createHash('sha1')
  .update(deviceIdBytes)
  .update(payload.opaqueValue)
  .update(payload.bundleIdBytes)
  .digest();
const matches = timingSafeEqual(expected, payload.sha1Hash);
```

**Deduplicate on transaction ids, never on the receipt or JWS bytes.** A
legacy receipt is BER, and one correctly signed receipt can be re-chunked
into different byte strings that carry the same signed content.

### App Store Server Notifications V2

A notification nests more JWS inside its own payload. Apple POSTs
`{"signedPayload": "<JWS>"}`; verify that, then verify whichever of
`data.signedTransactionInfo` and `data.signedRenewalInfo` the notification
payload carries. A `TEST` notification carries neither:

```js
function verifyNotification(signedPayload) {
  const outer = verifier.verifySignedData(signedPayload);
  if (!outer.verified) return denied(outer.failure.reason);
  const notification = JSON.parse(outer.payload.json);

  const data = notification.data ?? {};
  const transaction = data.signedTransactionInfo && verifier.verifySignedData(data.signedTransactionInfo);
  const renewal = data.signedRenewalInfo && verifier.verifySignedData(data.signedRenewalInfo);
  if (transaction && !transaction.verified) return denied(transaction.failure.reason);
  if (renewal && !renewal.verified) return denied(renewal.failure.reason);

  return {
    notificationType: notification.notificationType,
    subtype: notification.subtype,
    transaction: transaction && JSON.parse(transaction.payload.json),
    renewalInfo: renewal && JSON.parse(renewal.payload.json),
  };
}
```

## The clock

The package reads your clock once per call, before it looks at the input,
and the module uses the value for two things:

- **the certificate-validity instant, when the input states no usable date
  of its own**: a receipt whose creation date (attribute 12) is missing or
  does not parse, a JWS with neither a representable `signedDate` nor a
  representable `receiptCreationDate`. Otherwise the module judges the chain
  at the date the input states.
- **`request_date`** in the endpoint's response.

A clock that throws, or answers anything but epoch milliseconds between 0
and `Number.MAX_SAFE_INTEGER`, makes the call `INTERNAL_ERROR` (21009 at the
endpoint), whatever the input.

## Input limits

The module measures each input before it decodes anything. The caps are
fixed, the same in every package of this library, and not options:

- **the endpoint request body and the receipt base64 string**: 3,145,728
  UTF-8 bytes. Over it is `TOO_LARGE`, 21002 at the endpoint (Apple answers
  HTTP 413 there; check the body's length before the call to do the same).
- **the compact JWS**: 262,144 UTF-8 bytes, `TOO_LARGE`.
- **JSON nesting**: no bound of its own. The module skips a value nobody
  reads without building it, so only the size caps bound a request body or
  a JWS header (docs/rust-core/DECISIONS.md R40).

The package copies at most as many bytes of an input into the module as the
module's `init` answer states (`max_input_bytes`, one over the largest cap:
3,145,729 today), so an oversized input costs no more module memory than
that and still gets the module's own `TOO_LARGE`. The package keeps no copy
of the number.

`receipt-data` must be standard base64 with canonical `=` padding and
nothing else, as Apple's `verifyReceipt` accepts it. `x5c` entries are
standard base64, JWS segments unpadded canonical base64url.

**Memory.** `bench/memory.mjs` measures one call on a hostile receipt at
the cap: 3 MiB of tiny attributes in a CMS envelope with no signer. The
module refuses it before it reads the payload. Measured on 2026-09-29 on
Node 22.22.2: a fresh process peaked at 98 MiB for a tiny receipt and 113
to 119 MiB for the hostile one, and the module's own memory grew from
2 MiB to 16 MiB. An instance keeps the size it grew to for the life of its
`Verifier`. `bench/memory-workerd.mjs` runs the same receipt in workerd,
where the whole process peaked at 68 and 96 to 103 MiB.

## The endpoint

```js
import { Environment } from 'apple-purchase-receipt-verifier';

const body = verifier.verifyReceiptEndpoint(Environment.PRODUCTION, rawRequestBody);
```

`rawRequestBody` must be the request's raw JSON text. A framework whose body
parser defaults to `application/x-www-form-urlencoded` (or that only
populates `req.body` after parsing it as one) will hand this method a
stringified form object, not the JSON Apple's client sent, and
`receipt-data` will read as missing. Read the body as `application/json`
before calling this method, or parse it yourself and re-stringify it.

| Status | Meaning |
|---|---|
| `0` | verified, and the receipt matches the requested environment |
| `21002` | `receipt-data` is missing, malformed, or over the size cap |
| `21003` | the receipt did not authenticate |
| `21007` | a Sandbox receipt was sent to `Environment.PRODUCTION` |
| `21008` | a Production receipt was sent to `Environment.SANDBOX` |
| `21009` | not the client's fault: alert and reconcile, do not deny |

`AppleStatus` holds these (and the codes Apple's own servers can return,
which this local stand-in never produces) as named constants. Like Apple's
endpoint, this does **not** check the bundle id: compare
`receipt.bundle_id` in the response before granting anything.
[COMPARISON.md](https://github.com/emindeniz99/apple-purchase-receipt-verifier/blob/main/COMPARISON.md)
has the field-by-field fidelity account.

## Why offline

Signature verification cannot fail because a vendor endpoint is down, so you
can honour a purchase at once and reconcile it against the App Store Server
API afterwards. Refunds and revocations still need that reconciliation
pass: a signature proves what Apple signed, not what happened since.

This package is one of the library's packages for nine languages (Java,
Node, Python, Swift, Go, Ruby, Rust, PHP, .NET), which share one fixture
suite, including Apple's own official test fixtures. See the
[project README](https://github.com/emindeniz99/apple-purchase-receipt-verifier#readme)
for the full picture.

## Upgrading from 0.7

The API is 0.7's, with these differences:

| 0.7 | Now |
|---|---|
| `defaultConfig()` | `createConfig()`: the one way to build a config; with no options it is Apple's roots and the system clock, on both entry points |
| `defaultConfig().roots`: three parsed certificates | `createConfig().roots` is `null`: Apple's roots live in the module |
| `config.roots`: parsed certificates | the bytes of each root, as given |
| a root as DER or a PEM string | DER or PEM bytes: a string is a `TypeError`; pass `new TextEncoder().encode(pem)` |
| an unreadable root throws from `createConfig` | it throws a `TypeError` from `createVerifier` |
| the clock read only when a verdict needs it | the clock read once on every call |
| `cause` on `UNREADABLE_PAYLOAD`: the parser's error | no `cause`: the module reports its reason and message |
| `decodeReceiptBase64`, `decodeX5cEntry` | removed: the module decodes base64 |
| `VerificationError`, exported but never thrown | removed: a failure is the `failure` of the result; match on `failure.reason` |
| `unknownAttributes` in receipt order across types | ordered by type; each type's values keep receipt order |
| `environmentFromReceiptType(receipt.receiptType)`, `environmentFromJwsEnvironment(claim)` | removed: read `payload.environment` on a `ReceiptPayload` or a `JsonPayload`. A JWS's also reads a notification's `data.environment` and `summary.environment` |
| `createJsonPayload(json)` gives `{ json }` | `{ json, environment }`; pass the environment as a second argument, `null` when left out |
| Fastly Compute and Akamai EdgeWorkers | not supported |
| Deno with `--allow-read` | Deno with `--allow-read --allow-env=JCO_DEBUG` |

Upgrading from 0.6: see the 0.7 CHANGELOG entry.

## Testing

```bash
npm test               # build (jco transpile, tsc), then the node:test suite
npm run lint           # oxlint
npm run format:check   # prettier --check
npm run test:runtimes  # Node, Bun, Deno, workerd, @edge-runtime/vm
npm run runtime:browser -- chromium firefox webkit   # needs playwright
```

`npm run build` transpiles `wasm/aprv.component.wasm`, which is not in git:
copy it into place (CI takes it from the rust-wasm job), or set
`APRV_COMPONENT` to its path.

`node scripts/g1.mjs DROP_DIR` runs everything above plus the cross-host
corpus parity, timings and memory against a directory holding a new
module's component, call files and reference rows.

`test/conformance.test.js` runs `fixtures/cases.json`, the cross-language
vector file every package of this library answers, as one named test per
case per entry point, and fails unless every case ran on both. A
`decodeBase64` case runs its texts through `verifyReceipt` (and, for `x5c`,
through a JWS that carries the text), since the module does the decoding.

`test/facade.test.js`, `test/abi.test.js` and `test/wire.test.js` pin the
package's own part: misuse at `createVerifier`, the environment and clock
handling, the input bytes, recovery after a failure inside an instance,
the module's traps on ABI misuse, and how the module's answers become the
types above.

## Changelog

One version across every language:
[CHANGELOG.md](https://github.com/emindeniz99/apple-purchase-receipt-verifier/blob/main/CHANGELOG.md)
/ [releases](https://github.com/emindeniz99/apple-purchase-receipt-verifier/releases).

## Licence

MIT; see [LICENSE](./LICENSE). The code compiled into `aprv.wasm` keeps its
own licences, in `licenses/`.
