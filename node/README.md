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

// Build once, share everywhere: the roots are parsed once, not per call.
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

ESM, Node 20+. No method throws for input the caller does not control: every
verify call returns a result object, never a rejected promise or a thrown
error, for anything short of a JS engine failure.

The library answers one question: did Apple sign this? It checks the chain
to a pinned root, Apple's marker OIDs and the signature, and hands back
everything the payload says. Whether the payload is for your app, your
environment, your user and still current is your decision, made on the
fields it returns ([What to check after verification](#what-to-check-after-verification)).

## WebCrypto-only runtimes

`apple-purchase-receipt-verifier/web` is a second entry point that verifies
the same things using nothing but `crypto.subtle`, `TextDecoder` and
`Uint8Array`. Same function names, same option names, same `Reason`
vocabulary; every call that touches `crypto.subtle` returns a Promise, so
`createConfig`, `defaultConfig` and every `Verifier` method are async there.
Porting between the two is adding or removing `await` — nothing else
differs: trust roots take the same `Uint8Array | string` inputs, and every
byte-valued field on a verified payload (`opaqueValue`, `sha1Hash`,
`bundleIdBytes`, the values in `unknownAttributes`) is a plain `Uint8Array`
in both builds.

```js
import { createConfig, createVerifier } from 'apple-purchase-receipt-verifier/web';

const verifier = createVerifier(await createConfig());

const receiptResult = await verifier.verifyReceipt(receiptBase64);
const jwsResult = await verifier.verifySignedData(jws);
```

Which entry point a runtime needs:

| Runtime | Entry point |
|---|---|
| Node 20+, Bun, Deno | either |
| Cloudflare Workers with `nodejs_compat` (compatibility date 2024-09-23 or later, or `nodejs_compat_v2` on an older one) | either |
| Cloudflare Workers with no compatibility flags | `/web` |
| Vercel Edge runtime, Next.js edge middleware | `/web` |
| Fastly Compute, Akamai EdgeWorkers | `/web` |

Everything else is shared source, including the DER reader, the CMS walk,
the receipt attribute grammar and the `Reason` vocabulary, so the two builds
cannot drift apart on what a receipt says. `npm test` runs every shared
fixture through both builds and requires the same verdict.

`npm run test:runtimes:web` runs the web build on Node, on the Vercel Edge
runtime (`@edge-runtime/vm`) and on Cloudflare workerd configured with no
compatibility flags at all. `npm run test:runtimes:fastly` adds Fastly
Compute: `js-compute-runtime` builds the smoke test to wasm and Fastly's own
local runtime, viceroy, serves it. viceroy is a Rust binary rather than an
npm package, so it is a separate script; install it with
`cargo install viceroy --locked` and the runner says so if it is missing.

Akamai EdgeWorkers is expected to work — it implements the same WebCrypto
API — but is untested: it has no local runtime to run it in, so the claim
for it rests on what the build asks of a runtime rather than on a passing
run. That list is short: `crypto.subtle.digest` (SHA-1, SHA-256),
`crypto.subtle.importKey` in `'jwk'` format, `crypto.subtle.verify` for
RSASSA-PKCS1-v1_5 (SHA-1 and SHA-256) and for ECDSA (P-256 and P-384,
SHA-256 and SHA-384), plus `TextDecoder`. **SHA-1 with RSASSA-PKCS1-v1_5 is
not optional**: Apple's legacy receipt chain is signed
`sha1WithRSAEncryption` from the leaf up, so a runtime that refuses SHA-1
even for verification cannot verify a legacy app receipt at all. Node,
workerd and the Vercel Edge runtime all accept it; a test in
`runtime-smoke/web-smoke.mjs` verifies a genuine 187-purchase legacy receipt
on each of them, which is where that support gets proved.

A test also reads the emitted module graph and fails if anything reachable
from the web entry point imports a `node:` module, imports anything
non-relative, or so much as mentions `Buffer` or `process`.

## What it will never do

These are the properties the library exists to hold, and each is asserted by
a test rather than only documented.

- **It never reads the operating system's trust store.** Anchors come from
  the `roots` a caller passes to `createConfig`, or from `defaultConfig()`,
  which holds Apple's three published roots bundled at build time, so they
  work unchanged in a container with no filesystem access. There is no
  `node:tls`, no `NODE_EXTRA_CA_CERTS`, and no code path to a system store —
  a whole test file exists to prove a certificate authority this *process*
  genuinely trusts still buys an attacker nothing.
- **It never touches the network.** No OCSP, no CRL, no AIA fetch, no root
  download. Revocation checking is disabled by design; an integrator who
  needs it must layer it on top.
- **It never uses a key no pinned root vouched for.** The chain is built
  top-down, from the pinned roots, so a certificate carrying an attacker's
  key (their choice of size and exponent) is never used to check anything
  ([Stranger certificates](#stranger-certificates)).
- **It never returns anything partial.** A failed result carries a
  `failure` and no `payload`; a verified one carries a `payload` that
  passed every check, and no `failure`.
- **It never logs, meters or calls back into your code** except for the
  clock you give it. `Reason` is the whole observability surface, and a
  failure message never quotes the input.

## The API

### `createConfig` / `defaultConfig`: the roots and the clock

```js
import { createConfig, defaultConfig } from 'apple-purchase-receipt-verifier';

const config = defaultConfig(); // Apple's three roots, the system clock

const pinned = createConfig({
  roots: [rootDer],              // Uint8Array or PEM string; replaces the defaults
  clock: () => 1_735_689_600_000, // epoch milliseconds; replaces Date.now
});
```

An empty `roots` array is a `TypeError` from `createVerifier`, never a
verdict: a verifier with no roots would reject everything, and nobody would
notice until production. `defaultConfig()` throws `Error` if the bundled
roots do not match their published SHA-256 fingerprints — check for that at
startup, since a call made with a config it fails to produce would never
exist.

### `createVerifier`: three methods

| Method | Input | Result |
|---|---|---|
| `verifyReceipt(base64)` | the base64 receipt an app sends | `VerificationResult<ReceiptPayload>` |
| `verifySignedData(jws)` | any Apple-signed compact JWS | `VerificationResult<JsonPayload>`: `{ json }`, the signed JSON text |
| `verifyReceiptEndpoint(environment, requestJson)` | a `verifyReceipt` request body | Apple's response body, as a JSON string, always |

`VerificationResult<T>` is `{ verified: true, payload: T } | { verified:
false, failure: Failure }` — check `result.verified` before touching either
field. The endpoint never fails to answer: the Apple status code is a field
of the body, for every input.

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
payload.unknownAttributes;         // Map<number, Uint8Array[]> in receipt order
payload.toJson();                  // JSON with the same value in every port
```

Decoding follows the rules every port shares: the first occurrence of an
attribute wins; every attribute that does not end up in a typed field (a
later copy, or a value that does not decode, whose field is then `null`) is
kept raw in `unknownAttributes`, the in-app ones in that purchase's own; an
empty date string means "not set" and is not kept raw. `toJson()` writes
JSON whose parsed value is the same in every port; the bytes may differ.

### `Failure` and `Reason`

`Failure` is `{ reason, message, cause? }`; `cause` is present only for
`UNREADABLE_PAYLOAD` and `INTERNAL_ERROR` — behind any other reason it would
be a parser exception about unverified input, whose message can quote raw
certificate text. Match on `failure.reason`; never parse `failure.message`.

| `Reason` | Raised when | Endpoint status |
|---|---|---|
| `MALFORMED` | the base64, ASN.1, CMS or JWS structure is broken, or a structural bound is exceeded | 21002 |
| `TOO_LARGE` | the input is over its size cap and was not decoded | 21002 |
| `INVALID_SIGNATURE` | the signature did not verify | 21003 |
| `UNTRUSTED_CHAIN` | the chain does not reach a pinned root | 21003 |
| `INVALID_CERTIFICATE` | a certificate does not decode, or is outside its validity window at the chain instant | 21003 |
| `INVALID_CERTIFICATE_PURPOSE` | a certificate lacks Apple's marker OID for its place | 21003 |
| `UNREADABLE_PAYLOAD` | the chain and signature passed, but the signed content does not parse | 21009 |
| `INTERNAL_ERROR` | the library failed unexpectedly, or the configured clock threw; no input makes a correct library answer it | 21009 |

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

For a JWS, read the claims off `JSON.parse(result.payload.json)`:
`bundleId`, `environment`, `appAppleId` for a Production `AppTransaction`,
`revocationDate`, `expiresDate`, and `signedDate` for freshness. Apple's own
[`app-store-server-library`](https://github.com/apple/app-store-server-library-node)
publishes typed decoder classes for the transaction, renewal and
notification shapes, if you want them instead of reading the object by hand.
No payload is rejected for its age, as in Apple's own libraries: the right
limit depends on the endpoint (Apple retries a server notification for
days), so apply one yourself:

```js
if (Date.now() - (payload.signedDate ?? 0) > 5 * 60 * 1000) { /* too old here */ }
```

**The device hash** is yours too, when you have the device's identifier:

```js
import { createHash } from 'node:crypto';

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
payload carries — a `TEST` notification carries neither:

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

The clock is read at most once per call, and only when one of these needs
it, after the input has passed every check that comes before:

- **the certificate-validity instant, when the input states no usable date
  of its own**: a receipt whose creation date (attribute 12) is missing or
  does not parse, a JWS without a representable `signedDate`. Otherwise the
  chain is judged at the date the input states.
- **`request_date`** in the endpoint's response.

A certificate outside its validity window at that instant is
`INVALID_CERTIFICATE`. A clock that throws is contained as `INTERNAL_ERROR`
(21009 at the endpoint), with a fixed message.

## What the checks are, and in what order

The order is observable and is part of the contract: an input that fails an
early check reports that check's reason, not a later one.

**JWS.** Size cap → three segments, each strict base64url → header JSON
(strict UTF-8, no byte order mark, nothing but whitespace after the object),
`alg` ES256 and exactly three `x5c` entries → the certificates decode → the
chain at `signedDate` (or the clock), the intermediate checked against the
pinned roots **before** the leaf is checked against the intermediate →
**leaf marker OID** `1.2.840.113635.100.6.11.1` → **intermediate marker
OID** `1.2.840.113635.100.6.2.1` → ES256 signature. As on the receipt path,
a chain that does not reach a pinned root is `UNTRUSTED_CHAIN` whatever
markers it carries; validity is part of the chain check, so an expired
chain that lacks a marker, or has a broken signature, is
`INVALID_CERTIFICATE` (owner, 2026-09-27). A key on a curve this library
does not implement is `INVALID_CERTIFICATE`, judged only once it has been
vouched for and is about to be used.

**Receipt.** Size cap → strict base64 → CMS parse, including the syntax of
every `SignerInfo`'s `signedAttrs`, whatever its position → at most four
`SignerInfo`s and ten embedded certificates → the creation date alone
(nothing else in the payload is read yet) → for each `SignerInfo`: the
signer's certificate → the chain, top-down from the pinned roots, at the
creation date or the clock → **signer marker OID** → **WWDR marker OID on
the intermediate** → the signer's key on a curve this library implements →
the CMS signature. One `SignerInfo` passing is enough; when none does, the
first one's failure is the verdict. Then the full payload parse, where any
failure is `UNREADABLE_PAYLOAD`.

The receipt signer may use any algorithm `node:crypto` / `crypto.subtle`
verify: RSA PKCS#1 v1.5, RSA-PSS or ECDSA on P-256 and P-384, over MD5,
SHA-1 or the SHA-2 family. A signer that chains to a pinned root and carries
Apple's marker is trusted whatever it signs with, so a change on Apple's
side does not reject genuine receipts. The same goes for certificate
signatures in the chain. A `signatureAlgorithm` that names a hash
(`sha256WithRSAEncryption`, `ecdsa-with-SHA384`, the RSA-PSS parameters)
must name the `SignerInfo`'s `digestAlgorithm`, or the signature is
`INVALID_SIGNATURE`; `rsaEncryption` and `id-ecPublicKey` name none and
take the digest.

The bundled roots are checked against their published SHA-256 fingerprints
when they load, all three or none; `defaultConfig()` throws if any do not
match, so a call made with a config it fails to produce would never exist.

`x5c[2]` is never compared to an anchor and never trusted, and neither is a
receipt's embedded copy of its root: the chain terminates at an anchor the
caller pinned. Trust anchors are trusted by fiat, so **an anchor's own
expiry is not checked**, which is what lets a receipt signed years ago
under a since-expired chain verify at its own creation date.

A certificate on the path (not the anchor) that marks critical an extension
a PKIX validator does not process makes the path `UNTRUSTED_CHAIN`, as it
does for a PKIX validator. Processed are keyUsage, basicConstraints,
certificatePolicies, policyMappings, policyConstraints, inhibitAnyPolicy,
nameConstraints, subjectAltName, issuingDistributionPoint and
deltaCRLIndicator, and on the leaf also cRLDistributionPoints and
extKeyUsage. A certificate's `signatureValue` decodes only whole-byte
aligned, as a DER signature always is. In `signedAttrs`, `contentType` or
`messageDigest` twice, or a `contentType` that differs from the
`eContentType`, is `INVALID_SIGNATURE`.

An embedded certificate that does not decode is fatal, and the reason
depends on which one it is: the **signer** is `INVALID_CERTIFICATE`, any
other entry `MALFORMED`, because the certificate bag is unsigned.

### Stranger certificates

A receipt's certificate bag is not signed, so anyone can add to it. A
certificate there that no pinned root vouches for, directly or through a
certificate it vouched for, is ignored: it never reaches the path builder
and its key is never used, so a genuine receipt padded with such
certificates still verifies. The walk starts at the roots, so the cost of a
stranger is a name comparison, however large or broken its key. The shared
denial-of-service cases pin this with a `maxMillis` time budget.

## Input limits

Base64 decoding, ASN.1 parsing and JSON parsing all allocate in proportion
to their input, and all of them run before any signature is checked. So
each input is measured first. The caps are fixed constants, the same in the
default and the `/web` build and in every port of this library. They are
not options.

The receipt and request caps are Apple's own limit. Measured on 2026-09-23
against both of Apple's verifyReceipt endpoints (production and sandbox), a
request body of 3,145,728 bytes is answered normally and one of 3,145,729
bytes gets HTTP 413. Apple counts UTF-8 bytes, not characters.
`fixtures/cases-0.7.json` holds every port to these numbers from both sides.

- **the endpoint request body and the receipt base64 string**: 3,145,728
  UTF-8 bytes (`MAX_REQUEST_BYTES`, `MAX_RECEIPT_BYTES`). Over it is
  `TOO_LARGE`, 21002 at the endpoint (Apple answers HTTP 413 there — check
  the body's length before the call to do the same).
- **the compact JWS**: 262,144 UTF-8 bytes (`MAX_JWS_BYTES`), `TOO_LARGE`.
- **JSON nesting depth 64.** Counted while parsing, since `JSON.parse` has
  no depth option. A deeper request body or JWS is `MALFORMED`.

A JavaScript string holds UTF-16 units, so strings are measured in UTF-8
bytes without being encoded: more units than the cap is over it, three
times the units within the cap is within it, and only a string between the
two is walked, stopping at the first byte past the cap.

`receipt-data` is decoded exactly as Apple's `verifyReceipt` accepts it:
standard base64 with canonical `=` padding and nothing else — whitespace,
base64url and omitted or extra padding are all refused, as at Apple. `x5c`
entries are standard base64, JWS segments unpadded canonical base64url, so
one signed payload has one accepted spelling.

## The endpoint

```js
import { Environment } from 'apple-purchase-receipt-verifier';

const body = verifier.verifyReceiptEndpoint(Environment.PRODUCTION, rawRequestBody);
```

`rawRequestBody` must be the request's raw JSON text. A framework whose body
parser defaults to `application/x-www-form-urlencoded` (or that only
populates `req.body` after parsing it as one) will hand this method a
stringified form object, not the JSON Apple's client actually sent, and
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
which this local stand-in never produces) as named constants. Local 21007 /
21008 routing fails closed: only receipt types `Production` and
`ProductionVPP` count as production. Like Apple's endpoint, this does
**not** check the bundle id: compare `receipt.bundle_id` in the response
before granting anything. `password` and `exclude-old-transactions` are
accepted for wire compatibility and never read. Fields that exist only in
Apple's server-side database (`latest_receipt_info`, `pending_renewal_info`,
`latest_receipt`) are never produced. 64-bit ids
(`adam_id`/`app_item_id`/`download_id`/`version_external_identifier`) are
written as raw JSON numbers, exactly as Apple's own endpoint does, even
though this library's own `ReceiptPayload` carries them as decimal strings;
`*_ms` date fields are JSON strings. A field the receipt does not carry is
left out of the response entirely, never sent as JSON `null`. See
[COMPARISON.md](https://github.com/emindeniz99/apple-purchase-receipt-verifier/blob/main/COMPARISON.md)
for the field-by-field fidelity account.

## Known issue: legacy receipts on RHEL 9's own Node.js

The legacy Apple receipt chain and its CMS signature are SHA-1. Node.js from
nodejs.org, nvm or the official Docker images bundles its own OpenSSL and is
not affected. RHEL's `nodejs` package (also on Alma and Rocky) is built
against the system OpenSSL, which the DEFAULT crypto policy stops from
verifying SHA-1 signatures, so with it a genuine legacy receipt answers
`UNTRUSTED_CHAIN`. Observed on AlmaLinux 9.8 on 2026-09-24. Newer receipts
(SHA-256 chains) and every JWS are unaffected; FIPS mode is untested.

Until the fix ships, use an upstream Node.js build, or run
`update-crypto-policies --set DEFAULT:SHA1` on that host.

## Why offline

Signature verification cannot fail because a vendor endpoint is down, so a
purchase can be honoured immediately and reconciled against the App Store
Server API afterwards. Refunds and revocations still need that
reconciliation pass — a signature proves what Apple signed, not what
happened since.

This is one of nine implementations (Java, Node, Python, Swift, Go, Ruby,
Rust, PHP, .NET) that share a single fixture suite, including Apple's own
official test fixtures, and are required to agree byte for byte. See the
[project README](https://github.com/emindeniz99/apple-purchase-receipt-verifier#readme)
for the full picture and
[COMPARISON.md](https://github.com/emindeniz99/apple-purchase-receipt-verifier/blob/main/COMPARISON.md)
for how it differs from Apple's official libraries.

## Upgrading from 0.6

0.7 replaces the three classes with one `Verifier` built from a `Config`, and
takes no policy: no bundle id, no accepted environments, no app Apple id, no
device id. Methods return a result object instead of throwing, and no
longer accept raw DER — only the base64 string an app actually sends.

| 0.6 | 0.7 |
|---|---|
| `new ReceiptVerifier({ trustedRoots, bundleId }).verify(base64 \| der)` | `createVerifier(createConfig({ roots })).verifyReceipt(base64)`, then compare `payload.bundleId` |
| `verifyReceiptCore(der, roots)` | base64-encode, then `verifyReceipt` |
| device-hash checking on the verifier | compute the hash yourself from `opaqueValue` and `bundleIdBytes` (above) |
| `new JwsVerifier({ trustedRoots, bundleId, acceptedEnvironments }).verifyTransaction/verifyAppTransaction/verifyRaw(jws)` | `verifier.verifySignedData(jws)`, then read the claims from `JSON.parse(payload.json)` |
| `new VerifyReceiptEndpoint({ trustedRoots, environment }).verifyReceiptJson(body)` | `verifier.verifyReceiptEndpoint(environment, body)` |
| `appleReceiptRoots()`, `appleJwsRoots()` | `defaultConfig().roots` (one set, shared by every method) |
| a `Date` argument for `request_date` | `createConfig({ clock: () => epochMs })` |
| `VerificationError` (thrown) | `result.failure` (`{ reason, message, cause? }`, never thrown for input) |
| `AppReceipt` (`Date` fields, `bigint` ids) | `ReceiptPayload` (`*Ms` epoch milliseconds, ids as decimal strings) |

| 0.6 `Reason` | 0.7 `Reason` |
|---|---|
| `INVALID_JWS_FORMAT`, `INVALID_RECEIPT_FORMAT`, `MALFORMED_REQUEST` | `MALFORMED` |
| `REQUEST_TOO_LARGE` | `TOO_LARGE` |
| `INVALID_CHAIN` | `UNTRUSTED_CHAIN`, or `INVALID_CERTIFICATE` for a certificate outside its validity window |
| `INTERNAL_ERROR` for signed content that does not parse | `UNREADABLE_PAYLOAD` |
| `WRONG_BUNDLE_ID`, `WRONG_ENVIRONMENT`, `WRONG_APP_APPLE_ID`, device-hash mismatch | gone: the caller's own checks |

## Testing

```bash
npm test              # typecheck, then the whole node:test suite
npm run lint           # oxlint
npm run format:check   # prettier --check
npm run test:runtimes  # Node, Bun, Deno, three workerd configurations
npm run test:runtimes:web    # the web build on Node, the Vercel Edge runtime, workerd
npm run test:runtimes:fastly # the web build on Fastly Compute (needs viceroy)
```

`test/conformance-0.7.test.js` runs `fixtures/cases-0.7.json`, the normative
cross-language vector file every port of this library answers, as one named
test per case **per build** (Node and `/web`), and fails unless every case
ran on both. The adapter carries no case-specific knowledge: it builds a
config from the case, dispatches on the operation and evaluates the expected
JSON Pointers on the result. `decodeBase64` cases call the two base64
decoders directly, and a case with a `maxMillis` budget is timed after a
warm-up call.

`test/trust-store-isolation.test.js` asserts the "no ambient trust" property
from three directions: environmentally (a child process started with
`NODE_EXTRA_CA_CERTS` naming a bundle that holds the fixture roots, proven
live with a real TLS handshake, and the library still refuses), structurally
(a source scan over `src/` for anything that could reach a trust store or
the network, and a check that the web build imports nothing Node-specific),
and positionally (a spy on the anchor array proves the chain builder sees
exactly the caller's list, in order, nothing appended).

`fuzz/` is a separate npm project (`fuzz/README.md`) so `npm ci` here never
pulls the native fuzzing addon; `test/fuzz-targets.test.js` runs its six
targets' seed corpora, plus a deterministic mutation sweep, as plain
`node:test` cases, so their invariants are checked on every push even
without the fuzzer installed.

## Changelog

One version across every language —
[CHANGELOG.md](https://github.com/emindeniz99/apple-purchase-receipt-verifier/blob/main/CHANGELOG.md)
/ [releases](https://github.com/emindeniz99/apple-purchase-receipt-verifier/releases).

## Licence

MIT — see [LICENSE](./LICENSE).
