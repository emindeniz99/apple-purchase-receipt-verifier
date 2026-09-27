# apple-purchase-receipt-verifier

Verify Apple in-app purchases locally — no calls to Apple's servers.

Replaces the deprecated `verifyReceipt` endpoint by validating StoreKit 2
signed JWS transactions and legacy PKCS#7 receipts against pinned Apple root
certificates.

## Installation

```bash
composer require emindeniz99/apple-purchase-receipt-verifier
```

**The package is the repository root, not this directory.** Packagist reads
`composer.json` from a repository root and nowhere else, so the manifest
Composer installs is the one at the top of this nine-language monorepo. It
autoloads `EminDeniz99\ApplePurchaseReceiptVerifier\` from `php/src/`, and a
root `.gitattributes` allowlist trims the archive Composer downloads to this
port: the sources, the pinned Apple roots, the two licences and this file.
`php/composer.json` stays the development manifest, with the require-dev block
and the lockfile the test suite installs, and `tools/check-php-package.mjs`
fails the build when the two disagree or when the archive loses something.

Until the owner submits the repository to Packagist (the one remaining step,
in [BOOTSTRAP.md](../BOOTSTRAP.md)), consume it from a local clone with a path
repository pointing at the repository root:

```json
{
  "repositories": [
    { "type": "path", "url": "../apple-purchase-receipt-verifier" }
  ],
  "require": { "emindeniz99/apple-purchase-receipt-verifier": "*" }
}
```

Requires **PHP 8.2+** (64-bit), `ext-openssl` and `ext-json`. One runtime
dependency: `psr/clock`, the PSR-20 clock interface — a single interface, no
code, no transitive dependencies.

## Quick start

One `Verifier`, built from a `Config`, exposes the three entry points. It is
immutable and reusable once constructed, and none of its `verify*` methods
throw: each returns a `VerificationResult` (or, for the endpoint, a JSON
string) that reports failure instead of raising.

```php
use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;

$verifier = Verifier::create(Config::defaults());  // Apple's three pinned roots, system clock
```

**StoreKit 2 signed transaction or renewal info (compact JWS):**

```php
$result = $verifier->verifySignedData($jws);
if (!$result->verified()) {
    throw new RuntimeException("{$result->failure->reason->value}: {$result->failure->message}");
}
$payload = json_decode($result->payload->json, true);  // the verified claims, as an array
```

**Legacy PKCS#7 app receipt (base64):**

```php
$result = $verifier->verifyReceipt($receiptBase64);
if (!$result->verified()) {
    throw new RuntimeException("{$result->failure->reason->value}: {$result->failure->message}");
}
$receipt = $result->payload;  // a ReceiptPayload
echo $receipt->bundleId, ' ', count($receipt->inApp), "\n";
```

**A `verifyReceipt`-shaped request body, verified offline:**

```php
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;

$responseJson = $verifier->verifyReceiptEndpoint(Environment::Production, $requestBody);
```

`$requestBody` is the raw JSON body Apple's endpoint would have received
(`{"receipt-data": "...", "password": "..."}`); `$responseJson` is the JSON
string Apple's endpoint would have answered, `status` field included. See
"The verifyReceipt-compatible endpoint" below for the raw-body caveat and the
status table.

## Why offline

Signature verification cannot fail because a vendor endpoint is down, so a
purchase can be honoured immediately and reconciled against the App Store
Server API afterwards. Refunds and revocations still need that reconciliation
pass — a signature proves what Apple signed, not what happened since.

This is one of nine implementations sharing a single fixture suite, including
Apple's own official test fixtures, which are required to agree byte for
byte. See the [project README](../README.md) for the full picture and
[COMPARISON.md](../COMPARISON.md) for how it differs from Apple's official
libraries.

## Integrating: from verified payload to entitlement

Verification proves Apple signed the bytes. It does not prove the presenter
owns them, and it says nothing about what happened after the signature. The
[project README](../README.md#integrating-from-verified-payload-to-entitlement)
lays out the full flow once, with a reason-to-next-step table; here are its
two branches in this port's 0.7 API.

Both branches follow the same shape: verify, deny on any failure, then run
the post-verification checklist below yourself — 0.7 has no
constructor-supplied bundle id or environment allowlist to do it for you.

```php
// Branch A: StoreKit 2 signed transaction
$result = $verifier->verifySignedData($jws);
if (!$result->verified()) {
    log($result->failure->reason->value);  // deny; nothing partial is returned
    return;
}
$payload = json_decode($result->payload->json, true);
if (($payload['bundleId'] ?? null) !== 'com.example.app') {
    return;  // step 1 of the checklist below
}
$environment = Environment::fromJwsEnvironment($payload['environment'] ?? null);
if (($payload['revocationDate'] ?? null) !== null) {
    return;  // refunded or revoked as of signing time
}
$expires = $payload['expiresDate'] ?? null;
if ($expires !== null && $expires <= $nowMs) {
    return;  // subscription term had ended
}
grant($payload['productId'], $environment, $payload['transactionId']);  // idempotent on transactionId

// Branch B: legacy PKCS#7 app receipt
$result = $verifier->verifyReceipt($receiptBase64);
if (!$result->verified()) {
    log($result->failure->reason->value);
    return;
}
$receipt = $result->payload;
if ($receipt->bundleId !== 'com.example.app') {
    return;
}
$environment = Environment::fromReceiptType($receipt->receiptType);
foreach ($receipt->inApp as $purchase) {
    if ($purchase->cancellationDateMs !== null) {
        continue;
    }
    if ($purchase->expiresDateMs !== null && $purchase->expiresDateMs <= $nowMs) {
        continue;
    }
    grant($purchase->productId, $environment, $purchase->transactionId);
}
```

**Freshness is your call.** Neither method rejects a payload for its age; the
signing instant (`signedDate` / the receipt's creation date) only decides
what certificate-validity window the chain is judged against. The right
freshness limit depends on the endpoint (Apple retries a server notification
for days, and a device may legitimately present an old but genuine receipt),
so apply one yourself where it fits.

## Post-verification checklist

A verified payload is only proof of what Apple signed. Nothing here checks
whether it applies to *your* app or has already been used. Every caller does
these four things with the signed fields before granting anything:

1. **Bundle id.** Compare it against your app's bundle id yourself.
   Legacy: `$receipt->bundleId`. JWS: `$payload['bundleId']`.
2. **Environment.** `Environment::fromReceiptType($receipt->receiptType)` for
   a legacy receipt, `Environment::fromJwsEnvironment($payload['environment'] ?? null)`
   for a JWS payload. Decide whether you accept `Sandbox` here; both return
   `null` for a receipt type or environment claim you don't recognise, which
   fails closed if you require a specific `Environment`.
3. **Product id.** Compare `productId` / `$payload['productId']` against the
   catalogue of products you actually sell: a signature proves Apple signed
   it, not that it's a product your server still grants.
4. **Idempotency.** Key your own bookkeeping on the transaction id
   (`transactionId` / `$payload['transactionId']`) so a replayed or retried
   JWS/receipt is not granted twice.

None of this is checked by `verifyReceipt()`, `verifySignedData()` or
`verifyReceiptEndpoint()` themselves: 0.7 dropped constructor-supplied policy
(bundle id, allowed environments) entirely; every check above is read off
the returned payload by the caller, every time.

## Device hash

Legacy receipts carry a device-binding hash (attribute 5,
`ReceiptPayload::$sha1Hash`) that Apple's on-device code computes as
`SHA-1(device_id ‖ opaque_value ‖ bundle_id_bytes)`. The library does not run
this check itself: the design treats it as a caller decision, since
`device_id` is something only the caller has (the app supplies its own device
identifier bytes; there is no single canonical source across platforms).

```php
$expected = hash('sha1', $deviceIdBytes . $receipt->opaqueValue . $receipt->bundleIdBytes, true);
if (!hash_equals((string) $expected, (string) $receipt->sha1Hash)) {
    throw new RuntimeException('receipt was not issued for this device');
}
```

`opaqueValue` and `bundleIdBytes` are the raw attribute value octets, not the
decoded string, because the hash is defined over the DER bytes Apple signed.
Use `hash_equals()`, not `===`, when comparing hashes — a straight string
comparison is not constant-time.

## App Store Server Notifications V2

A V2 notification body is itself a compact JWS whose decoded payload carries
further compact JWS strings nested inside it (`data.signedTransactionInfo`,
`data.signedRenewalInfo`). Verify the outer envelope, then verify each nested
one the same way:

```php
$outer = $verifier->verifySignedData($requestBody);
if (!$outer->verified()) {
    throw new RuntimeException("{$outer->failure->reason->value}: {$outer->failure->message}");
}
$notification = json_decode($outer->payload->json, true);

$data = $notification['data'] ?? [];
foreach (['signedTransactionInfo', 'signedRenewalInfo'] as $key) {
    $nestedJws = $data[$key] ?? null;
    if ($nestedJws === null) {
        continue;
    }
    $nested = $verifier->verifySignedData($nestedJws);
    if (!$nested->verified()) {
        throw new RuntimeException("{$key}: {$nested->failure->reason->value}: {$nested->failure->message}");
    }
    // json_decode($nested->payload->json, true) is the transaction or renewal
    // info: run the post-verification checklist above on it before acting.
}
```

Each nested JWS is checked against the same pinned roots as the outer one;
there is nothing notification-specific about `verifySignedData()` itself.

## The verifyReceipt-compatible endpoint

`verifyReceiptEndpoint()` is a stateless, one-shot replacement for Apple's
deprecated endpoint: same request body, same response body, same status
codes, verified offline against the pinned roots instead of by calling
Apple. It never throws. Fields that only Apple's own server-side database can
supply (`latest_receipt_info`, `pending_renewal_info`) are not produced. Like
Apple's own endpoint, it checks no bundle id: compare
`json_decode($response, true)['receipt']['bundle_id']` yourself.

| status | meaning |
|---|---|
| 0 | Valid. `environment` and `receipt` are present in the response. |
| 21002 | `receipt-data` is missing, not a string, too large, or the body isn't valid JSON. |
| 21003 | The receipt failed to authenticate (bad signature, untrusted chain, expired or wrong-purpose certificate). |
| 21007 | A sandbox receipt was sent to `Environment::Production`. |
| 21008 | A production receipt was sent to `Environment::Sandbox`. |
| 21009 | Internal data access error (the library's own code faulted); alert, don't retry. |

No other `verifyReceipt` status (21000, 21001, 21004, 21005, 21006, 21010,
21100-21199) is ever returned: those describe HTTP-method, shared-secret and
Apple-server-side conditions this offline replacement cannot produce. See
`AppleStatus` for the named constants behind each code.

**Read the raw body.** A web framework that parses
`application/x-www-form-urlencoded` bodies rebuilds the request from parsed
fields, which is not byte-for-byte the JSON Apple's endpoint contract
expects. Read the raw request body and pass it straight through:

```php
function handleVerifyReceipt(ServerRequestInterface $request, Verifier $verifier): ResponseInterface
{
    $rawBody = (string) $request->getBody();
    $responseJson = $verifier->verifyReceiptEndpoint(Environment::Production, $rawBody);

    return $response->withStatus(200)
        ->withHeader('Content-Type', 'application/json')
        ->withBody($streamFactory->createStream($responseJson));
}
```

## Decode rules

Reading a legacy receipt's attributes follows a few fixed rules, the same in
every port:

- **First occurrence wins.** If Apple's payload repeats an attribute type
  (it shouldn't, but the parser doesn't assume that), the first occurrence
  decides the field; later ones are ignored. This applies to the receipt
  creation date too, since it anchors the certificate-validity check.
- **Dates** are `YYYY-MM-DDTHH:MM:SSZ` exactly (RFC 3339, UTC, no fractional
  seconds, no offset); anything else leaves the field `null` rather than
  failing the receipt. Decoded dates are epoch milliseconds (always ending
  in `000`, since receipts carry whole seconds).
- **Strings** are `UTF8String` or `IA5String` only; `IA5String` bytes ≥ 0x80
  fail to decode (7-bit ASCII, by definition). A string that fails to decode
  leaves the field `null` (or, for `bundleId`, only `bundleIdBytes` is set,
  see below) rather than failing the receipt.
- **`unknownAttributes`** holds the raw value octets of every attribute type
  the payload doesn't model as a named field, keyed by attribute type, in
  receipt order, so a field Apple adds later is never silently dropped.
  `bundleId` (attribute 2) is the one exception: a decode failure there does
  not also appear in `unknownAttributes`, because `bundleIdBytes` already
  carries the raw value unconditionally.
- **64-bit ids** (`appItemId`, `downloadId`, `versionExternalIdentifier`,
  `webOrderLineItemId`) are plain PHP `int`; `ReceiptPayload::toJson()` and
  `InAppPurchase::writeJson()` render them as JSON strings (JSON numbers lose
  precision above 2^53) and everything else as JSON numbers, matching every
  other port's canonical form byte for byte.

## Upgrading from 0.6

0.7 is a breaking change: `JwsVerifier` and `ReceiptVerifier` are gone,
policy checks (bundle id, allowed environments) are no longer constructor
arguments, and every failure is a `VerificationResult`/`Failure` instead of a
thrown `VerificationException`.

| 0.6 | 0.7 |
|---|---|
| `new ReceiptVerifier($roots, $bundleId)->verify($b64)` | `Verifier::create(Config::builder()->roots($roots)->build())->verifyReceipt($b64)`, then compare `$result->payload->bundleId` yourself |
| `new JwsVerifier($roots, $bundleId, $environments)->verifyTransaction($jws)` | `Verifier::create(Config::builder()->roots($roots)->build())->verifySignedData($jws)`, then compare `$payload['bundleId']` / `$payload['environment']` yourself |
| `AppleRootCerts::receiptRoots()` / `AppleRootCerts::jwsRoots()` | `AppleRootCerts::pinnedRoots()` (one method, one pinned set, for both paths) |
| thrown `VerificationException` with `->reason` | `VerificationResult::$failure` (`Failure::$reason`, `->message`, `->cause`); nothing throws |
| `Reason::InvalidReceiptFormat`, `::InvalidJwsFormat` | `Reason::Malformed` |
| `Reason::RequestTooLarge` | `Reason::TooLarge` |
| `Reason::InvalidChain` | `Reason::UntrustedChain` |
| `$endpoint->verifyReceiptResult($body)->toResponse()` | `Verifier::create(...)->verifyReceiptEndpoint($environment, $body)` (returns the JSON string directly; no `VerifyReceiptResult`, no environment re-render without re-verifying) |
| `VerifyReceiptEndpoint::MAX_REQUEST_BYTES` | 3 MiB (3,145,728 bytes), no longer a public constant — see "Input limits" below |
| `ReceiptVerifier::MAX_RECEIPT_BYTES` | 3 MiB (3,145,728 bytes), no longer a public constant |
| `JwsVerifier::MAX_JWS_BYTES` | 256 KiB (262,144 bytes), no longer a public constant |
| `TransactionPayload::$expiresDate` / `->$revocationDate` | read the same keys straight off `json_decode($result->payload->json, true)` (there is no longer a typed JWS model, only the verified JSON text) |
| `$receiptVerifier->verify($receipt, $deviceGuid)` | verify, then compute the device hash yourself (see "Device hash" above) |
| `ReceiptVerifier::verifyReceiptCore()` | gone — `verifyReceipt()` is the one entry point, and it never filtered by bundle id to begin with |
| PHP 8.1+ | PHP 8.2+ |

## Trust model

- **Pinned anchors only.** Trust comes from the anchors you pass and from
  nothing else. This library has no code path to the operating system trust
  store, to a distribution CA bundle, or to the process's `openssl.cafile`
  setting: `openssl_cms_verify()`, `openssl_pkcs7_verify()` and
  `openssl_x509_checkpurpose()` all take a CA path and none of them appears
  anywhere in `src/`. A test tokenises every source file to keep it that way,
  and another points OpenSSL's own `SSL_CERT_FILE` at a CA that signed the
  chain and proves it buys an attacker nothing.
- **No network, ever.** No OCSP, no CRL, no AIA fetch, no root download.
  Revocation checking is disabled by design; that is the accepted trade-off
  for offline verification, and it is what Apple's own libraries do in offline
  mode.
- **The chain is walked top-down.** A certificate's signature is checked only
  against a key a pinned root has already vouched for; an untrusted
  candidate's key is never decoded, let alone used to verify anything, so a
  stranger certificate sitting among the embedded ones costs nothing beyond
  being counted and ignored.
- **Apple marker OIDs are mandatory.** The JWS leaf must carry
  `1.2.840.113635.100.6.11.1` and the intermediate `1.2.840.113635.100.6.2.1`
  with `CA:TRUE`; the receipt signer must carry `1.2.840.113635.100.6.11.1`
  and its intermediate the WWDR marker too. Without the receipt check, any
  Apple developer's own distribution certificate — which chains through the
  same WWDR intermediate to the same root — could sign a fully forged
  receipt.
- **Validity at signing time.** Apple's signing certificates rotate and
  expire; a receipt is valid if its chain was valid when Apple signed it, or,
  when the receipt or JWS states no signing time, at the configured clock
  (see "What the clock can move" below).
- **Any receipt signer algorithm Apple has used.** RSA PKCS#1 v1.5 and
  ECDSA over P-256/P-384, with MD5 through SHA-512 digests — no
  algorithm allowlist beyond what the trusted chain and OpenSSL itself can
  verify. A relabel — a `signatureAlgorithm` naming a different hash than
  `digestAlgorithm` — is refused.
- **No RSA-PSS receipt signers.** A SignerInfo signed with RSASSA-PSS fails
  as `INVALID_SIGNATURE`, even when the signature is genuine. Apple has never
  signed a receipt with PSS. PHP's `openssl_verify()` has no PSS mode, so
  supporting it would take hand-written EMSA-PSS padding checks, and the
  signer chooses its own algorithm, so that code would sit on the forgery
  path. This port does not hand-write crypto. The other ports may verify PSS
  signers; the shared conformance case leaves it to each port. Certificate
  chain links are unaffected: OpenSSL checks those itself, PSS included.
- **Several SignerInfos, and several certificates claiming the same
  identity.** A receipt with more than one SignerInfo verifies when at least
  one does, tried in order; when more than one embedded certificate carries a
  SignerInfo's issuer and serial, each is tried in turn, and a key is used
  only after its own chain and marker checks pass.
- **All three published Apple roots are pinned**, in one shared set for both
  verification paths. Apple documents the JWS chain as ending in "an Apple
  root certificate" without naming one, so anchoring on a single root would
  break silently if Apple ever re-anchored a path.
- **Reject rather than repair.** A parser that cannot represent an input
  fails it; it never substitutes a sentinel. An attribute type outside
  `[0, 2^31-1]`, a negative integer, trailing bytes after the CMS blob: all
  rejected. A date or a known attribute's value that does not decode is kept
  raw and the receipt still verifies — decode failures are not trust
  failures — but the top-level attribute SET itself must be well formed.
- **Only a `VerificationResult` failure escapes** a public entry point.
  Containment is categorical, not a list of expected types.

You can pass your own anchors instead of the bundled ones — that is what
`Config::builder()->roots(...)` is for — at your own risk.

## What the clock can move

`Config` carries a PSR-20 `ClockInterface`; omitted, `SystemClock` is
installed. It reaches exactly two things:

- **`request_date`** in `verifyReceiptEndpoint()`'s response, read once per
  call.
- **The chain-validity instant**, but only when the receipt or JWS states no
  signing time of its own — a receipt with no attribute 12, or a JWS payload
  with no `signedDate` (or one that does not parse). When the input states a
  time, the chain is judged at that time regardless of what the clock reads.

This is a deliberate change from 0.6, where the clock reached `request_date`
only and a dateless input was always judged at real time. 0.7 makes the
fallback instant configurable too, so a test can pin "now" for a dateless
input the same way it pins `request_date`, without reaching for a
process-wide time mock. A caller injecting a clock to work around skew, or to
pin `request_date` in a test, must still not thereby be able to accept a
chain that is not valid at the instant it actually cares about.

`SystemClock` is public API, and any PSR-20 implementation drops in —
`symfony/clock`'s `MockClock`, `lcobucci/clock`, or four lines of your own.

## Input limits

Base64 decoding and JSON parsing both allocate a multiple of their input
before any signature is checked, so the input is measured first. The byte
limits are Apple's, fixed in every port of this library, not `Config`
options.

- **Receipt size** (3 MiB, 3,145,728 bytes): the base64 text given to
  `verifyReceipt()`, in UTF-8 bytes, before decoding. A larger receipt is
  `Reason::TooLarge`.
- **Request body size** (3 MiB, 3,145,728 bytes): the request body given to
  `verifyReceiptEndpoint()`, before it is parsed. A larger body is
  `Reason::TooLarge` (status 21002).
- **JWS size** (256 KiB, 262,144 bytes): the compact JWS text given to
  `verifySignedData()`, before it is split into segments. A larger JWS is
  `Reason::TooLarge`.
- **JSON nesting depth 64**, member names to 50,000 characters and numbers
  to 1,000 characters: checked before any JSON is parsed — by a manual byte
  scan, not `json_decode()`'s own depth parameter, which bounds nesting only
  — in the request body, the JWS header and the JWS payload alike. Outside
  any of those is `Reason::Malformed`.
- **ASN.1 nesting depth 32**, 20,000 nodes and 48 MiB of retained parser
  state per parse: checked before any certificate is decoded. Outside any of
  those is `Reason::Malformed`.
- **10 embedded certificates, 4 SignerInfos**, enforced before any
  certificate is decoded or any signature is checked.

`fixtures/cases-0.7.json` holds every port to these same numbers, from both
sides of each boundary.

### Why PHP needs its own headroom

PHP has no zero-copy slice: every `substr()` allocates and every ASN.1 node
is a real object, so a `Der` parse retains roughly `2 × depth × input` bytes
— a megabyte of minimal two-byte DER nodes costs about 72 MB of parser state
without the node budget above. Against a `php.ini-production` default
`memory_limit` of 128M, that turns a megabyte of attacker bytes into a fatal
out-of-memory error, which is **not a `Throwable`**: no `catch` in this
library, nor in yours, can turn a fatal error into a verdict, and the worker
dies with no answer at all. Every "never throws" promise in this README
holds only because the input is bounded before it is allocated — the 48 MiB
retained-byte budget above exists specifically because bounding depth and
node count separately is not enough (a shape nested deep but built of many
small siblings can be cheap on both of those axes and still cost tens of
megabytes; the retained-byte budget bounds the product instead).

Give a worker that hands raw request bodies to `verifyReceiptEndpoint()` a
`memory_limit` of at least 384M — `MemoryExhaustionTest` runs the costliest
vectors this library knows about at that limit and asserts the process
survives every one of them. Decoding the body yourself before calling the
library does not avoid the cost, it only moves the same `json_decode` out of
this library and back into your own code, unmeasured.

## Known platform caveats

- **64-bit only.** Apple ships epoch-millisecond timestamps (~1.7×10¹²),
  which a 32-bit `int` cannot hold — `json_decode` would return floats and
  every date comparison would silently drift. `Verifier::create()` refuses a
  32-bit build with a `\RuntimeException` rather than drifting.
- **Known issue: genuine legacy receipts fail on RHEL 9.** The legacy Apple
  receipt chain and its CMS signature are SHA-1, and RHEL 9's DEFAULT crypto
  policy (also Alma and Rocky) makes the system OpenSSL refuse SHA-1
  signatures. `ext-openssl` uses that OpenSSL, so a genuine legacy receipt is
  `Reason::UntrustedChain`. Observed on AlmaLinux 9.8 on 2026-09-24. Newer
  receipts (SHA-256 chains) and every JWS are unaffected; FIPS mode is
  untested. Until the fix ships, run
  `update-crypto-policies --set DEFAULT:SHA1` on that host. The planned fix
  checks SHA-1 signatures on Apple's pinned legacy chain only, through
  phpseclib, and adds an AlmaLinux 9 CI job (ROADMAP.md).
- **`ext-openssl` is not literally universal.** It is bundled everywhere in
  practice, but a hardened build without it exists. The `"ext-openssl": "*"`
  requirement turns that into a Composer error rather than a runtime fatal.

## Debugging a receipt by hand

See the [project README](../README.md#debugging-a-receipt-by-hand) for the
`openssl` commands that open a receipt or a JWS payload without verifying it
(useful when a verification fails and you want to see what arrived).

## Development

```bash
composer install                             # installs composer.lock
vendor/bin/phpunit                            # everything
vendor/bin/phpunit --testsuite conformance    # the shared cross-language vectors
vendor/bin/phpunit --group mutation           # the mutation pass
vendor/bin/phpstan analyse
vendor/bin/php-cs-fixer fix
fuzz/run.sh all 60                            # the six coverage-guided fuzz targets
```

`fuzz/` holds coverage-guided targets over the DER, CMS and X.509 readers and
the `Verifier`'s three entry points, run with a pinned `nikic/php-fuzzer`
phar that the run script downloads and digest-checks. It is not a Composer
dependency, and deliberately so — see `fuzz/README.md`, which also lists the
targets and the invariant each one asserts beyond "nothing but a verdict
escapes".

`php/certs/` is a checked copy of the repository-root `certs/`, and
`src/Internal/RootsData.php` is generated from that copy by
`php/tools/gen-roots.php`. CI diffs both. Regenerate with:

```bash
php php/tools/gen-roots.php
```

`composer.lock` is committed and CI installs from it, so no run resolves a
version range. `config.platform.php` is `8.2.0` in `composer.json`, matching
the 8.2+ floor.

## Licence

MIT — see [LICENSE](../LICENSE).
