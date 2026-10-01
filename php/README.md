# apple-purchase-receipt-verifier

Verify Apple in-app purchases locally — no calls to Apple's servers.

Replaces the deprecated `verifyReceipt` endpoint by validating StoreKit 2
signed JWS transactions and legacy PKCS#7 receipts against pinned Apple root
certificates.

## Installation

```bash
composer require emindeniz99/apple-purchase-receipt-verifier
vendor/bin/aprv-install
```

The verification does not run in PHP. It runs in `aprv`, one small binary
that hosts the module every language of this project shares (a WebAssembly
module built on OpenSSL 4, in a Wasmtime sandbox). This package is the PHP
API in front of it: it reads your clock, hands the bytes to `aprv` and maps
the answer onto the types below. `vendor/bin/aprv-install` downloads the
binary for your platform from the GitHub Release this package version was cut
with and checks it against the SHA-256 that `binaries.json` pins in the
package; a wrong hash installs nothing. Nothing downloads at request time.

| Platform | Binary |
|---|---|
| Linux x86-64, arm64 (static, glibc and musl) | `aprv-x86_64-unknown-linux-musl`, `aprv-aarch64-unknown-linux-musl` |
| macOS Intel, Apple silicon | `aprv-x86_64-apple-darwin`, `aprv-aarch64-apple-darwin` |
| Windows x64, arm64 | `aprv-x86_64-pc-windows-msvc.exe`, `aprv-aarch64-pc-windows-msvc.exe` |

Anywhere else, or where you would rather not run a process per call, run the
same binary as a server (`aprv serve`, or the Docker image) and pass a
`Transport\HttpTransport` (see "Two ways to reach aprv"). The installer says so
on an unsupported platform.

`aprv-install` writes to `php/bin/` inside the package directory, which
`composer install` and `composer update` replace: run it again after either,
or add it as a script of your project (`"post-install-cmd":
"vendor/bin/aprv-install"`, and the same for `post-update-cmd`).

**The package is the repository root, not this directory.** Packagist reads
`composer.json` from a repository root and nowhere else, so the manifest
Composer installs is the one at the top of this nine-language monorepo. It
autoloads `EminDeniz99\ApplePurchaseReceiptVerifier\` from `php/src/`, exposes
`php/bin/aprv-install`, and a root `.gitattributes` allowlist trims the archive
Composer downloads to this port: the sources, the installer, its manifest, the
two licences and this file. It carries no certificate: Apple's three roots are
compiled into the module `aprv` runs.
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

Requires **PHP 8.2+** (64-bit) and `ext-json`. One runtime dependency:
`psr/clock`, the PSR-20 clock interface, a single interface with no code and
no transitive dependencies. No `ext-openssl`: nothing in PHP touches a
certificate. `ext-curl` is needed for the server transport, and lets the
installer download over HTTPS without `ext-openssl`.

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

`create` checks that `aprv` is where it should be and speaks the ABI this
package was written for, and throws when it is not: at startup, never on the
first request.

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

## What runs per call

**By default, one `aprv` process per call.** `Verifier::create()` starts
nothing; each call starts `aprv verify-receipt` (or `verify-signed-data`,
`verify-receipt-endpoint production|sandbox`) with an argv array, so no shell
parses anything, writes the input to its stdin, reads the JSON from its
stdout and waits for it to exit. The process lives about 12 ms and ends with
the call, so a hostile input reaches nothing that outlives it. The exit status
carries the outcome: 0 is a result (verified or not), 3 an input over the
size cap, 70 a trap or a load failure, and 2 a configuration the module
refuses (which `create` has already checked).

**Or a server you run.** For a busy worker, run `aprv serve` beside PHP and
pass a transport; one keep-alive curl handle then carries every call
(about 3.5 ms for a genuine receipt in the spike, against 11.6 ms per process):

```php
use EminDeniz99\ApplePurchaseReceiptVerifier\Transport\HttpTransport;

$verifier = Verifier::create(
    Config::defaults(),
    new HttpTransport('http://127.0.0.1:8080', $token),   // the server's X-Aprv-Token, if it has one
);
```

The server speaks plain HTTP, binds `127.0.0.1` unless `APRV_LISTEN` says
otherwise, and should have a token when it listens beyond loopback; put TLS in
front of it when the path is not a private one. No proxy is used. The roots
live in the server (`aprv serve --roots FILE`, or the built-in ones), so
`create` fetches `GET /v1/info` and refuses a server whose roots are not
exactly your `Config`'s: a server that trusts something else would answer a
different question than the one you asked.

`Verifier::create(Config, ?Transport)` takes the transport as its second
argument, so `Config` stays exactly the 0.7 one. `CliTransport` also takes an
explicit binary path (`new CliTransport('/usr/local/bin/aprv')`), for a binary
you installed yourself; without one it uses the one `aprv-install` put in
`php/bin/`. A transport serves one `Verifier`.

**The clock** is read once per call, before the input is looked at, and sent
as `--now-ms` (or the `X-Aprv-Now-Ms` header). A clock that throws, or that is
before 1970, is `INTERNAL_ERROR` (status 21009 at the endpoint).

**Custom roots** go to `aprv` as one owner-only temporary file per `Verifier`
(`--roots FILE`, one base64 DER certificate per line), written by `create` and
deleted when the `Verifier` is destroyed. `create` runs the module once with
them, so a root it refuses is an `InvalidArgumentException` at startup.

**Six outcomes, kept distinct.**

| Outcome | What you see |
|---|---|
| Verified | `$result->payload` |
| Verification failure | a `Failure` with one of the eight `Reason`s, no `cause` |
| Caller misuse | `InvalidArgumentException` from `create()`: an empty root list, a root that is not a certificate, a server that trusts other roots or refuses the token |
| ABI mismatch, no binary | `RuntimeException` from `create()`, naming the ABI version this package expects and the one it found |
| Trap or unreadable answer | `Reason::InternalError`, `cause` a `Transport\ModuleFaultException` |
| `aprv` did not answer | `Reason::InternalError`, `cause` a `Transport\ServerProcessException` (it could not start, died, timed out, the connection broke, HTTP 5xx) |

`Failure::$cause` is set only for the last two and for a clock that threw:
the module's own verdicts, `INTERNAL_ERROR` and `UNREADABLE_PAYLOAD` included,
carry none. An input over the 3 MiB cap is `TOO_LARGE` (status 21002 at the
endpoint), as the module answers it.

## Why offline

Signature verification cannot fail because a vendor endpoint is down, so a
purchase can be honoured immediately and reconciled against the App Store
Server API afterwards. Refunds and revocations still need that reconciliation
pass — a signature proves what Apple signed, not what happened since.

This is the PHP API of a project with nine language packages, held to one
fixture suite that includes Apple's own official test fixtures, on which they
are required to agree on every verdict and every decoded value. See the [project README](../README.md) for the full picture and
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
| 21009 | Internal data access error: the receipt authenticated but its signed content does not parse, or the library itself failed. Deterministic; alert, don't retry. |

No other `verifyReceipt` status (21000, 21001, 21004, 21005, 21006, 21010,
21100-21199) is ever returned: those describe HTTP-method, shared-secret and
Apple-server-side conditions this offline replacement cannot produce. See
`AppleStatus` for the named constants behind each code.

**Read the raw body.** A web framework that parses
`application/x-www-form-urlencoded` bodies rebuilds the request from parsed
fields, which is not byte-for-byte the JSON Apple's endpoint contract
expects. Read the raw request body and pass it straight through:

```php
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;

// $responseFactory and $streamFactory are your framework's PSR-17 factories.
function handleVerifyReceipt(
    ServerRequestInterface $request,
    Verifier $verifier,
    ResponseFactoryInterface $responseFactory,
    StreamFactoryInterface $streamFactory,
): ResponseInterface {
    $rawBody = (string) $request->getBody();
    $responseJson = $verifier->verifyReceiptEndpoint(Environment::Production, $rawBody);

    return $responseFactory->createResponse(200)
        ->withHeader('Content-Type', 'application/json')
        ->withBody($streamFactory->createStream($responseJson));
}
```

## Decode rules

Reading a legacy receipt's attributes follows a few fixed rules, the same in
every port:

- **First occurrence wins.** If Apple's payload repeats an attribute type
  (it shouldn't, but the parser doesn't assume that), the first occurrence
  decides the field; later copies are kept raw in `unknownAttributes`. This
  applies to the receipt creation date too, since it anchors the
  certificate-validity check.
- **Dates** are `YYYY-MM-DDTHH:MM:SSZ` exactly (RFC 3339, UTC, no fractional
  seconds, no offset); anything else leaves the field `null` rather than
  failing the receipt, and a non-empty string that does not parse is kept
  raw. An empty date string means "not set". Decoded dates are epoch
  milliseconds (always ending in `000`, since receipts carry whole seconds).
- **Strings** are `UTF8String` or `IA5String` only; `IA5String` bytes ≥ 0x80
  fail to decode (7-bit ASCII, by definition). A string that fails to decode
  leaves the field `null` (or, for `bundleId`, only `bundleIdBytes` is set,
  see below) rather than failing the receipt.
- **`unknownAttributes`** holds the raw value octets of every attribute that
  does not end up in a named field, keyed by attribute type, in receipt
  order: a type the payload doesn't model, a later copy of a known one, and
  a known one whose value does not parse. A field Apple adds later is never
  silently dropped. `bundleId` (attribute 2) is the one exception: a decode
  failure there does not also appear in `unknownAttributes`, because
  `bundleIdBytes` already carries the raw value unconditionally.
- **64-bit ids** (`appItemId`, `downloadId`, `versionExternalIdentifier`,
  `webOrderLineItemId`) are plain PHP `int`; `ReceiptPayload::toJson()`
  renders them as JSON strings (JSON numbers lose precision above 2^53) and
  everything else as JSON numbers, through `json_encode()`: the same value
  every other port writes, though the bytes may differ.

## Upgrading from 0.7

The public API is 0.7's: `Verifier::create`, the three verify methods,
`Config`, `Reason`, the result and payload types; only `AppleRootCerts` is
gone. What changes is what runs underneath, and what you can see of it:

| 0.7 | 0.8 |
|---|---|
| PHP parsed and verified, on `ext-openssl` | `aprv` verifies; `ext-openssl` is no longer required, and `vendor/bin/aprv-install` (or a server URL) is |
| `Verifier::create(Config)` | `Verifier::create(Config, ?Transport)`: the second argument picks the CLI (default) or a server |
| `Config::defaults()->roots` listed Apple's three certificates; PEM text was accepted | it is `null`, which means the module's built-in Apple roots (an empty list is refused at `create`); roots are DER or PEM strings, and "Apple's plus mine" is all four |
| `AppleRootCerts::pinnedRoots()` returned Apple's three roots | removed: the package carries no copy of them. Read them from Apple's PKI page or the repository's `certs/` |
| `Failure::$cause` carried the parser's exception | it is set only when the wrapper produced `INTERNAL_ERROR` (the module trapped, `aprv` did not answer, the clock threw) |
| a hostile input could exhaust `memory_limit` | it cannot: the parsing is out of PHP |

## Upgrading from 0.6

0.7 is a breaking change: `JwsVerifier` and `ReceiptVerifier` are gone,
policy checks (bundle id, allowed environments) are no longer constructor
arguments, and every failure is a `VerificationResult`/`Failure` instead of a
thrown `VerificationException`.

| 0.6 | 0.7 |
|---|---|
| `new ReceiptVerifier($roots, $bundleId)->verify($b64)` | `Verifier::create(Config::builder()->roots($roots)->build())->verifyReceipt($b64)`, then compare `$result->payload->bundleId` yourself |
| `new JwsVerifier($roots, $bundleId, $environments)->verifyTransaction($jws)` | `Verifier::create(Config::builder()->roots($roots)->build())->verifySignedData($jws)`, then compare `$payload['bundleId']` / `$payload['environment']` yourself |
| `AppleRootCerts::receiptRoots()` / `AppleRootCerts::jwsRoots()` | `Config::defaults()` (one pinned set, for both paths) |
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

- **Pinned anchors only.** Trust comes from the roots you pass and, when you
  pass none, from the three Apple roots compiled into the module. Nothing in
  this package, `aprv` or the module reads the operating system trust store, a
  CA bundle or an OpenSSL configuration file, and PHP's `ext-openssl` is not
  involved at all.
- **No network, ever.** No OCSP, no CRL, no AIA fetch, no root download.
  Revocation checking is disabled by design; that is the accepted trade-off
  for offline verification, and it is what Apple's own libraries do in offline
  mode. `aprv-install` is the one thing that downloads, once, when you run it.
- **The verdict is the module's.** This package parses no ASN.1, checks no
  signature and decides nothing about trust; a test tokenises every source
  file and fails on a call to a crypto function. The chain rules, Apple's
  marker OIDs, the signature algorithms and the validity-at-signing-time rule
  are the module's and are the same in every language of the project
  (`fixtures/cases.json` holds them all to the same answers).
- **The process boundary.** In the default transport a receipt is parsed by a
  process that starts for that call and ends with it, inside the module's
  WebAssembly sandbox (256 MiB of memory, a 10 s time limit per call).
  Isolation protects your PHP worker from a hostile input; it does not make a
  wrong verdict right, which is why the module is checked by every language's
  conformance suite and by fuzzing.
- **The binary is pinned.** `aprv-install` runs a downloaded file only after
  its SHA-256 matches the one in `binaries.json`, which ships inside the
  package, so a replaced release asset installs nothing. A server you run
  yourself is yours to trust; `create` checks its roots and ABI, not its
  provenance.
- **Reject rather than repair.** A wrapper that cannot read the module's answer
  fails the call as `INTERNAL_ERROR`; it never substitutes a verdict.
- **Only a `VerificationResult` failure escapes** a public entry point.
  Containment is categorical, not a list of expected types.

You can pass your own anchors instead of the built-in ones, as DER or PEM
strings, which the module tells apart (a PEM string holding several
certificates is one entry): `Config::builder()->roots([$myRoot])->build()`.
"Apple's roots plus mine" is all four, Apple's three read from Apple's PKI
page or the repository's `certs/`: the package carries no copy. With a
server URL, the server reports the SHA-256 of each root as its `--roots`
file decodes it, and a PEM block there decodes to its DER, so give the
`Config` DER for a server whose file holds PEM. Leaving the roots out (`Config::defaults()`,
or a builder that never calls `roots()`) means the built-in Apple roots. An
empty list is not "no roots": `Verifier::create` refuses it with an
`InvalidArgumentException`, so a list that came up empty by mistake never
widens to Apple's roots.

## What the clock can move

`Config` carries a PSR-20 `ClockInterface`; omitted, `SystemClock` is
installed. It reaches exactly two things in the module:

- **`request_date`** in `verifyReceiptEndpoint()`'s response.
- **The chain-validity instant**, but only when the receipt or JWS states no
  signing time of its own: a receipt with no attribute 12, or a JWS payload
  with no `signedDate` (or one that does not parse). When the input states a
  time, the chain is judged at that time regardless of what the clock reads.

The clock is read once per call and crosses to `aprv` as epoch milliseconds,
so a test can pin "now" for a dateless input without a process-wide time mock.
A caller injecting a clock to work around skew, or to pin `request_date` in a
test, must still not thereby be able to accept a chain that is not valid at
the instant it actually cares about.

`SystemClock` is public API, and any PSR-20 implementation drops in:
`symfony/clock`'s `MockClock`, `lcobucci/clock`, or four lines of your own.

## Input limits

The limits are the module's, fixed in every language of this library, and not
`Config` options; this package adds none.

- **Receipt size** (3 MiB, 3,145,728 bytes): the base64 text given to
  `verifyReceipt()`, in UTF-8 bytes. A larger receipt is `Reason::TooLarge`.
- **Request body size** (3 MiB): the request body given to
  `verifyReceiptEndpoint()`. A larger body is `Reason::TooLarge` (status 21002).
- **JWS size** (256 KiB, 262,144 bytes): the compact JWS given to
  `verifySignedData()`. A larger JWS is `Reason::TooLarge`.
- **Anything over 3 MiB** never reaches the module: `aprv` refuses it (exit
  status 3, HTTP 413) and the façade answers as the module answers an
  over-cap input.
- **JSON nesting depth 64**, member names to 50,000 characters and numbers to
  1,000 characters, **ASN.1 nesting depth 32**, **10 embedded certificates**,
  **4 SignerInfos** and **six certificates below the anchor**: the module
  checks them before any certificate is decoded or any signature is checked,
  and answers `Reason::Malformed` (or `UnreadablePayload` for a signed
  payload) with no PHP memory cost.

`fixtures/cases.json` holds every port to these numbers, from both sides of
each boundary. Because the parsing is out of PHP, a hostile input can no
longer exhaust a PHP worker's `memory_limit`: the façade holds the input, the
module's JSON and their decoded copies, and nothing grows with an input's
structure.

## Cost per call

Measured with `php bench/bench.php --aprv PATH`, which times the three
operations on the two genuine sandbox receipts through each transport (PHP
8.4.19 CLI, one thread, a shared 4-vCPU guest, against the release binary
that embeds the 0.7 component). Other jobs kept the machine at a load average
near 10 while this ran, so read the numbers as an order of magnitude (the
script's JSON also carries the best sample of each, `us_per_op_min`):

| Call | Receipt | CLI, one process per call | HTTP, keep-alive |
|---|---|---:|---:|
| `verifyReceipt` | genuine g5 receipt (2 purchases) | 37.7 ms | 9.0 ms |
| `verifyReceiptEndpoint` | genuine g5 receipt (2 purchases) | 30.5 ms | 7.3 ms |
| `verifyReceipt`, tampered signature | genuine g5 receipt (2 purchases) | 34.5 ms | 6.6 ms |
| `verifyReceipt` | genuine legacy receipt (187 purchases) | 56.3 ms | 23.8 ms |
| `verifyReceiptEndpoint` | genuine legacy receipt (187 purchases) | 85.2 ms | 66.1 ms |
| `verifyReceipt`, tampered signature | genuine legacy receipt (187 purchases) | 31.6 ms | 13.6 ms |

The process start dominates the CLI figure: running `aprv verify-receipt`
directly on the same g5 receipt took 30.5 ms (best 18.9 ms) under the same
load, against 37.7 ms (best 26.3 ms) through the façade, whose own share is
a `proc_open` and the JSON decode. The spike measured
11.6 ms per call for the g5 receipt through the CLI and 3.56 ms over HTTP on
a faster, idle machine. A worker that verifies many receipts per second
should use the server transport.

## Known platform caveats

- **64-bit only.** Apple ships epoch-millisecond timestamps (~1.7×10¹²),
  which a 32-bit `int` cannot hold: `Verifier::create()` refuses a 32-bit
  build with a `\RuntimeException` rather than drifting.
- **No binary, no verifier.** Without an `aprv` binary or a server the package
  cannot verify anything, and says so at `create()`. Where the installer has
  no binary for your platform it names the server option.
- **`proc_open` must be allowed.** The default transport needs it (a hardened
  `disable_functions` list often removes it); use `HttpTransport` there.
- **The CLI transport on Windows** writes the whole input before it reads the
  answer (Windows pipes cannot be polled), which `aprv` allows because it
  reads its whole input first. It has not been exercised in CI yet.
- **PHP-FPM and long-running workers** keep the `Verifier` (and so its roots
  file) for their lifetime; the file is deleted when the object is destroyed
  or the process ends normally.

## Debugging a receipt by hand

See the [project README](../README.md#debugging-a-receipt-by-hand) for the
`openssl` commands that open a receipt or a JWS payload without verifying it
(useful when a verification fails and you want to see what arrived).

## Development

```bash
composer install                              # installs composer.lock
export APRV_BIN=/path/to/aprv                 # the suite runs against the real binary
vendor/bin/phpunit                            # everything
vendor/bin/phpunit --testsuite conformance    # every shared case: CLI transport, then HTTP against a local aprv serve
vendor/bin/phpstan analyse
vendor/bin/php-cs-fixer fix
fuzz/run.sh all 60                            # the four coverage-guided fuzz targets
php bench/bench.php --aprv "$APRV_BIN"        # per-call cost through both transports
```

The suite never skips for a missing binary: without `APRV_BIN` it looks where
`aprv-install` puts one and fails loudly if there is none. The binary is never
committed. Two suites hold the rest of the behaviour: `FacadeTest` (over a
fake transport: the clock, the six outcomes, every way an answer can be
unreadable) and `CliTransportTest` / `HttpTransportTest` (over a fake `aprv`
and a fake server: argv, exit statuses, problem codes, the roots file, the
fingerprint check), and `InstallerTest` serves the binary from a local HTTP
server to check that a wrong hash installs nothing.

**The corpus.** `tools/corpus.php` runs the corpus call files (1,179 rows plus
5,000 mutants, every clock pinned) through the façade over one transport and
compares each row byte for byte with the module's own answers. A row whose
input is over 3,145,728 bytes is refused by `aprv` first (exit 3, HTTP 413) and
counts as answered when the module's answer is the size refusal.
`tools/rerun.sh APRV_BINARY G1_DIR` runs the phpunit suites and the corpus over
both transports as one command.

**Releasing.** `binaries.json` ships with no tag and no hashes. The release
pins them with `php php/tools/update-binaries.php --tag vX.Y.Z --sums
SHA256SUMS` on the release branch, before the tag (`CI-NOTES.md`).

`composer.lock` is committed and CI installs from it, so no run resolves a
version range. `config.platform.php` is `8.2.0` in `composer.json`, matching
the 8.2+ floor.

## Licence

MIT — see [LICENSE](../LICENSE).
