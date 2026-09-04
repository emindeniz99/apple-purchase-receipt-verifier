# apple-purchase-receipt-verifier

Verify Apple in-app purchases locally — no calls to Apple's servers.

Replaces the deprecated `verifyReceipt` endpoint by validating StoreKit 2
signed JWS transactions and legacy PKCS#7 receipts against pinned Apple root
certificates.

```bash
composer require emindeniz99/apple-purchase-receipt-verifier
```

```php
use EminDeniz99\ApplePurchaseReceiptVerifier\AppleRootCerts;
use EminDeniz99\ApplePurchaseReceiptVerifier\Environment;
use EminDeniz99\ApplePurchaseReceiptVerifier\Jws\JwsVerifier;
use EminDeniz99\ApplePurchaseReceiptVerifier\Receipt\ReceiptVerifier;

// Legacy PKCS#7 app receipt — DER bytes or the base64 the client sends.
$receipt = (new ReceiptVerifier(AppleRootCerts::receiptRoots(), 'com.example.app'))
    ->verify($receiptBase64);
echo $receipt->receiptType, ' ', count($receipt->inAppPurchases), "\n";

// StoreKit 2 signed transaction.
$transaction = (new JwsVerifier(
    AppleRootCerts::jwsRoots(),
    'com.example.app',
    [Environment::Production, Environment::Sandbox],
))->verifyTransaction($jws);
echo $transaction->productId, ' ', $transaction->expiresDate, "\n";
```

Requires **PHP 8.1+** (64-bit), `ext-openssl` and `ext-json`. One runtime
dependency: `psr/clock`, which is the PSR-20 clock interface — a single
interface, no code, no transitive dependencies.

## Why offline

Signature verification cannot fail because a vendor endpoint is down, so a
purchase can be honoured immediately and reconciled against the App Store
Server API afterwards. Refunds and revocations still need that reconciliation
pass — a signature proves what Apple signed, not what happened since.

This is one of several implementations sharing a single fixture suite,
including Apple's own official test fixtures, which are required to agree byte
for byte. See the [project README](../README.md) for the full picture and
[COMPARISON.md](../COMPARISON.md) for how it differs from Apple's official
libraries.

## The three entry points

### `JwsVerifier` — StoreKit 2 and Server Notifications V2

```php
new JwsVerifier(
    array $trustedRoots,              // DER bytes or PEM text
    string $bundleId,
    array $acceptedEnvironments,      // Environment[]
    ?int $appAppleId = null,
    ?int $maxSignedAgeSeconds = null,
    ?Psr\Clock\ClockInterface $clock = null,
);
```

- `verifyTransaction(string $jws): TransactionPayload` — checks bundle id and
  environment.
- `verifyAppTransaction(string $jws): AppTransactionPayload` — checks bundle
  id, environment (`receiptType`) and, in Production, the app Apple id.
- `verifyRaw(string $jws): array` — chain and signature only, all claims
  returned. For payload types with no model of their own: renewal info,
  notification envelopes. **It enforces no claim** — you check `bundleId` and
  `environment` yourself.

Include `Environment::Sandbox` in the accept set on any endpoint App Review
can reach: App Review runs production builds against sandbox, so a
single-environment hard fail rejects purchases during review.

`TransactionPayload::isActiveAt(DateTimeInterface $now): bool` answers the
entitlement question — not revoked, and for a subscription not expired. It
reads the signed claims only, so a refund that happened after signing is
invisible to it.

**Dates in a JWS payload are epoch milliseconds, exactly as Apple ships them**
(`signedDate`, `purchaseDate`, `expiresDate`, `revocationDate`, …). That is
contractual across every port of this library. Receipt attributes are the
opposite case and become `DateTimeImmutable`.

Every claim Apple sent, modelled or not, stays reachable through
`$payload->claims`.

### `ReceiptVerifier` — legacy PKCS#7 app receipts

```php
new ReceiptVerifier(
    array $trustedRoots,
    string $bundleId,
    int $maxReceiptBytes = 2097152,
    int $nodeBudget = 20000,
);
```

- `verify(string $receipt, ?string $deviceGuid = null): AppReceipt`.
  `$receipt` is the DER bytes or their base64 — a value starting with the DER
  `SEQUENCE` tag (`0x30`) is taken as DER, anything else is base64 decoded
  first, so both transport forms work with and without a device GUID.
- `ReceiptVerifier::verifyReceiptCore(string $receipt, array $trustedRoots): AppReceipt`
  is public and **skips the bundle-id check** — the primitive the endpoint
  needs. If you call it, compare `$receipt->bundleId` yourself.

`$deviceGuid` is **raw GUID bytes, not hex**. Passing a hex string is the most
likely misuse and produces a plain `DEVICE_HASH_MISMATCH` with no hint — use
`hex2bin($guidHex)`. The same applies to every byte-valued property
(`opaqueValue`, `sha1Hash`, `bundleIdBytes`, and the values in
`unknownAttributes`): PHP spells bytes and text both `string`, so `AppReceipt`
and `InAppPurchase` each publish a `BINARY_PROPERTIES` constant naming which
is which.

Attribute types this library does not model are exposed raw and undecoded in
`$receipt->unknownAttributes`, keyed by type, so a field Apple adds later stays
reachable without a library release.

**`ReceiptVerifier` takes no clock.** See "What the clock can move" below.

### `VerifyReceiptEndpoint` — the deprecated endpoint, locally

```php
$endpoint = new VerifyReceiptEndpoint(
    AppleRootCerts::receiptRoots(),
    Environment::Production,          // or Environment::Sandbox
);

// PSR-7: JSON body in, JSON body out.
$response->getBody()->write($endpoint->verifyReceiptJson((string) $request->getBody()));
```

`verifyReceipt(mixed $body): array` takes and returns the decoded body;
`verifyReceiptJson(string $json): string` is the raw-wire twin. **Neither ever
throws** — like Apple's endpoint, a failure is a `status` in the body:

| Condition | `status` |
|---|---|
| body not an object, or `receipt-data` missing / not a string / empty / undecodable | `21002` |
| the receipt is malformed | `21002` |
| the receipt fails to authenticate | `21003` |
| endpoint is Production and the receipt is not a production one | `21007` |
| endpoint is Sandbox and the receipt is a production one | `21008` |
| anything unexpected | `21009` |
| otherwise | `0`, plus `environment` and `receipt` |

Environment routing fails closed: only receipt types `Production` and
`ProductionVPP` count as production. `ProductionVPPSandbox`, `Xcode`, a type
Apple adds later, and a missing attribute all route as non-production.

Like Apple's endpoint, this does **not** check the bundle id — compare
`receipt.bundle_id` yourself. `password` and `exclude-old-transactions` are
accepted for wire compatibility and never read. `21000`, `21004`, `21005`,
`21006`, `21010`, the `21100`–`21199` range and `is_retryable` are never
produced; see [COMPARISON.md](../COMPARISON.md).

## The error vocabulary

Every failure is a `VerificationException` carrying a `Reason`. **The reason is
a value, never a message string** — `match` on it, never parse text:

```php
use EminDeniz99\ApplePurchaseReceiptVerifier\Reason;
use EminDeniz99\ApplePurchaseReceiptVerifier\VerificationException;

try {
    $transaction = $verifier->verifyTransaction($jws);
} catch (VerificationException $e) {
    return match ($e->reason) {
        Reason::WrongBundleId, Reason::WrongEnvironment => $this->reject($e->reason->value),
        Reason::StalePayload                            => $this->askClientToRefresh(),
        default                                         => $this->flagAsForged($e->reason->value),
    };
}
```

Eleven reasons, and the vocabulary is closed — a twelfth would be a change to
every port of this library in one go. `$e->reason->value` is the canonical
`SCREAMING_SNAKE` token, byte-identical to the other ports', so a log line and
a metrics label read the same in every language.

| Case | `->value` | Means |
|---|---|---|
| `Reason::InvalidJwsFormat` | `INVALID_JWS_FORMAT` | not three segments, bad base64url/JSON, wrong `alg`, malformed `x5c` |
| `Reason::InvalidCertificate` | `INVALID_CERTIFICATE` | an `x5c` entry is not a parseable certificate |
| `Reason::InvalidCertificatePurpose` | `INVALID_CERTIFICATE_PURPOSE` | a certificate lacks the Apple marker OID its position requires |
| `Reason::InvalidChain` | `INVALID_CHAIN` | the chain does not reach a pinned anchor, or is not valid at the signing instant |
| `Reason::InvalidSignature` | `INVALID_SIGNATURE` | the signature does not check out |
| `Reason::WrongBundleId` | `WRONG_BUNDLE_ID` | the payload's bundle id is not the configured one |
| `Reason::WrongEnvironment` | `WRONG_ENVIRONMENT` | the environment is outside the accepted set |
| `Reason::WrongAppAppleId` | `WRONG_APP_APPLE_ID` | a Production AppTransaction does not name the configured app Apple id |
| `Reason::InvalidReceiptFormat` | `INVALID_RECEIPT_FORMAT` | the receipt is not a parseable CMS SignedData / attribute set |
| `Reason::DeviceHashMismatch` | `DEVICE_HASH_MISMATCH` | the device binding does not hold |
| `Reason::StalePayload` | `STALE_PAYLOAD` | signed longer ago than `maxSignedAgeSeconds` |

The exception message is `"REASON: detail"` for readability only. It is not
part of the API, nothing should parse it, and it never contains receipt bytes,
claim values or key material — the reason code is the entire observability
surface. This library does no logging, emits no metrics and takes no callbacks.

**Misconfiguration is not a verdict.** An empty trust-anchor list, an empty
bundle id, an empty accept set, a non-Production/Sandbox endpoint environment:
all raise `\InvalidArgumentException`. A `catch (VerificationException)` must
never swallow your own bug as "the receipt was bad".

## What the clock can move

`JwsVerifier` and `VerifyReceiptEndpoint` take an optional PSR-20
`ClockInterface`; omitted, `SystemClock` is installed. It drives exactly two
things:

1. the `STALE_PAYLOAD` comparison in `JwsVerifier`;
2. the `request_date` / `_ms` / `_pst` triple in `VerifyReceiptEndpoint`.

**Certificate validity is never judged by an injected clock.** It is judged at
the payload's own `signedDate` / `receiptCreationDate`, or at the receipt's
attribute-12 creation date — and where the input states neither, at the system
clock, read directly. A caller injecting a clock to test staleness, or to work
around skew, must not thereby be able to accept an expired chain or expire a
live one.

That is also why **`ReceiptVerifier` has no clock parameter at all**: it would
have no consumer, and an option with no consumer is an invitation to wire it
into the one place it must never reach.

`SystemClock` is public API, and any PSR-20 implementation drops in —
`symfony/clock`'s `MockClock`, `lcobucci/clock`, or four lines of your own.

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
- **Apple marker OIDs are mandatory.** The JWS leaf must carry
  `1.2.840.113635.100.6.11.1` and the intermediate `1.2.840.113635.100.6.2.1`
  with `CA:TRUE`; the receipt signer must carry `1.2.840.113635.100.6.11.1`.
  Without the receipt check, any Apple developer's own distribution
  certificate — which chains through the same WWDR intermediate to the same
  root — could sign a fully forged receipt.
- **Validity at signing time.** Apple's signing certificates rotate and
  expire; a receipt is valid if its chain was valid when Apple signed it. Every
  chain function takes that instant as a required parameter with no default.
- **All three published Apple roots are pinned**, in both sets. Apple
  documents the JWS chain as ending in "an Apple root certificate" without
  naming one, so anchoring on a single root would break silently if Apple ever
  re-anchored a path.
- **Reject rather than repair.** A parser that cannot represent an input fails
  it; it never substitutes a sentinel. An attribute type outside
  `[0, 2^31-1]`, a rolled-over date, a negative integer, trailing bytes after
  the CMS blob: all rejected.
- **Only `VerificationException` escapes** a public entry point. Containment is
  categorical, not a list of expected types.

You can pass your own anchors instead of the bundled ones — that is what the
constructor argument is for — at your own risk.

## Defensive bounds

Everything this library parses is attacker-controlled, and PHP has no
zero-copy slice: every `substr()` allocates and every ASN.1 node is a real
object. Measured on PHP 8.4, a megabyte of minimal two-byte DER nodes costs
about 72 MB of parser state, against a `php.ini-production` default
`memory_limit` of 128M. So:

| Bound | Default | Why |
|---|---|---|
| ASN.1 nesting depth | 32 | PHP gained `zend.max_allowed_stack_size` in 8.3; on 8.1 an unbounded recursive parser segfaults rather than raising |
| ASN.1 nodes per parse | 20,000 | the largest genuine fixture — a 79 KB receipt with 187 in-app purchases — decodes to under 3,000 |
| ASN.1 retained bytes per parse | 32 MiB | that same fixture retains 967 KB; see below for why bounding node count is not enough |
| Receipt size | 2 MiB | Apple receipts are tens of KB |
| JWS size | 256 KiB | every JWS in the corpus, Apple's own mock notification data included, is under 2.5 KB |
| `verifyReceiptJson` request body | 1 MiB | the largest genuine receipt is 106 KB of base64, and `json_decode` expands a breadth bomb ~48× |
| Embedded certificates | 10 | enforced *before* any certificate is decoded, because decoding and RSA-checking candidate issuers is the expensive half |
| Chain path length | 6 | well past any Apple chain |

The receipt size and node bounds are constructor arguments if your corpus is
unusual. The rest are not: they are security properties.

**Why a node budget is not enough on its own.** Depth and node count bound
different axes, and the cost is their *product*: a value nested N levels deep is
copied N times on the way down, so retained parser state is roughly
`2 × depth × input`. Deep-but-large nesting is cheap on both bounded axes — 600
sibling chains of 31 `SEQUENCE`s around 3 KB each is 19,201 nodes at depth 31 in
1.9 MB of input, inside the node budget, the depth ceiling and the receipt cap
alike — and cost 92 MB of parser state. The retained-byte budget bounds that
product; it brings the same input down to 28 MB.

**These are correctness bounds, not tuning knobs.** Running out of memory in PHP
raises a *fatal error*, and a fatal error is not a `Throwable`: no `catch` in
this library can turn one into a verdict, so the worker dies with no answer at
all. Every promise made about which errors escape — `verifyReceiptCore` raising
only `VerificationException`, `VerifyReceiptEndpoint` never throwing — holds
only because the input is bounded before it is allocated.

## Known platform caveats

- **64-bit only.** Apple ships epoch-millisecond timestamps (~1.7×10¹²), which
  a 32-bit `int` cannot hold — `json_decode` would return floats and every date
  comparison would silently drift. The constructors refuse a 32-bit build with
  a `\RuntimeException` rather than drifting.
- **SHA-1 and distribution crypto policy.** Genuine legacy receipts are signed
  SHA-1/RSA. A PHP built against a policy-restricted OpenSSL — RHEL 9's
  SHA-1-disabled crypto policy, or a FIPS build — may refuse that signature and
  report `INVALID_SIGNATURE` on a perfectly genuine receipt. This is OpenSSL's
  behaviour, not the library's, and PHP shares the exposure with the Python and
  Ruby ports. It has **not** been reproduced on such a container; if you deploy
  on one, verify a legacy receipt before you rely on it.
- **`ext-openssl` is not literally universal.** It is bundled everywhere in
  practice, but a hardened build without it exists. The `"ext-openssl": "*"`
  requirement turns that into a Composer error rather than a runtime fatal.

## Development

```bash
composer install
vendor/bin/phpunit                      # everything
vendor/bin/phpunit --testsuite conformance   # the shared cross-language vectors
vendor/bin/phpunit --group mutation          # the mutation pass
vendor/bin/phpstan analyse
```

`php/certs/` is a checked copy of the repository-root `certs/`, and
`src/Internal/RootsData.php` is generated from that copy by
`php/tools/gen-roots.php`. CI diffs both. Regenerate with:

```bash
php php/tools/gen-roots.php
```

No `composer.lock` is committed. A library spanning PHP 8.1–8.5 cannot express
its dev toolchain in one lock — a lock resolved on 8.1 pins PHPUnit 10.5 for
every leg, and one resolved on 8.5 will not install on 8.1 at all. The
`--prefer-lowest` CI leg is the substitute for the reproducibility a lock would
give. This is a deliberate divergence from the Node port's committed-lockfile
posture.

## Licence

MIT — see [LICENSE](../LICENSE).
