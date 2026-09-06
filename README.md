# apple-purchase-receipt-verifier

[![ci](https://github.com/emindeniz99/apple-purchase-receipt-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/emindeniz99/apple-purchase-receipt-verifier/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/apple-purchase-receipt-verifier?logo=npm)](https://www.npmjs.com/package/apple-purchase-receipt-verifier)
[![PyPI](https://img.shields.io/pypi/v/apple-purchase-receipt-verifier?logo=python&logoColor=white)](https://pypi.org/project/apple-purchase-receipt-verifier/)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.emindeniz99/apple-purchase-receipt-verifier?logo=apachemaven)](https://central.sonatype.com/artifact/io.github.emindeniz99/apple-purchase-receipt-verifier)
[![SwiftPM](https://img.shields.io/github/v/tag/emindeniz99/apple-purchase-receipt-verifier?label=SwiftPM&logo=swift)](https://swiftpackageindex.com/emindeniz99/apple-purchase-receipt-verifier)
[![Swift versions](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Femindeniz99%2Fapple-purchase-receipt-verifier%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/emindeniz99/apple-purchase-receipt-verifier)
[![Platforms](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Femindeniz99%2Fapple-purchase-receipt-verifier%2Fbadge%3Ftype%3Dplatforms)](https://swiftpackageindex.com/emindeniz99/apple-purchase-receipt-verifier)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

## What it does

Verifies Apple in-app purchases **locally, with zero Apple server calls** —
a replacement for the deprecated `verifyReceipt` endpoint. Cryptographically
proves that purchase data a client presents (StoreKit 2 signed JWS
transactions, or legacy PKCS#7 app receipts) was signed by Apple, by
validating the certificate chain against pinned Apple root CAs. Nine
implementations, one normative algorithm, one shared fixture set they all
verify byte-for-byte: **Java** (8+), **Node** (20+, zero runtime deps),
**Python** (3.9+), **Swift** (6.1+), **Go** (1.22+), **Ruby** (3.1+),
**Rust** (1.74+), **PHP** (8.1+) and **.NET** (netstandard2.0 and net8.0).
[SUPPORT-MATRIX.md](SUPPORT-MATRIX.md) lists every line CI runs and the rule
that adds or drops one.

Each implementation also ships **`VerifyReceiptEndpoint`** — a drop-in
local replacement for the deprecated `verifyReceipt` endpoint speaking
Apple's exact request/response/status-code wire contract (incl. local
21007/21008 sandbox routing). Hand it a parsed request body, or hand it the
raw JSON body as a string and get the JSON response body back, so an HTTP
handler can pipe the bytes through untouched. See
[COMPARISON.md](./COMPARISON.md) for the field-by-field fidelity account and
the gaps only Apple's servers can fill.

Start with [INTENT.md](./INTENT.md) (why + trust model), then
[PLAN.md](./PLAN.md) (algorithms + decisions + API shape), then
[ROADMAP.md](./ROADMAP.md) (what's next).
[THREAT-MODEL.md](./THREAT-MODEL.md) is the security account: what is
attacker-controlled, each mitigation with the test that proves it, the
non-goals, and the residual risks.

## Upstream

The legacy-receipt half of this design was proposed to Apple's official
app-store-server-library in all four languages — an `AppReceiptVerifier`
alongside each library's `ReceiptUtility`, reusing their existing chain
verification:
[java#268](https://github.com/apple/app-store-server-library-java/pull/268),
[swift#133](https://github.com/apple/app-store-server-library-swift/pull/133),
[python#208](https://github.com/apple/app-store-server-library-python/pull/208),
[node#427](https://github.com/apple/app-store-server-library-node/pull/427).
Apple closed all four: the receipt format is deprecated and they are not
adding this level of verification to their libraries
([maintainer's comment](https://github.com/apple/app-store-server-library-java/issues/267#issuecomment-5433242622)).
So there is no official implementation to wait for. This repository is
where signature verification of legacy receipts lives — in the four
languages of Apple's libraries, and in five more — against the same root
certificates:
the chain check to Apple's pinned roots, the `verifyReceipt`-compatible
endpoint, the Java 8 floor and the zero-dependency Node build.

## Installing

Four of the nine implementations are published today, all as
**`apple-purchase-receipt-verifier`**, in lockstep versions cut from this
repository's tags.

| Registry | Install | How you import it |
|---|---|---|
| [Maven Central](https://central.sonatype.com/artifact/io.github.emindeniz99/apple-purchase-receipt-verifier) | `io.github.emindeniz99:apple-purchase-receipt-verifier` | `import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;` |
| [npm](https://www.npmjs.com/package/apple-purchase-receipt-verifier) | `npm install apple-purchase-receipt-verifier` | `import { JwsVerifier } from 'apple-purchase-receipt-verifier';` |
| [PyPI](https://pypi.org/project/apple-purchase-receipt-verifier/) | `pip install apple-purchase-receipt-verifier` | `from apple_purchase_receipt_verifier import JwsVerifier` |
| [SwiftPM](https://swiftpackageindex.com/emindeniz99/apple-purchase-receipt-verifier) | `.package(url: "https://github.com/emindeniz99/apple-purchase-receipt-verifier.git", from: "0.2.1")` | `import ApplePurchaseReceiptVerifier` |

The import namespace is the registry name in each ecosystem's casing
convention (`applepurchasereceiptverifier` / `apple_purchase_receipt_verifier` /
`ApplePurchaseReceiptVerifier`) — one name everywhere.

**The five newer ports are not installable from a registry yet.** Go, Ruby,
Rust and .NET are wired into `release.yml` and are waiting on one owner action
each: a pending trusted publisher for RubyGems, a first manual publish for
crates.io and NuGet, a public repository for the Go module proxy. Those
actions, per registry and in order, are in [BOOTSTRAP.md](./BOOTSTRAP.md); the
rows above gain entries once the first release goes out.

PHP is the fifth, and its install path is:

```bash
composer require emindeniz99/apple-purchase-receipt-verifier
```

```php
use EminDeniz99\ApplePurchaseReceiptVerifier\Jws\JwsVerifier;
```

Packagist reads `composer.json` from a repository root and nowhere else, so
that manifest is now the repository root's, autoloading
`EminDeniz99\ApplePurchaseReceiptVerifier\` from `php/src/` while the port
itself stays in `php/`. `php/composer.json` remains the development manifest.
Packagist needs no publish job and no token: once the owner submits the
repository, it imports tags on its own. That submission is the one remaining
action, and it is in [BOOTSTRAP.md](./BOOTSTRAP.md); the command above starts
working at the first tag after it.

**JavaScript runtimes.** The npm package has two entry points.
`apple-purchase-receipt-verifier` is the default and is unchanged:
synchronous, needing `node:crypto`'s `X509Certificate` and nothing else. It
runs on Node 20+, Bun, Deno and Cloudflare Workers; on Workers set
`nodejs_compat` with a compatibility date of **2024-09-23 or later**, or
`nodejs_compat_v2` explicitly on an older date — that flag supplies the
global `Buffer` the DER handling uses, and CI runs both spellings.

`apple-purchase-receipt-verifier/web` is the same verification on
`crypto.subtle` alone: same class names, same options, same
`VerificationError` reasons, with every method returning a Promise. It
imports no `node:` module and touches no `Buffer`, so it also runs where
only WebCrypto exists: the Vercel Edge runtime, Next.js edge middleware,
Cloudflare Workers with no compatibility flags and Fastly Compute, each of
them exercised on every push. Akamai EdgeWorkers implements the same
WebCrypto API and is expected to work too, but is untested: there is no
local runtime for it that CI can run. Neither entry point reads a file, so
`appleReceiptRoots()` and `appleJwsRoots()` work inside a bundle either way.

CI proves the default build on Node, Bun, Deno and workerd (`cd node && npm
run test:runtimes`) and the web build on Node, the Vercel Edge runtime and
flagless workerd (`npm run test:runtimes:web`). The Node suite runs every
shared fixture through both builds and fails on any difference of verdict;
[node/README.md](node/README.md#webcrypto-only-runtimes) has the per-runtime
table and the three places the web API is not just `await`.

## Integrating: from verified payload to entitlement

Verification proves Apple signed the bytes. It does not prove the presenter
owns them, and it says nothing about what happened after the signature. The
flow below is the shape this library is meant to sit inside; each port's
README carries the same steps written in its own API.

There are two branches because clients send two things, and both are
first-class here. StoreKit 2 apps send a signed JWS transaction. StoreKit 1
apps and older SDKs still send the base64 PKCS#7 app receipt, the blob that
used to be POSTed to Apple's now-deprecated `verifyReceipt` endpoint, and
`VerifyReceiptEndpoint` is the drop-in replacement for that call: the same
request body, the same response body, the same status codes, answered offline
against pinned roots.

### Branch A: StoreKit 2 signed transaction

```text
1. RECEIVE
   POST /purchases { jws }          the client's jwsRepresentation

2. VERIFY, OFFLINE
   verifier = JwsVerifier(
       trustedRoots         = appleJwsRoots(),
       bundleId             = "com.example.app",
       acceptedEnvironments = { Production, Sandbox },   // App Review runs
                                                         // production builds
                                                         // against Sandbox
       maxSignedAge         = FRESHNESS_WINDOW)          // 5 minutes
   payload = verifier.verifyTransaction(jws)
   on failure:
       log(reason)                  // the reason table below says what next
       deny                         // nothing partial is returned

3. REVOKED?
   if payload.revocationDate is set:
       deny                         // refunded or revoked as of signing time

4. FRESH, OR ASK APPLE
   // a payload inside FRESHNESS_WINDOW reached step 3, so it is a live
   // snapshot and can be granted with no network call at all
   on STALE_PAYLOAD from step 2:
       // step 2 returned no payload, so the id for this call comes from the
       // client's own request, never from the payload that failed to verify
       signed  = appStoreServerApi.getTransactionInfo(request.transactionId)
       payload = verifier.verifyTransaction(signed)   // same verifier
       back to step 3 with the re-signed payload

5. REPLAY GUARD
   if store.grantExists(payload.transactionId):
       deny                         // this purchase already unlocked something
   store.recordGrant(payload.transactionId,
                     payload.originalTransactionId,   // subscriptions
                     userId)

6. GRANT
   grant(userId, payload.productId)
```

### Branch B: legacy PKCS#7 app receipt

```text
1. RECEIVE
   POST /purchases { receiptData }  the base64 app receipt

2. VERIFY, OFFLINE
   verifier = ReceiptVerifier(
       trustedRoots = appleReceiptRoots(),
       bundleId     = "com.example.app")
   receipt = verifier.verify(receiptData)
   on failure:
       log(reason)
       deny
   // Or hand the request body straight to VerifyReceiptEndpoint and read
   // `status`: 0, 21002, 21003, 21007, 21008, 21009. Like Apple's endpoint
   // it does not check the bundle id, so compare receipt.bundle_id yourself.

3. REFUNDED OR EXPIRED?
   purchase = receipt.inAppPurchases matching the product you are unlocking
   if purchase.cancellationDate is set:
       deny                         // refunded or cancelled as of signing time
   if purchase.expiresDate is set and in the past:
       deny                         // the subscription term had already ended

4. FRESH, OR REFRESH
   // a receipt is a snapshot of the same kind: Apple re-signs it whenever the
   // app refreshes it, and a refunded purchase carries cancellationDate
   if now - receipt.creationDate > FRESHNESS_WINDOW:
       ask the client to refresh its receipt and re-send, or
       signed  = appStoreServerApi.getTransactionInfo(purchase.transactionId)
       payload = jwsVerifier.verifyTransaction(signed)
       decide from the re-signed payload instead
   // ReceiptVerifier has no maxSignedAge option: on this path the window is
   // yours to compare against the receipt's own creation date

5. REPLAY GUARD
   if store.grantExists(purchase.transactionId):
       deny
   store.recordGrant(purchase.transactionId,
                     purchase.originalTransactionId,
                     userId)

6. GRANT
   grant(userId, purchase.productId)
```

### Both branches

**Refunds and cancellations after step 6** arrive as App Store Server
Notifications V2, which are Apple-signed JWS this library verifies on either
branch:

```text
POST /apple/notifications { signedPayload }
    claims = jwsVerifier.verifyRaw(signedPayload)   // enforces no claim:
                                                    // check bundleId yourself
    on REFUND or REVOKE: revoke(userId, transactionId)
```

**Why a fresh payload needs no network call.** Apple re-signs a transaction
every time the app fetches it, and a refunded transaction carries
`revocationDate` (JWS) or `cancellation_date` (receipt) from then on. So a
payload signed seconds ago, with neither field set, is Apple's current answer
about that purchase, and step 3 is the whole check. Five minutes is a
reasonable default for the window. On the JWS path `maxSignedAge` enforces it
and an older payload fails step 2 as `STALE_PAYLOAD`; on the receipt path
there is no such option, so compare the receipt's creation date yourself.

**Step 4 is the only place either branch talks to Apple, and it is optional.**
Get Transaction Info by `transactionId`, or the subscription status endpoint,
answers with a freshly signed JWS, which goes through the same verifier before
anything is decided from it. A client that can re-fetch a current
`jwsRepresentation`, or refresh its app receipt, removes the step entirely:
answer a stale payload by asking for a fresh one.

**Dedupe on the transaction id, not on the bytes.** A legacy receipt is BER,
so one correctly signed receipt has several byte spellings; the id is the
identifier (PLAN.md D4). For a subscription keep `originalTransactionId`
beside it, since that is what ties renewals to one purchase.

### What to do per reason

Three classes, and the class is what decides whether a rejection is worth an
alert. Every reason denies the payload in front of you; only `STALE_PAYLOAD`
says the next attempt could succeed.

| Reason | Class | Response |
|---|---|---|
| `INVALID_JWS_FORMAT` | client bug | Deny. The client sent something that is not a compact JWS, or truncated one. |
| `INVALID_RECEIPT_FORMAT` | client bug | Deny. Malformed, truncated, not base64, or over the size bound. `21002` at the endpoint. |
| `INVALID_CERTIFICATE` | client bug | Deny. An `x5c` entry or a receipt signer is not a parseable certificate, which mangled transport also produces. |
| `DEVICE_HASH_MISMATCH` | client bug | Deny. The receipt is bound to a different device than the GUID supplied, or the GUID was passed as hex rather than raw bytes. |
| `WRONG_ENVIRONMENT` | client bug | Deny, and check the accept set: an endpoint App Review can reach must include Sandbox. At the endpoint this is `21007` / `21008` instead. |
| `INVALID_CHAIN` | possible fraud | Deny and alert. The path does not reach a pinned Apple root, or was not valid when the payload was signed. `21003` at the endpoint. |
| `INVALID_SIGNATURE` | possible fraud | Deny and alert. The bytes were altered after Apple signed them. |
| `INVALID_CERTIFICATE_PURPOSE` | possible fraud | Deny and alert. A certificate chaining to an Apple root without the marker OID its position requires: a developer's own certificate signing a forged payload looks exactly like this. |
| `WRONG_BUNDLE_ID` | possible fraud | Deny and alert. A genuine Apple-signed payload for another app. |
| `WRONG_APP_APPLE_ID` | possible fraud | Deny and alert. A Production `AppTransaction` naming a different app Apple id. |
| `STALE_PAYLOAD` | retry later | Not a rejection of the purchase. Take step 4: ask the client for a fresh payload, or fetch one from the App Store Server API. |

The vocabulary is closed and identical in all nine ports, so this table is one
policy across every backend language. What signatures still cannot tell you,
and why replay and refund bookkeeping are the caller's job, is in
[INTENT.md](./INTENT.md) and [THREAT-MODEL.md](./THREAT-MODEL.md) section 4.

## How to run the test suites

```bash
# Java (library targets Java 8; build with any modern JDK + Maven)
cd java && mvn test

# Node (strict TypeScript, zero runtime deps; Node >= 20)
cd node && npm install && npm test    # both entry points, every shared fixture
cd node && npm run test:runtimes       # default build on Bun, Deno and Cloudflare workerd
cd node && npm run test:runtimes:web   # /web build on Vercel Edge and flagless workerd

# Python (>= 3.9; uv installs the locked dependencies)
cd python && uv sync && uv run python -m unittest discover -s tests

# Swift (Swift 6.1+; Linux or macOS 13+; manifest lives at the repo root)
swift test

# Go (>= 1.22; no dependencies)
cd go && go test ./...

# Ruby (>= 3.1; no runtime dependencies, minitest through rake)
cd ruby && rake test

# Rust (>= 1.74)
cd rust && cargo test

# PHP (>= 8.1; installs php/composer.lock)
cd php && composer install && vendor/bin/phpunit

# .NET (SDK 8.0+; runs the net8.0 suite and the netstandard2.0 floor suite)
cd dotnet && dotnet test -c Release
```

All nine suites verify the same three shared fixture tiers:

1. `fixtures/generated/` — deterministic cross-language fixtures (fake
   Apple PKI) written by the Java `FixtureGeneratorTest`; regenerate only
   deliberately, then re-run **every** suite.
2. `fixtures/apple-official/` — Apple's own library test fixtures
   (vendored, MIT): their test-CA-signed JWS mocks verify, their negative
   cases fail with our exact reason codes, and their genuine Xcode
   receipts/payloads are **rejected** against the real pinned Apple roots
   (anchor-pinning proof).
3. `fixtures/public-receipts/` — **genuine Apple-signed**
   sandbox and legacy receipts (vendored, MIT) that must verify against
   the real pinned Apple root, plus an Xcode receipt that must be rejected
   — the strongest tier (real Apple bytes).

The vectors those suites run the fixtures under live in
[`fixtures/cases.json`](./fixtures/cases.json): one language-neutral case per
semantic fact, giving the fixture bytes, the verifier config, and either the
payload fields the call must return or the canonical reason it must raise.
Each language reads it through a thin adapter, so the file is the contract and
a behavior change means editing it. `node tools/lint-cases.mjs` validates it
against `fixtures/cases.schema.json` and re-hashes every registered fixture;
CI runs the same check. See [CONTRIBUTING.md](./CONTRIBUTING.md) for how to
add a case.

Five ports additionally generate a throwaway "Apple" PKI per run for inputs
the shared fixtures cannot express: `java/.../TestPki.java`,
`go/testpki_test.go`, `ruby/test/test_pki.rb`, `php/tests/Support/TestPki.php`
and `dotnet/tests/.../TestPki.cs`. Those are native suites, not a shared tier.

Every port also has coverage-guided fuzz targets, run for a fixed budget by
its own CI job (`go-fuzz`, `rust-fuzz`, `node-fuzz`, `ruby-fuzz`, `php-fuzz`,
`dotnet-fuzz`, `python-fuzz`, `swift-fuzz`, `java-fuzz`) and seeded from
`fixtures/`, so a crasher is a mutation of a genuine receipt or JWS. The
targets share three invariants: nothing panics or traps, every failure is the
port's typed verification error, and an input one anchor set accepts must be
refused by an unrelated one — the last is what lets a fuzzer find a wrong
acceptance, not only a crash. Each `<port>/fuzz/README.md` lists its targets;
[THREAT-MODEL.md](./THREAT-MODEL.md) says what they are for and PLAN.md D16
why the parsers they cover are hand-written.

Production trust anchors are all three published Apple root certificates in
[`certs/`](./certs) (from [Apple PKI](https://www.apple.com/certificateauthority/)):
`AppleIncRootCertificate.cer`, `AppleRootCA-G2.cer` and `AppleRootCA-G3.cer`.
Today's chains end at Apple Inc. Root (legacy PKCS#7 receipts) and Apple Root
CA - G3 (JWS signed data), but Apple's own guidance is to trust every root on
its PKI page rather than a specific one — see PLAN.md D15 for the sourced
rationale. Each language bundles its own copy as packaged resources;
verifiers also accept caller-supplied anchors.

## Notes / learnings

- **Both paths are first-class**: StoreKit 2 JWS requires iOS 15+ *and* a
  migrated app — iOS ≤14 devices and unmigrated StoreKit 1 apps still send
  PKCS#7 receipts. Chain validity is checked at *signing time* (JWS
  `signedDate` / receipt creation date), not "now", so old payloads survive
  Apple's certificate rotations.
- **Prior art** (survey in PLAN.md §1, re-verified 2026-08): Apple's
  official libraries verify JWS but only *extract* from legacy receipts
  without validation; the sole server-side legacy validator we found
  (Python `iap-local-receipt`) has been abandoned since ~2016. No
  maintained library does both paths server-side in any of our languages.
- **Signature validity ≠ entitlement**: replay protection (transaction-id
  bookkeeping) and refund/status tracking are deliberately out of scope —
  see INTENT.md. `isActiveAt`/`isActive` helpers + the optional
  max-signed-age policy cover subscription expiry from the signed claims.
