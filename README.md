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

Verifies Apple in-app purchases **locally, with zero Apple server calls**, as
a replacement for the deprecated `verifyReceipt` endpoint. It proves
cryptographically that purchase data a client presents (StoreKit 2 signed JWS
transactions, or legacy PKCS#7 app receipts) was signed by Apple, by
validating the certificate chain against pinned Apple root CAs. Nine
implementations, one normative algorithm, one shared fixture set on which
they agree on every verdict and every decoded value: **Java** (8+), **Node**
(20+, zero runtime deps), **Python** (3.10+), **Swift** (6.1+), **Go**
(1.22+), **Ruby** (3.3+), **Rust** (1.85+), **PHP** (8.2+) and **.NET**
(netstandard2.0 and net8.0), plus **C and C++ via a C ABI over the Rust
port**, which any FFI-capable runtime (Elixir NIFs, Lua, ctypes, P/Invoke)
can load. [SUPPORT-MATRIX.md](SUPPORT-MATRIX.md) lists every line CI runs and
the rule that adds or drops one. [PORTS.md](PORTS.md) shows which features
each port ships.

Every implementation exposes the same three methods on one `Verifier`, built
once from a `Config` (the pinned roots and a clock):

- **`verifyReceipt(base64)`** checks a legacy PKCS#7 app receipt and returns
  its decoded payload.
- **`verifySignedData(jws)`** checks any Apple-signed StoreKit 2 JWS
  (transaction, renewal info, app transaction, server notification) and
  returns the payload JSON exactly as Apple signed it.
- **`verifyReceiptEndpoint(environment, requestJson)`** is a drop-in local
  replacement for the deprecated `verifyReceipt` endpoint: it takes the raw
  request body and returns the response body Apple would send, with Apple's
  status codes and local 21007/21008 sandbox routing, so an HTTP handler
  can pipe the bytes through untouched.

The first two return a `VerificationResult`: the payload when Apple signed
the input, otherwise a failure carrying one of eight reasons. None of them
throws for any input, and none takes a bundle id, environment or product id:
those checks are yours ([Using the result](#using-the-result)). Method names
follow each language's casing. [COMPARISON.md](./COMPARISON.md) has the
field-by-field fidelity account and the gaps only Apple's servers can fill.

## Quick start

Java: build the verifier once, verify a legacy app receipt or a StoreKit 2
JWS, then check the bundle id yourself.

```java
Verifier verifier = Verifier.create(Config.defaults());   // once, at startup; share it

// A legacy PKCS#7 app receipt, as the base64 string the app sends.
VerificationResult<ReceiptPayload> receiptResult = verifier.verifyReceipt(receiptBase64);
if (!receiptResult.verified()) {
    deny(receiptResult.failure().reason());               // see "What to do per reason"
    return;
}
ReceiptPayload receipt = receiptResult.payload();
if (!"com.example.app".equals(receipt.bundleId())) deny("OTHER_APP");
// receipt.inApp() lists every purchase; pick yours by product id and expiry

// A StoreKit 2 signed transaction, renewal info, app transaction or notification.
VerificationResult<JsonPayload> result = verifier.verifySignedData(jws);
if (!result.verified()) {
    switch (result.failure().reason()) {
        case INTERNAL_ERROR: case UNREADABLE_PAYLOAD: page(result.failure()); break; // do not retry
        default: deny(result.failure().reason());
    }
    return;
}
JWSTransactionDecodedPayload tx =   // Apple's model class (Java 11+) via Jackson, or your own
        mapper.readValue(result.payload().json(), JWSTransactionDecodedPayload.class);
if (!"com.example.app".equals(tx.getBundleId())) deny("OTHER_APP");
```

Node, the same steps:

```js
import { createConfig, createVerifier } from 'apple-purchase-receipt-verifier';

const verifier = createVerifier(createConfig()); // build once, share everywhere

// A legacy app receipt, as the base64 string the app sends.
const receiptResult = verifier.verifyReceipt(receiptBase64);
if (!receiptResult.verified) {
  return denied(receiptResult.failure.reason); // see "What to do per reason"
}
if (receiptResult.payload.bundleId !== 'com.example.app') {
  return denied('OTHER_APP');
}
// receiptResult.payload.inApp lists every purchase

// A StoreKit 2 signed transaction, renewal info, app transaction or notification.
const result = verifier.verifySignedData(jws);
if (!result.verified) {
  return denied(result.failure.reason);
}
const transaction = JSON.parse(result.payload.json);
if (transaction.bundleId !== 'com.example.app') {
  return denied('OTHER_APP');
}
```

The other seven ports have the same three methods, in their own casing:
[Python](python/README.md), [Swift](swift/README.md), [Go](go/README.md),
[Ruby](ruby/README.md), [Rust](rust/README.md), [PHP](php/README.md) and
[.NET](dotnet/README.md). The [Java](java/README.md) and [Node](node/README.md)
READMEs document the full API.

## Installing

Five of the nine implementations are published today, all as
**`apple-purchase-receipt-verifier`**, in lockstep versions cut from this
repository's tags.

The version is `0.x`. Until 1.0, a minor release may break the API: 0.7
replaces the 0.6 classes with a new `Verifier` without a deprecation
period. Read the [CHANGELOG](./CHANGELOG.md) before you bump the minor
version, and pin it.

| Registry | Install | How you import it |
|---|---|---|
| [Maven Central](https://central.sonatype.com/artifact/io.github.emindeniz99/apple-purchase-receipt-verifier) | `io.github.emindeniz99:apple-purchase-receipt-verifier` | `import io.github.emindeniz99.applepurchasereceiptverifier.Verifier;` |
| [npm](https://www.npmjs.com/package/apple-purchase-receipt-verifier) | `npm install apple-purchase-receipt-verifier` | `import { createConfig, createVerifier } from 'apple-purchase-receipt-verifier';` |
| [PyPI](https://pypi.org/project/apple-purchase-receipt-verifier/) | `pip install apple-purchase-receipt-verifier` | `from apple_purchase_receipt_verifier import Config, Verifier` |
| [SwiftPM](https://swiftpackageindex.com/emindeniz99/apple-purchase-receipt-verifier) | `.package(url: "https://github.com/emindeniz99/apple-purchase-receipt-verifier.git", from: "0.7.0")` | `import ApplePurchaseReceiptVerifier` |
| [Go module proxy](https://pkg.go.dev/github.com/emindeniz99/apple-purchase-receipt-verifier/go) | `go get github.com/emindeniz99/apple-purchase-receipt-verifier/go` | `import applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"` |

The import namespace is the registry name in each ecosystem's casing
convention (`applepurchasereceiptverifier` / `apple_purchase_receipt_verifier` /
`ApplePurchaseReceiptVerifier`), one name everywhere.

Ruby, Rust, .NET and PHP are not in the table yet. Ruby, Rust and .NET are
wired into `release.yml` and wait on one owner action each (a
pending trusted publisher for RubyGems, a first manual publish for crates.io
and NuGet), listed in [BOOTSTRAP.md](./BOOTSTRAP.md); each gains a row once
its first release goes out. PHP will install from Packagist with
`composer require emindeniz99/apple-purchase-receipt-verifier` and
`use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;`, starting at the
first tag after the owner submits the repository to Packagist
([BOOTSTRAP.md](./BOOTSTRAP.md#packagist-php--layout-a-is-landed-two-owner-actions-remain)
explains the root `composer.json`). C and C++ have no registry entry and are
not meant to: they build from source against the Rust port, and
[rust/ffi/README.md](rust/ffi/README.md) covers the ABI, the example
consumers and the prebuilt binaries still to come.

## JavaScript runtimes

The npm package has two entry points. The default,
`apple-purchase-receipt-verifier`, is synchronous and runs on Node 20+, Bun,
Deno and Cloudflare Workers (with `nodejs_compat` and a compatibility date of
2024-09-23 or later, or `nodejs_compat_v2` on an older date).
`apple-purchase-receipt-verifier/web` does the same verification on
`crypto.subtle` alone, with every method returning a Promise, for runtimes
that only have WebCrypto: the Vercel Edge runtime, Next.js edge middleware,
Cloudflare Workers without flags and Fastly Compute. Akamai EdgeWorkers is
expected to work but untested. The runtime table, what CI proves on each and
how the two APIs differ are in
[node/README.md](node/README.md#webcrypto-only-runtimes).

## Using the result

The library proves Apple signed the bytes; what the purchase entitles is your
decision, made on the payload. In short:

1. **Verify offline** with one shared `Verifier`. On failure, deny and log
   the reason ([What to do per reason](#what-to-do-per-reason)).
2. **Check it is yours**: compare the bundle id (`com.example.app`) and the
   environment yourself. Accept Sandbox only where App Review reaches it, and
   record it with the grant.
3. **Revoked or expired**: deny when `revocationDate` is set or `expiresDate`
   is past. For a receipt, drop in-app entries with a cancellation date and
   judge a subscription by the entry with the latest expiry.
4. **Freshness is your call**: compare the payload's `signedDate` (or the
   receipt's creation date) with a window you choose, and re-fetch from the
   App Store Server API or the client when it is too old. This optional
   step is the only one that talks to Apple.
5. **Dedupe on the transaction id**, never on the bytes, and keep
   `originalTransactionId` for subscriptions.
6. **Refunds after the grant** arrive as App Store Server Notifications V2,
   which this library verifies like any other JWS.

[INTEGRATION.md](./INTEGRATION.md) has the full flow for both branches,
StoreKit 2 JWS and legacy receipt, including the notification handler.

### What to do per reason

Three classes, and the class is what decides whether a rejection is worth an
alert. Every reason except `UNREADABLE_PAYLOAD` and `INTERNAL_ERROR` denies
the payload in front of you. Those two are not a verdict on the client at
all.

| Reason | Class | Response |
|---|---|---|
| `MALFORMED` | client bug | Deny. Not base64, not a CMS envelope or a compact JWS, truncated, or past a structural bound (JSON nesting, embedded certificates, SignerInfos). Decided before any signature check. `21002` at the endpoint. |
| `TOO_LARGE` | client bug | Deny. Over a fixed size cap: 3,145,728 UTF-8 bytes for a receipt or an endpoint request body, 262,144 for a JWS. `21002` at the endpoint. |
| `INVALID_CERTIFICATE` | client bug | Deny. An `x5c` entry or a receipt signer is not a parseable certificate, which mangled transport also produces, or a certificate was outside its validity window at the signing date. `21003` at the endpoint. |
| `UNTRUSTED_CHAIN` | possible fraud | Deny and alert. The path does not reach a pinned Apple root. `21003` at the endpoint. |
| `INVALID_SIGNATURE` | possible fraud | Deny and alert. The bytes were altered after Apple signed them. `21003` at the endpoint. |
| `INVALID_CERTIFICATE_PURPOSE` | possible fraud | Deny and alert. A certificate chaining to an Apple root without the marker OID its position requires: a developer's own certificate signing a forged payload looks exactly like this. `21003` at the endpoint. |
| `UNREADABLE_PAYLOAD` | not the client's | The chain and signature verified, but the content Apple signed does not parse. Deterministic: the same bytes fail the same way, so do not retry the library. Log the cause with the library version, alert, and settle the purchase through the App Store Server API by transaction id; grant provisionally only if the business accepts that. `21009` at the endpoint. |
| `INTERNAL_ERROR` | not the client's | The library itself failed before it could decide: a runtime missing an algorithm, or a clock that throws. Alert, do not retry. `21009` at the endpoint. |

A payload for another app, another environment or another app Apple id
verifies: the library returns what Apple signed and leaves those checks to
you (step 2 of each branch in [INTEGRATION.md](./INTEGRATION.md)).

The vocabulary is closed and identical in all nine ports, so this table is one
policy across every backend language. What signatures still cannot tell you,
and why replay and refund bookkeeping are the caller's job, is in
[INTENT.md](./INTENT.md) and [THREAT-MODEL.md](./THREAT-MODEL.md) section 4.

## Upstream

The legacy-receipt half of this design was proposed to Apple's official
app-store-server-library in all four languages, as an `AppReceiptVerifier`
alongside each library's `ReceiptUtility` that reuses their existing chain
verification:
[java#268](https://github.com/apple/app-store-server-library-java/pull/268),
[swift#133](https://github.com/apple/app-store-server-library-swift/pull/133),
[python#208](https://github.com/apple/app-store-server-library-python/pull/208),
[node#427](https://github.com/apple/app-store-server-library-node/pull/427).
Apple closed all four: the receipt format is deprecated and they are not
adding this level of verification to their libraries
([maintainer's comment](https://github.com/apple/app-store-server-library-java/issues/267#issuecomment-5433242622)).
So there is no official implementation to wait for. This repository is
where signature verification of legacy receipts lives, in the four languages
of Apple's libraries and in five more, against the same root certificates:
the chain check to Apple's pinned roots, the `verifyReceipt`-compatible
endpoint, the Java 8 floor and the zero-dependency Node build.

## Documentation map

Start with INTENT, then PLAN, then ROADMAP.

- [INTENT.md](./INTENT.md): why the library exists, and its trust model.
- [PLAN.md](./PLAN.md): algorithms, numbered decisions, API shape, prior-art survey (section 1).
- [ROADMAP.md](./ROADMAP.md): what is next.
- [THREAT-MODEL.md](./THREAT-MODEL.md): attacker-controlled inputs, each mitigation with its test, non-goals, residual risks.
- [RECEIPT-FIELDS.md](./RECEIPT-FIELDS.md): every receipt attribute the genuine fixtures carry, which ones Apple documents, and Apple's chain-of-trust steps mapped onto the code.
- [COMPARISON.md](./COMPARISON.md): field-by-field fidelity, and the gaps only Apple's servers can fill.
- [SUPPORT-MATRIX.md](./SUPPORT-MATRIX.md): every runtime line CI runs, and the rule that adds or drops one.
- [PORTS.md](./PORTS.md): which features each port ships.
- [BENCHMARKS.md](./BENCHMARKS.md): cross-port benchmarks, same operations on the same fixtures.
- [INTEGRATION.md](./INTEGRATION.md): the full flow from verified payload to entitlement.
- [CONTRIBUTING.md](./CONTRIBUTING.md): test suites, fixture tiers, conformance vectors, fuzzing, commits, releases.
- [SECURITY.md](./SECURITY.md): reporting a vulnerability, supported versions, dependency policy.
- [BOOTSTRAP.md](./BOOTSTRAP.md): the one-time owner action each registry needs before CI can publish to it.

## Trust anchors

Production trust anchors are all three published Apple root certificates in
[`certs/`](./certs) (from [Apple PKI](https://www.apple.com/certificateauthority/)):
`AppleIncRootCertificate.cer`, `AppleRootCA-G2.cer` and `AppleRootCA-G3.cer`.
Today's chains end at Apple Inc. Root (legacy PKCS#7 receipts) and Apple Root
CA - G3 (JWS signed data), but Apple's own guidance is to trust every root on
its PKI page rather than a specific one; PLAN.md D15 has the sourced
rationale. Each language bundles its own copy as packaged resources or
compiled-in constants; a `Config` also accepts caller-supplied roots.

## Debugging a receipt by hand

`openssl` opens a receipt without verifying it, which helps when a
verification fails and you want to see what arrived:

```bash
base64 -d receipt.b64 > receipt.der
openssl cms -cmsout -print -inform DER -in receipt.der          # envelope, signer, certificates
openssl asn1parse -inform DER -in receipt.der                   # the raw ASN.1 tree
openssl pkcs7 -inform DER -in receipt.der -print_certs -noout   # the certificate chain only
```

For a StoreKit 2 JWS, `cut -d. -f2 | base64 -d` prints the payload (add
`=` padding if your `base64` complains). Keep production receipts and
tokens off websites that decode them for you: they carry transaction ids
and your bundle id.

## Notes / learnings

- **Both paths are first-class**: StoreKit 2 JWS requires iOS 15+ *and* a
  migrated app, so iOS ≤14 devices and unmigrated StoreKit 1 apps still send
  PKCS#7 receipts. Chain validity is checked at *signing time* (JWS
  `signedDate` / receipt creation date), not "now", so old payloads survive
  Apple's certificate rotations.
- **Prior art** (survey in PLAN.md §1, re-verified 2026-08): Apple's
  official libraries verify JWS but only *extract* from legacy receipts
  without validation; the sole server-side legacy validator we found
  (Python `iap-local-receipt`) has been abandoned since ~2016. No
  maintained library does both paths server-side in any of our languages.
- **Signature validity ≠ entitlement**: replay protection (transaction-id
  bookkeeping) and refund/status tracking are deliberately out of scope
  (see INTENT.md). Whether a payload entitles a user is the caller's rule too,
  read off `revocationDate` and `expiresDate`; a billing grace period (in
  the renewal info), `isUpgraded` and later refunds need App Store Server
  Notifications V2 or the App Store Server API. How old a signed payload may
  be is likewise the caller's decision, made on its `signedDate`.
