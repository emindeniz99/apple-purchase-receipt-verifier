# apple-purchase-receipt-verifier

[![ci](https://github.com/emindeniz99/apple-purchase-receipt-verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/emindeniz99/apple-purchase-receipt-verifier/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/emindeniz99/apple-purchase-receipt-verifier/badge)](https://scorecard.dev/viewer/?uri=github.com/emindeniz99/apple-purchase-receipt-verifier)
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
validating the certificate chain against pinned Apple root CAs.

One Rust core does the verification. It is compiled to one WebAssembly
module, `aprv.wasm`, and packages for nine languages run it: **Java**
(8+), **Node** (20+, zero runtime deps), **Python** (3.10+), **Swift**
(6.3+), **Go** (1.25+), **Ruby** (3.3+), **Rust** (1.85+), **PHP** (8.2+)
and **.NET** (netstandard2.0, tested on .NET 8 and later). Java also keeps
its own, independent implementation over BouncyCastle, maintained beside
the core as a second opinion on every verdict. **`aprv-server`** runs the
same module as an HTTP server, a Docker image or a one-shot CLI for any
other language (or as a Cloudflare Worker over the Node package, see
[node/examples/cloudflare-worker](node/examples/cloudflare-worker/)), and **C and C++** can link the core through a C ABI, which
any FFI-capable runtime (Elixir NIFs, Lua, ctypes, P/Invoke) can load. The
core and the Java implementation answer the same 393 cases of
[`fixtures/cases.json`](./fixtures/cases.json), and every package runs all
of them. [PORTS.md](PORTS.md) shows what each package runs on, and
[SUPPORT-MATRIX.md](SUPPORT-MATRIX.md) lists every line CI runs and the
rule that adds or drops one.

Every package exposes the same three methods on one `Verifier`, built
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

The other packages have the same three methods, in their own casing:
[Java `-wasm`](java-wasm/README.md), [Python](python/README.md),
[Swift](swift/README.md), [Go](go/README.md), [Ruby](ruby/README.md),
[Rust](rust/README.md), [PHP](php/README.md) and [.NET](dotnet/README.md).
The [Java](java/README.md) and [Node](node/README.md) READMEs document the
full API; [aprv-server](rust/server/README.md) documents the server and
its CLI.

## Installing

Every package is published as **`apple-purchase-receipt-verifier`**, or
that name in its ecosystem's casing, in lockstep versions cut from this
repository's tags. 0.8.0 is the first release of the one-core design; the
API is 0.7's.

The version is `0.x`. Until 1.0, a minor release may break the API: 0.7
replaced the 0.6 classes with a new `Verifier` without a deprecation
period. Read the [CHANGELOG](./CHANGELOG.md) before you bump the minor
version, and pin it.

| Registry | Install | How you import it |
|---|---|---|
| [Maven Central](https://central.sonatype.com/artifact/io.github.emindeniz99/apple-purchase-receipt-verifier) | `io.github.emindeniz99:apple-purchase-receipt-verifier` (the Java implementation); `io.github.emindeniz99:apple-purchase-receipt-verifier-wasm` (the core) is not yet published ([why](java-wasm/README.md)); depend on one, never both | `import io.github.emindeniz99.applepurchasereceiptverifier.Verifier;` |
| [npm](https://www.npmjs.com/package/apple-purchase-receipt-verifier) | `npm install apple-purchase-receipt-verifier` | `import { createConfig, createVerifier } from 'apple-purchase-receipt-verifier';` |
| [PyPI](https://pypi.org/project/apple-purchase-receipt-verifier/) | `pip install apple-purchase-receipt-verifier` | `from apple_purchase_receipt_verifier import Config, Verifier` |
| [SwiftPM](https://swiftpackageindex.com/emindeniz99/apple-purchase-receipt-verifier) | `.package(url: "https://github.com/emindeniz99/apple-purchase-receipt-verifier.git", from: "0.7.0")` | `import ApplePurchaseReceiptVerifier` |
| [Go module proxy](https://pkg.go.dev/github.com/emindeniz99/apple-purchase-receipt-verifier/go) | `go get github.com/emindeniz99/apple-purchase-receipt-verifier/go` | `import applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"` |
| RubyGems | `gem "apple-purchase-receipt-verifier"` | `require "apple_purchase_receipt_verifier"` |
| NuGet | `dotnet add package ApplePurchaseReceiptVerifier` | `using ApplePurchaseReceiptVerifier;` |
| Packagist | `composer require emindeniz99/apple-purchase-receipt-verifier`, then `vendor/bin/aprv-install` | `use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;` |
| crates.io | `cargo add apple-purchase-receipt-verifier` | `use apple_purchase_receipt_verifier::{Config, Verifier};` |
| GitHub Releases, GHCR | the `aprv` binary for your platform, or `ghcr.io/emindeniz99/aprv-server` | HTTP, or `aprv verify-receipt` on stdin |

The import namespace is the registry name in each ecosystem's casing
convention (`applepurchasereceiptverifier` / `apple_purchase_receipt_verifier` /
`ApplePurchaseReceiptVerifier`), one name everywhere.

Maven Central (the main artifact; `-wasm` is held), npm, PyPI, SwiftPM
and the Go proxy publish on every release. RubyGems, NuGet, Packagist and Docker Hub each wait on a one-time
owner action, listed in [BOOTSTRAP.md](./BOOTSTRAP.md). The Rust crate
stays at 0.7 on crates.io until `openssl-sys` accepts OpenSSL 4; building
the 0.8 core from source needs `OPENSSL_NO_VENDOR=1 OPENSSL_DIR=<OpenSSL
4>` ([rust/openssl/README.md](rust/openssl/README.md)). C and C++ build
from source against the core, and [rust/ffi/README.md](rust/ffi/README.md)
covers the ABI and the example consumers.

## How it runs

| Package | Runs the core on |
|---|---|
| Java `-wasm` | Endive (the module compiled to JVM bytecode, no native code) on Java 11+; `aprv-server` as a supervised child process on Java 8 |
| Java (main artifact) | its own implementation over BouncyCastle |
| Node | the JS engine's WebAssembly, through bindings jco generates |
| Go | wazero, with no cgo |
| Python | wasmtime-py |
| Ruby | the `wasmtime` gem |
| Swift | WasmKit, an interpreter; no JIT entitlement |
| .NET | Wasmtime .NET |
| PHP | `aprv-server`, one process per call or a server URL |
| Rust, C ABI | natively, in the caller's process |

No wrapper parses a receipt, checks a signature or decides trust: each
reads the clock, moves the input into the module, and maps the module's
JSON answer onto its language's types. A fix in the core reaches every
package in the next release, and the packages cannot disagree about a
verdict. The module imports one function, a source of random bytes: it
cannot read a file, the network, the environment or the clock, so a
parser bug a hostile receipt reaches stays inside the module's sandbox
rather than running in your process. Each package checks its copy of the
module against a pinned SHA-256; the release publishes the hash with SLSA
provenance and a CycloneDX SBOM, and `tools/reproduce-wasm.sh` rebuilds
the module from a tag and compares it. [THREAT-MODEL.md](./THREAT-MODEL.md)
§6 to §10 says what the sandbox does and does not protect.

What was measured before the release:

- The module answers every case of `fixtures/cases.json` through a host
  that traps on any import but `random-get`, with no trap, and answered
  every one of the 6,179 rows of the generated corpora (1,179 receipts and
  5,000 mutants) byte for byte as its native build
  ([aprv.wasm parity](docs/evidence/2026-09-29-aprv-wasm-parity.md),
  [review fixes](docs/evidence/2026-09-29-core-review-fixes.md)).
- Every package answered the shared cases and the corpora through its own
  host layer, row for row as the module does; `aprv-server` refuses the 27
  rows over the 3 MiB cap before the module, as Apple's endpoint does
  ([migration status](docs/rust-core/STATUS.md)).
- Against the Java implementation, over 7,647 calls (the cases, the
  corpora and the fuzz seeds), the core never differed in verdict or
  payload on the corpora and never accepted anything unsigned; every
  other difference is recorded with its reason
  ([differential campaign](docs/evidence/2026-09-29-differential-campaign.md)).
- Five adversarial reviews of the core found nothing in memory safety,
  isolation or trust; what they did find is fixed and logged
  ([REVIEW-LOG.md](docs/rust-core/REVIEW-LOG.md)).

Speed depends on the host; [BENCHMARKS.md](./BENCHMARKS.md) has the
numbers. Python and Ruby compile the module once per process (seconds on
a loaded machine, a tenth of a second from Python's cache), so build the
`Verifier` at start-up, never per request.

## JavaScript runtimes

The npm package runs the same module on every runtime; its two entry
points differ only in that `apple-purchase-receipt-verifier/web` returns
Promises. It runs on Node 20+, Bun, Deno (with
`--allow-read --allow-env=JCO_DEBUG`), Cloudflare Workers with no
compatibility flag, Vercel Edge and browsers through a bundler. Fastly
Compute and Akamai EdgeWorkers are not supported: neither runs
WebAssembly. The runtime table and what CI proves on each are in
[node/README.md](node/README.md#runtimes).

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
| `MALFORMED` | client bug | Deny. Not base64, not a CMS envelope or a compact JWS, truncated, or past a structural bound (embedded certificates, SignerInfos; in Java also JSON nesting). Decided before any signature check. `21002` at the endpoint. |
| `TOO_LARGE` | client bug | Deny. Over a fixed size cap: 3,145,728 UTF-8 bytes for a receipt or an endpoint request body, 262,144 for a JWS. `21002` at the endpoint. |
| `INVALID_CERTIFICATE` | client bug | Deny. An `x5c` entry or a receipt signer is not a parseable certificate, which mangled transport also produces, or a certificate was outside its validity window at the signing date. `21003` at the endpoint. |
| `UNTRUSTED_CHAIN` | possible fraud | Deny and alert. The path does not reach a pinned Apple root. `21003` at the endpoint. |
| `INVALID_SIGNATURE` | possible fraud | Deny and alert. The bytes were altered after Apple signed them. `21003` at the endpoint. |
| `INVALID_CERTIFICATE_PURPOSE` | possible fraud | Deny and alert. A certificate chaining to an Apple root without the marker OID its position requires: a developer's own certificate signing a forged payload looks exactly like this. `21003` at the endpoint. |
| `UNREADABLE_PAYLOAD` | not the client's | The chain and signature verified, but the content Apple signed does not parse. Deterministic: the same bytes fail the same way, so do not retry the library. Log the failure with the library version, alert, and settle the purchase through the App Store Server API by transaction id; grant provisionally only if the business accepts that. `21009` at the endpoint. |
| `INTERNAL_ERROR` | not the client's | The library itself failed before it could decide: a trap inside the module, an `aprv-server` that did not answer, a runtime missing an algorithm, or a clock that throws. Alert, do not retry. `21009` at the endpoint. |

A payload for another app, another environment or another app Apple id
verifies: the library returns what Apple signed and leaves those checks to
you (step 2 of each branch in [INTEGRATION.md](./INTEGRATION.md)).

The vocabulary is closed and identical in every package, so this table is
one policy across every backend language. What signatures still cannot tell
you, and why replay and refund bookkeeping are the caller's job, is in
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
endpoint, the Java 8 floor and the zero-dependency Node package.

## Documentation map

Start with INTENT, then PLAN, then ROADMAP.

- [INTENT.md](./INTENT.md): why the library exists, and its trust model.
- [PLAN.md](./PLAN.md): algorithms, numbered decisions (D17 onward are the one-core design), API shape, prior-art survey (section 1).
- [ROADMAP.md](./ROADMAP.md): what is next.
- [THREAT-MODEL.md](./THREAT-MODEL.md): attacker-controlled inputs, each mitigation with its test, where the core runs and what isolates it, non-goals, residual risks.
- [RECEIPT-FIELDS.md](./RECEIPT-FIELDS.md): every receipt attribute the genuine fixtures carry, which ones Apple documents, and Apple's chain-of-trust steps mapped onto the code.
- [COMPARISON.md](./COMPARISON.md): field-by-field fidelity, and the gaps only Apple's servers can fill.
- [PORTS.md](./PORTS.md): what each package runs the core on, its floor, platforms and one-command check.
- [SUPPORT-MATRIX.md](./SUPPORT-MATRIX.md): every runtime line CI runs, the platforms each package reaches, and the rule that adds or drops one.
- [BENCHMARKS.md](./BENCHMARKS.md): per-host benchmarks, same operations on the same fixtures.
- [INTEGRATION.md](./INTEGRATION.md): the full flow from verified payload to entitlement.
- [CONTRIBUTING.md](./CONTRIBUTING.md): building the module, the test suites, fixture tiers, conformance vectors, behaviour changes, adding a wrapper, commits, releases.
- [SECURITY.md](./SECURITY.md): reporting a vulnerability, supported versions, dependency policy.
- [BOOTSTRAP.md](./BOOTSTRAP.md): the one-time owner action each registry needs before CI can publish to it.
- [docs/rust-core/](./docs/rust-core/README.md): the plan behind 0.8.0, its decisions (R1 to R34), the review log and the migration's status.

## Trust anchors

Production trust anchors are all three published Apple root certificates in
[`certs/`](./certs) (from [Apple PKI](https://www.apple.com/certificateauthority/)):
`AppleIncRootCertificate.cer`, `AppleRootCA-G2.cer` and `AppleRootCA-G3.cer`.
Today's chains end at Apple Inc. Root (legacy PKCS#7 receipts) and Apple Root
CA - G3 (JWS signed data), but Apple's own guidance is to trust every root on
its PKI page rather than a specific one; PLAN.md D15 has the sourced
rationale. The Rust core compiles them in, so every package that runs the
module carries them inside `aprv.wasm`; the Java implementation carries them
as constants. A `Config` also accepts caller-supplied roots.

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
- **One core, one second opinion**: nine hand-written implementations
  became one Rust core on OpenSSL in 0.8.0, so a security fix is made once.
  The Java implementation stays independent on purpose: a bug in the core
  or in OpenSSL would reach every Wasm package at once, and a second
  implementation answering the same cases is what catches it.
