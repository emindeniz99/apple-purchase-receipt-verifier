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
implementations, one normative algorithm, one shared fixture set on which
they agree on every verdict and every decoded value: **Java** (8+), **Node** (20+, zero runtime deps),
**Python** (3.10+), **Swift** (6.1+), **Go** (1.22+), **Ruby** (3.3+),
**Rust** (1.85+), **PHP** (8.2+) and **.NET** (netstandard2.0 and net8.0) —
plus **C and C++ via a C ABI over the Rust port**, which any FFI-capable
runtime (Elixir NIFs, Lua, ctypes, P/Invoke) can load.
[SUPPORT-MATRIX.md](SUPPORT-MATRIX.md) lists every line CI runs and the rule
that adds or drops one. [PORTS.md](PORTS.md) shows which features each
port ships.

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
those checks are yours (see below). Method names follow each language's
casing. See
[COMPARISON.md](./COMPARISON.md) for the field-by-field fidelity account and
the gaps only Apple's servers can fill.

Start with [INTENT.md](./INTENT.md) (why + trust model), then
[PLAN.md](./PLAN.md) (algorithms + decisions + API shape), then
[ROADMAP.md](./ROADMAP.md) (what's next).
[THREAT-MODEL.md](./THREAT-MODEL.md) is the security account: what is
attacker-controlled, each mitigation with the test that proves it, the
non-goals, and the residual risks.
[RECEIPT-FIELDS.md](./RECEIPT-FIELDS.md) is the legacy-receipt reference:
every attribute type the genuine fixtures carry, which ones Apple documents,
and Apple's chain-of-trust procedure mapped step by step onto the code.

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

Five of the nine implementations are published today, all as
**`apple-purchase-receipt-verifier`**, in lockstep versions cut from this
repository's tags.

The version is `0.x`. Until 1.0, a minor release may break the API: 0.7
replaces the 0.6 classes with a new `Verifier` without a deprecation
period. Read the CHANGELOG before you bump the minor version, and pin it.

| Registry | Install | How you import it |
|---|---|---|
| [Maven Central](https://central.sonatype.com/artifact/io.github.emindeniz99/apple-purchase-receipt-verifier) | `io.github.emindeniz99:apple-purchase-receipt-verifier` | `import io.github.emindeniz99.applepurchasereceiptverifier.Verifier;` |
| [npm](https://www.npmjs.com/package/apple-purchase-receipt-verifier) | `npm install apple-purchase-receipt-verifier` | `import { createConfig, createVerifier } from 'apple-purchase-receipt-verifier';` |
| [PyPI](https://pypi.org/project/apple-purchase-receipt-verifier/) | `pip install apple-purchase-receipt-verifier` | `from apple_purchase_receipt_verifier import Config, Verifier` |
| [SwiftPM](https://swiftpackageindex.com/emindeniz99/apple-purchase-receipt-verifier) | `.package(url: "https://github.com/emindeniz99/apple-purchase-receipt-verifier.git", from: "0.7.0")` | `import ApplePurchaseReceiptVerifier` |
| [Go module proxy](https://pkg.go.dev/github.com/emindeniz99/apple-purchase-receipt-verifier/go) | `go get github.com/emindeniz99/apple-purchase-receipt-verifier/go` | `import applereceipt "github.com/emindeniz99/apple-purchase-receipt-verifier/go"` |

**C and C++ have no registry entry and are not meant to.** The C ABI in
[`rust/ffi/`](rust/ffi/) is built from source against the Rust port: a
`cdylib`/`staticlib` and a generated header, seven functions, JSON as the
interchange. Prebuilt binaries per OS and architecture are a later step, not
a shipped one. See [rust/ffi/README.md](rust/ffi/README.md). Three example
consumers call it, one of each kind: C++17 through the header in
[`rust/ffi/examples/cpp/`](rust/ffi/examples/cpp/), Python through ctypes
with no compiler in
[`rust/ffi/examples/python/`](rust/ffi/examples/python/), and Elixir over a
NIF shim in [`rust/ffi/examples/elixir/`](rust/ffi/examples/elixir/).

The import namespace is the registry name in each ecosystem's casing
convention (`applepurchasereceiptverifier` / `apple_purchase_receipt_verifier` /
`ApplePurchaseReceiptVerifier`) — one name everywhere.

**Four newer ports are not installable from a registry yet.** Ruby, Rust
and .NET are wired into `release.yml` and are waiting on one owner action
each: a pending trusted publisher for RubyGems, a first manual publish for
crates.io and NuGet. Those actions, per registry and in order, are in
[BOOTSTRAP.md](./BOOTSTRAP.md); the rows above gain entries once the first
release goes out. Go, the fifth newer port, needed no such action:
`proxy.golang.org` has served it since `go/v0.4.0`.

PHP is the fourth, and its install path is:

```bash
composer require emindeniz99/apple-purchase-receipt-verifier
```

```php
use EminDeniz99\ApplePurchaseReceiptVerifier\Config;
use EminDeniz99\ApplePurchaseReceiptVerifier\Verifier;
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
`crypto.subtle` alone: same function names, same options, same `Reason`
values, with `createConfig`, `defaultConfig` and every `Verifier` method
returning a Promise. It
imports no `node:` module and touches no `Buffer`, so it also runs where
only WebCrypto exists: the Vercel Edge runtime, Next.js edge middleware,
Cloudflare Workers with no compatibility flags and Fastly Compute, each of
them exercised on every push. Akamai EdgeWorkers implements the same
WebCrypto API and is expected to work too, but is untested: there is no
local runtime for it that CI can run. Neither entry point reads a file: the
Apple roots `defaultConfig()` returns are compiled in, so they work inside a
bundle either way.

CI proves the default build on Node, Bun, Deno and workerd (`cd node && npm
run test:runtimes`) and the web build on Node, the Vercel Edge runtime and
flagless workerd (`npm run test:runtimes:web`). The Node suite runs every
shared fixture through both builds and fails on any difference of verdict;
[node/README.md](node/README.md#webcrypto-only-runtimes) has the per-runtime
table and the three places the web API is not just `await`.

## Integrating: from verified payload to entitlement

The full two-branch flow, from a verified StoreKit 2 transaction or legacy
receipt to a granted purchase, is in [INTEGRATION.md](./INTEGRATION.md).

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

## How to run the test suites

```bash
# Java (library targets Java 8; build with any modern JDK + Maven)
cd java && mvn test

# Node (strict TypeScript, zero runtime deps; Node >= 20)
cd node && npm install && npm test    # both entry points, every shared fixture
cd node && npm run test:runtimes       # default build on Bun, Deno and Cloudflare workerd
cd node && npm run test:runtimes:web   # /web build on Vercel Edge and flagless workerd

# Python (>= 3.10; uv installs the locked dependencies)
cd python && uv sync && uv run python -m unittest discover -s tests

# Swift (Swift 6.1+; Linux or macOS 13+; manifest lives at the repo root)
swift test

# Go (>= 1.22; no dependencies)
cd go && go test ./...

# Ruby (>= 3.3; no runtime dependencies, minitest through rake)
cd ruby && rake test

# Rust (>= 1.85)
cd rust && cargo test

# PHP (>= 8.2; installs php/composer.lock)
cd php && composer install && vendor/bin/phpunit

# .NET (SDK 8.0+; runs the net8.0 suite and the netstandard2.0 floor suite)
cd dotnet && dotnet test -c Release
```

All nine suites verify the same three shared fixture tiers:

1. `fixtures/generated/` and `fixtures/generated-0.7/` — deterministic
   cross-language fixtures (fake Apple PKI) written by the Java
   `FixtureGeneratorTest` and the `*Fixtures` generators beside it; the
   receipts in `generated-0.7/` carry the WWDR marker 0.7 checks.
   Regenerate only deliberately, then re-run **every** suite.
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
payload fields the call must return or the reason it must fail with.
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

Cross-port benchmarks (same operations, same fixtures): [BENCHMARKS.md](./BENCHMARKS.md).

Production trust anchors are all three published Apple root certificates in
[`certs/`](./certs) (from [Apple PKI](https://www.apple.com/certificateauthority/)):
`AppleIncRootCertificate.cer`, `AppleRootCA-G2.cer` and `AppleRootCA-G3.cer`.
Today's chains end at Apple Inc. Root (legacy PKCS#7 receipts) and Apple Root
CA - G3 (JWS signed data), but Apple's own guidance is to trust every root on
its PKI page rather than a specific one — see PLAN.md D15 for the sourced
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
  see INTENT.md. Whether a payload entitles a user is the caller's rule too,
  read off `revocationDate` and `expiresDate`; a billing grace period (in
  the renewal info), `isUpgraded` and later refunds need App Store Server
  Notifications V2 or the App Store Server API. How old a signed payload may
  be is likewise the caller's decision, made on its `signedDate`.
