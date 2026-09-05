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

PHP has no publishing path at all. Packagist reads `composer.json` from a
repository root and this port's manifest is `php/composer.json`, so there is
nothing for Packagist to read and no publish job to add. The layouts that
would fix it, and their costs, are in BOOTSTRAP.md; until the owner picks one,
`php/` is vendored rather than installed.

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
them exercised on every push, and — by the same property, though there is no
local runtime to run it in — Akamai EdgeWorkers. Neither entry point reads
a file, so `appleReceiptRoots()` and `appleJwsRoots()` work inside a bundle
either way.

CI proves the default build on Node, Bun, Deno and workerd (`cd node && npm
run test:runtimes`) and the web build on Node, the Vercel Edge runtime and
flagless workerd (`npm run test:runtimes:web`). The Node suite runs every
shared fixture through both builds and fails on any difference of verdict;
[node/README.md](node/README.md#webcrypto-only-runtimes) has the per-runtime
table and the three places the web API is not just `await`.

## How to run the test suites

```bash
# Java (library targets Java 8; build with any modern JDK + Maven)
cd java && mvn test

# Node (strict TypeScript, zero runtime deps; Node >= 20)
cd node && npm install && npm test    # both entry points, every shared fixture
cd node && npm run test:runtimes       # default build on Bun, Deno and Cloudflare workerd
cd node && npm run test:runtimes:web   # /web build on Vercel Edge and flagless workerd

# Python (>= 3.9; needs: pip install cryptography asn1crypto)
cd python && python3 -m unittest discover -s tests

# Swift (Swift 6.1+; Linux or macOS 13+; manifest lives at the repo root)
swift test

# Go (>= 1.22; no dependencies)
cd go && go test ./...

# Ruby (>= 3.1; no runtime dependencies, minitest through rake)
cd ruby && rake test

# Rust (>= 1.74)
cd rust && cargo test

# PHP (>= 8.1; no lockfile is committed, so resolve first)
cd php && composer update && vendor/bin/phpunit

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
