# Fuzz targets

Six coverage-guided targets over the parsers this package hand-writes and the
verifiers a consumer calls. `run.sh` pairs each with the fixture directories
that seed it, so nothing under `fixtures/` is copied here.

```bash
npm ci                       # installs the fuzzer, this directory only
npm --prefix .. run build    # the targets import ../dist
./run.sh all                 # every target, 60 s each
./run.sh parse-cms 600       # one target, ten minutes
```

## The fuzzer: Jazzer.js

[`@jazzer.js/core`](https://github.com/CodeIntelligenceTesting/jazzer.js), from
Code Intelligence. It is libFuzzer compiled into a Node native addon, driven by
coverage counters that a Babel instrumentation pass writes into the JavaScript
it loads — so it is the same kind of tool as `cargo fuzz` and `go test -fuzz`,
not a random-input loop, and it takes libFuzzer's corpus directories and flags
directly. The `run.sh` here is a near-copy of `rust/fuzz/run.sh` for that
reason.

The alternative, `jsfuzz`, was rejected on maintenance: its last release is
1.0.15 from January 2021 and its repository has been archived since. Jazzer.js
published 4.0.0 in April 2026, declares `node >= 14`, and installs and runs
clean on the Node 20-26 lines this package supports. A fuzzer that has not
shipped in five years cannot be trusted to keep working on a Node line it has
never seen, and it is the one dev dependency whose whole job is to survive
contact with hostile input.

Jazzer.js instruments ES modules through a Node loader hook, which matters
here: this package is ESM, and the targets import `../dist/*.js` directly.
Coverage numbers below are libFuzzer's own (`cov:` = edges, `ft:` = features),
so they are comparable between runs but not with the Rust port's.

## The targets

| target | what it reaches | invariant beyond "nothing crashes" |
|---|---|---|
| `parse-der` | `der.js`: `parse` on raw bytes, then `octetStringValue`, `tbsParts`, `hasExtension` | failures are `ParseError`, never `TypeError`/`RangeError` |
| `parse-cms` | `cms.js`: `parseCms`, `findSignerCertIndex`, and the two signed-attribute readers | `parseCms` fails only as `VerificationError` |
| `verify-receipt` | `verifyReceiptCore`: CMS, payload, chain, signature | an accepted receipt fails against an unrelated anchor set |
| `verify-receipt-base64` | `ReceiptVerifier.verify` on the string a client sends | failures are `VerificationError` |
| `verify-transaction` | the three `JwsVerifier` entry points | a JWS `verifyRaw` accepts under the fixture root fails under Apple's roots |
| `endpoint-json` | `VerifyReceiptEndpoint.verifyReceiptJson` on a request body | it never throws, and the answer is always JSON with a numeric `status` |

The anchor-set invariant is the one that lets a fuzzer find "accepts what it
should not" rather than only crashes: without it, an input that verifies tells
you nothing about *why* it verified. `verify-receipt` anchors on the pinned
Apple roots plus `fixtures/generated/receipt-root.der`, so the shared fixture
receipts and the two public Apple receipts get past the chain check and the
fuzzer can explore what lies beyond it; the unrelated set is the fixture *JWS*
root.

There is no `parse-certificate` target, the one the Rust port has and this one
does not. The Node build parses certificates with `node:crypto`'s
`X509Certificate` — OpenSSL — rather than with code from this repository, so
fuzzing it would fuzz Node. The X.509 reading this package *does* hand-write,
`tbsParts` and `hasExtension` in `der.js`, is reached from `parse-der`.

## Seeds, corpus, crashers

Seeds are the shared fixtures, passed as extra libFuzzer corpus directories.
libFuzzer writes new units only to the first directory, so `corpus/<target>/`
here grows across runs while `fixtures/` is read-only. `corpus/`, `artifacts/`
and `.seeds-generated/` are gitignored: a corpus is a cache, not a record.

`seeds/endpoint-json/` holds the four hand-written request bodies that are not
copies of anything. The fifth seed, the one carrying a genuine receipt, is
built by `run.sh` from `fixtures/public-receipts/receipt-sandbox-g5.b64` into
`.seeds-generated/`, so that receipt keeps exactly one copy in the repository.

A crasher lands under `artifacts/<target>/`, which is gitignored **on
purpose**: reduce it and pin it as a test under `../test/`, where it runs on
every Node line in the matrix rather than only when someone runs the fuzzer.

## Why this is a separate npm project

`package.json` here is private and has its own lockfile, so `npm ci` in `node/`
— the install every other CI job and every contributor performs — does not
pull a native fuzzing addon. The published tarball is unaffected either way:
`node/package.json` ships `files: ["dist", "certs"]`, so nothing under `fuzz/`
has ever been in it.

`node-fuzz` in `.github/workflows/ci.yml` runs each target for a fixed budget
on every push.
