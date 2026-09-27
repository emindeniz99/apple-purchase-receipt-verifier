# Fuzz targets

Six coverage-guided targets over the readers this port hand-writes and the
verifiers a consumer calls. `run.sh` pairs each with the fixture directories
that seed it, so nothing under `fixtures/` is copied here.

```bash
./run.sh all              # every target, 60 s each
./run.sh readers 600      # one target, ten minutes
FUZZ_SANITIZERS=fuzzer,address ./run.sh receipt-der 600
```

`run.sh` builds first, so there is no separate build step. Nothing is
installed: the fuzzer ships with the Swift toolchain.

## The fuzzer: SwiftPM's libFuzzer support

`swift build -Xswiftc -sanitize=fuzzer` links Swift code against the same
libFuzzer that drives `cargo fuzz` and Clang's `-fsanitize=fuzzer`, and
instruments it with the same coverage counters. An executable target whose
entry point is

```swift
@_cdecl("LLVMFuzzerTestOneInput")
public func fuzz(_ start: UnsafePointer<UInt8>?, _ count: Int) -> CInt
```

then *is* a libFuzzer binary and takes libFuzzer's corpus directories and
flags directly, which is why `run.sh` is close to a copy of
`rust/fuzz/run.sh`. The flag is passed to every target in the graph, not only
to the five that define an entry point: coverage instrumentation has to reach
swift-asn1 and swift-certificates for the fuzzer to steer into them.
`-enable-testing` goes with it, so `Sources/FuzzSupport` can
`@testable import` the library and drive its internal readers.

No third-party fuzzing dependency exists for Swift that is worth preferring
to this: the toolchain already carries libFuzzer, so a wrapper would add a
version to keep current without adding a mutator or a coverage signal.

### The entry point, and why it is not the documented one

Every write-up of this says to compile the fuzz target `-parse-as-library`,
so that the target has no entry point of its own and libFuzzer's `main` is
the one that links. On Linux, with SwiftPM, that does not link at all:

```
ld.gold: error: undefined symbol 'receipt_der_main' referenced in expression
```

SwiftPM builds a Linux executable target by aliasing `main` to the module's
own entry point (`--defsym main=<module>_main`), and `-parse-as-library` is
precisely what stops that symbol from being emitted. So each target here
keeps an ordinary `main.swift` and starts the fuzzer itself, by calling
`LLVMFuzzerRunDriver` — the same driver libFuzzer's `main` calls, taking the
same argv. It lives in a different object file inside `libclang_rt.fuzzer`
from the one defining `main`, so that member is never pulled in and nothing
collides. `FuzzSupport.runFuzzer` is the whole of it.

## Why a separate package

A published package's manifest is part of its public surface. Declaring six
libFuzzer executables in the root `Package.swift` would put them in front of
every consumer who reads it, and SwiftPM would build them for anyone who ran
`swift build` at the root — for targets nobody outside this directory can
run, since they only link with the sanitizer flags above.

So `swift/fuzz/Package.swift` is a package of its own that depends on the
library by path (`.package(path: "../..")`). The root manifest is unchanged
by this directory, and `swift test` at the root neither builds nor knows
about any of it.

`Package.resolved` here is its own, and pins its own versions — the same
arrangement as `rust/fuzz/Cargo.lock`. It resolves independently of the root
manifest's, so it can sit a patch or two ahead; that is not drift to correct.
The `swift` job proves the library against the root's pins. `run.sh` builds
with `--force-resolved-versions`, so this package builds the revisions its own
`Package.resolved` names and never re-resolves on a runner.

## The targets

| target | what it reaches | invariant beyond "nothing traps" |
|---|---|---|
| `receipt-der` | `Verifier.verifyReceipt` on the base64 of the input bytes: the BER-tolerant CMS walk, the unverified creation-date read, the certificate-bag walk, the top-down chain check, the marker OIDs, the signer signature, then the payload parse | an accepted receipt fails against an unrelated anchor set |
| `receipt-base64` | `Verifier.verifyReceipt(base64:)` on the input text — the receipt-base64 rule, then the whole DER path | the same anchor-set invariant, through the transport form a client sends |
| `jws` | `Verifier.verifySignedData`: segment split, strict base64url, header and payload JSON under their bounds, `x5c`, chain at the signed date, marker OIDs, ES256 | a JWS accepted under the fixture root is refused under Apple's pinned roots |
| `endpoint-json` | `Verifier.verifyReceiptEndpoint` on a request body, through to the response rendering | the answer is always a JSON object with a numeric `status` from the 0.7 status table |
| `receipt-payload` | the payload parser (attribute-SET walk, string/integer/date decoders) and the unverified creation-date read, called directly | a parse failure is `PayloadError`, and the creation-date read agrees with the parsed `receiptCreationDateMs` |
| `readers` | `decodeReceiptBase64`, `decodeBase64URLStrict` | each reader's own documented rule, restated independently — see below |

The verify methods never throw in 0.7, so every verifier target instead
requires that the answer is never `INTERNAL_ERROR`: input must not be able to
raise the internal-error alarm, and no target configures the one thing that
legitimately produces it (an empty root set). In Swift the "nothing traps"
half is worth as much again, because `fatalError`, a force-unwrap of `nil`,
an out-of-range index and an arithmetic overflow all abort the process rather
than throw — none of them are catchable, and all of them are reachable from a
parser handed hostile bytes.

The anchor-set invariant is what lets a fuzzer find "accepts what it should
not" rather than only crashes: without it, an input that verifies tells you
nothing about *why* it verified. The receipt targets anchor on the pinned
Apple roots (read from the repository's `certs/`) plus
`fixtures/generated-0.7/receipt-root.der`, so the shared 0.7 fixture receipts
and the two public Apple receipts get past the chain check and the fuzzer can
explore what lies beyond it; the unrelated set is the fixture *JWS* root — a
real anchor from the same generator that signed none of them. The 0.6
receipts under `fixtures/generated/` stay in the seed set, but their
intermediates lack the WWDR marker 0.7 requires, so they stop at that check.

### What `readers` restates

Each internal reader has a documented rule, and the target re-derives that
rule rather than re-running the implementation:

- `decodeReceiptBase64`: an accepted string decodes to exactly as many bytes
  as its data characters encode (four characters carry three bytes; a
  trailing group of two or three carries one or two), so no padding rule can
  drop or invent a byte.
- `decodeBase64URLStrict`: re-encoding an accepted segment's bytes reproduces
  the segment character for character — the canonicity claim, which is what
  gives a segment whose last character carries non-zero unused bits somewhere
  to fail.

### Reaching the payload parser

In 0.7 the full payload parse runs only after the chain and a signer
signature have verified, so the verifier targets reach it only for inputs
that verify. `receipt-payload` therefore calls the parser directly, through
the `@testable` shim in `Sources/FuzzSupport`, and drives the one read that
does run on unverified bytes — the attribute-12 creation date that picks the
chain instant — on the same input. The two must agree whenever the set
parses: both take the first attribute 12, and a disagreement would judge the
chain at an instant other than the date the caller is handed.

## Seeds, corpus, crashers

Seeds are the shared fixtures, passed as extra libFuzzer corpus directories.
libFuzzer reads all of them and writes new units only to the first, so
`corpus/<target>/` here grows across runs while `fixtures/` stays read-only.
`corpus/`, `artifacts/` and `.seeds-generated/` are gitignored: a corpus is a
cache, not a record.

`seeds/endpoint-json/` holds the four hand-written request bodies that are
copies of nothing. The fifth, the one carrying a genuine receipt, is built by
`run.sh` from `fixtures/public-receipts/receipt-sandbox-g5.b64` into
`.seeds-generated/`, so that receipt keeps exactly one copy in the repository.

A crasher lands under `artifacts/<target>/`, gitignored **on purpose**:
reduce it and pin it as a test under `../Tests/`, where it runs on every
Swift version in the matrix rather than only when someone runs the fuzzer.

`APRV_FIXTURES` points a target at the fixture tree; `run.sh` sets it. Unset,
a target falls back to `fixtures/` five directories above its own source, so
a binary run by hand from a normal checkout still finds them. A missing
fixture is reported as a setup failure and not as a crasher.

## CI

`swift-fuzz` in `.github/workflows/ci.yml` runs each target for a fixed
budget on every push, in the same digest-pinned `swift:6.3` container image
the `swift` and `swift-format` jobs use.
