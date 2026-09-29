# CI notes for the Swift host (lane C, rust-core migration)

For the integrator. This lane does not touch `.github/`; everything the
workflows need to change for the WasmKit host is here. Nothing needs a
secret.

## What changed under CI

- `Package.swift` (repository root) is `swift-tools-version:6.3` with
  `platforms: [.macOS(.v15), .iOS(.v18)]` and one dependency, WasmKit
  `from: "0.4.1"` with only its `MultiThread` trait. swift-certificates,
  swift-asn1 and swift-crypto are gone from the manifest and from
  `Package.resolved`.
- **The floor is WasmKit 0.4.1, not the plan's 0.4.0.** 0.4.1 (tagged
  2026-09-29) fixes a use-after-free under software bounds checking: the
  interpreter kept its cached memory base across a host call, and a host
  function that re-enters the guest and grows its memory (random-get does
  exactly that, through `cabi_realloc`) left the next load reading freed
  memory. 0.4.0 must not be resolvable.
- `Package.resolved` pins WasmKit 0.4.1 and, because WasmKit's manifest
  declares them, swift-argument-parser 1.8.2 and swift-syntax 604.0.0. Neither
  is compiled for this package's product (only WasmKit's CLI and WIT tools
  use them), but SwiftPM resolves them, so a clean build fetches swift-syntax
  (about 40 MB of git history into the SwiftPM cache).
- **Every Swift job copies the module into
  `swift/Sources/ApplePurchaseReceiptVerifier/Resources/aprv.wasm` before
  building** (gitignored on the lane branch per the owner's 100 KB rule;
  SwiftPM refuses to build without the declared resource), and the copy must
  match `aprv.wasm.sha256`. A job that tests the module `rust-wasm` built
  writes that build's hash into `aprv.wasm.sha256` in its own checkout (the
  sha256sum line, `<hex>  aprv.wasm`), as `refresh-wasm-copies` will.
- `aprv.wasm.sha256` (committed) pins the G1b module: the review-fixed 0.7
  core on OpenSSL 4 (`lane/core` c4410c7), 3,009,278 bytes,
  `9c0a581c...0f263`. The module itself stays uncommitted on the lane
  branch; the integrator commits the release module and its pin together.
- `Resources/licenses/` holds the licence texts of the code compiled into the
  module (OpenSSL, wasi-libc with musl, the Rust standard library), copied
  from the Node host's `node/licenses/`, and ships as a resource.
- The hand-written verifier is gone. The last commit that has it is the
  lane's branch point `9ffbf70`; use it as the oracle and as the source of
  the port-only tests (Phase 7 step 1). `swift/Sources/.../certs` stays for
  `check-cert-copies.mjs` (Phase 7 deletes it); the manifest excludes it.

## Tests need a release build

WasmKit interprets, and a debug build of the interpreter is about 50 to 150
times slower than a release build here: one genuine receipt took about 2 s
in debug (0.26 s for a malformed one), and the 200-call memory test took
490 s. So every `swift test` in CI runs optimised, with testing enabled for
the `@testable` imports:

```sh
swift test -c release -Xswiftc -enable-testing --force-resolved-versions
```

A debug `swift build --build-tests` is still worth keeping as a compile
check (it catches `#if DEBUG`-only breakage), but not a debug test run: the
23 cases with `maxMillis` 2,000 fail on time alone in debug.

## Jobs

| Job | Change |
|---|---|
| `swift` (Linux matrix) | drop the `6.1` and `6.2` legs: the manifest's tools version is 6.3, which they cannot read. Keep `swift:6.3@sha256:56ef1be2...` (the floor) and add the newest line (6.4) when its digest is pinned. Replace both steps with the one command above; the old debug step goes (see above), the release one stays. A cold release build of WasmKit took 4 min 43 s here on 2 of 4 shared cores; the whole suite then ran in 2 min 27 s. Raise `timeout-minutes` to 45. |
| `swift-macos` | `runs-on: macos-15` (or `macos-latest` as long as it is 15+ with Xcode carrying Swift 6.3+), the same command. |
| `swift-ios` (new) | the iOS compile the plan asks for, which cannot be done on Linux: on `macos-15`, `xcodebuild build -scheme ApplePurchaseReceiptVerifier -destination 'generic/platform=iOS' -skipPackagePluginValidation` (the library product's scheme; `xcodebuild -list` names it if SwiftPM spells it differently). It proves the package and WasmKit compile for iOS 18 with the software bounds checking the package selects (mprotect is compiled only for Linux and macOS). Nothing runs on a device. |
| `swift-format` | unchanged command; `swift format lint --strict --recursive swift/Sources swift/Tests` (6.3.3) is clean on this branch. |
| `swift-fuzz` | the targets are now `receipt-der`, `receipt-base64`, `jws` and `endpoint-json` (`receipt-payload` and `readers` went with the hand-written parsers); `run.sh` no longer passes `-enable-testing`. With the round-13 stand-in the `requireNoInternalError` invariant fired at once (its 0.6 wire); with the G1 module the wire is the one this package reads, so the job can run again once the module is copied into place first. `swift/bench` still builds with `swift build --package-path swift/bench --force-resolved-versions`; its manifest is tools 6.3 now. |
| `smoke-swiftpm` | image to `swift:6.3@sha256:56ef1be2...`. `.github/smoke/swiftpm-smoke/Package.swift`: `swift-tools-version:6.3`, `platforms: [.macOS(.v15), .iOS(.v18)]`. `Sources/Smoke/main.swift`: `config.roots.count == 3` no longer compiles; the defaults are `roots == nil` (the module's built-in roots), so replace the check with `guard config.roots == nil`. The rest (g5 verifies, one flipped signature bit is `INVALID_SIGNATURE`) stands. |
| post-publish `swiftpm` | same image and smoke changes. |
| `wasm-copies` | for Swift: `cd swift/Sources/ApplePurchaseReceiptVerifier/Resources && sha256sum -c aprv.wasm.sha256`, and the hash in that file must equal the build's. The package checks the pair when it loads the module, so a copy swapped without its hash file answers `INTERNAL_ERROR` to every call (and `Config.builder().roots(...)` throws). |
| `release-please.yml` `refresh-wasm-copies` | **must also rewrite each copy's `.sha256`**: today it copies `aprv.wasm` over every committed copy and leaves `aprv.wasm.sha256` stale, which breaks both the Go and the Swift package on the release branch. For each copy `f`: `printf '%s  aprv.wasm\n' "$WASM_SHA256" > "$f.sha256"`, and add those files to the commit. |
| `one-implementation` | add `swift` to `--enforce`. `swift/Sources` imports only Foundation and WasmKit now; the SHA-256 that checks the module is 60 lines of Swift in `Host/SHA256.swift` (no crypto module), which the gate allows by design. `SourceIsolationTests` holds the same rule inside the test suite. |
| `dependabot.yml` | the three `swift` entries stay; the swift-crypto/-asn1/-certificates history goes with them. Add an ignore for WasmKit `>= 0.5.0` only if 0.5 raises a floor; 0.4.x patch releases should arrive (0.4.1 was a security fix). |
| `certs` job (`check-cert-copies.mjs`) | unchanged: the copy is still in the tree. |

## The gate, in one command

`swift/scripts/gate.sh DIR [--pin] [--bench]` runs everything this lane
checks against one module build, where `DIR` has the G1 layout (`aprv.wasm`,
`calls/<corpus>.pinned.jsonl`, `rows/module-<corpus>.jsonl`, `same.py`):
it checks the module against the pin (`--pin` rewrites the pin), copies it
into place, builds optimised, runs the whole suite with the 311 cases, runs
the five corpora through the package's host layer
(`MeasurementTests.testCorpus`, the `Guest` the `Verifier` uses) and
compares each corpus's rows byte for byte with the module's reference rows,
and with `--bench` times the public API. `SCRATCH_PATH` and `OUT` set the
build and output directories. The corpus is scratch data, not in the
repository, so the corpus step is a manual or nightly job, not a push gate.

G1b (2026-09-29): 338 of 338 cases, the whole suite green (57 tests, 2
measurement tests skipped), 6,179 of 6,179 corpus rows identical to the
module's reference rows, 0 traps.

## Speed

`swift run -c release --package-path swift/bench bench --threads` times the
public API with a plain release build (no `-enable-testing`): g5 and the
fixture JWS, one and four threads, per second and per CPU-second, and the
start-up to the first answer, and the peak resident set. Results on
2026-09-29 (stand-in and G1 module) are in the README and the hand-back. The round-7 spike's own harness, rebuilt and run on the same
machine within the same minutes, measured 28 to 33 ms per g5 and 126 ms per
JWS, where it recorded 13.3 ms and 54.7 ms on 2026-09-26; this package
measured 26 ms and 100 to 111 ms. The machine, not the package, halved the
plan's numbers, and the JWS is at the 10 per second per core floor on it.

`MeasurementTests.testSpeed` (`APRV_BENCH=1`, optional
`APRV_BENCH_SECONDS`) prints start-up (hash and parse, instance, init, first
and second g5) and g5 and JWS throughput through the public API on one and
four threads. Not a CI job; the numbers are in the README and the hand-back.
