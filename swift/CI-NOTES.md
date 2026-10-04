# CI notes for the Swift host (lane C, rust-core migration)

For the integrator. This lane does not touch `.github/`; everything the
workflows need to change for the WasmKit host is here. Nothing needs a
secret.

## What changed under CI

- `Package.swift` (repository root) is `swift-tools-version:6.3` with
  `platforms: [.macOS(.v15), .iOS(.v18)]` and two dependencies: WasmKit
  `from: "0.4.1"` with only its `MultiThread` trait, and swift-crypto
  `"3.0.0" ..< "6.0.0"` for its `Crypto` product, which hashes the module
  against its pin. swift-certificates and swift-asn1 are gone from the
  manifest.
- **swift-crypto is a range, not `from: "5.0.0"`.** Apple's
  app-store-server-library-swift requires swift-crypto `"1.0.0" ..<
  "4.0.0"`, and swift-nio-ssh and swift-container-plugin `..< "5.0.0"`, so
  a 5.0.0 floor left this package unresolvable next to them. The one call,
  `SHA256.hash(data:)`, is the same from 3.0.0 on, and 3.0.0 has no
  dependencies of its own. `swift-crypto-floor` (below) is what makes the
  3.0.0 floor a tested claim.
- **The floor is WasmKit 0.4.1, not the plan's 0.4.0.** 0.4.1 (tagged
  2026-09-29) fixes a use-after-free under software bounds checking: the
  interpreter kept its cached memory base across a host call, and a host
  function that re-enters the guest and grows its memory (random-get does
  exactly that, through `cabi_realloc`) left the next load reading freed
  memory. 0.4.0 must not be resolvable.
- `Package.resolved` pins WasmKit 0.4.1 and swift-crypto 5.0.0 and, because
  their manifests declare them, swift-argument-parser 1.8.2, swift-syntax
  604.0.0 and swift-asn1 1.7.3. None of those three is compiled for this
  package's product (only WasmKit's CLI and WIT tools use the first two,
  only swift-crypto's `CryptoExtras` the third), but SwiftPM resolves them,
  so a clean build fetches swift-syntax (about 40 MB of git history into the
  SwiftPM cache). On Linux, `Crypto` compiles swift-crypto's vendored
  BoringSSL; on Apple platforms it is CryptoKit.
- **Every Swift job copies the module into
  `swift/Sources/ApplePurchaseReceiptVerifier/Resources/aprv.wasm` before
  building** (gitignored on the lane branch per the owner's 100 KB rule;
  SwiftPM refuses to build without the declared resource), and the copy must
  match `aprv.wasm.sha256`. A job that tests the module `rust-wasm` built
  writes that build's hash into `aprv.wasm.sha256` in its own checkout (the
  sha256sum line, `<hex>  aprv.wasm`), as `refresh-wasm-copies` will.
- `aprv.wasm.sha256` (committed) pins the G1c module, the final one before
  integration (`rust-core` b863252), 2,760,476 bytes, `a35b9fce...40a1`.
  The module itself stays uncommitted on the lane branch; the integrator
  commits the release module and its pin together.
- `Resources/licenses/` holds the licence texts of the code compiled into the
  module (OpenSSL, wasi-libc with musl, the Rust standard library), copied
  from the Node host's `node/licenses/`, and ships as a resource.
- The hand-written verifier is gone. The last commit that has it is the
  lane's branch point `9ffbf70`; use it as the oracle and as the source of
  the port-only tests (Phase 7 step 1). `swift/Sources/.../certs` is gone
  since Phase 7 (below).

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
| `swift-crypto-floor` (new) | the manifest's swift-crypto floor, on Linux in the 6.3 container: `swift package resolve --force-resolved-versions` checks out the committed pins, `swift package resolve swift-crypto --version 3.0.0` moves that one pin (the subcommand only moves a dependency the workspace already holds, hence the first resolve; swift-asn1 drops out, since 3.0.0 does not depend on it), a grep checks that the pin records 3.0.0's commit `629f0b679d0fd0a6ae823d7f750b9ab032c00b80`, then the `swift` job's debug build and release tests run with `--force-resolved-versions`. The committed `Package.resolved` stays at the newest release. |
| `swift-macos` | `runs-on: macos-15` (or `macos-latest` as long as it is 15+ with Xcode carrying Swift 6.3+), the same command. |
| `swift-ios` (new) | the iOS compile the plan asks for, which cannot be done on Linux: on `macos-15`, `xcodebuild build -scheme ApplePurchaseReceiptVerifier -destination 'generic/platform=iOS' -skipPackagePluginValidation` (the library product's scheme; `xcodebuild -list` names it if SwiftPM spells it differently). It proves the package and WasmKit compile for iOS 18 with the software bounds checking the package selects (mprotect is compiled only for Linux and macOS). Nothing runs on a device. |
| `swift-format` | unchanged command; `swift format lint --strict --recursive swift/Sources swift/Tests` (6.3.3) is clean on this branch. |
| `swift-fuzz` | the targets are now `receipt-der`, `receipt-base64`, `jws` and `endpoint-json` (`receipt-payload` and `readers` went with the hand-written parsers); `run.sh` no longer passes `-enable-testing`. With the round-13 stand-in the `requireNoInternalError` invariant fired at once (its 0.6 wire); with the G1 module the wire is the one this package reads, so the job can run again once the module is copied into place first. `swift/bench` still builds with `swift build --package-path swift/bench --force-resolved-versions`; its manifest is tools 6.3 now. |
| `smoke-swiftpm` | image to `swift:6.3@sha256:56ef1be2...`. `.github/smoke/swiftpm-smoke/Package.swift`: `swift-tools-version:6.3`, `platforms: [.macOS(.v15), .iOS(.v18)]`. `Sources/Smoke/main.swift`: `config.roots.count == 3` no longer compiles; the defaults are `roots == nil` (the module's built-in roots), so replace the check with `guard config.roots == nil`. The rest (g5 verifies, one flipped signature bit is `INVALID_SIGNATURE`) stands. |
| post-publish `swiftpm` | same image and smoke changes. |
| `wasm-copies` | for Swift: `cd swift/Sources/ApplePurchaseReceiptVerifier/Resources && sha256sum -c aprv.wasm.sha256`, and the hash in that file must equal the build's. The package checks the pair when it loads the module, so a copy swapped without its hash file answers `INTERNAL_ERROR` to every call (and `Verifier(config:)` over the caller's own roots throws). |
| `release-please.yml` `refresh-wasm-copies` | **must also rewrite each copy's `.sha256`**: today it copies `aprv.wasm` over every committed copy and leaves `aprv.wasm.sha256` stale, which breaks both the Go and the Swift package on the release branch. For each copy `f`: `printf '%s  aprv.wasm\n' "$WASM_SHA256" > "$f.sha256"`, and add those files to the commit. |
| `one-implementation` | add `swift` to `--enforce`. `swift/Sources` imports Foundation, WasmKit and, in `Host/AprvModule.swift` only, `import struct Crypto.SHA256` for the SHA-256 that checks the module, the one entry in the gate's Swift allowlist. The crypto bans live in the gate alone; `SourceIsolationTests` checks other things: that no source names a network API or a trust store, and that WasmKit and swift-crypto are the only dependencies. |
| `dependabot.yml` | the three `swift` entries stay, and now watch swift-crypto and the swift-asn1 it brings into `Package.resolved` as well as WasmKit; the swift-certificates history goes. Add an ignore for WasmKit `>= 0.5.0` only if 0.5 raises a floor; 0.4.x patch releases should arrive (0.4.1 was a security fix). |
| `certs` job (`check-cert-copies.mjs`) | the Swift copy is gone in Phase 7 (below); the job needs no change. |

## The gate, in one command

`swift/scripts/gate.sh DIR [--pin] [--bench]` runs everything this lane
checks against one module build, where `DIR` has the corpus archive's
layout (`aprv.wasm`, `aprv.component.wasm` and `aprv.wit` with their
`SHA256SUMS`, `calls/<corpus>.pinned.jsonl`, `rows/module-<corpus>.jsonl`,
`same.py`): it checks the module against the pin (`--pin` accepts another
module), puts it in place with `.github/scripts/place-module.sh` for this
run only, builds optimised, runs the whole suite with every shared case, runs
the five corpora through the package's host layer
(`MeasurementTests.testCorpus`, the `Guest` the `Verifier` uses) and
compares each corpus's rows byte for byte with the module's reference rows,
and with `--bench` times the public API. `SCRATCH_PATH` and `OUT` set the
build and output directories. The corpus is scratch data, not in the
repository, so the corpus step is a manual or nightly job, not a push gate.

G1c (2026-09-29): 377 of 377 cases, the whole suite green (59 tests, 2
measurement tests skipped), 6,179 of 6,179 corpus rows identical to the
module's reference rows, 0 traps.

G1d (2026-09-29, the final module, pin `4e9d2d85...dd`): 384 of 384 cases,
the whole suite green (60 tests, 2 measurement tests skipped), 6,179 of
6,179 corpus rows identical to the module's reference rows, 0 traps, with
no wrapper change.

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

## Phase 7

`swift/Sources/ApplePurchaseReceiptVerifier/certs` is gone, with the
`exclude: ["certs"]` line in the root `Package.swift`: the library had not
read it since the WasmKit host landed (`Config().roots` is `nil`,
the module's compiled-in roots). The README's SwiftPM line now reads
`from: "0.8.0"`, the first release built this way.

| Where | Change |
|---|---|
| `ci.yml` | nothing: no job generated or diffed the Swift copy beyond `check-cert-copies.mjs`, which no longer finds it. |
| `one-implementation` | nothing: `swift/Sources` has no allowlist entry and no hit. |


## macOS arm64: the interpreter loop

The first `swift-macos` run (macos-26, Xcode 26.6, Swift 6.3.3, WasmKit
0.4.1, release build) died in the first test: `Execution.swift:470`, WasmKit's
`runRoot`, reported `-[_ContiguousArrayStorage<ValueType> domain]:
unrecognized selector`, then signal 11. An `Error` value that was really an
array of WasmKit's `ValueType` reached code that bridged it to `NSError`.
The failing test's own steps are not involved: it was the first guest call
of the process, and a refused configuration is a JSON answer, not a thrown
error or a trap. A trapped instance is never called again (`Guest.dead`).

The same release build passes on Linux x86-64, and so does a release build
with AddressSanitizer (`--sanitize=address`, `AbiTests`: no memory error).
WasmKit's own CI runs its macOS tests in debug only. The one place WasmKit
turns a raw pointer into a Swift `Error` is its direct-threaded loop
(`runDirectThreaded`: `unsafeBitCast(rawError, to: Error.self)` after the C
handlers return), the default on x86-64 and arm64. The package now picks
the token-threaded loop, which is plain Swift, everywhere except Linux
x86-64 (`AprvModule.threadingModel`), and a test pins the choice per
platform. `MeasurementTests.testSpeed` with `APRV_BENCH_THREADING` compares
the two loops on one machine: on Linux x86-64 the token loop verified g5 at
24 per CPU-second against 48 and the JWS at 6 against 10. Whether the token
loop clears macOS is shown by the next `swift-macos` run, not here.
