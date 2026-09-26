# Migration plan

Target: [ARCHITECTURE.md](./ARCHITECTURE.md). Choices:
[DECISIONS.md](./DECISIONS.md). Starting point: [INVENTORY.md](./INVENTORY.md).

Rules for every phase:

- **No old implementation leaves before its replacement passes its gate.**
  Until then it is a differential oracle.
- **A divergence is a finding.** Investigate it, and add a
  `fixtures/cases.json` case that pins the right answer. Never edit a vector
  to make a binding pass. A divergence from the Java reference is recorded
  in R20; one that changes an Apple-signed input's verdict, or accepts
  something unsigned, is a bug (R20).
- **One phase, one or more PRs, one release at most.** Maven Central allows
  7 releases a month, and every tag spends one. Keep 2 in reserve.
- Estimates are ranges. The deciding factor is named next to each.
- Version numbers below show the sequence. release-please picks the real
  ones from the commits.

## Phase 0: inventory and spikes (done)

INVENTORY.md and the
[spike evidence](../evidence/2026-09-25-rust-core-spikes.md). The spikes
answered the four blocker questions from the brief. The substrate rounds
of 2026-09-26 (listed under R21) then moved the core onto OpenSSL and
changed the wasm answers:

| Blocker question | Answer |
|---|---|
| Can Java 8 use UniFFI Kotlin acceptably? | Yes, if the surface has no unsigned integers |
| Does the core compile for the wasm targets? | With OpenSSL (R21): not for `wasm32-unknown-unknown`, where `openssl-sys` does not compile. Yes for `wasm32-wasip1` with wasi-sdk's libc and a link-time C file; the module then imports only `aprv.clock_now_ms` and `aprv.random_get`, and the clock goes through a seam (R10) |
| Does every current JS runtime load the wasm? | Node, Bun, Deno, workerd, Chromium, Firefox and WebKitGTK: yes, 1,179 of 1,179 rows the same as native ([OpenSSL CMS everywhere §2](../evidence/2026-09-26-openssl-cms-everywhere.md)). Fastly JS and Akamai: no (R5) |
| Can UniFFI model the API? | Yes. Records, enums, errors, optional args and objects all worked |

## Phase 1: make the core ready to be the only implementation

Estimate: 2 to 6 weeks. The owner's review pace decides it. The code work
now includes the OpenSSL adapter and the per-target OpenSSL builds (R21,
R12).

| Step | Work | Verify |
|---|---|---|
| 1.1 | **OpenSSL substrate (R21).** Add the `aprv-openssl` adapter crate, the only `unsafe` crate below the bindings: the CMS path (`CMS_SignerInfo_cert_cmp`, `CMS_SignerInfo_verify`, `CMS_SignerInfo_verify_content`), `X509_verify_cert` over the pinned roots only with the historical-time verify callback, EVP for JWS, and the payload through `payload.c`'s ASN.1 templates and `ASN1_item_d2i`. Move receipts, JWS and the device hash onto it. Delete `rust/src/cms.rs`, `x509.rs`, `chain.rs`, `crypto.rs` and `asn1.rs`, the public modules of the same names, `TrustAnchor::certificate()`, and the `rsa`, `p256`, `p384`, `sha1`, `sha2` and `digest` dependencies; `roots.rs` keeps the DER after `d2i_X509`. Rewrite `tests/common` and the five test files that use the deleted modules (`tests/asn1.rs`, `hostile.rs`, `receipt_negative.rs`, `trust_pinning.rs`, `jws_negative.rs`; [ASN.1 payload note §1](../evidence/2026-09-26-openssl-asn1-payload.md)). | `cargo test` green; nothing named `asn1` left in `rust/src`; `cases.json` passes through the C ABI; the evidence's 1,179-row corpus answers as the payload note's template build did |
| 1.1a | **Native OpenSSL build.** OpenSSL 4.0.2 through `openssl-src` 400.x with a one-line `[patch.crates-io]` of `openssl-sys`'s manifest until upstream accepts 400.x, or `OPENSSL_DIR`. Set `OPENSSL_CONFIG_DIR` to a path that does not exist. | The vendored and `OPENSSL_DIR` builds give identical rows (as in [OpenSSL CMS everywhere §1](../evidence/2026-09-26-openssl-cms-everywhere.md)); the isolation test finds no config or trust file opened |
| 1.2 | Add the `system_now()` seam; on wasm it reads the `aprv.clock_now_ms` import, declared in the adapter (R10, SURFACE.md §4.1). | `transaction/accept-payload-without-a-signed-date` passes in `aprv.wasm`; the 58 clock-reading rows of the wasm bake-off do not trap |
| 1.3 | New CI job `rust-wasm`: build `aprv.wasm` (the C ABI for `wasm32-wasip1`, wasi-sdk's libc, OpenSSL 4.0.2 compiled by wasi-sdk, the link-time C file whose WASI stubs trap), then run the full conformance suite and corpus on every change through a host that traps on any unexpected import. | All cases; no trap; the module's imports are exactly `aprv.clock_now_ms` and `aprv.random_get` |
| 1.4 | Make `rust/` a Cargo workspace (core, adapter, ffi, bindings). | `cargo test --workspace --locked` |
| 1.5 | Create `aprv-surface` (generator-free, SURFACE.md) and `aprv-wire` (the JSON view moved out of `rust/ffi`). Add `tools/check-layering.mjs`, the C ABI lints and `CAPABILITIES.toml` (SURFACE.md §7). | The C ABI's C++ and ctypes conformance pass unchanged; the layering check passes, and fails on a planted `uniffi` dependency in the core and on a planted `asn1` module |
| 1.6 | Close the C ABI gaps from PORTS.md: `verified` flag, re-render, `REQUEST_TOO_LARGE`, base64 decode entry point, fuzz target. | The C ABI runs the `decodeBase64` groups; its PORTS.md row is all ✅ |
| 1.7 | Profile receipt and JWS on native and in `aprv.wasm`. Record the results in BENCHMARKS.md, including a JWS row, which exists in no port today. Speed is informational (R21). | The numbers are committed with their method |
| 1.8 | **Differential campaign:** replay every port's fuzz corpus (Rust, Jazzer, atheris, go-fuzz, Jazzer.js, libFuzzer Swift, ruzzy, SharpFuzz, PHP) through the Rust core and the port. Compare `reason`. Include the Native Image spike's corpora (811 hostile inputs, 22 signature algorithm inputs) and its JVM-versus-C-ABI harness, pointed at the published 0.7.x jar from Maven Central, pinned by version and checksum (R8). | Every divergence is in R20's recorded list with its reason. None changes an Apple-signed input's verdict or accepts something unsigned; one that does is a bug and gets fixed. Each one found becomes a case where the answer is part of the contract. |
| 1.9 | **Owner review of the core**, module by module, the adapter's `unsafe` and the two C files included. The checklist maps each THREAT-MODEL §3 mitigation to its code and test. The log lives in `docs/rust-core/REVIEW-LOG.md`. | Every module signed off |
| 1.10 | **Test inventory.** List every behavior test that exists in only one port's suite (Java, Node, Python, Swift, Go, Ruby, PHP, .NET), deduplicated against `fixtures/cases.json` and each other. Tests about a binding's own API shape, concurrency or packaging stay with the binding and are marked so. | The inventory is committed; every entry names its target case or says "stays with the binding" |
| 1.11 | **Fuzzing.** Drop `parse-der`, `parse-certificate` and `parse-cms` with the modules they fuzzed; keep `verify-receipt` and `verify-transaction`. Add a scheduled CI fuzz job over an OpenSSL build instrumented with ASan and libFuzzer coverage, so the fuzzer reaches into OpenSSL too. The evidence ran 4 × 45 min and 2 × 45 min campaigns this way and found nothing ([follow-up §4.2](../evidence/2026-09-26-substrate-followup.md), [OpenSSL CMS everywhere §4](../evidence/2026-09-26-openssl-cms-everywhere.md)). | The job runs on schedule; a finding opens an issue with the reproducer (test keys only) |
| 1.12 | **Each R12 target with OpenSSL** (open item the owner deferred, R12). Build OpenSSL and the C ABI for every target and run at least the smoke test there; this can land here or in CI before 0.8.0. | Every target green, or dropped under R12's "Out" with the reason |
| 1.13 | **Private-receipt drift check** (owner, 2026-09-26). A local-only script reads receipts from a folder outside the repository, runs the verifier, and prints only verdicts and unknown attribute type numbers: no values, nothing personal. Production receipts never enter the repository, its history, CI, issues or PRs (CLAUDE.md). The owner runs it about monthly, or hands receipts to an AI agent session that keeps them in a scratch folder only. A new attribute type found this way becomes a test built from a generated receipt with the same shape. | The script exists and runs on a folder of generated receipts; its output holds no receipt values |

**Gate G1:**
- conformance green on native and in `aprv.wasm` on the trap host;
- `aprv.wasm` imports exactly `aprv.clock_now_ms` and `aprv.random_get`;
- the differential campaign is closed: every divergence recorded in R20,
  none of them a bug under R20's rule;
- the review log is complete;
- the test inventory (1.10) exists.

Release: none. Phase 1 touches only the Rust crate and the C ABI, and
neither is on a registry (the crates.io debut waits, R19). Nothing changes
for the five live packages (Maven, npm, PyPI, SwiftPM, Go). The owner's
0.7.0 fix from `main` is not part of the migration.

## Phase 2: UniFFI binding and the Python package

Estimate: 1 to 2 weeks. The wheel matrix on Windows ARM and musl decides
it.

| Step | Work | Verify |
|---|---|---|
| 2.1 | `aprv-uniffi` exposes the whole surface (ARCHITECTURE §3). `uniffi.toml` sets names per language. | `uniffi-bindgen generate` for Kotlin, Swift and Python in CI; a public-API dump diffs clean |
| 2.2 | `python/` becomes a maturin project (`bindings = "uniffi"`). The wheel matrix follows R12. | Wheels build on every target |
| 2.3 | Rewire `test_conformance.py` and the other suites to the binding. `test_trust_isolation.py` now asserts an empty runtime-dependency set. | 186/186 on CPython 3.10 to 3.14 |
| 2.4 | Clean-install smoke: fresh venv, install the built wheel (never the source tree), run the genuine receipt. Add an AlmaLinux 9 leg with the SHA-1 legacy receipt. | Green on Linux glibc/musl, macOS and Windows; RHEL 9 no longer fails |
| 2.5 | Differential: PyPI 0.6.0 against the new wheel on all cases and the atheris corpus. | Same `reason` everywhere |
| 2.6 | Move Python's port-only behavior tests into `fixtures/cases.json` (step 1.10's list), then delete the hand-written Python verifier. Keep `python/fuzz`, now aimed at the binding (it proves the binding never crashes the interpreter). | Every 1.10 entry for Python is a case or marked "stays with the binding"; CI green |

**Gate G2:** as in the table, plus a post-publish smoke from real PyPI on
3.10.

Release: none on its own; ships in 0.8.0 with every other package
(R19). The CHANGELOG marks it breaking because `cryptography` and
`asn1crypto` are gone and dates or ids may change shape.

## Phase 3: Java through UniFFI Kotlin

Estimate: 1 to 2 weeks. The Alpine/JNA question and the façade size
decide it.

| Step | Work | Verify |
|---|---|---|
| 3.1 | The Maven build compiles the generated Kotlin (`jvmTarget 1.8`, `-Xjdk-release=1.8`, `disable_java_cleaner`), then packs natives from the R12 matrix into the JNA resource paths. | The jar lists all 18 R12 JVM native paths; `javap` shows major 52 |
| 3.2 | Java façade only where R13 allows. | Façade diff reviewed for zero logic; the one-implementation grep passes |
| 3.3 | Port the JUnit suites (conformance, trust isolation, hostile, caps). | 186/186 |
| 3.4 | Keep every JVM leg: `java-runtime-8` on real Temurin 8, JDK 11-26, distroless ×4, Spring Boot 4.0/4.1, `jvm-interop` (Kotlin, Scala). | All green |
| 3.5 | Native-access legs on JDK 25/26: default (one warning, documented), `--enable-native-access=ALL-UNNAMED` (silent), `--illegal-native-access=deny` (documented failure). | Output asserted |
| 3.6 | Alpine leg (musl) with the library override. | Genuine receipt verifies on `eclipse-temurin:21-alpine` |
| 3.7 | Move Java's port-only behavior tests into `fixtures/cases.json` (step 1.10's list), then delete the hand-written Java verifier. No copy of its source stays (R8): the differential job runs the Native Image spike's harness against the published 0.7.x jar, downloaded from Maven Central and pinned by version and checksum. | Every 1.10 entry for Java is a case or marked "stays with the binding"; the differential job runs nightly; the one-implementation grep passes |

**Gate G3:** as in the table, plus a post-publish smoke from real Maven
Central, compiled and run on Temurin 8.

Release: none on its own; ships in 0.8.0 (R19).

## Phase 4: npm through the plain wasm module

Estimate: 1 to 3 weeks. The façade (keeping the options API) and the
runtime matrix decide it.

| Step | Work | Verify |
|---|---|---|
| 4.1 | Package `aprv.wasm` (step 1.3) with a hand-written JS façade of about 100 lines and a hand-written `index.d.ts` (R21, ARCHITECTURE §6.4). The façade supplies `aprv.clock_now_ms` and `aprv.random_get` (`crypto.getRandomValues`, never `Math.random`) and refuses any other import. | Façade diff reviewed for zero logic; the wasm size budget is set from the first real build |
| 4.2 | Package layout and `exports` conditions (ARCHITECTURE §6.4). The façade has trap recovery. | `npm pack` content check in release, OpenSSL and wasi-libc license texts included; `publint`-style exports check in CI |
| 4.3 | Conformance through the package on Node 20/22/24/26. Runtime smokes: Bun, Deno, workerd ×3, `@edge-runtime/vm`, and headless Chromium, Firefox and WebKit (new). | 186/186 on Node; the genuine receipt and JWS on every runtime |
| 4.4 | Forced-trap test: an adapter-only debug export panics, the façade recovers, and the next call succeeds. A second test, on a debug build, calls one of the stubbed WASI functions and checks that it traps and that the façade recovers. | Tests green |
| 4.5 | Drop Fastly and Akamai (R5): the job, README rows and SUPPORT-MATRIX rows. | CHANGELOG breaking note |
| 4.6 | Publish the Node numbers. Apply R4 (its trigger is an open owner question). | BENCHMARKS.md updated |
| 4.7 | Move Node's port-only behavior tests into `fixtures/cases.json` (step 1.10's list), then delete `node/src` verifier code. Keep the conformance and runtime smokes. | Every 1.10 entry for Node is a case or marked "stays with the binding"; the one-implementation grep finds no `node:crypto` or `crypto.subtle` |
| 4.8 | Once the migration is on main, report Bun's WASI `random_get` bug upstream (Bun 1.3.11 returns the wrong value and overwrites module memory). Recheck on the current Bun first. Repro: [bun-random-get.mjs](../evidence/2026-09-26-security-substrate-bakeoff/wasm/bun-random-get.mjs). | Issue link recorded here, or "fixed in Bun x.y" |
| 4.9 | **Memory in workerd** (R21, owner Q32). Run the hostile 3 MiB receipt of tiny attributes through the package in workerd, whose isolate limit is 128 MB. The evidence measured 145 MiB peak in Route C on Node against 67 MiB for a tiny receipt ([ASN.1 payload note §3](../evidence/2026-09-26-openssl-asn1-payload.md)). | The peak and the outcome are recorded in BENCHMARKS.md; if the isolate fails, the failure is closed (an error, never an acceptance) and the owner decides what follows |

**Gate G4:** as in the table, plus a post-publish smoke from real npm on
Node 20 and in workerd.

Release: none on its own; ships in 0.8.0 (R19).

## Phase 5: Swift

Estimate: 1 to 3 weeks. The Linux spike already passed on Swift 6.2.4
and 6.4 (evidence row 14); Windows (5.6) is the unmeasured part.

| Step | Work | Verify |
|---|---|---|
| 5.1 | **Linux spike first:** Rust staticlib in an SE-0482 artifact bundle, consumed by a Swift 6.2 package in the `swift:6.2` container. Check the `llvm-objdump` dependency audit against Rust's `libgcc_s`/unwind and pthread references. | A consumer links and verifies the g5 receipt. If it fails, stop and report before step 5.2. |
| 5.2 | Build the XCFramework (macOS arm64/x86_64) and the Linux static slices. Localize every symbol that is not `uniffi_*`/`ffi_*`. | The exported-symbol list matches an allowlist |
| 5.3 | Commit the generated Swift. `Package.swift` gets a `binaryTarget(url:checksum:)`. Floor: tools 6.2. | Regenerate-and-diff gate |
| 5.4 | `release-please.yml` builds the bundle on the release PR branch and commits the checksum. `release.yml` uploads the identical file. | A dry-run release on a fork resolves the checksum |
| 5.5 | Port `ConformanceCasesTests` and the trust and concurrency tests. Keep `async` only where the façade needs it (the Rust calls are sync). | 186/186 on Linux 6.2/6.3 and macOS |
| 5.6 | **Windows (R12):** a `swift-windows` CI leg on `windows-latest` and `windows-11-arm` with Swift 6.2 from swift.org consumes the artifact bundle's Windows `.lib` slices and runs the conformance suite. | 186/186 on both. If SwiftPM on Windows cannot link the bundle, Windows leaves the Swift package's claims and R12 records why. |
| 5.7 | Move Swift's port-only behavior tests into `fixtures/cases.json` (step 1.10's list), then delete the hand-written Swift verifier. | Every 1.10 entry for Swift is a case or marked "stays with the binding"; the one-implementation grep finds no `X509`, `_CryptoExtras` or `SwiftASN1` imports |

**Gate G5:** as in the table, plus a post-publish smoke with `swift run
Smoke` from the real tag.

Release: none on its own; ships in 0.8.0 (R19).

## Phase 6: Go (assumes R6 = wazero)

Estimate: 1 to 2 weeks. The instance pool and the JSON mapping onto the
existing Go types decide it.

| Step | Work | Verify |
|---|---|---|
| 6.1 | Go loads the same `aprv.wasm` that npm ships (built in step 1.3, R21). Go supplies its two imports: `aprv.clock_now_ms` from the wall clock and `aprv.random_get` from `crypto/rand`; any other import is refused. | The module instantiates in wazero with exactly those two imports; the corpus runs the same as native, as it did on wazero in the evidence |
| 6.2 | Go wrapper: `//go:embed aprv.wasm`, compile once, `sync.Pool` of instances, a discarded instance after a trap, JSON decode into today's Go types. | `go test -race`, 186/186 |
| 6.3 | Commit `aprv.wasm` (about 3 MB raw). A `go-wasm-reproducible` job rebuilds it with the pinned wasi-sdk and OpenSSL and compares the SHA-256. | Hash match |
| 6.4 | Keep `go-platforms` (macOS, Windows). Add a `CGO_ENABLED=0` build and a `FROM scratch` smoke. | Green |
| 6.5 | Raise the `go.mod` floor to what wazero requires. Update SUPPORT-MATRIX. | The floor leg runs |
| 6.6 | Move Go's port-only behavior tests into `fixtures/cases.json` (step 1.10's list), then delete the Go verifier. | Every 1.10 entry for Go is a case or marked "stays with the binding"; the one-implementation grep finds no `crypto/x509` or `crypto/rsa` in `go/` |

**Gate G6:** as in the table, plus a post-publish smoke with `go get` from
the proxy.

Release: none on its own; ships in 0.8.0 (R19).

## Phase 7: remove what is left, rewrite the rules

Estimate: 3 to 5 days.

1. Move the port-only behavior tests of Ruby, PHP and .NET into
   `fixtures/cases.json` (step 1.10's list). Then delete `ruby/`, `php/`,
   `dotnet/` and root `composer.json`, with their CI jobs, dependabot
   entries, release-please extra files, `certs` copies, BOOTSTRAP.md
   sections and post-publish legs. Use one commit per port (R9).
2. Shrink `check-cert-copies.mjs` to `rust/certs`. Delete
   `node/scripts/gen-roots.mjs` and `node/src/roots-data.ts`.
3. Rewrite CLAUDE.md:
   - "The nine implementations are one product" becomes "one
     implementation, bindings test the boundary";
   - update the certs-copy invariant and the "one version, N files" list;
   - add "bindings contain no verification logic";
   - add "generated outputs are regenerated in the same commit";
   - add the R21 invariants: no hand-written ASN.1, CMS or X.509; the
     adapter is the only `unsafe` crate below the bindings; `aprv.wasm`
     imports exactly two functions; the OpenSSL version and tarball hash
     are pinned in one place.
4. Rewrite CONTRIBUTING.md (how to change behaviour now), PORTS.md (it
   becomes a binding-capability table), SUPPORT-MATRIX.md, THREAT-MODEL.md
   (the new boundaries: OpenSSL in the trusted base, the adapter's
   `unsafe`, UniFFI, `aprv.wasm` and its two imports, JNA, native
   artifacts) and
   PLAN.md (D17 onward from DECISIONS.md, D16 marked superseded).
5. Turn on the final gate: a CI job that fails if any published package
   source imports a crypto, X.509 or ASN.1 API.

**Gate G7:** that job green, the docs merged, ROADMAP items deleted as they
ship.

## CI changes

| Job | Change |
|---|---|
| `rust`, `rust-lint`, `rust-fuzz`, `rust-supply-chain` | Workspace-wide. cargo-deny also covers the binding crates and the adapter. `rust-fuzz` loses `parse-der`, `parse-certificate` and `parse-cms` (R21). |
| `rust-fuzz-openssl` (new, scheduled) | `verify-receipt` and `verify-transaction` over an OpenSSL build instrumented with ASan and libFuzzer coverage (step 1.11). Needs nightly for `-Zsanitizer`, like the evidence campaigns. |
| `rust-ffi` | Stays on ubuntu, macOS and Windows. Builds the C ABI, with OpenSSL linked statically, from the workspace. Adds the OpenSSL isolation test (planted `SSL_CERT_FILE`, `SSL_CERT_DIR`, `OPENSSL_CONF`). |
| `rust-wasm` (new) | Builds `aprv.wasm` (`wasm32-wasip1`, wasi-sdk, OpenSSL 4.0.2) and runs the full corpus on every change through a host that traps on any unexpected import; any trap or any row that differs from native fails. Checks the import list is exactly `aprv.clock_now_ms` and `aprv.random_get`. |
| `java-reference` (new, nightly) | The Native Image spike's harness: the corpus through the published 0.7.x jar (pinned version and checksum) and the Rust core. New differences go to R20 (R8). |
| `bindings-generate` (new) | Pinned uniffi and cbindgen. Regenerate Swift, the header and Go's `aprv.wasm`, then diff. Public-API dumps diff. |
| `native-artifacts` (new, test build) | The R12 matrix, each target building OpenSSL too (step 1.12). Build and smoke-load on each runner. Test jobs may cache. |
| `one-implementation` (new) | Grep gate from ARCHITECTURE §8. |
| `python`, `java*`, `node*`, `swift*`, `go*` | Same matrices, now testing the binding. Add Alpine legs (Java, Python) and a browser leg (npm). |
| `node-runtimes-fastly` | Removed (R5) |
| `java-hardened-policy` | Kept as proof: the verdict no longer depends on host policy |
| `ruby*`, `php*`, `dotnet*`, `elixir-ffi` | Ruby, PHP and .NET go in Phase 7. `elixir-ffi` stays as a C ABI example. |
| Fuzz jobs of removed ports | Removed. Per-binding fuzz jobs stay where they test the boundary (Jazzer, atheris, Jazzer.js). |
| `zizmor` | Stays at 0 findings. New jobs follow the same pinning and `persist-credentials: false` rules. |

ROADMAP's "Smarter CI" item (path filters, one aggregate job) fits here:
with one core, a change under `rust/` triggers every binding, and a change
under `node/` triggers only npm.

## Release workflow changes

- `release.yml` keeps its filename: npm, PyPI, RubyGems, crates.io and
  NuGet trusted publishing match it.
- A new `build-natives` job in `release.yml` builds every R12 target with
  **no cache**, attests each artifact, and hands them to the publish jobs as
  workflow artifacts. Artifacts from `ci.yml` never feed a publish. Each
  target builds OpenSSL 4.0.2 from the pinned source (`openssl-src` 400.x
  or a checked tarball through `OPENSSL_DIR`), with `OPENSSL_CONFIG_DIR`
  set to a path that does not exist.
- A new `build-wasm` job builds `aprv.wasm` once, with no cache: wasi-sdk
  (pinned by SHA-256; wasi-sdk 34 publishes no checksum, so the first
  download sets the hash) and OpenSSL 4.0.2 compiled by it. npm ships that
  file, and the job fails unless its SHA-256 equals Go's committed copy.
- Every package that carries OpenSSL ships its license and NOTICE text;
  `aprv.wasm` adds wasi-libc's and Rust std's (R12). The package-content
  checks fail when one is missing.
- Per publish job:
  - `publish-pypi` uploads the maturin wheels plus the sdist;
  - `publish-maven` assembles the jar from those natives;
  - `publish-npm` packs `aprv.wasm` from `build-wasm` with the hand-written
    façade (no native targets);
  - `publish-crates` publishes the core;
  - a new `release-assets` job with `contents: write` uploads the Swift
    bundle and the C ABI archives to the GitHub Release.
- `release-please.yml` gains two steps on the release branch, next to the
  existing lockfile refresh:
  - build the Swift bundle and write its checksum into `Package.swift`;
  - stop refreshing `rust/ffi/Cargo.lock` once the workspace lands (one
    lockfile, `rust/Cargo.lock`);
  - rebuild and check the Go `aprv.wasm`.
- `release-please-config.json`:
  - drops `ruby/.../version.rb` and `dotnet/Directory.Build.props` in
    Phase 7;
  - adds the version fields of new manifests, such as `python/Cargo.toml`
    if maturin needs one;
  - `rust/Cargo.toml` stays.
- `post-publish-smoke.yml`: the legs stay and test the real registries.
  Remove RubyGems and NuGet in Phase 7. Add a C ABI archive leg (download
  from the Release, verify the attestation, run the C example).

## Acceptance tests for the finished migration

The migration is finished when every line below holds on the default
branch.

1. `one-implementation` finds no crypto, X.509 or ASN.1 API in `java/`,
   `node/`, `python/`, `swift/` or `go/` outside test code.
2. `rust/src` still has `#![forbid(unsafe_code)]` and the same lint wall,
   and no `asn1`, `x509`, `cms`, `chain` or `crypto` module. `unsafe`
   exists only in the OpenSSL adapter, `rust/ffi` and
   `rust/bindings/wasm`, each listed in THREAT-MODEL.
3. Every published package passes 186/186 `fixtures/cases.json` cases
   through its binding.
4. Java: a Temurin 8 program compiles against the published jar and
   verifies the g5 receipt, and JDK 11 to 26 pass. Native-access behaviour
   is asserted and documented.
5. Python: a wheel from real PyPI verifies the g5 receipt on 3.10 in a
   clean venv, on glibc, musl, macOS and Windows.
6. npm: one package from real npm verifies the g5 receipt on Node 20, Bun,
   Deno, workerd, Chromium, Firefox and WebKit. Its `aprv.wasm` imports
   exactly `aprv.clock_now_ms` and `aprv.random_get`, and the full corpus
   passes on the trap host.
7. Swift: `swift run Smoke` from the real tag verifies it on Linux (6.2)
   and macOS.
8. Go: `go get` from the proxy with `CGO_ENABLED=0` verifies it.
9. C ABI: the header regenerates without a diff, and the exported symbols
   match the header. C++ and ctypes conformance pass on three OSes (`rust-ffi`),
   and the Elixir NIF example passes on Linux (`elixir-ffi`).
   The Release archive verifies against its attestation.
10. Differential: the Phase 1 campaign and each phase's old-against-new run
    are closed, every divergence recorded in R20 with its reason and none
    of them a bug under R20's rule. The `java-reference` job runs nightly.
    On the final tree, the Native Image spike's harness runs the same
    corpus (cases, 811 hostile inputs, 22 algorithm inputs) through the
    published 0.7.x jar from Maven Central, pinned by version and checksum,
    and through the Rust core. Every difference is one R20 records.
11. Docs: Rust doc comments show up in KDoc, Swift and Python `help()`
    (spot-checked in CI by grepping the generated output). The npm
    `index.d.ts` is hand-written and carries JSDoc for every export.
12. Every native and wasm artifact in a release has a SHA-256 and a
    provenance attestation, and every package ships OpenSSL's license and
    NOTICE text.
13. OpenSSL builds and the smoke test passes on every target R12 still
    lists (step 1.12).
14. Each port's behavior tests are in `fixtures/cases.json` or marked as
    staying with a binding (step 1.10), and the scheduled OpenSSL fuzz job
    has run (step 1.11).

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Wasm speed on Node (about 2x `node:crypto` per receipt, about 6x per JWS; R4) disappoints users | medium | medium | Publish the numbers; R4's trigger (an open owner question) |
| Go through wazero is about 12x slower per receipt than today's Go port (2,495 against 207 µs, different runs) | high (measured) | medium | R6 alternatives: the opt-in cgo fast path |
| An OpenSSL vulnerability affects the verification path | certain over time: OpenSSL publishes security advisories | high | The OpenSSL version and tarball hash are pinned in one place and watched (`openssl-src` bumps, OpenSSL advisories, RustSec for rust-openssl). A release picks up a fix by bumping the pin: every native target and `aprv.wasm` rebuild with no cache, and the conformance run and corpus must pass. That bump is a security bump of a shipped dependency, which CLAUDE.md's release budget counts as release-worthy; the budget keeps 2 Maven Central releases in reserve for it. |
| OpenSSL does not build or pass on some R12 targets | unknown: only Linux x86_64 built so far | medium | Step 1.12 before 0.8.0; a failing target leaves R12's list with the reason |
| `openssl-sys` keeps requiring `openssl-src` 300.x | medium | low in the workspace, medium for crates.io users | A one-line `[patch.crates-io]` in the workspace; `OPENSSL_DIR` as the alternative. The patch does not reach crates.io users (R21 open item 3) |
| Static archives carry OpenSSL's symbols and collide with a consumer's own OpenSSL | unknown (unmeasured) | medium for `.a` and Swift users | Symbol localization and the exported-symbol check (ARCHITECTURE §6.3) cover OpenSSL's symbols too |
| A hostile 3 MiB receipt costs about +58 MiB over today's reader, which refused it (R21) | certain (measured) | low natively, unknown in workerd (128 MB isolate) | Bounded by the 3 MiB input cap; step 4.9 measures workerd |
| A wasi-sdk release renames the wasi-libc symbol the link-time C file defines | low | low | The link fails loudly with undefined imports, and the import check catches it (wasm bake-off §6) |
| Apple adds a receipt attribute | certain over time | low | It lands in `unknownAttributes`; the private-receipt drift check (step 1.13) reports new type numbers |
| JNA fails on Alpine (its own `jnidispatch`) | unknown | high for Alpine users | Phase 3.6 leg. Fallback: document `gcompat`, or add a musl-specific loader in the façade. |
| SE-0482 rejects Rust's staticlib dependencies on Linux | **resolved**: the spike linked and ran on Swift 6.2.4 and 6.4 | — | Keep a Linux consumer build in CI; strip the 50 MB static library before release |
| A wasm trap leaves an instance corrupted | low (lint wall) | medium | Trap recovery and a forced-trap test (ARCHITECTURE §5) |
| Monoculture: one Rust or OpenSSL bug hits every language | low-medium | high | R8 (the 0.7.x jar as reference), fuzzing into OpenSSL, owner review log, differential campaign |
| UniFFI is pre-1.0 and breaks between minors (0.32 changed byte buffers) | high | low-medium | Pin; upgrade in a dedicated PR with full conformance |
| Prebuilt binaries widen the supply-chain surface | certain | medium | No-cache release builds, attestations, reproducible Go wasm, SHA256SUMS, pinned OpenSSL and wasi-sdk hashes |
| Reproducible Rust builds across runners are harder than expected, now with C inside | medium | low | Pin the toolchain, wasi-sdk and OpenSSL, remap paths; worst case, build the Go wasm once in release and diff only in PR CI |
| Maven Central budget during the phased releases | low | medium | One release per phase, at most two phases a month |
| Owner review becomes the bottleneck | high | schedule only | Phase 1 is the critical path by design. Later phases touch no security code. |
