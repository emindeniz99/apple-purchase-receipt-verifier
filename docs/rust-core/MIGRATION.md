# Migration plan

Target: [ARCHITECTURE.md](./ARCHITECTURE.md). Choices:
[DECISIONS.md](./DECISIONS.md). Starting point: [INVENTORY.md](./INVENTORY.md).

Rules for every phase:

- **No old implementation leaves before its replacement passes its gate.**
  Until then it is a differential oracle.
- **A divergence is a finding.** Investigate it, and add a
  `fixtures/cases.json` case that pins the right answer. Never edit a vector
  to make a binding pass.
- **One phase, one or more PRs, one release at most.** Maven Central allows
  7 releases a month, and every tag spends one. Keep 2 in reserve.
- Estimates are ranges. The deciding factor is named next to each.
- Version numbers below show the sequence. release-please picks the real
  ones from the commits.

## Phase 0: inventory and spikes (done)

INVENTORY.md and the
[spike evidence](../evidence/2026-09-25-rust-core-spikes.md). The spikes
answered the four blocker questions from the brief:

| Blocker question | Answer |
|---|---|
| Can Java 8 use UniFFI Kotlin acceptably? | Yes, if the surface has no unsigned integers |
| Does the core compile for the wasm targets? | Yes, after dropping three `std` features; the clock needs a seam |
| Does every current JS runtime load the wasm? | Node, Bun, Deno, workerd: yes. Fastly JS and Akamai: no (R5) |
| Can UniFFI model the API? | Yes. Records, enums, errors, optional args and objects all worked |

## Phase 1: make the core ready to be the only implementation

Estimate: 2 to 6 weeks. The owner's review pace decides it; the code work
alone is about a week.

| Step | Work | Verify |
|---|---|---|
| 1.1 | Drop the `std` features on `rsa`/`p256`/`p384` (R11). | `cargo test` green, plus a new CI check that `cargo tree -i getrandom --target wasm32-unknown-unknown` finds nothing |
| 1.2 | Add the `system_now()` seam with the `js-clock` feature (R10). | `transaction/accept-payload-without-a-signed-date` passes on wasm32-unknown-unknown |
| 1.3 | New CI job `rust-wasm`: run the conformance suite on `wasm32-unknown-unknown` (Node runner) and `wasm32-wasip1` (wasmtime). | All 186 cases, both targets |
| 1.4 | Make `rust/` a Cargo workspace (core, ffi, bindings). | `cargo test --workspace --locked` |
| 1.5 | Create `aprv-surface`: binding-shaped types plus the JSON view moved out of `rust/ffi`. | The C ABI's C++ and ctypes conformance pass unchanged |
| 1.6 | Close the C ABI gaps from PORTS.md: `verified` flag, re-render, `REQUEST_TOO_LARGE`, base64 decode entry point, fuzz target. | The C ABI runs the `decodeBase64` groups; its PORTS.md row is all ✅ |
| 1.7 | Profile receipt and JWS on native and wasm. Record the results in BENCHMARKS.md, including a JWS row, which exists in no port today. | The numbers are committed with their method |
| 1.8 | **Differential campaign:** replay every port's fuzz corpus (Rust, Jazzer, atheris, go-fuzz, Jazzer.js, libFuzzer Swift, ruzzy, SharpFuzz, PHP) through the Rust core and the port. Compare `reason`. | Zero open divergences. Each one found becomes a case. |
| 1.9 | **Owner review of the core**, module by module. The checklist maps each THREAT-MODEL §3 mitigation to its code and test. The log lives in `docs/rust-core/REVIEW-LOG.md`. | Every module signed off |
| 1.10 | First crates.io publish (BOOTSTRAP.md steps). | `cargo add apple-purchase-receipt-verifier` works; post-publish smoke `crates` leg green |

**Gate G1:**
- conformance green on native and both wasm targets;
- the differential campaign is closed;
- the review log is complete;
- `getrandom` is absent from the wasm build.

Release: 0.7.0, which carries the C ABI fixes and the crates.io debut.
Nothing changes for the five live packages (Maven, npm, PyPI, SwiftPM, Go).

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
| 2.6 | Delete the hand-written Python verifier. Keep `python/fuzz`, now aimed at the binding (it proves the binding never crashes the interpreter). | CI green |

**Gate G2:** as in the table, plus a post-publish smoke from real PyPI on
3.10.

Release: 0.8.0, marked breaking in the CHANGELOG because `cryptography`
and `asn1crypto` are gone and dates or ids may change shape.

## Phase 3: Java through UniFFI Kotlin

Estimate: 1 to 2 weeks. The Alpine/JNA question and the façade size
decide it.

| Step | Work | Verify |
|---|---|---|
| 3.1 | The Maven build compiles the generated Kotlin (`jvmTarget 1.8`, `-Xjdk-release=1.8`, `disable_java_cleaner`), then packs natives from the R12 matrix into the JNA resource paths. | The jar lists all eight native paths (six glibc/macOS/Windows plus two musl); `javap` shows major 52 |
| 3.2 | Java façade only where R13 allows. | Façade diff reviewed for zero logic; the one-implementation grep passes |
| 3.3 | Port the JUnit suites (conformance, trust isolation, hostile, caps). | 186/186 |
| 3.4 | Keep every JVM leg: `java-runtime-8` on real Temurin 8, JDK 11-26, distroless ×4, Spring Boot 4.0/4.1, `jvm-interop` (Kotlin, Scala). | All green |
| 3.5 | Native-access legs on JDK 25/26: default (one warning, documented), `--enable-native-access=ALL-UNNAMED` (silent), `--illegal-native-access=deny` (documented failure). | Output asserted |
| 3.6 | Alpine leg (musl) with the library override. | Genuine receipt verifies on `eclipse-temurin:21-alpine` |
| 3.7 | If R8 = B: move today's Java code to `java/oracle/` (test scope, unpublished) and add a Jazzer differential target, Java against Rust. | The differential target runs in the nightly fuzz job |

**Gate G3:** as in the table, plus a post-publish smoke from real Maven
Central, compiled and run on Temurin 8.

Release: 0.9.0, planned inside one calendar month with spare Central
budget.

## Phase 4: npm through wasm-bindgen

Estimate: 1 to 3 weeks. The façade (keeping the options API) and the
runtime matrix decide it.

| Step | Work | Verify |
|---|---|---|
| 4.1 | `aprv-wasm` built with pinned wasm-bindgen (plus pinned binaryen `wasm-opt` if the size win is worth a tool). | The wasm size budget is set from the first real build |
| 4.2 | Package layout and `exports` conditions (ARCHITECTURE §6.4). The TypeScript façade has trap recovery. | `npm pack` content check in release; `publint`-style exports check in CI |
| 4.3 | Conformance through the package on Node 20/22/24/26. Runtime smokes: Bun, Deno, workerd ×3, `@edge-runtime/vm`, and headless Chromium (new). | 186/186 on Node; the genuine receipt and JWS on every runtime |
| 4.4 | Forced-trap test: an adapter-only debug export panics, the façade recovers, and the next call succeeds. | Test green |
| 4.5 | Drop Fastly and Akamai (R5): the job, README rows and SUPPORT-MATRIX rows. | CHANGELOG breaking note |
| 4.6 | Publish the Node numbers. Apply R4's trigger. | BENCHMARKS.md updated |
| 4.7 | Delete `node/src` verifier code. Keep the conformance and runtime smokes. | The one-implementation grep finds no `node:crypto` or `crypto.subtle` |

**Gate G4:** as in the table, plus a post-publish smoke from real npm on
Node 20 and in workerd.

Release: 0.10.0.

## Phase 5: Swift

Estimate: 1 to 3 weeks. The SE-0482 Linux audit decides it; nobody has
measured it yet.

| Step | Work | Verify |
|---|---|---|
| 5.1 | **Linux spike first:** Rust staticlib in an SE-0482 artifact bundle, consumed by a Swift 6.2 package in the `swift:6.2` container. Check the `llvm-objdump` dependency audit against Rust's `libgcc_s`/unwind and pthread references. | A consumer links and verifies the g5 receipt. If it fails, stop and report before step 5.2. |
| 5.2 | Build the XCFramework (macOS arm64/x86_64) and the Linux static slices. Localize every symbol that is not `uniffi_*`/`ffi_*`. | The exported-symbol list matches an allowlist |
| 5.3 | Commit the generated Swift. `Package.swift` gets a `binaryTarget(url:checksum:)`. Floor: tools 6.2. | Regenerate-and-diff gate |
| 5.4 | `release-please.yml` builds the bundle on the release PR branch and commits the checksum. `release.yml` uploads the identical file. | A dry-run release on a fork resolves the checksum |
| 5.5 | Port `ConformanceCasesTests` and the trust and concurrency tests. Keep `async` only where the façade needs it (the Rust calls are sync). | 186/186 on Linux 6.2/6.3 and macOS |
| 5.6 | Delete the hand-written Swift verifier. | The one-implementation grep finds no `X509`, `_CryptoExtras` or `SwiftASN1` imports |

**Gate G5:** as in the table, plus a post-publish smoke with `swift run
Smoke` from the real tag.

Release: 0.11.0.

## Phase 6: Go (assumes R6 = wazero)

Estimate: 1 to 2 weeks. The instance pool and the JSON mapping onto the
existing Go types decide it.

| Step | Work | Verify |
|---|---|---|
| 6.1 | `aprv-wasi`: `alloc`/`dealloc`, one export per operation, JSON in and out, built on the `aprv-surface` JSON view. | Its Rust tests plus a wasmtime run of the conformance cases |
| 6.2 | Go wrapper: `//go:embed aprv.wasm`, compile once, `sync.Pool` of instances, a discarded instance after a trap, JSON decode into today's Go types. | `go test -race`, 186/186 |
| 6.3 | Commit `aprv.wasm`. A `go-wasm-reproducible` job rebuilds it and compares the SHA-256. | Hash match |
| 6.4 | Keep `go-platforms` (macOS, Windows). Add a `CGO_ENABLED=0` build and a `FROM scratch` smoke. | Green |
| 6.5 | Raise the `go.mod` floor to what wazero requires. Update SUPPORT-MATRIX. | The floor leg runs |
| 6.6 | Delete the Go verifier (unless R8 = C). | The one-implementation grep finds no `crypto/x509` or `crypto/rsa` in `go/` |

**Gate G6:** as in the table, plus a post-publish smoke with `go get` from
the proxy.

Release: 0.12.0.

## Phase 7: remove what is left, rewrite the rules

Estimate: 3 to 5 days.

1. Delete `ruby/`, `php/`, `dotnet/` and root `composer.json`, with their
   CI jobs, dependabot entries, release-please extra files, `certs` copies,
   BOOTSTRAP.md sections and post-publish legs. Use one commit per port
   (R9).
2. Shrink `check-cert-copies.mjs` to `rust/certs`. Delete
   `node/scripts/gen-roots.mjs` and `node/src/roots-data.ts`.
3. Rewrite CLAUDE.md:
   - "The nine implementations are one product" becomes "one
     implementation, bindings test the boundary";
   - update the certs-copy invariant and the "one version, N files" list;
   - add "bindings contain no verification logic";
   - add "generated outputs are regenerated in the same commit".
4. Rewrite CONTRIBUTING.md (how to change behaviour now), PORTS.md (it
   becomes a binding-capability table), SUPPORT-MATRIX.md, THREAT-MODEL.md
   (the new boundaries: UniFFI, wasm, wasi, JNA, native artifacts) and
   PLAN.md (D17 onward from DECISIONS.md, D16 marked superseded).
5. Turn on the final gate: a CI job that fails if any published package
   source imports a crypto, X.509 or ASN.1 API.

**Gate G7:** that job green, the docs merged, ROADMAP items deleted as they
ship.

## CI changes

| Job | Change |
|---|---|
| `rust`, `rust-lint`, `rust-fuzz`, `rust-supply-chain` | Workspace-wide. cargo-deny also covers the binding crates. |
| `rust-ffi` | Stays on ubuntu, macOS and Windows. Builds the C ABI from the workspace. |
| `rust-wasm` (new) | Conformance on `wasm32-unknown-unknown` and `wasm32-wasip1`. Hostile corpora on wasm must not trap. The `getrandom` check. |
| `bindings-generate` (new) | Pinned uniffi and wasm-bindgen. Regenerate Swift, the header and Go wasm, then diff. Public-API dumps diff. |
| `native-artifacts` (new, test build) | The R12 matrix. Build and smoke-load on each runner. Test jobs may cache. |
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
  workflow artifacts. Artifacts from `ci.yml` never feed a publish.
- Per publish job:
  - `publish-pypi` uploads the maturin wheels plus the sdist;
  - `publish-maven` assembles the jar from those natives;
  - `publish-npm` builds the wasm itself (no native targets);
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
   `node/`, `python/`, `swift/` or `go/` outside test and oracle code.
2. `rust/src` still has `#![forbid(unsafe_code)]` and the same lint wall.
   `unsafe` exists only in `rust/ffi` and `rust/bindings/wasi`, each
   listed in THREAT-MODEL.
3. Every published package passes 186/186 `fixtures/cases.json` cases
   through its binding.
4. Java: a Temurin 8 program compiles against the published jar and
   verifies the g5 receipt, and JDK 11 to 26 pass. Native-access behaviour
   is asserted and documented.
5. Python: a wheel from real PyPI verifies the g5 receipt on 3.10 in a
   clean venv, on glibc, musl, macOS and Windows.
6. npm: one package from real npm verifies the g5 receipt on Node 20, Bun,
   Deno, workerd and Chromium.
7. Swift: `swift run Smoke` from the real tag verifies it on Linux (6.2)
   and macOS.
8. Go: `go get` from the proxy with `CGO_ENABLED=0` verifies it.
9. C ABI: the header regenerates without a diff, and the exported symbols
   match the header. C++ and ctypes conformance pass on three OSes (`rust-ffi`),
   and the Elixir NIF example passes on Linux (`elixir-ffi`).
   The Release archive verifies against its attestation.
10. Differential: the Phase 1 campaign and each phase's old-against-new run
    closed with zero open divergences. If R8 = B, the oracle job runs
    nightly.
11. Docs: Rust doc comments show up in KDoc, Swift, Python `help()` and
    `.d.ts` (spot-checked in CI by grepping the generated output).
12. Every native and wasm artifact in a release has a SHA-256 and a
    provenance attestation.

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Wasm speed on Node (about 5.3x) disappoints users | medium | medium | R4 trigger, publish numbers, R11 work |
| Go through wazero is 30x slower than today's Go port | high (measured) | medium | R6 alternatives; R8 option C keeps the Go port |
| JNA fails on Alpine (its own `jnidispatch`) | unknown | high for Alpine users | Phase 3.6 leg. Fallback: document `gcompat`, or add a musl-specific loader in the façade. |
| SE-0482 rejects Rust's staticlib dependencies on Linux | **resolved**: the spike linked and ran on Swift 6.2.4 and 6.4 | — | Keep a Linux consumer build in CI; strip the 50 MB static library before release |
| A wasm trap leaves an instance corrupted | low (lint wall) | medium | Trap recovery and a forced-trap test (ARCHITECTURE §5) |
| Monoculture: one Rust bug hits every language | low-medium | high | R8, fuzzing, owner review log, differential campaign |
| UniFFI is pre-1.0 and breaks between minors (0.32 changed byte buffers) | high | low-medium | Pin; upgrade in a dedicated PR with full conformance |
| Prebuilt binaries widen the supply-chain surface | certain | medium | No-cache release builds, attestations, reproducible Go wasm, SHA256SUMS |
| Reproducible Rust builds across runners are harder than expected | medium | low | Pin the toolchain, remap paths; worst case, build the Go wasm once in release and diff only in PR CI |
| Maven Central budget during the phased releases | low | medium | One release per phase, at most two phases a month |
| Owner review becomes the bottleneck | high | schedule only | Phase 1 is the critical path by design. Later phases touch no security code. |
