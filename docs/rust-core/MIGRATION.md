# Migration plan

Target: [ARCHITECTURE.md](./ARCHITECTURE.md). Choices:
[DECISIONS.md](./DECISIONS.md). Starting point: [INVENTORY.md](./INVENTORY.md)
(0.7.0). Rewritten on 2026-09-28 on the Wasm-first basis.

Rules for every phase:

- **No old implementation leaves before its replacement passes its gate.**
  Until then it is a differential oracle. The Java implementation never
  leaves (R33).
- **A divergence is a finding.** Investigate it and add a
  `fixtures/cases.json` case that pins the right answer. Never edit a case
  to make a host pass. A divergence between the core and the Java
  implementation is recorded in R20; one that changes an Apple-signed
  input's verdict, or accepts something unsigned, is a bug.
- **One release.** The phases land on the `rust-core` integration branch
  and ship together as 0.8.0 (R19). No phase cuts a release.
- **One branch, one review.** `rust-core` (the renamed plan branch)
  carries the plan, the evidence and every phase; each lane works on a
  branch off it and merges back with a real merge commit when its gate
  passes; `main` is merged into it on every `main` change. The owner
  reads nothing lane by lane: the agents review each other's work
  (step 1.10 and the gates), and the owner's one read is the final pull
  request from `rust-core` to `main` (owner, 2026-09-29).
- **Pace.** The work is agent-driven and the lanes below run in
  parallel; the estimates are bounded by the work itself and by CI time,
  not by a review calendar.
- **The Maven Central budget.** 7 releases, about 80 MB and about 1,000
  files per calendar month (CLAUDE.md); keep 2 releases in reserve.
- Version numbers below show the sequence; release-please picks the real
  ones from the commits.

## Phase 0: evidence (done)

The 23 notes of 2026-09-25 to 2026-09-29 in [../evidence/](../evidence/):
the binding spikes, the substrate rounds that put the core on OpenSSL,
the Wasm routes, ABI v1, `aprv-server`, one round per host, and the two
canonical-ABI rounds that fixed the export ABI. README.md summarises what
they settled.

## Phase 1: the core, `aprv.wasm` and the canonical ABI

Estimate: the OpenSSL substrate (1.1) and the differential campaign
(1.8) bound it; with the other lanes running beside it, days to a few
weeks rather than the 2 to 6 weeks set on 2026-09-25 for an owner-paced
review.

| Step | Work | Verify |
|---|---|---|
| 1.1 | **OpenSSL substrate (R21).** Add `aprv-openssl`: the CMS path, `X509_verify_cert` over the pinned roots with the historical-time callback, EVP for JWS, the payload through `payload.c`'s templates. Delete `asn1.rs`, `x509.rs`, `cms.rs`, `chain.rs`, `crypto.rs`, their public modules and the RustCrypto dependencies. Rewrite the tests that used them. Apply R21's `unsafe` goals. | `cargo test`; nothing named `asn1` in `rust/src`; the 1,179-row corpus answers as the template build did ([ASN.1 payload][payload]); every raw `openssl-sys` call sits in a small safe function with a `// SAFETY:` comment |
| 1.2 | **Native OpenSSL build.** `openssl-src` 400.x through the one-line `[patch.crates-io]`, or `OPENSSL_DIR`; `OPENSSL_CONFIG_DIR` set to a path that does not exist. | Vendored and `OPENSSL_DIR` builds give identical rows ([CMS everywhere §1][cms]); the isolation test finds no config or trust file opened |
| 1.3 | **Workspace and layering.** `rust/` becomes one workspace. Create `aprv-surface` (the 0.7 model) and `aprv-wire` (the 0.7 JSON). Add `tools/check-layering.mjs` (SURFACE.md §9). | `cargo test --workspace --locked`; the layering check passes, and fails on a planted `wasmtime` dependency in the core and a planted `asn1` module |
| 1.4 | **The canonical ABI (`aprv-abi`).** The WIT of ARCHITECTURE.md §4 in `rust/bindings/abi/wit/aprv.wit`; wit-bindgen (pinned) generates the guest glue; four bodies call the surface: `init` with the roots, `now-ms: u64` on every verify call, `env: u32` matched in the guest, `list<u8>` inputs, no policy. The link-time C file answers `clock_time_get` from the call's `now-ms` and traps on every other WASI function except `random_get`, which forwards to the `random-get` import. Check whether `wasi:random/random@0.2`'s `get-random-bytes` can be that import (R34); keep our `host` interface if it costs size or speed. Move the base64 decode into one public core function the ABI calls. Strip or hide the two internal `#[no_mangle]` symbols the C file needs so they are not exports ([canonical ABI final][cabifinal], finding 7). | The ABI tests of the final round on a hand-rolled host and a component runtime (env 2, 255, 2^32-1 trap; verify before `init` and a second `init` trap; a bad root is `{"ok":false}` and `init` retries; a wrong-length `random-get` traps; trap isolation; 2,000 calls leave memory the same size); `wasm-tools component wit` reads back the committed WIT; the module imports exactly `random-get` |
| 1.5 | **`rust-wasm` job.** Build `aprv.wasm` once with the pinned rustc, wit-bindgen, wasi-sdk (by SHA-256) and OpenSSL tarball, no cache; wrap it with `wasm-tools component new` (no adapter); publish both hashes as job outputs; run the corpus (1,179 rows plus 5,000 mutants) through a host that traps on any unexpected import. Run `tools/reproduce-wasm.sh` against the artifact (R34). | All rows equal to native; no trap; import list exactly `random-get`; the second build's hash equals the first |
| 1.6 | **Node as the first host.** jco (pinned) transpiles the component; a prototype of the npm façade over the generated bindings runs all 311 cases, one test each, and the corpus. | 311/311; the corpus byte-identical to native; the glue's `JCO_DEBUG` read and its coercion of a string where the WIT says `list<u8>` are handled in the façade ([canonical ABI final][cabifinal], findings 2 and 6) |
| 1.7 | **`init` cost.** Measure `init` against one g5 and one JWS call, in Node and through Wasmtime. The spike's fresh lifecycle cost about 1.6 ms more per receipt than the pool ([aprv-server §3][server]). | The numbers are recorded in an evidence note. If `init` exceeds 10% of a call, `aprv-server`'s default becomes `--lifecycle pool` (R23) |
| 1.8 | **Differential campaign (R33).** The corpus and every port's fuzz corpus (Jazzer, atheris, go-fuzz, Jazzer.js, libFuzzer Swift, ruzzy, SharpFuzz, PHP) through the core and the 0.7 Java implementation. Compare verdicts and reasons. | Every divergence is in R20 with its reason; none changes an Apple-signed verdict or accepts something unsigned |
| 1.9 | **Private-receipt drift check** (owner, 2026-09-26). A local script reads receipts from a folder outside the repository and prints only verdicts and unknown attribute type numbers. Production receipts never enter the repository, its history, CI, issues or PRs (CLAUDE.md). A new type becomes a test built from a generated receipt of the same shape. | The script runs on a folder of generated receipts; its output holds no values |
| 1.10 | **Adversarial review of the core,** module by module, by review agents that did not write it (a separate session per module, or a review workflow): the adapter's `unsafe`, `payload.c`, the link-time C file and `aprv-abi`. The checklist maps each root THREAT-MODEL §3 mitigation to its code and test. The log lives in `docs/rust-core/REVIEW-LOG.md` and is written for the owner's one read at the final pull request. | Every module signed off by a reviewer other than its author; every finding fixed or recorded with its reason |
| 1.11 | **Test inventory.** Every behaviour test that exists in one port's suite only, deduplicated against `cases.json`. Tests of a host's own API shape, pooling or packaging stay with the host. | Committed; every entry names its target case or says "stays with the host" |
| 1.12 | **Fuzzing.** Keep `verify-receipt`, `verify-receipt-base64`, `verify-transaction` and `endpoint-json`, drop `parse-der`, `parse-certificate` and `parse-cms` with their modules, add a target that enters through the ABI. A scheduled job fuzzes over an OpenSSL build instrumented with ASan and libFuzzer, as the evidence campaigns did ([follow-up §4][followup], [CMS everywhere §4][cms]). | The job runs on schedule; a finding opens an issue with a reproducer built from test keys only |
| 1.13 | **C ABI on the surface.** `rust/ffi` moves onto `aprv-surface` and `aprv-wire`, gains the lints of SURFACE.md §9 and its own fuzz target; its header is generated by cbindgen and diffed in CI (R34). | Its C++ and ctypes harnesses pass the 311 cases; a stale committed header fails the job |
| 1.14 | **Wire schemas (R34).** JSON Schema 2020-12 files in `rust/bindings/wire/schema/` for the verify-receipt result, the verify-signed-data result, and `init`'s configuration and answer, written from `0.7-api.md`'s JSON rules (ids as strings, dates as epoch milliseconds, `null` for missing, unknown attributes keyed by decimal type). | Every corpus answer from the core, the C ABI and `aprv.wasm` validates; a planted wrong type fails the check |
| 1.15 | **Provenance and SBOM for the module (R34).** The `rust-wasm` job attests `aprv.wasm` and the component with SLSA build provenance and attaches a CycloneDX SBOM that names rustc, wit-bindgen, wasi-sdk, wasi-libc and OpenSSL by version and hash. | `gh attestation verify` passes on the artifact; a script checks the SBOM names the pinned versions |

**Gate G1:** the core and `aprv.wasm` pass the 311 cases and the corpus;
the module imports exactly `random-get`, its WIT reads back unchanged,
its hash is published by CI and reproduced once; the ABI tests pass on
Node; `init` is measured and the server's lifecycle default decided; the
wire schemas validate every answer; the differential campaign is closed;
the review log is complete; the test inventory exists.

## Phase 2: `aprv-server`

| Step | Work | Verify |
|---|---|---|
| 2.1 | `rust/server/`: the `aprv` binary with `serve`, the one-shot CLI and `precompile`; Wasmtime 49 runtime-only plus `component-model`, `bindgen!` over the WIT, the release's component precompiled for an explicit baseline target and embedded as a `.ccwasm` (R31, R23). The `precompile` step runs with the same Wasmtime features as the serving binary, in the same build ([canonical ABI final][cabifinal], finding 1). | `info` reports the component hash and the feature set; the runtime-only build refuses a `.wasm`, a tampered `.ccwasm` and a file precompiled with other features ([aprv-server §2][server]); first result in about 14 ms in process |
| 2.2 | **The `Config` over the wire.** Roots at start (a standalone server's own configuration; the managed child after the token on stdin) and `init` per instance; `now-ms` per request (an HTTP header, a CLI argument), the server's clock when absent; root fingerprints served so a client can refuse a mismatch. | The 311 cases through HTTP and through the CLI, with the cases' roots and clocks |
| 2.3 | **Managed mode:** `127.0.0.1:0`, the stdin token, the port on stdout, exit on stdin EOF. | The spike's Temurin 8 checks: crash and restart, no orphan after `close()`, `System.exit` or `kill -9` ([aprv-server §6][server]) |
| 2.4 | **Static musl** for x86_64 and aarch64 with musl's malloc and `cli-fast-exit`; macOS and Windows builds for x86_64 and arm64. | `readelf` shows no INTERP and no NEEDED; the binary runs from an empty chroot and on Alpine; the CLI exits within the glibc build's time ([static musl][musl]) |
| 2.5 | **Limits.** `StoreLimits` of 256 MiB, one instance; the 3 MiB body cap answered with 413; a guest time limit through epoch interruption. | Hostile-module tests on the server: an infinite loop ends at the limit, a 1 GiB grow is refused, the process survives |
| 2.6 | **Docker.** The multi-stage distroless image, base pinned by digest, the `org.opencontainers.image.*` annotations (source, revision, version, licenses, description), published to GHCR; Docker Hub once the owner has created the namespace and token (R34). | amd64 and arm64 images build; a smoke test verifies g5 with `APRV_LISTEN` set, nothing answers without it, and `docker inspect` shows the annotations |
| 2.7 | **Corpus** over HTTP, fresh and pool lifecycles, on every Linux build. | 6,153 rows byte-identical, the 25 over-cap bodies answered 413, the one inexpressible row, 0 different, as in the spike ([aprv-server §4][server]) |
| 2.8 | **OpenAPI 3.1 (R34).** `rust/server/openapi.yaml` describes every route, referencing the wire schemas of step 1.14; served at `GET /openapi.json`. Spectral lints it; Schemathesis runs it against the server. | Spectral at 0 findings with the ruleset committed; Schemathesis passes; a route added without a document entry fails the job |
| 2.9 | **RFC 9457 Problem Details (R34).** 401, 413 and the three 500 codes answer `application/problem+json` with `type`, `title`, `status`, `detail` and the existing code in `code`; verification results stay HTTP 200 with the module's JSON. | The OpenAPI document declares the problem shape; the 311 cases and the limit tests see the new bodies; the Java and PHP clients map them to the outcomes of ARCHITECTURE.md §4 |
| 2.10 | **Provenance and SBOM for the binaries and the image (R34).** SLSA build provenance and a CycloneDX SBOM naming Wasmtime, rustc, musl and the embedded component's hash, per binary and for the image; `tools/reproduce-server.sh` for the Linux static builds. | `gh attestation verify` passes on each; the SBOM check script passes; the Linux rebuild reproduces the hash |

**Gate G2:** as in the table, on every platform the server ships for.

## Phase 3: Java, the `-wasm` artifact

| Step | Work | Verify |
|---|---|---|
| 3.1 | **One reactor.** `java/` becomes a parent POM with two modules: the main artifact (today's code, unchanged) and `-wasm`. | Both build from the parent at one version; `javap` shows major 52 for the façade and the server client, 55 for the Endive classes |
| 3.2 | **Endive engine.** The pinned `endive-compiler-maven-plugin` compiles the release's `aprv.wasm` with `interpreterFallback` FAIL; the pool of R23 with `ByteArrayMemory`; the hand-rolled canonical ABI call of the final round (35 lines, a signature table, `cabi_realloc`, the return area, `cabi_post_*`); `random-get` from `SecureRandom`. | No native file or native-loading call in any jar on the consumer classpath ([Endive §6][endive]); a forced trap discards the instance and the next call succeeds; N threads over the corpus give the single-thread rows |
| 3.3 | **Server engine and the `Engine` API.** `Engine.endive()`, `Engine.server(ServerSource...)`, `cacheDirectory(path)`, the default by JVM version, the five sources in the user's order, the pinned hashes, the managed-mode client with one write per request and `TCP_NODELAY`. | Each source tested alone and in orders; a wrong hash is never executed; no system property or environment variable is read |
| 3.4 | **Classifier jars** `linux-x86_64` and `linux-aarch64` attached to `-wasm` (R26). | `maven()` finds and runs each on its architecture |
| 3.5 | **Classpath guard.** A marker resource in each artifact, a startup check, a Gradle capability conflict. | Both jars on one classpath fail fast; a Gradle build that asks for both fails at resolution |
| 3.6 | **The 311 cases** against the main artifact, against `-wasm` with Endive on JDK 11 to 27, and with the server engine on Temurin 8 (`java-runtime-8`) and on a current JDK. | 311/311 in every run |
| 3.7 | **Endive corpus CI.** The corpus through the built jar on every change on Linux x64 and arm64, macOS arm64, Windows x64 and arm64; s390x under QEMU before each release. | Every row byte-identical to native, or the build fails |
| 3.8 | **`Config.runtimeProbe` in `-wasm`:** define what it probes (instantiating one instance and calling `init`, or reaching the server). | Documented; a failing probe throws at `create` |
| 3.9 | The JVM legs of 0.7.0 (distroless, Spring Boot 4.0 and 4.1, `jvm-interop`) run for both artifacts where the JDK meets the engine. | All green |

**Gate G3:** as in the table, plus a post-publish smoke from real Maven
Central: the main artifact and `-wasm` on Java 8 (server engine) and on
Java 11 (Endive).

## Phase 4: Node and Go

| Step | Work | Verify |
|---|---|---|
| 4.1 | **npm façade** over jco's generated bindings (step 1.6's prototype): one instance, `random-get` from `crypto.getRandomValues`, any other import refused, trap recovery (a component instance refuses calls after a trap; the façade replaces it), the `exports` conditions of ARCHITECTURE.md §7.4 rebuilt around jco's instantiation modes. | Façade diff reviewed for zero logic; `npm pack` content check with the licence texts and the minified glue |
| 4.2 | **Runtimes:** the 311 cases on Node 20, 22, 24 and 26; smokes on Bun, Deno (with `--allow-env=JCO_DEBUG` documented, or the read removed), workerd, `@edge-runtime/vm`, Chromium, Firefox, WebKit. Where jco's glue does not load (workerd's static import is the first to check), the fallback is a hand-rolled façade over the core exports, as Endive's. | 311/311 on Node; the genuine receipt on every runtime |
| 4.3 | **Memory in workerd:** the hostile 3 MiB receipt of tiny attributes, against the 128 MB isolate ([ASN.1 payload §3][payload]). | Peak recorded in BENCHMARKS.md; if the isolate fails, it fails closed and the owner decides |
| 4.4 | **Drop Fastly and Akamai** (R5). | The job and the README and SUPPORT-MATRIX rows are gone; the CHANGELOG marks it breaking |
| 4.5 | Report Bun's WASI `random_get` bug upstream after rechecking it on the current Bun (Bun 1.3.11 returned the wrong value and overwrote module memory; [repro][bunrepro]). | Issue link recorded, or "fixed in Bun x.y" |
| 4.6 | **Go:** `//go:embed aprv.wasm`, compile once, a `sync.Pool`, the hand-rolled canonical ABI call of the final round (66 lines), trap discard, any other import refused; the committed copy's SHA-256 checked against the release build. | `go test -race`; 311/311; the hash matches |
| 4.7 | **Go floor and deployment:** `CGO_ENABLED=0` build, `FROM scratch` smoke, macOS and Windows legs; check the chosen wazero release against the `go` directive (R30). | Green; the floor raised only if wazero requires it |

**Gate G4:** as in the table, plus post-publish smokes from real npm (Node
20, workerd) and from the Go proxy with `CGO_ENABLED=0`.

## Phase 5: Python, Swift, Ruby, .NET

| Step | Work | Verify |
|---|---|---|
| 5.1 | **Python** over wasmtime-py (R27): the plain `.wasm`, the canonical ABI called by hand over the core exports with `Memory.write`, not the typed component API (its `list<u8>` lowering costs 1.1 µs per byte, [canonical ABI final][cabifinal] finding 3), host functions on one process-wide `Linker`, the pool, `Config.cache` with THREAT-MODEL.md §8's rules and an environment variable for the path, store limits. | 311/311 on CPython 3.10 to 3.14, glibc, musl, macOS and Windows; a read-only and a foreign-owned cache directory both turn the cache off and still verify |
| 5.2 | **Python install failure** (R28): on a platform without a wasmtime-py wheel, installation stops with the pointer to `aprv-server` or the C ABI, instead of `import` failing later ([Python wasmtime][pywt]). | A leg on one such platform (for example i686 under QEMU) shows the message at install |
| 5.3 | **Python docs:** the compile at start (about 1 s on 4 CPUs, 3 s on one), the cache, Lambda's cost per new container, worker processes rather than threads. | README reviewed |
| 5.4 | **Swift** over WasmKit 0.4.0: the hand-rolled canonical ABI call of the final round (37 lines), every range checked before memory is touched, one store per thread, `aprv.wasm` committed as a resource with its hash checked. Record which bounds-checking mode the shipped configuration uses (THREAT-MODEL.md §2). | 311/311 on Linux and macOS with Swift 6.3; an iOS build compiles |
| 5.5 | **Ruby** over the `wasmtime` gem: `to_func(gvl: false)`, instances from a pool or thread-local, store limits. | 311/311 on Ruby 3.3, 3.4, 4.0; four threads scale ([Ruby][ruby]) |
| 5.6 | **.NET** over `Wasmtime`: netstandard2.0 and net8.0 targets, process-wide `Engine`, `Module` and `Linker`, store limits; the Alpine limitation documented. | 311/311 on .NET 8, 9 and 10, and the netstandard2.0 build on Mono |

**Gate G5:** as in the table, plus post-publish smokes from PyPI (3.10),
the Swift tag, RubyGems and NuGet (once bootstrapped).

## Phase 6: PHP

| Step | Work | Verify |
|---|---|---|
| 6.1 | The PHP 8.2 façade over the CLI transport (default) and the HTTP transport, passing the `Config` roots and the clock's `now_ms` (step 2.2). | 311/311 through the CLI on PHP 8.2 to 8.5; the same through a server URL |
| 6.2 | **`aprv install`:** download the binary for this platform from GitHub Releases, check the pinned SHA-256, install it where the façade looks. | A wrong hash installs nothing; an unsupported platform gets a message naming the server URL option |
| 6.3 | **Packagist** from the root `composer.json`, once the owner submits the repository and installs its GitHub App. | A post-publish smoke with `composer require` |

**Gate G6:** as in the table.

## Phase 7: delete, rewrite, release 0.8.0

1. Move the port-only behaviour tests of the eight non-Java ports into
   `fixtures/cases.json` (step 1.11's list), then delete the eight
   hand-written verifiers (`node/src`, `python/`, `go/`, `swift/`, `ruby/`,
   `php/`, `dotnet/` verifier code, and the Rust ports' own reader
   modules already gone in 1.1), one commit per language. **The Java
   implementation stays.**
2. Shrink the `certs/` copies to what remains: `rust/certs` and Java's
   constants. Delete `node/scripts/gen-roots.mjs`, `node/src/roots-data.ts`
   and the Ruby, PHP and .NET inlined roots.
3. Rewrite CLAUDE.md: the "Behavior changes" section becomes the R33 rule
   (the Rust core, the Java implementation and `fixtures/` in one PR); the
   certs-copy invariant; the "one version, many files" list with the new
   version constants; "wrappers contain no verification logic"; `aprv.wasm`
   imports exactly `random-get` and its WIT is the contract.
4. Rewrite CONTRIBUTING.md, PORTS.md (a host-capability table), the root
   SUPPORT-MATRIX.md and THREAT-MODEL.md from this folder's files, and
   PLAN.md (D17 onward from DECISIONS.md, D16 marked superseded for the
   eight ports).
5. Turn on the final gate: the `one-implementation` job fails if a
   non-Java wrapper imports a crypto, X.509 or ASN.1 API.
6. Merge `rust-core` into `main` with a real merge commit; release-please
   opens 0.8.0.

**Gate G7:** that job green, the docs merged, every acceptance test below
holding.

## Lanes: what runs in parallel

The WIT is fixed (R23), so the round-13 spike module and component
([canonical ABI final][cabifinal]) stand in for the real ones. Anything
that depends only on the ABI starts at once; only the parity gates wait
for the real module. Each lane is a branch off `rust-core`, merged back
with a real merge commit when its gate passes.

| Lane | Work | Depends on | Gate |
|---|---|---|---|
| A, the core | Steps 1.1 to 1.4 in order, then 1.7, 1.8, 1.10; the critical path | nothing | G1 |
| B, the server | All of Phase 2 against the spike component; the HTTP layer, managed mode, musl, Docker, OpenAPI, RFC 9457 touch no core code | the ABI only; the real component swapped in after G1 | G2 |
| C, host ABI layers | One branch per language: the façade over the spike module (Endive, wazero, WasmKit, the jco façade, Python, Ruby, .NET), pooling, trap recovery, the façade tests | the ABI only; the 311 cases run after G1 | G3 to G5 |
| D, supply chain and CI | Steps 1.13 to 1.15, 2.8 to 2.10, the `release.yml` jobs, the CI matrix rows, the schemas and scripts | nothing | each job green |
| E, the Java API | Steps 3.1, 3.3, 3.5: the reactor, `Engine`, `ServerSource`, the managed client, the classpath guard, against the spike server | the ABI only | G3 |
| F, PHP | Phase 6 against the spike server | lane B's binary | G6 |
| Owner | Docker Hub, Packagist, the Sonatype question, the Java 8 distribution, the Wasmi follow-up (below) | nothing | — |

The lanes converge at G1: every host's parity run and Phase 7's
deletions wait for the real module. The spike module carries the 0.6
core, so a few rows answer differently from 0.7 until lane A lands; lane
C tests against the ABI tests and the corpus shape first, and against
the 311 cases after G1.

## CI matrix

| Job | What it runs |
|---|---|
| `rust`, `rust-lint`, `rust-supply-chain` | Workspace-wide, cargo-deny and RustSec over the core, the adapter, the ABI, the C ABI and the server |
| `rust-fuzz`, `rust-fuzz-openssl` (scheduled) | The fuzz targets, the second over an OpenSSL build instrumented with ASan and libFuzzer (nightly for `-Zsanitizer`) |
| `rust-wasm` | Builds `aprv.wasm` and the component, checks the import list and the WIT read-back, runs the corpus on the trap host and the ABI tests, validates every answer against the wire schemas, reproduces the build once; its SHA-256 feeds every job below |
| `rust-ffi` | The C ABI on Ubuntu, macOS and Windows, the 311 cases through C++ and ctypes, the cbindgen header diff, the OpenSSL isolation test |
| `aprv-server` | Linux x86_64 (glibc and static musl), aarch64 (static musl, arm64 runner), macOS and Windows builds; the 311 cases over HTTP and the CLI; the corpus; hostile-module limits; Spectral over the OpenAPI document and Schemathesis against the server; the Docker image smoke with its annotations |
| `java` | The main artifact on JDK 11 to 27, as today |
| `java-runtime-8` | The main artifact and the `-wasm` server engine on a real Java 8 JVM (Temurin, then Zulu or Corretto) |
| `java-wasm-endive` | `-wasm` with Endive: the 311 cases on JDK 11 to 27; the corpus on Linux x64 and arm64, macOS arm64, Windows x64 and arm64 |
| `java-wasm-s390x` (before each release) | The Endive corpus on s390x under QEMU, the big-endian check |
| `java-classpath-guard` | Both artifacts on one classpath fail; Gradle refuses both |
| `java-differential` (nightly) | The corpus through the Java implementation and the core; new differences go to R20 |
| `node`, `node-runtimes` | Node 20, 22, 24, 26 × 311 cases; Bun, Deno, workerd, edge-runtime, three browsers |
| `go`, `go-platforms` | The floor and supported lines × 311 cases, `-race`, `CGO_ENABLED=0`, macOS, Windows |
| `python` | CPython 3.10 to 3.14 × 311 cases on Linux glibc and musl, macOS, Windows; the cache rules; the install-failure leg |
| `swift` | Swift 6.3 on Linux and macOS × 311 cases; an iOS compile |
| `ruby` | Ruby 3.3, 3.4, 4.0 × 311 cases; thread scaling |
| `dotnet` | .NET 8, 9, 10 × 311 cases; netstandard2.0 on Mono |
| `php` | PHP 8.2 to 8.5 × 311 cases through the CLI; one leg over HTTP |
| `wasm-copies` | Every committed or packed `aprv.wasm` equals the build's SHA-256 |
| `one-implementation` | The grep gate of ARCHITECTURE.md §9 |
| `zizmor` | Stays at 0 findings; new jobs pin every action by SHA and set `persist-credentials: false` |

Test jobs may cache; publish jobs never do. ROADMAP's "Smarter CI" item
fits here: a change under `rust/` triggers every host, a change under
`node/` only npm.

## Release artifact matrix

| Artifact | Destination | Size, from the evidence |
|---|---|---|
| `aprv.wasm` with its SHA-256, SLSA provenance and CycloneDX SBOM | GitHub Release | 2,967,116 B raw, 2,713,063 stripped, for the canonical-ABI core module ([canonical ABI final][cabifinal]) |
| The component (`aprv.component.wasm`) and `aprv.wit`, attested like the module | GitHub Release; the input of jco and of the server's `precompile` | 2,969,558 B raw, 2,442 more than the core ([canonical ABI final][cabifinal]) |
| `openapi.yaml`, the wire schemas, `SHA256SUMS` | GitHub Release | small |
| `aprv-server`, Linux x86_64 static musl | GitHub Release; Maven classifier `linux-x86_64` | 3,656,734 B gzipped ([static musl §1][musl]) |
| `aprv-server`, Linux aarch64 static musl | GitHub Release; Maven classifier `linux-aarch64` | 3,390,574 B gzipped ([static musl §1][musl]) |
| `aprv-server`, macOS x86_64 and arm64, Windows x86_64 and arm64 | GitHub Release | not built; the glibc x86_64 build is 3,580,885 B gzipped for reference |
| Docker image | GHCR; Docker Hub after the owner's setup | not built |
| Java main artifact (jar, sources, javadoc) | Maven Central | not re-measured for 0.8.0; unchanged code |
| Java `-wasm` (jar, sources, javadoc) | Maven Central | 1,762,214 B for the Endive spike's library jar ([Endive §4][endive]); Endive's `runtime` and `wasm` are 0.17 and 0.21 MB but are Endive's uploads, not ours |
| npm package | npm | 1,001,740 B for the Route C spike tarball ([CMS everywhere §2][cms]) |
| Go module (`go/v0.8.0` tag, `aprv.wasm` committed) | Go proxy | the module file, about 2.95 MB raw, added to git each release |
| Python wheel and sdist | PyPI | 978,842 B for the spike's `py3-none-any` wheel ([Python wasmtime][pywt]) |
| Swift package (tag, `aprv.wasm` committed) | SwiftPM from git | the module file, as Go's |
| Ruby gem | RubyGems | 977 KB for the spike's facade gem ([Ruby][ruby]) |
| .NET package | NuGet | 1,985,780 B for the spike's nupkg, both targets each embedding the module ([.NET][dotnet]) |
| PHP package | Packagist (from git) | no binary; `aprv install` fetches the server |
| Core crate | crates.io, when needed (R19) | not measured |

**Maven Central per release:** the two classifier jars and the `-wasm`
jar come to about 8.8 MB, plus the main artifact's jars and the sources
and javadoc jars, which were not re-measured. Against about 80 MB a
month, the 7-release count binds before size does. Whether one deployment
of two artifactIds counts as one release event is the owner's check
below.

**Release workflow changes.** `release.yml` keeps its filename (trusted
publishing matches it). A `build-wasm` job builds `aprv.wasm` and the
component once with no cache, attests both (SLSA provenance) and attaches
their SBOMs; a `build-server` job builds the server binaries per platform
with no cache, embedding a `.ccwasm` precompiled from that component for
an explicit baseline target with the serving binary's Wasmtime features;
the publish jobs take those artifacts and never rebuild them. `publish-maven` deploys both
artifactIds and the classifiers; a `publish-image` job pushes to GHCR;
a `release-assets` job with `contents: write` uploads `aprv.wasm`, the
server binaries, `SHA256SUMS` and the attestations. `release-please.yml`
refreshes the committed Go and Swift copies of `aprv.wasm` on the release
branch and checks their hash. New version constants join
`release-please-config.json` in the commit that adds them.

## Acceptance tests for the finished migration

1. `one-implementation` finds no crypto, X.509 or ASN.1 API in the
   non-Java wrappers outside test code.
2. `rust/src` keeps `#![forbid(unsafe_code)]` and its lint wall, with no
   `asn1`, `x509`, `cms`, `chain` or `crypto` module; `unsafe` lives only
   in `aprv-openssl`, `aprv-abi`, `rust/ffi` and `aprv-server`.
3. The released `aprv.wasm` imports exactly `random-get`, its WIT reads
   back as committed, and every package's copy has its published SHA-256.
4. Every host passes all 311 cases, one test each: the main Java artifact,
   `-wasm` on both engines, npm, Go, Python, Swift, Ruby, .NET, PHP,
   `aprv-server` (HTTP and CLI) and the C ABI.
5. Java: the main artifact and `-wasm` (server engine) verify g5 from real
   Maven Central on Java 8; `-wasm` (Endive) on Java 11; the Endive corpus
   run is byte-identical on every leg, s390x included; both jars on one
   classpath fail fast.
6. npm from the real registry verifies g5 on Node 20, Bun, Deno, workerd
   and the three browsers.
7. Python from real PyPI verifies g5 on 3.10 in a clean venv on glibc,
   musl, macOS and Windows, and refuses to install on a platform without a
   wasmtime-py wheel.
8. Go from the proxy with `CGO_ENABLED=0`, Swift from the tag, Ruby and
   .NET from their registries, PHP through `aprv install`, each verify g5.
9. `aprv-server`: the static binaries run from an empty chroot; the Docker
   image verifies g5 with `APRV_LISTEN` set; hostile-module limits hold.
10. The differential job runs nightly; every difference is in R20 and
    none is a bug under R20's rule.
11. Every artifact has a SHA-256, a SLSA provenance attestation and a
    CycloneDX SBOM naming the pinned toolchain and OpenSSL; every package
    carries OpenSSL's licence and NOTICE; `tools/reproduce-wasm.sh`
    reproduces the released module's hash.
12. Every corpus answer validates against the wire schemas; Spectral and
    Schemathesis pass on the server's OpenAPI 3.1 document, and its
    non-result errors are RFC 9457.

## The ARM64 spike branch

ARM64 speed is unmeasured: rounds 10 and 11 ran aarch64 under QEMU for
correctness only, and round 11's `scripts/arm64-native.sh` waits for a
native runner ([static musl §6][musl], [final Python round §3][pyfinal]).
Before Phase 2's gate, a branch `spike/arm64-runtime` carries **one
temporary workflow** on GitHub's arm64 runners (Linux, and macOS where it
applies) that measures the static aarch64 server, wasmtime-py and Endive
on ARM64 with the existing scripts. The workflow follows the CI hygiene
rules (actions pinned by SHA, `persist-credentials: false`, least
privilege). Its results and scripts land as an evidence note and folder
(`docs/evidence/<date>-arm64-runtime`), and the workflow is deleted
afterwards.

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Endive miscompiles: 1.1.0 is young (1.0 on 2026-06-26) and does no post-compilation verification ([Endive §2, §10][endive]) | unknown | high: wrong answers | The byte-for-byte corpus on every change and on s390x before each release; the version pinned, bumped only with the full run |
| `init` costs more than 10% of a call; the spike's fresh lifecycle already cost about 1.6 ms more per receipt ([aprv-server §3][server]) | medium | low: the server's default becomes the pool | Step 1.7 decides by the rule in R23 |
| jco's generated glue does not load on a runtime the npm package supports (workerd's static import is untested with it) | medium | low | Step 4.2: a hand-rolled façade over the core exports, 35 lines, on that runtime |
| wit-bindgen or jco changes its generated code between releases | certain over time | low: the WIT read-back and the corpus catch a drift | Both pinned by version; bumped only with the full run, like Endive |
| A wrapper passes an out-of-range `env` or a wrapped `now-ms` through a generated binding that does not range-check ([canonical ABI final][cabifinal], finding 2) | low | low: the guest traps on `env`; a wrapped `now-ms` moves the chain instant | Each wrapper's `Environment` type and clock read are the only path to those arguments; the façade tests try 2, -1 and 2^32+1 |
| Python's cold start: about 3 s on one vCPU per new process or Lambda container ([runtime options][pyopt]) | certain (measured) | medium for serverless users | The cache for servers; documentation; Winch once wasmtime-py exposes it |
| wasmtime-py threads do not scale past two ([Python wasmtime][pywt]) | certain (measured) | low | Worker processes, documented |
| WasmKit's JWS margin is 1.7 to 1.9 times the floor on a server core; phones unmeasured ([Swift WasmKit][swift]) | medium | medium on slow cores | Benchmarks in Phase 5; the owner decides if a platform falls below the floor (R4) |
| No guest time limit in the in-process Wasmtime hosts or, until step 2.5, the server | medium | medium: a looping input holds a worker | Epoch interruption in the server; the runtime's limits in each host (THREAT-MODEL.md §5) |
| Wasmtime .NET releases irregularly (three in 12 months) and ships no musl library ([.NET][dotnet]) | certain | low to medium | Alpine users take `aprv-server`; the floor tracks the package |
| Temurin 8 builds end in late 2026 | certain | medium for the Java 8 leg | Move the leg to Zulu or Corretto 8 (owner action) |
| Maven Central counts 0.8.0 as more than one release event | unknown | medium | The owner asks Sonatype or reads the Usage Center before 0.8.0 |
| An OpenSSL advisory | certain over time | high | One `aprv.wasm` and the server binaries rebuild; a security bump of a shipped dependency is release-worthy under CLAUDE.md's budget, and 2 releases stay in reserve |
| A Wasmtime major bump in the server | certain (monthly majors) | low | The server's `.cwasm` is rebuilt with the binary; hosts' runtime floors move independently |
| ARM64 speed unknown | unknown | medium | The ARM64 spike branch above |
| The Go floor has to rise for wazero | medium | low | Step 4.7; a minor-version bump before 1.0 (root SUPPORT-MATRIX rule 2) |
| workerd's 128 MB isolate against a hostile receipt's 145 MiB peak in Node | medium | medium on workerd | Step 4.3; fail closed |
| The `x5c` `decodeBase64` cases need a JWS harness in each host (SURFACE.md §6) | certain | low | Phase 1 builds it once for the runners |
| Monoculture: one core or OpenSSL bug reaches every Wasm-hosted package | low to medium | high | The maintained Java implementation (R33), fuzzing into OpenSSL, the owner's review |
| A replaced GitHub Release asset | low | high | The SHA-256 pins inside the `-wasm` jar and the Composer package |
| No owner review until the final pull request: a wrong security decision in the core is caught only by the agents, the fixtures, the differential job and the fuzzers | medium | high | Step 1.10's reviewer is never the author; the Java implementation is the second opinion on every row (R33); the review log is written for the owner's final read, and a finding that changes an Apple-signed verdict stops the lane |

## Owner actions

1. **Docker Hub:** create the namespace and an access token, and store it
   for `release.yml` (BOOTSTRAP.md gets the entry). GHCR needs nothing.
2. **Packagist:** submit the repository and install Packagist's GitHub
   App (BOOTSTRAP.md, Packagist).
3. **Sonatype release count:** ask central-support@sonatype.com, or read
   the Usage Center after a test deployment, whether one deployment of two
   artifactIds with classifiers counts as one release event; record the
   answer in CLAUDE.md's release budget.
4. **Wasmi upstream follow-up:** track the issue reported privately on
   2026-09-27 until upstream publishes a fix.
5. **Java 8 CI distribution:** choose Zulu 8 or Corretto 8 for the
   `java-runtime-8` leg before Temurin 8 builds end.
6. Already pending in BOOTSTRAP.md and needed for 0.8.0's new registries:
   the RubyGems and NuGet first publishes.

[cabifinal]: ../evidence/2026-09-29-canonical-abi-final.md
[cms]: ../evidence/2026-09-26-openssl-cms-everywhere.md
[payload]: ../evidence/2026-09-26-openssl-asn1-payload.md
[followup]: ../evidence/2026-09-26-substrate-followup.md
[server]: ../evidence/2026-09-26-aprv-server.md
[musl]: ../evidence/2026-09-27-static-musl-server.md
[endive]: ../evidence/2026-09-26-endive-build-time-jvm.md
[pywt]: ../evidence/2026-09-26-python-wasmtime.md
[pyopt]: ../evidence/2026-09-27-python-runtime-options.md
[pyfinal]: ../evidence/2026-09-27-python-runtime-final.md
[swift]: ../evidence/2026-09-26-swift-wasmkit.md
[ruby]: ../evidence/2026-09-26-ruby-wasmtime.md
[dotnet]: ../evidence/2026-09-26-dotnet-wasmtime.md
[bunrepro]: ../evidence/2026-09-26-security-substrate-bakeoff/wasm/bun-random-get.mjs
