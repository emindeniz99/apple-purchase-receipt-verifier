# One Rust core: the migration plan

Status on 2026-09-29: **accepted plan, rewritten on the Wasm-first
basis; the export ABI fixed as the canonical ABI over WIT (R23) and the
standards of R34 adopted.** 0.7.0 shipped on 2026-09-28 (tag `v0.7.0`, merged into
`rust-core`) with nine hand-written implementations of one API.
The Rust core lands in **0.8.0 under the same API and the same
`fixtures/cases.json`**. Every package moves in that one release (R19).
Breaking changes stay allowed before 1.0, and floors may rise (R30).
Every owner question is settled (table below); Phase 1 can start.

## The idea

Today nine implementations in nine languages repeat one security
algorithm: ASN.1, X.509, CMS, JWS, chain policy, caps and Apple's rules.
In 0.8.0:

- **One Rust core** on OpenSSL 4 (R21): OpenSSL parses the ASN.1, CMS and
  X.509 and does the signature arithmetic; the Rust code keeps Apple's
  policy.
- **One canonical `aprv.wasm`**, built once per release for
  `wasm32-wasip1` with wasi-sdk's libc and a link-time C file. It imports
  exactly one function, `random-get`, and exposes four typed operations
  through the canonical ABI, described in one WIT file (R23).
- **Thin wrappers in nine languages** run that one file. Each host is a
  Wasm runtime the language already has: Endive (Java 11+), native
  WebAssembly (JS), wazero (Go), wasmtime-py (Python), WasmKit (Swift),
  the wasmtime gem (Ruby), Wasmtime .NET. Java 8 and PHP reach the same
  module through `aprv-server`, one Rust binary that runs it in a child
  process (R22).
- **One independent Java implementation**, the 0.7 BouncyCastle one,
  kept and maintained side by side as the main Maven artifact and as the
  live differential oracle for the core (R25, R33).

A security fix then lands in Rust, rebuilds one `aprv.wasm`, and reaches
every Wasm-hosted package in the next release. No wrapper parses a
receipt, checks a signature or decides trust. The Rust core never runs as
native code inside a caller's process unless the caller builds the C ABI
themselves (R32).

## Read in this order

1. [INVENTORY.md](./INVENTORY.md): what 0.7.0 ships, where, and how big.
2. [SURFACE.md](./SURFACE.md): the 0.7 API is the surface; the fixture
   file is the contract.
3. [ARCHITECTURE.md](./ARCHITECTURE.md): crates, `aprv.wasm`, the
   canonical ABI, the instance model, time, and one chapter per host.
4. [THREAT-MODEL.md](./THREAT-MODEL.md): the isolation classes A to E,
   per host, and what a guest compromise reaches.
5. [SUPPORT-MATRIX.md](./SUPPORT-MATRIX.md): floors and platforms per
   language in 0.8.0.
6. [DECISIONS.md](./DECISIONS.md): R1 to R34 in their final state, and
   one table of rejected alternatives.
7. [MIGRATION.md](./MIGRATION.md): seven phases with gates, CI, release
   artifacts, risks and the owner's actions.

The evidence behind every number is under [../evidence/](../evidence/),
dated 2026-09-25 to 2026-09-29.

## What the spikes settled

**The core.**

- **OpenSSL 4.0.2 with the CMS API carries the core** (R21). It answers
  as the Java implementation does on 1,028 of 1,048 rows the C ABI can
  express, all 22 signature-algorithm inputs included, and none of the
  other 20 is a forgery. Coverage-guided fuzzing with OpenSSL instrumented
  found nothing in any campaign ([ASN.1 payload][payload],
  [follow-up][followup], [CMS everywhere][cms]).
- **It builds for Wasm.** `wasm32-unknown-unknown` cannot build
  `openssl-sys` (20 × E0432). A `wasm32-wasip1` build with wasi-sdk's libc
  and a link-time C file gave the native answers on all 1,179 corpus rows
  on nine hosts ([CMS everywhere §2, §3][cms]).
- **One small ABI carries all of it.** ABI v1 kept every cryptographic
  verdict and every endpoint answer on all 6,179 rows (the 1,179 corpus
  rows plus 5,000 mutants), trapped on every misuse the 33 mandatory tests
  try, and cost nothing measurable against the earlier bridge
  ([ABI v1][abi]).
- **The canonical ABI carries it just as well.** The same core module
  with four typed exports from a WIT file answered 6,176 of the 6,179
  rows byte-identically on eight hosts (wazero, Endive and WasmKit by
  hand; jco on Node, Deno and Bun, wasmtime-py and Rust Wasmtime through
  bindings), the other 3 being intended; every misuse trapped on every
  host; the module grew 0.47%; `aprv-server`'s runtime-only Wasmtime
  loaded the precompiled component in 14 ms to the first result
  ([canonical ABI][cabi], [canonical ABI final][cabifinal]).

**The hosts.** Every host below answered all 6,179 rows byte-identically
to Node and passed the 37 ABI and facade tests (the 33 mandatory tests
plus 4 of the facade's contract):

| Host | g5 receipt | JWS | Note |
|---|---:|---:|---|
| Node (V8), one instance | 1,343 µs | 4,819 µs | [ABI v1][abi] |
| Endive 1.1.0, JDK 21, `ByteArrayMemory`, 1 / 4 threads | 154.7 / 482.2 per s | 52.6 / 166.8 per s | [ABI v1][abi], [Endive][endive] |
| wasmtime-py 49.0.0, plain `.wasm` | 1,783 µs | 5,198 µs | [Python wasmtime][pywt] |
| WasmKit 0.4.0, Swift 6.3.3 | 13.3 ms | 54.7 ms | [Swift WasmKit][swift] |
| wasmtime gem 48.0.1, `gvl: false` | 1,334 µs | 4,709 µs | [Ruby][ruby] |
| Wasmtime .NET 48.0.2, .NET 10 | 1,310 µs | 4,541 µs | [.NET][dotnet] |
| `aprv-server`, static musl, fresh instance, over HTTP | 218.6 per server CPU-s | 95.9 per server CPU-s | [static musl][musl] |

Every row clears the owner's guideline of about 10 verifications per
second per core (R4). WasmKit's JWS row is the thinnest margin, 1.7 to 1.9
times the floor. wazero ran the same corpus identically
([CMS everywhere §2][cms]) and, through the canonical ABI, 238.5 g5 and
77.0 JWS per second ([canonical ABI final][cabifinal]).

**Java 8 without native code in the JVM.** A pure-Java client supervising
`aprv-server` as a child passed 31 of 31 checks on Temurin 8: it survives
a deliberate child abort, restarts the child, and leaves no orphan however
the JVM ends. A g5 call costs 3.87 ms from Java 8
([aprv-server §6][server]).

**The server ships as one static binary per Linux architecture.** Static
musl builds for x86_64 and aarch64 run from an empty chroot and on
Alpine, 6 to 8% slower than glibc, 3.66 MB and 3.39 MB gzipped. A
one-line change stops the one-shot CLI paying 55 ms of unwinder teardown
([static musl][musl]).

**Python compiles the plain module at start.** wasmtime-py spends about
1 s on 4 CPUs and 3 s on one compiling `aprv.wasm` once per process
(934 ms and 2,923 ms). Wasmtime's own cache brings a warm start to 95 ms.
A precompiled `.cwasm` would start in 62 to 72 ms, and is rejected because
it ties the wheel to one Wasmtime major (R27;
[runtime options][pyopt], [execution modes][modes]).

**What did not work,** each in the rejected table of DECISIONS.md with its
measured reason: pywasm (0.006 JWS per second), Pulley (4.6 to 7.5 JWS per
second), WAMR's interpreter (9.4) and JITs (cold starts of 0.45 s to
153 s), Wasmi's generic C API (no fuel, no memory limiter), mimalloc (no
gain, 11 to 17 MiB more RSS), Wasmi as the Python default
([final Python round][pyfinal]).

## Owner calls (all settled)

| # | Question | Decision |
|---|---|---|
| R22 (2026-09-28) | The principle? | Wasm first everywhere: one `aprv.wasm`; a native parser never runs inside a caller's process by default |
| Export ABI, R23 (2026-09-29) | What is `aprv.wasm`'s export ABI? | The canonical ABI (the Component Model's calling convention) over one WIT file: `init`, `verify-receipt`, `verify-signed-data`, `verify-receipt-endpoint`, inputs as `list<u8>`, `env` as `u32`, `now-ms` as `u64`, outputs as `string`. Component runtimes bind it (jco, Wasmtime `bindgen!`); the others call the core exports by hand in 35 to 66 lines. Confirmed by two spike rounds on eight hosts |
| Q49 (d), R23 (2026-09-28) | Instance model? | `Verifier.create(config)` owns a small pool; each instance gets `init` once; one call at a time per instance; a trapped instance is discarded; no handles, nothing to free. Node: one instance. `aprv-server`: fresh instance per request unless Phase 1 measures `init` above 10% of a call, then `--lifecycle pool` |
| Q51 (b), R24 (2026-09-28) | What does the clock decide, and where is it read? | Once per call in the wrapper, passed as `now-ms`; used for the chain instant when the input carries no date and for `request_date` (the 0.7 rule). The module imports only `random-get` |
| Per-call `now` (2026-09-28) | A public per-call time argument? | Dropped, as in 0.7. The ABI carries `now-ms` per call anyway, so an override later is additive |
| Standards, R34 (2026-09-29) | Which published standards does 0.8.0 adopt? | JSON Schema 2020-12 for the wire shapes; OpenAPI 3.1 with Spectral and Schemathesis for `aprv-server`; RFC 9457 for its non-result errors; SLSA provenance and a CycloneDX SBOM per artifact; a reproducible-build script; OCI image annotations; cbindgen for the C header; `wasi:random/random@0.2` as the import if Phase 1 confirms it. JCS considered and not adopted |
| Java artifacts, R25 (2026-09-28) | How many, and on which floor? | Two, both Java 8: the pure-Java BouncyCastle artifact, unchanged and maintained, and `apple-purchase-receipt-verifier-wasm` with the same package and class names; a classpath guard refuses both at once |
| Engine / ServerSource, R25 (2026-09-28) | How does `-wasm` choose its engine? | Programmatically and explicitly, never through system properties or environment variables of ours: `Verifier.create(config)` picks by JVM version (Endive on 11+, the server on 8); `Engine.endive()`; `Engine.server(ServerSource...)` with `url`, `executable`, `maven`, `github`, `download`, in the user's order, default `[maven, github]` |
| Q44, R26 (2026-09-28) | Server binaries on Maven Central? | Classifier jars of the static musl server for `linux-x86_64` and `linux-aarch64`; macOS and Windows binaries from GitHub Releases |
| Q52 (a), R27 (2026-09-28) | Python runtime? | wasmtime-py, at or above the current major with no pin to one major |
| Q45 / Q53 (a), R27 (2026-09-28) | Compiled code for Python? | The plain `.wasm`, compiled at start; Wasmtime's `Config.cache` on by default, silently off when the cache directory is read-only, path overridable by an environment variable; Lambda pays the compile per new container, documented |
| Q54, R28 and R30 (2026-09-28) | Floors, and platforms without a wasmtime-py wheel? | Java 8, Python 3.10, Swift 6.3 with macOS 15 and iOS 18, Ruby 3.3, .NET netstandard2.0 (tested on net8+), Node 20, Go as today, PHP 8.2. Where wasmtime-py has no wheel, install fails with a message that points to `aprv-server` or the C ABI |
| Q47 (a), R29 (2026-09-28) | PHP? | One-shot `aprv` CLI per call by default, an optional server URL, and an `aprv install` command that downloads the binary from GitHub Releases against a pinned SHA-256 |
| R31 (2026-09-28) | Server build? | Wasmtime 49 runtime-only with an embedded baseline `.cwasm`; static musl on Linux; musl's own malloc; `cli-fast-exit`. Exotic CPUs stay open |
| R33 (2026-09-28), supersedes R8 | What independent checking survives? | The maintained Java implementation, run against the core on all 311 cases in CI and on the corpus in the differential job |
| R21 (2026-09-26) | Security substrate? | OpenSSL 4 through rust-openssl, CMS API, our own chain policy, ASN.1 templates for the payload |
| R4, R5, R6, R19, R20 | npm, Fastly/Akamai, Go, versions, Apple compatibility | Plain Wasm for npm; drop Fastly and Akamai; wazero for Go; one 0.8.0 release; `fixtures/cases.json` is the contract and a divergence that changes an Apple-signed verdict is a bug |

The mapping of the Q numbers to their subjects follows the grouping in the
owner's brief of 2026-09-28.

[payload]: ../evidence/2026-09-26-openssl-asn1-payload.md
[followup]: ../evidence/2026-09-26-substrate-followup.md
[cms]: ../evidence/2026-09-26-openssl-cms-everywhere.md
[abi]: ../evidence/2026-09-26-wasm-abi-v1.md
[cabi]: ../evidence/2026-09-29-canonical-abi-spike.md
[cabifinal]: ../evidence/2026-09-29-canonical-abi-final.md
[endive]: ../evidence/2026-09-26-endive-build-time-jvm.md
[pywt]: ../evidence/2026-09-26-python-wasmtime.md
[swift]: ../evidence/2026-09-26-swift-wasmkit.md
[ruby]: ../evidence/2026-09-26-ruby-wasmtime.md
[dotnet]: ../evidence/2026-09-26-dotnet-wasmtime.md
[musl]: ../evidence/2026-09-27-static-musl-server.md
[server]: ../evidence/2026-09-26-aprv-server.md
[pyopt]: ../evidence/2026-09-27-python-runtime-options.md
[modes]: ../evidence/2026-09-27-wasm-execution-modes.md
[pyfinal]: ../evidence/2026-09-27-python-runtime-final.md
