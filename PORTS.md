# Hosts

What each package runs the verification on, where it runs, and how to
check it. Every package exposes the same API (one `Verifier`, built from a
`Config` of roots and a clock, with `verifyReceipt`, `verifySignedData` and
`verifyReceiptEndpoint`) and answers the same 377 cases of
`fixtures/cases.json`, one test each. The verdicts come from two places
only: the Rust core, which every package but the Java main artifact runs
as `aprv.wasm`, and the Java implementation. No wrapper holds a parser, a
signature check or a trust decision ([CONTRIBUTING.md](./CONTRIBUTING.md)).
[SUPPORT-MATRIX.md](./SUPPORT-MATRIX.md) says which language lines CI runs.

## Host capabilities

"Module" says how the package gets `aprv.wasm`: committed in git (Go and
Swift, because their registries build from the git tree) or packed by the
release job from the one module it built. Either way the package checks
the file against a pinned SHA-256 before it runs it. "Input into the
module" is the most any wrapper copies into the module's memory: the
input caps themselves (3,145,728 UTF-8 bytes for a receipt's base64 or an
endpoint body, 262,144 for a JWS) are the core's, the same everywhere, so
one byte over the cap is enough for the module to answer `TOO_LARGE`.

| Package | Runs the core on | Floor | Platforms | Module | Input into the module | Roots in `Config` | One-command check |
|---|---|---|---|---|---|---|---|
| Java, main artifact | nothing: the independent Java implementation over BouncyCastle | Java 8 | any Java 8+ JVM | none | no module; the same caps in Java | `Set<X509Certificate>`; defaults are its own constants | `mvn -B -f java/pom.xml verify` |
| Java `-wasm`, Endive engine | Endive 1.1.0: the module compiled to JVM bytecode when the jar is built; no native code | Java 11 | any Java 11+ JVM, one jar | compiled into the jar from the release's module | at most 3,145,729 bytes | as the main artifact | `java-wasm/scripts/g1.sh` |
| Java `-wasm`, server engine | `aprv-server` as a supervised child process (or a server you run) | Java 8 | Linux x86_64 and aarch64 through the classifier jars; macOS and Windows through `ServerSource.github()`; anywhere through `url()` or `executable()` | the server binary: classifier jar or GitHub Release asset, SHA-256 pinned in the jar | the server's 3,145,728-byte body cap (413) | as the main artifact; sent to the child at start | `java-wasm/scripts/g1.sh` (server legs) |
| Node (npm) | jco 1.35.0's bindings of the component, on the runtime's own WebAssembly | Node 20 | Node, Bun, Deno (`--allow-env=JCO_DEBUG`), Cloudflare Workers, Vercel Edge, browsers | packed in the tarball (the component, transpiled) | at most 3,145,729 bytes | DER `Uint8Array`; `null` means the module's roots | `node node/scripts/g1.mjs DIR` |
| Go | wazero v1.12.0, no cgo | Go 1.25 | where wazero runs; `CGO_ENABLED=0`, cross-compiled, `FROM scratch` | committed: `go/internal/wasm/aprv.wasm` | at most 3,145,729 bytes | `[]*x509.Certificate`; none means the module's roots | `go/internal/corpusrun/g1.sh` |
| Python (PyPI) | wasmtime-py `>=49`; the module compiled at start, with an on-disk cache | Python 3.10 | where wasmtime-py ships a wheel: Linux glibc and musl, macOS, Windows, on x86_64 and arm64; elsewhere install stops with a pointer to `aprv-server` | packed in platform-tagged wheels | at most 3,145,729 bytes | DER `bytes` | `python/tools/g1.sh` |
| Ruby (RubyGems) | the `wasmtime` gem `>= 48.0.1`, calls without the GVL | Ruby 3.3 (3.4 on Windows arm64) | where the gem ships a prebuilt native gem: Linux glibc and musl, macOS, Windows, on x86_64 and arm64 | packed in the gem | at most 3,145,729 bytes | DER strings, or objects with `#to_der` | `docs/evidence/2026-09-29-ruby-host/scripts/g1.sh` |
| Swift (SwiftPM) | WasmKit 0.4.1, an interpreter; software bounds checks | Swift 6.3, macOS 15, iOS 18 | Linux, macOS, iOS; no JIT entitlement needed | committed: `swift/Sources/ApplePurchaseReceiptVerifier/Resources/aprv.wasm` | at most 3,145,729 bytes | `[[UInt8]]?`, DER; `nil` means the module's roots | `swift/scripts/gate.sh DIR` |
| .NET (NuGet) | Wasmtime .NET 48.0.2 | netstandard2.0; tested on .NET 8 and later | Wasmtime's native libraries: `linux-x64` (glibc 2.28), `linux-arm64`, `osx-x64`, `osx-arm64`, `win-x64`, `win-arm64`; no musl, no 32-bit (Alpine takes `aprv-server`) | embedded in the assembly | at most 3,145,729 bytes | `X509Certificate2`, read for its DER only | `docs/evidence/2026-09-29-dotnet-host/scripts/g1.sh` |
| PHP (Packagist) | `aprv-server`: one `aprv` process per call by default, or a server URL | PHP 8.2, 64-bit | where an `aprv` binary exists; the Linux static binaries are pinned per release, every other platform uses a server URL | none in the package; `vendor/bin/aprv-install` downloads the binary and checks the SHA-256 in `php/binaries.json` | the binary's 3,145,728-byte cap (exit 3, or 413) | DER roots, written for the binary as `--roots FILE`; a server URL must report the same roots | `php/tools/rerun.sh APRV_BINARY DIR` |
| `aprv-server` | Wasmtime 49 runtime-only, running the component precompiled at build time; HTTP, managed child, one-shot CLI | none for its users; Rust for the build | Linux x86_64 and aarch64 (static musl), macOS x86_64 and arm64, Windows x86_64 and arm64; a distroless image on GHCR | the component, precompiled and embedded in the binary | 3,145,728 bytes of body or stdin (413, exit 3); 256 MiB of linear memory; 10 s of guest time per call | `--roots FILE`, one base64 DER per line or PEM; none means the module's roots | `rust/server/scripts/check-component.sh` |
| Rust crate | native: the core over OpenSSL 4, in the caller's process | Rust 1.85 | wherever the crate and OpenSSL 4 build | none | the core's caps | `TrustAnchor::from_der` values in `Config::builder().roots(...)` | `cargo test --locked --workspace` in `rust/` |
| C ABI (`rust/ffi`) | native: the core over OpenSSL 4, in the caller's process; source only | Rust 1.85 to build it | Linux, macOS and Windows in CI | none | the core's caps | DER roots passed to `aprv_verifier_new` | the C++ and ctypes harnesses (`rust/ffi/README.md`) |

The one-command checks run everything the package's CI job runs plus the
parity run over the corpora of generated receipts against a directory
holding a module, its call files and its reference rows. Each script's
header names what it needs.

Notes:

- **In process or not.** Every Wasm host keeps the module in a sandbox
  inside the caller's process (THREAT-MODEL.md, "Where the core runs").
  The Java server engine and PHP put an operating-system process boundary
  around it too. The Rust crate and the C ABI run the core and OpenSSL as
  native code in the caller's process, which is the caller's choice; no
  package does that by default.
- **Roots.** "The module's roots" are Apple's three published roots,
  compiled into `aprv.wasm`; `Config.defaults()` (or its spelling) selects
  them. An explicitly empty root list is refused at `Verifier` creation in
  every package but PHP, where it means the module's roots: a verifier
  that trusts nothing would reject everything silently. A root the module
  cannot read as a certificate fails `Verifier` creation too. To trust
  Apple's roots and your own, pass all four.
- **The clock** is read once per call, before the input is looked at, and
  passed to the module as `now-ms`. A clock that throws is `INTERNAL_ERROR`
  (21009 at the endpoint).
- **A trap** in the module is `INTERNAL_ERROR` for that call; the instance
  is discarded and the next call runs on a fresh one. A module that is not
  the one the package was built for fails at `Verifier` creation.
- **Speed and start-up** differ a lot between hosts (Python and Ruby
  compile the module at start; WasmKit interprets it). BENCHMARKS.md has
  what was measured.

## The API, per language

The same three methods in each language's idiom. docs/design/0.7-api.md is
the contract.

| Package | Result form | Clock |
|---|---|---|
| Java (both artifacts) | `VerificationResult<T>` | `java.time.Clock` |
| Node | `{ verified, payload } \| { verified, failure }` | `() => number` |
| Go | `(payload, error)`, the error a `*Failure` | `func() int64` |
| Python | `VerificationResult` | callable returning epoch ms |
| Ruby | result object | proc returning epoch ms |
| Swift | `VerificationResult` | closure returning epoch ms |
| .NET | `VerificationResult<T>` | `Func<long>` |
| PHP | `VerificationResult` | PSR-20 `ClockInterface` |
| Rust | `Result<Payload, Failure>` | closure returning epoch ms |
| C ABI | a JSON document and a status code | a fixed instant in ms, or `NULL` for the system clock |
| `aprv-server` | the module's JSON, HTTP 200; RFC 9457 problems for everything that is not a result | `X-Aprv-Now-Ms` header or `--now-ms`, else the server's clock |

- Both caps are Apple's: 3,145,728 bytes answered, 3,145,729 refused with
  HTTP 413, counted in UTF-8 bytes (measured 2026-09-23, COMPARISON.md).
  `fixtures/cases.json` pins them as a MUST, and no caller can change
  either cap. Go and Swift no longer export them as constants; an input
  over a cap is `TOO_LARGE` (DECISIONS.md R41).
- A `Config` is built one way per package, in the language's idiom
  (DECISIONS.md R41): `Config(roots=..., clock=...)` in Python,
  `Config.new(roots:, clock:)` in Ruby, `new Config(roots: ..., clock: ...)`
  in PHP, `Config::default()` or `Config::builder()` in Rust. Python's
  `Config.create`/`Config.defaults`, Ruby's `Config.builder`, PHP's
  `ConfigBuilder` and Rust's `Config::defaults()` are gone.
- `receipt-data` and `x5c` entries are canonical standard base64 only, as
  Apple's `verifyReceipt` was measured to accept it (THREAT-MODEL.md
  §3.8). The module decodes them; no wrapper has a base64 decoder of its
  own, so each wrapper's runner reaches the `decodeBase64` cases through
  `verifyReceipt` and through a JWS whose `x5c` carries the text.
- Nothing checks the bundle id, the endpoint included, as Apple's did not.
  Each package README lists the checks that stay with the caller.
- Java's main artifact runs a startup probe at `Verifier.create` (its
  crypto engines and the bundled roots' signatures), with an opt-out in
  `Config`. In every Wasm package, creating a `Verifier` instantiates the
  module and calls `init` with the roots, so a module that cannot run or a
  root it refuses fails there too.
