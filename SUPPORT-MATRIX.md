# Support matrix

Which language versions this repository tests, which platforms each package
runs on, and the rule that decides both. The vendor statuses are a snapshot
taken 2026-09-29 from [endoflife.date](https://endoflife.date); refresh it
with `node tools/support-matrix.mjs` and compare the output with the
matrices in `.github/workflows/ci.yml`. What each package runs the core on
is in [PORTS.md](./PORTS.md).

The `support-matrix` workflow runs `node tools/support-matrix.mjs --check`
every Monday (and on demand), writes its output to the job summary, and
fails when a line in the tables below is past its vendor's end of life.
It reads the tables themselves: a row whose text says `floor` or `kept`
stays a leg past EOL on purpose (rules 1 and 2) and is not checked, so a
failed run means a row to drop, or to mark kept with its reason. Rust and
Swift are not checked: CI tests Rust's current stable, and endoflife.date
does not track Swift.

## The rule

1. **Every line the vendor still supports is a CI leg.** Active and
   security-only lines both count. A push runs each package's full suite on
   each leg, so "supported" here means tested, not "should work".
2. **The floor each package declares is a CI leg too, even after the vendor
   drops it.** The floor is what the manifest promises consumers: `engines`
   in node, `Requires-Python`, `rust-version`, `TargetFramework`,
   `required_ruby_version`, the composer `php` constraint, the `go`
   directive, the Java release level, the Swift tools version and
   `platforms`. A floor moves only when a dependency, a security fix or CI
   forces it: a dependency that needs a newer line, a security fix that
   needs one, or a runner image or toolchain that CI can no longer get
   (owner, 2026-09-21, restated 2026-09-30). A newer line, or a vendor's
   end of support, moves nothing. Raising a floor is a breaking change for
   that package: a major bump after 1.0.0, a minor bump before it, as 0.7
   did for Ruby and PHP and 0.8 does for Swift.
3. **A new major joins the matrix in the first pull request after its GA.**
   Early-access and release-candidate builds are not tested.
4. **Dependabot bumps the tool pins, not the matrices.** Adding or dropping a
   matrix line is a deliberate change with a line in ROADMAP.md.
5. **A Wasm runtime's floor is part of the package's floor.** Where the
   runtime sets the language floor (WasmKit for Swift, wazero for Go), a
   runtime bump that would raise it waits for a floor decision, and
   Dependabot ignores it until then.

## Floors in 0.8.0

| Package | Floor | Was in 0.7.0 | What sets it |
|---|---|---|---|
| Java, main artifact | Java 8 | Java 8 | unchanged; the independent implementation |
| Java, `-wasm` artifact | Java 8; the Endive engine needs Java 11 | new | Endive 1.1.0 needs Java 11; on Java 8 the default engine is `aprv-server` |
| Node | 20 | 20 | unchanged |
| Python | 3.10 | 3.10 | unchanged; wasmtime-py `>=49` |
| Go | 1.25 | 1.22 | wazero v1.12.0 needs Go 1.25 |
| Ruby | 3.3 (3.4 on Windows arm64) | 3.3 | the `wasmtime` gem's prebuilt native gems |
| Swift | Swift 6.3, macOS 15, iOS 18 | Swift 6.1, macOS 13 | WasmKit 0.4.1 declares tools 6.3 and those platforms |
| .NET | netstandard2.0, tested on .NET 8 and later | netstandard2.0, net8.0 | the `Wasmtime` package |
| PHP | 8.2, 64-bit | 8.2 | unchanged |
| Rust crate and C ABI | Rust 1.85.0 | 1.85.0 | the workspace's `rust-version`; `aprv.wasm` itself is built with the pinned 1.98.1 |
| `aprv-server` | none for its users | new | a binary; its build pins `wasmtime` 49.0.1 |

Go's floor moved from 1.22 to 1.25, because wazero 1.12 needs it (owner,
2026-09-30; docs/rust-core/DECISIONS.md R30). Every other floor in the
table stays.

## Snapshot, 2026-09-29

Status is the vendor's: *active* means bug fixes still land, *security* means
security fixes only, *EOL* means nothing lands. Every line below is a CI leg;
the last column names the job. Every host job runs the module the same CI
run built (`rust-wasm`), never one from an earlier run.

### .NET

| Line | Type | Status | Ends | CI |
|---|---|---|---|---|
| 8.0 | LTS | active | 2026-11-10 | `dotnet` (ubuntu, windows, macOS), `smoke-nuget` |
| 9.0 | STS | active | 2026-11-10 | `dotnet`, `dotnet-trim` |
| 10.0 | LTS | active | 2028-11-14 | `dotnet`, `dotnet-fuzz` |
| netstandard2.0 | floor | n/a | while the library ships it | `dotnet-mono` |

.NET 11 ships in November 2026, the same day 8 and 9 end.

### Node

| Line | Type | Status | Ends | CI |
|---|---|---|---|---|
| 20 | floor | EOL 2026-04-30 | kept | `node`, `smoke-npm` |
| 22 | LTS | security | 2027-04-30 | `node`, `node-runtimes` (node, bun, deno, workerd, edge), `node-browsers` (Chromium, Firefox, WebKit) |
| 24 | LTS | active | 2028-04-30 | `node` |
| 26 | LTS | active | 2029-04-30 | `node` |

### Python

| Line | Status | Ends | CI |
|---|---|---|---|
| 3.10 | floor, security | 2026-10-31 | `python`, `python-musl`, `smoke-pypi` |
| 3.11 | security | 2027-10-31 | `python`, `python-musl` |
| 3.12 | security | 2028-10-31 | `python`, `python-musl` |
| 3.13 | active | 2029-10-31 | `python`, `python-musl`, `python-tools`, `python-fuzz` |
| 3.14 | active | 2030-10-31 | `python`, `python-musl` |

`python` runs every line on the six runner images wasmtime-py ships wheels
for (Linux x86_64 and arm64, macOS arm64 and x86_64, Windows x86_64 and
arm64), and again with a warm compile cache; `python-musl` runs them in
Alpine images on x86_64 and arm64. Python 3.15 ships in October 2026.

### Java

Dates are Oracle's. Eclipse Temurin and other vendors keep 8, 11 and 17 in
support for longer; the floor stays regardless.

| Line | Type | Status | Ends | CI |
|---|---|---|---|---|
| 8 | floor | EOL at Oracle | kept | `java-runtime-8` (the main artifact on a JDK 8 JVM), `java-wasm-runtime-8` (the `-wasm` server engine on a JDK 8 JVM) |
| 11 | LTS | EOL at Oracle 2023-09-30 | kept | `java`, `java-wasm-endive` (the Endive floor) |
| 17 | LTS | EOL at Oracle 2026-09-30 | kept | `java`, `java-wasm-endive` |
| 21 | LTS | active | 2028-09-30 | `java`, `java-wasm-endive`, `java-fuzz`, `jvm-interop`, `smoke-maven` |
| 25 | LTS | active | 2030-09-30 | `java`, `java-wasm-endive` |
| 27 | feature | active | 2027-03-31 | `java`, `java-wasm-endive` |

Java 28 ships 2027-03-17 and replaces 27 as the feature-release leg.
Temurin's Java 8 builds end in late 2026; the two Java 8 legs move to Zulu 8
or Corretto 8 before then (an owner decision, BOOTSTRAP.md).
`java-wasm-consumers` runs `jvm-interop` and the Spring Boot smoke on the
`-wasm` artifact, and `java-classpath-guard` proves both artifacts on one
classpath fail fast.

#### Spring Boot (consumer smoke)

Not a language line, but the framework most Java consumers integrate
through, and its BOM overrides the library's Jackson pin. The
`java-spring-boot` job runs `java/samples/spring-boot-smoke` for every Boot
line in open-source support on every Java LTS that line accepts (Boot 4
requires 17 or newer). Older Boot lines (3.5 and 2.7) are commercial-only and
are not tested.

| Line | Status | OSS ends | Java | CI |
|---|---|---|---|---|
| 4.0 | active | 2026-12-31 | 17 to 25 | `java-spring-boot` (17, 21, 25) |
| 4.1 | active | 2027-07-31 | 17 to 26 | `java-spring-boot` (17, 21, 25) |

When 4.0 ends, drop its leg; when 4.2 ships, add it.

### Go

Go supports the two newest minors only.

| Line | Status | Ends | CI |
|---|---|---|---|
| 1.25 | floor, EOL line | kept | `go`, `smoke-go` |
| 1.26 | active | when 1.28 ships | `go` |
| 1.27 | active | when 1.29 ships | `go`, `go-platforms` (macOS, Windows), `go-cross`, `go-scratch`, `go-race`, `go-lint`, `go-fuzz` |

Go 1.28 ships in February 2027. The floor moved from 1.22 to 1.25 on
2026-09-30 because wazero 1.12 requires it (rule 5); its dependency
`golang.org/x/sys` stays at v0.47.0, the newest release that builds on 1.25.

### Ruby

| Line | Status | Ends | CI |
|---|---|---|---|
| 3.3 | floor, security | 2027-03-31 | `ruby`, `ruby-gem`, `ruby-fuzz`, `smoke-rubygems` |
| 3.4 | active | 2028-03-31 | `ruby`, `ruby-macos`, `ruby-tools` |
| 4.0 | active | 2029-03-31 | `ruby`, `ruby-gem` |

Ruby 4.1 ships in December 2026. 0.7 raised the floor from 3.1 to 3.3 for
`Data` (rule 2), and 3.1 and 3.2, both past EOL, left the matrix with it.

### PHP

| Line | Status | Ends | CI |
|---|---|---|---|
| 8.2 | floor, security | 2026-12-31 | `php`, `php-lowest` |
| 8.3 | security | 2027-12-31 | `php` |
| 8.4 | active | 2028-12-31 | `php` (also over HTTP), `php-symfony-process-8`, `php-static`, `php-fuzz` |
| 8.5 | active | 2029-12-31 | `php` |

PHP 8.6 ships in November 2026. 0.7 raised the floor from 8.1 to 8.2 for
`readonly class` (rule 2), and 8.1, past EOL, left the matrix with it. The
PHP jobs run against the static Linux `aprv` binary the same CI run built.

### Rust

Rust supports the current stable only.

| Line | Status | CI |
|---|---|---|
| 1.85.0 | floor (`rust-version`) | `rust` |
| 1.98.1 | the pinned toolchain that builds `aprv.wasm` and `aprv-server` (`rust/rust-toolchain.toml`) | `rust-wasm`, `rust-wasm-checks`, `aprv-server` |
| stable | active | `rust`, `rust-lint`, `rust-supply-chain`, `rust-fuzz` (nightly), `smoke-crates` (held with crates.io) |
| beta | next stable | `rust` |

#### The C ABI (`rust/ffi`)

This crate promises a C99 header and a C ABI, so it pins no compiler version
and the matrix below is operating systems instead. The linker's contract is
what differs across them: symbol visibility, the import-library dance on
Windows, rpath on the two Unixes. Each leg uses whichever system compiler its
runner image ships.

| Line | Status | CI |
|---|---|---|
| Rust 1.85.0 | floor (`rust-version`, same as the library) | `rust-ffi` (ubuntu) |
| ubuntu-latest (gcc), macos-latest (clang), windows-latest (MSVC) | the linker matrix | `rust-ffi` |

Should a consumer's compiler ever be the thing that breaks, the fix belongs in
the header rather than in a new leg here.

### Swift

endoflife.date does not track Swift, and Apple patches only the newest
release. The floor is the oldest toolchain that builds the package, which
WasmKit sets.

| Line | Status | CI |
|---|---|---|
| 6.3 | floor | `swift` (Linux container), `swift-crypto-floor`, `swift-macos`, `swift-ios`, `swift-format`, `swift-fuzz`, `smoke-swiftpm` |
| 6.4 | current | `swift` (Linux container) |

## Platforms per package

"Tested" names what CI runs; a platform the runtime supports and CI does
not run is listed without a job.

| Package | Runs on | Tested |
|---|---|---|
| Java main | any Java 8+ JVM | Linux JDK 8 to 27; distroless images (`java-distroless`) |
| Java `-wasm`, Endive | any Java 11+ JVM; one jar for every platform | Linux JDK 11 to 27 |
| Java `-wasm`, server engine | Linux x86_64 and aarch64 through the classifier jars; macOS x86_64 and arm64 and Windows x86_64 and arm64 through the GitHub Release; anywhere through `url()` or `executable()` | Linux x86_64 on Temurin 8 and a current JDK |
| npm | Node 20+, Bun, Deno, Cloudflare Workers (workerd), Vercel Edge, Chromium, Firefox, WebKit | every runtime listed, in `node-runtimes` and `node-browsers` |
| Go | the platforms wazero supports; `CGO_ENABLED=0`, `FROM scratch` | Linux, macOS, Windows; cross-builds for darwin amd64 and arm64, windows amd64, linux arm64; an empty chroot |
| PyPI | where wasmtime-py ships a wheel: manylinux and musllinux x86_64 and aarch64, macOS x86_64 and arm64, Windows x86_64 and arm64 | all of those |
| RubyGems | the `wasmtime` gem's prebuilt gems: `x86_64-linux`, `x86_64-linux-musl`, `aarch64-linux`, `aarch64-linux-musl`, `x86_64-darwin`, `arm64-darwin`, `x64-mingw-ucrt`, `aarch64-mingw-ucrt` | Linux, macOS |
| SwiftPM | Linux, macOS 15+, iOS 18+ | Linux (6.3 and 6.4), macOS, an iOS build |
| NuGet | Wasmtime's native libraries: `linux-x64` (glibc 2.28), `linux-arm64` (glibc 2.18), `osx-x64`, `osx-arm64`, `win-x64`, `win-arm64` | Linux, macOS, Windows; netstandard2.0 on Mono |
| Packagist | where an `aprv` binary exists, or through a server URL | Linux x86_64, through the CLI and over HTTP |
| `aprv-server` | Linux x86_64 and aarch64 (static musl, any kernel of the architecture, glibc or musl, no loader), macOS x86_64 and arm64, Windows x86_64 and arm64; a distroless image for amd64 and arm64 | Linux x86_64 (glibc) and aarch64 (static musl), macOS arm64, Windows x86_64; the image on amd64 and arm64 |
| C ABI | wherever stable Rust and OpenSSL 4 build | Ubuntu, macOS, Windows |

Notes on the rows:

- **wasmtime-py's glibc tags overstate the floor.** Its x86_64 wheel is
  tagged `manylinux1` (glibc 2.5) but its library needs glibc 2.28; the
  aarch64 wheel needs 2.18 against its tag's 2.17. pip installs it on
  CentOS 7 or Amazon Linux 2, and loading fails there at import rather
  than at install.
- **.NET on Alpine.** The `Wasmtime` package ships no `linux-musl-*`
  library; .NET falls back to the glibc `linux-x64` one, which is
  expected to fail without `gcompat`. Alpine .NET users take `aprv-server`.
- **Ruby elsewhere.** The source gem builds with Rust and needs a
  Cranelift backend: possible on s390x and riscv64, not on 32-bit targets.
- **Exotic CPUs** (ppc64le, loongarch64, 32-bit) have no Cranelift
  backend. Whether `aprv-server` runs there is open
  (docs/rust-core/DECISIONS.md R31).

## In process, through the server, or refused at install

| Situation | What the user gets |
|---|---|
| A package whose Wasm runtime supports the platform | the module in a sandbox in the caller's process |
| Java 8 on a platform with a server binary | the `-wasm` artifact's server engine, by default; or the main artifact |
| Java 8 elsewhere | the main artifact; or the server engine through `url()` or `executable()` with a server built for that platform |
| Java 11+ anywhere | the Endive engine, or the main artifact |
| PHP | the server CLI or a server URL, on any platform a binary exists for |
| Python where wasmtime-py has no wheel | `pip install` stops with a message that points to `aprv-server` or the C ABI |
| .NET on Alpine | `aprv-server` |
| Any language, or any runtime we do not package | `aprv-server` over HTTP or its CLI, or the C ABI built from source |
| Fastly Compute JS, Akamai EdgeWorkers | not supported: neither runs WebAssembly |
| LLRT (AWS Low Latency Runtime) | not supported: not tested here, and it runs on QuickJS, which has no WebAssembly, per the vendor's documentation |
| CloudFront Functions | not supported: not tested here, and the runtime has no WebAssembly and limits a function to 10 KB of code, per the vendor's documentation |
| Hermes (React Native) | not supported: not tested here, and it has no `WebAssembly` object, per the vendor's documentation |
| GraalJS, Nashorn | not supported: not tested here. Per the vendors' documentation, neither offers the APIs the npm package loads the module with (`node:fs`, or `fetch` with `import.meta.url`), and Nashorn has no WebAssembly. On a JVM, use the Java artifacts |

**The Python platforms without a wheel.** wasmtime-py 49.0.0 has no wheel
for manylinux armv7l, i686, ppc64le, s390x and riscv64; `linux_armv6l`;
musllinux armv7l, i686, ppc64le and riscv64; and Windows win32. The package
publishes platform-tagged wheels only, so pip falls back to the source
distribution there, which stops with the pointer.

## Maven classifier platforms

The `-wasm` artifact carries the static musl `aprv-server` as two
classifier jars, found by `ServerSource.maven()`:

| Classifier | Binary | Jar |
|---|---|---:|
| `linux-x86_64` | static-pie, x86_64 musl | 4,210,771 B |
| `linux-aarch64` | static, aarch64 musl | |

Both run on any Linux kernel of their architecture, glibc or musl, with no
loader. The x86_64 jar size is the one lane E built around the 0.7 core's
component; the aarch64 jar has not been built outside CI. macOS and Windows
binaries are GitHub Release assets that `ServerSource.github()` downloads
against a SHA-256 pinned in the jar.

## What changes against 0.7.0

- Swift's floor rises to 6.3, macOS 15 and iOS 18.
- Python is bounded by wasmtime-py's wheels instead of `cryptography`'s;
  platforms without one move to `aprv-server` or the C ABI.
- .NET runs where Wasmtime ships a native library; Alpine and 32-bit move
  to `aprv-server`.
- npm drops Fastly Compute JS and Akamai EdgeWorkers.
- Ruby, .NET and PHP publish for the first time, once their registries
  are bootstrapped (BOOTSTRAP.md).
- Java gains the `-wasm` artifact; the main artifact is unchanged.

## Due next

| When | Change | Where |
|---|---|---|
| October 2026 | Python 3.15 joins `python:` and `python-musl` | ci.yml `python` jobs |
| November 2026 | .NET 11 joins `dotnet-version:` and the test projects' `TargetFrameworks` | ci.yml `dotnet` jobs, `dotnet/tests/*/*.csproj` |
| November 2026 | PHP 8.6 joins `php:` | ci.yml `php` job |
| Late 2026 | the Java 8 legs move from Temurin 8 to Zulu 8 or Corretto 8 | ci.yml `java-runtime-8`, `java-wasm-runtime-8` |
| December 2026 | Ruby 4.1 joins `ruby:` | ci.yml `ruby` job |
| February 2027 | Go 1.28 joins `go:` | ci.yml `go` job |
| March 2027 | Java 28 replaces 27 in `jdk:` | ci.yml `java` and `java-wasm-endive` jobs |

Vendor ends that change nothing here, because floors stay: Java 17 at Oracle
on 2026-09-30, Python 3.10 on 2026-10-31, .NET 8 and 9 on 2026-11-10, PHP 8.2
on 2026-12-31.
