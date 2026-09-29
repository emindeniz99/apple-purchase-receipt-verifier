# Support matrix for 0.8.0

Status: **target of the accepted plan**, 2026-09-28. The root
[SUPPORT-MATRIX.md](../../SUPPORT-MATRIX.md) describes what CI tests for
0.7.0 and keeps its rule: every supported language line and every
declared floor is a CI leg. This file says what 0.8.0 supports: the floor
of each package, the platforms each host reaches, and what happens on the
platforms it does not. The root file changes to match in Phase 7.

## 1. Floors

Owner, 2026-09-28 (DECISIONS.md R30).

| Package | Floor in 0.8.0 | At 0.7.0 | What sets it |
|---|---|---|---|
| Java, main artifact | Java 8 | Java 8 | unchanged |
| Java, `-wasm` artifact | Java 8; the Endive engine needs Java 11 | new | Endive requires Java 11 ([Endive §2][endive]); on Java 8 the default engine is `aprv-server` |
| Python | 3.10 | 3.10 | unchanged; wasmtime-py 49.0.0 declares `>=3.9` ([Python wasmtime][pywt]) |
| Swift | Swift 6.3, macOS 15, iOS 18 | Swift 6.1, macOS 13 | WasmKit declares `swift-tools-version:6.3` and `.macOS(.v15), .iOS(.v18)` ([Swift WasmKit][swift]); the package needs WasmKit 0.4.1, which fixes a use-after-free under software bounds checking that 0.4.0 has when a host function re-enters the guest (STATUS.md, lane Swift) |
| Ruby | 3.3 | 3.3 | the `wasmtime` gem's prebuilt native gems need Ruby ≥ 3.3 (≥ 3.4 on Windows arm64) ([Ruby][ruby]) |
| .NET | netstandard2.0, tested on net8 and later | netstandard2.0, net8.0 | the `Wasmtime` package reaches netstandard2.0; the spike ran .NET 8 and 10, and netstandard2.0 compiled but was not run on .NET Framework ([.NET][dotnet]) |
| Node | 20 | 20 | unchanged |
| Go | as today (1.22 in `go.mod`) | 1.22 | kept if the wazero release we need builds on it; wazero 1.12.0 fetched a Go 1.25 toolchain in the spikes ([rust-core spikes][spikes], Method), so Phase 4 checks and raises the floor only if it must |
| PHP | 8.2 | 8.2 | unchanged |
| Rust crate | the core's `rust-version` | 1.85.0 | the workspace's; `wasmtime` 49.0.1 in the server declares MSRV 1.96 ([aprv-server][server]), which binds only the server |

**Java 8 in CI.** Temurin's Java 8 builds end in late 2026 (0.7-api.md,
"The other ports"). The `java-runtime-8` leg, which runs the server engine
on a real Java 8 JVM, moves to Zulu 8 or Corretto 8 before then.

## 2. Platforms per host

"In-process Wasm" means the host runs `aprv.wasm` inside the caller's
process (isolation classes A to C, THREAT-MODEL.md §2). "Tested" names
what the evidence ran; CI adds the legs MIGRATION.md lists.

| Package | Host | Platforms | Tested in the evidence |
|---|---|---|---|
| Java main | the JVM | any Java 8+ JVM | as 0.7.0 |
| Java `-wasm`, Endive engine | JVM bytecode, no native code | any Java 11+ JVM; one jar for every platform | Linux x86-64, JDK 11, 17, 21, 25 ([Endive][endive]) |
| Java `-wasm`, server engine | `aprv-server` child | where a server binary exists (below), or any platform through `url()` or `executable()` | Temurin 8u504, Linux x86-64 ([aprv-server §6][server]) |
| npm | the runtime's WebAssembly | Node 20+, Bun, Deno, Cloudflare Workers (workerd), Vercel Edge, Chromium, Firefox, WebKit | Node, Bun, Deno, Chromium, Firefox, WebKitGTK, workerd ([CMS everywhere §2][cms]) |
| Go module | wazero | the platforms wazero supports | Linux x86-64 ([CMS everywhere §2][cms]) |
| PyPI | wasmtime-py | where wasmtime-py ships a wheel: manylinux x86_64 and aarch64, musllinux x86_64 and aarch64, macOS x86_64 (10.13) and arm64 (11.0), Windows amd64 and arm64, Android arm64 and x86_64 | Linux x86-64, CPython 3.12 and 3.10 ([Python wasmtime][pywt]) |
| SwiftPM | WasmKit | Linux, macOS 15+, iOS 18+ | Linux x86-64, Swift 6.3.3; iOS not built ([Swift WasmKit][swift]) |
| RubyGems | the `wasmtime` gem | prebuilt gems for `x86_64-linux`, `x86_64-linux-musl`, `aarch64-linux`, `aarch64-linux-musl`, `x86_64-darwin`, `arm64-darwin`, `x64-mingw-ucrt`, `aarch64-mingw-ucrt` | Linux x86-64, Ruby 3.3.6 ([Ruby][ruby]) |
| NuGet | the `Wasmtime` package | `linux-x64` (glibc 2.28), `linux-arm64` (glibc 2.18), `osx-x64`, `osx-arm64`, `win-x64`, `win-arm64` | Linux x86-64, .NET 8 and 10 ([.NET][dotnet]) |
| Packagist | `aprv-server` | where a server binary exists, or through a server URL | Linux x86-64, PHP 8.4 ([aprv-server §7][server]) |
| `aprv-server` | Wasmtime 49 in its own process | Linux x86_64 and aarch64 (static musl); macOS x86_64 and arm64; Windows x86_64 and arm64 | Linux x86-64 glibc and musl; aarch64 musl under QEMU for correctness only ([static musl][musl]) |
| C ABI | native, from source | wherever stable Rust and OpenSSL build | Ubuntu, macOS and Windows in `rust-ffi`, as today |

Notes on the rows:

- **wasmtime-py's glibc tags overstate the floor.** Its x86_64 wheel is
  tagged `manylinux1` (glibc 2.5) but its library needs glibc 2.28; the
  aarch64 wheel needs 2.18 against its tag's 2.17. pip installs it on
  CentOS 7 or Amazon Linux 2, and loading fails there (expected from the
  symbol versions, not run; [Python wasmtime][pywt]).
- **.NET on Alpine.** The `Wasmtime` package ships no `linux-musl-*`
  library; .NET falls back to the glibc `linux-x64` one, which is
  expected to fail without `gcompat` ([.NET][dotnet]). Alpine .NET users
  take `aprv-server`.
- **Ruby elsewhere.** The source gem builds with Rust and needs a
  Cranelift backend: possible on s390x and riscv64, not on 32-bit targets
  ([Ruby][ruby]).
- **macOS and Windows server binaries** have not been built yet; the
  sizes and speeds of those four are unmeasured ([aprv-server §11][server]).
- **Exotic CPUs** (ppc64le, loongarch64, 32-bit) have no Cranelift
  backend. Whether `aprv-server` runs there, through Pulley or otherwise,
  is open (DECISIONS.md R31).

## 3. In process, through the server, or refused at install

| Situation | What the user gets |
|---|---|
| A package whose Wasm runtime supports the platform | in-process Wasm |
| Java 8 on a platform with a server binary | the `-wasm` artifact's server engine, by default; or the main artifact |
| Java 8 elsewhere | the main artifact; or the server engine through `url()` or `executable()` with a server built for that platform |
| Java 11+ anywhere | the Endive engine, or the main artifact |
| PHP | the server CLI or a server URL, on any platform a binary exists for |
| Python where wasmtime-py has no wheel | install fails with a message that points to `aprv-server` or the C ABI (R28) |
| .NET on Alpine | `aprv-server` |
| Any language, or any runtime we do not package | `aprv-server` over HTTP or its CLI, or the C ABI built from source |
| Fastly Compute JS, Akamai EdgeWorkers | not supported: neither runs WebAssembly (R5) |

**The Python platforms without a wheel.** Of the 19 wheel tags R12 planned
in 2026-09, wasmtime-py 49.0.0 has no wheel for 11 ([Python
wasmtime][pywt]):

- manylinux armv7l, i686, ppc64le, s390x and riscv64;
- `linux_armv6l`;
- musllinux armv7l, i686, ppc64le and riscv64;
- Windows win32.

On all of them pip today installs wasmtime-py's `py3-none-any` wheel,
which holds only the Windows x86_64 DLL, and `import wasmtime` fails.
Phase 5 makes our package fail at install instead, with the pointer.

## 4. Maven classifier platforms

The `-wasm` artifact carries the static musl `aprv-server` as two
classifier jars (DECISIONS.md R26):

| Classifier | Binary | gzip -9 |
|---|---|---:|
| `linux-x86_64` | static-pie, x86_64 musl | 3,656,734 B |
| `linux-aarch64` | static, aarch64 musl | 3,390,574 B |

Sizes from [static musl §1][musl]. Both run on any Linux kernel of their
architecture, glibc or musl, with no loader. macOS and Windows binaries
are GitHub Release assets that `ServerSource.github()` downloads against
a SHA-256 pinned in the jar.

## 5. What changes against 0.7.0

- Swift's floor rises to 6.3, macOS 15 and iOS 18 (R30).
- Python is bounded by wasmtime-py's wheels instead of `cryptography`'s.
  The 0.7.0 package is a `py3-none-any` wheel over `cryptography`, which
  ships manylinux armv7l and ppc64le wheels among others
  ([rust-core spikes][spikes], "Which platforms other native libraries
  ship") and builds from source elsewhere; those platforms move to
  `aprv-server` or the C ABI (§3).
- npm drops Fastly Compute JS and Akamai EdgeWorkers (R5).
- Ruby, .NET and PHP publish for the first time, once their registries
  are bootstrapped (BOOTSTRAP.md).
- Java gains the `-wasm` artifact; the main artifact is unchanged.

[endive]: ../evidence/2026-09-26-endive-build-time-jvm.md
[pywt]: ../evidence/2026-09-26-python-wasmtime.md
[swift]: ../evidence/2026-09-26-swift-wasmkit.md
[ruby]: ../evidence/2026-09-26-ruby-wasmtime.md
[dotnet]: ../evidence/2026-09-26-dotnet-wasmtime.md
[spikes]: ../evidence/2026-09-25-rust-core-spikes.md
[server]: ../evidence/2026-09-26-aprv-server.md
[cms]: ../evidence/2026-09-26-openssl-cms-everywhere.md
[musl]: ../evidence/2026-09-27-static-musl-server.md
