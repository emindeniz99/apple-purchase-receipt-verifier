# Support matrix

Which language versions this repository tests, which of them the vendor still
supports, and the rule that decides both. Snapshot taken 2026-09-06 from
[endoflife.date](https://endoflife.date); refresh it with
`node tools/support-matrix.mjs` and compare the output with the matrices in
`.github/workflows/ci.yml`.

## The rule

1. **Every line the vendor still supports is a CI leg.** Active and
   security-only lines both count. A push runs each port's full suite on each
   leg, so "supported" here means tested, not "should work".
2. **The floor each package declares is a CI leg too, even after the vendor
   drops it.** The floor is what the manifest promises consumers: `engines`
   in node, `Requires-Python`, `rust-version`, `TargetFramework`,
   `required_ruby_version`, the composer `php` constraint, the `go`
   directive, the Java release level. A floor stays until it costs something:
   a dependency that needs a newer line, a runner image that disappears, or a
   language feature the port needs. Raising a floor is a breaking change for
   that port and gets a major bump.
3. **A new major joins the matrix in the first pull request after its GA.**
   Early-access and release-candidate builds are not tested.
4. **Dependabot bumps the tool pins, not the matrices.** Adding or dropping a
   matrix line is a deliberate change with a line in ROADMAP.md.

## Snapshot, 2026-09-06

Status is the vendor's: *active* means bug fixes still land, *security* means
security fixes only, *EOL* means nothing lands. Every line below is a CI leg;
the last column names the job.

### .NET

| Line | Type | Status | Ends | CI |
|---|---|---|---|---|
| 8.0 | LTS | active | 2026-11-10 | `dotnet` (ubuntu, windows, macOS), `dotnet-trim`, `dotnet-fuzz` |
| 9.0 | STS | active | 2026-11-10 | `dotnet` |
| 10.0 | LTS | active | 2028-11-14 | `dotnet` |
| netstandard2.0 | floor | n/a | while the library ships it | `dotnet-mono` |

.NET 11 ships in November 2026, the same day 8 and 9 end.

### Node

| Line | Type | Status | Ends | CI |
|---|---|---|---|---|
| 20 | floor | EOL 2026-04-30 | kept | `node`, `node-runtimes` (workerd-floor) |
| 22 | LTS | security | 2027-04-30 | `node` |
| 24 | LTS | active | 2028-04-30 | `node`, `node-runtimes` (node, bun, deno, workerd), `node-runtimes-fastly`, `node-fuzz` |
| 26 | LTS | active | 2029-04-30 | `node` |

### Python

| Line | Status | Ends | CI |
|---|---|---|---|
| 3.9 | floor, EOL 2025-10-31 | kept | `python` |
| 3.10 | security | 2026-10-31 | `python` |
| 3.11 | security | 2027-10-31 | `python`, `python-tools` |
| 3.12 | security | 2028-10-31 | `python` |
| 3.13 | active | 2029-10-31 | `python`, `python-fuzz` |
| 3.14 | active | 2030-10-31 | `python` |

Python 3.15 ships in October 2026.

### Java

Dates are Oracle's. Eclipse Temurin and other vendors keep 8, 11 and 17 in
support for longer; the floor stays regardless.

| Line | Type | Status | Ends | CI |
|---|---|---|---|---|
| 8 | floor | EOL at Oracle | kept | `java-runtime-8` (the artifact runs on a JDK 8 JVM) |
| 11 | LTS | EOL at Oracle 2023-09-30 | kept | `java` |
| 17 | LTS | active | 2026-09-30 | `java` |
| 21 | LTS | active | 2028-09-30 | `java`, `java-fuzz`, `jvm-interop` |
| 25 | LTS | active | 2030-09-30 | `java` |
| 26 | feature | active | 2026-09-18 | `java` |

Java 27 ships 2026-09-15 and replaces 26 as the feature-release leg.

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
| 1.22 to 1.25 | floor and EOL lines | kept | `go` |
| 1.26 | active | when 1.28 ships | `go` |
| 1.27 | active | when 1.29 ships | `go`, `go-platforms` (macOS, windows), `go-race`, `go-lint`, `go-fuzz` |

Go 1.28 ships in February 2027.

### Ruby

| Line | Status | Ends | CI |
|---|---|---|---|
| 3.1 | floor, EOL 2025-03-26 | kept | `ruby`, `ruby-gem` |
| 3.2 | EOL 2026-03-31 | kept | `ruby` |
| 3.3 | security | 2027-03-31 | `ruby`, `ruby-tools` |
| 3.4 | active | 2028-03-31 | `ruby`, `ruby-macos`, `ruby-fuzz` |
| 4.0 | active | 2029-03-31 | `ruby`, `ruby-gem` |

Ruby 4.1 ships in December 2026.

### PHP

| Line | Status | Ends | CI |
|---|---|---|---|
| 8.1 | floor, EOL 2025-12-31 | kept | `php`, `php-lowest` |
| 8.2 | security | 2026-12-31 | `php` |
| 8.3 | security | 2027-12-31 | `php`, `php-static`, `php-mutation`, `php-fuzz` |
| 8.4 | active | 2028-12-31 | `php` |
| 8.5 | active | 2029-12-31 | `php` |

PHP 8.6 ships in November 2026.

### Rust

Rust supports the current stable only.

| Line | Status | CI |
|---|---|---|
| 1.74.0 | floor (`rust-version`) | `rust` |
| stable (1.98 today) | active | `rust`, `rust-lint`, `rust-supply-chain`, `rust-fuzz` (nightly) |
| beta | next stable | `rust` |

#### The C ABI (`rust/ffi`)

This crate promises a C99 header and a C ABI, so it pins no compiler version
and the matrix below is operating systems instead. The linker's contract is
what differs across them: symbol visibility, the import-library dance on
Windows, rpath on the two Unixes. Each leg uses whichever system compiler its
runner image ships.

| Line | Status | CI |
|---|---|---|
| Rust 1.74.0 | floor (`rust-version`, same as the library) | `rust-ffi` (ubuntu) |
| ubuntu-latest (gcc), macos-latest (clang), windows-latest (MSVC) | the linker matrix | `rust-ffi` |

Should a consumer's compiler ever be the thing that breaks, the fix belongs in
the header rather than in a new leg here.

### Swift

endoflife.date does not track Swift, and Apple patches only the newest
release. The floor is the oldest toolchain that builds the package.

| Line | Status | CI |
|---|---|---|
| 6.1 | floor | `swift` (Linux container) |
| 6.2 | superseded | `swift` |
| 6.3 | current | `swift`, `swift-macos`, `swift-format`, `swift-fuzz` |

## Due next

| When | Change | Where |
|---|---|---|
| 2026-09-15 | Java 27 replaces 26 in `jdk:` | ci.yml `java` job |
| October 2026 | Python 3.15 joins `python:` | ci.yml `python` job |
| November 2026 | .NET 11 joins `dotnet-version:` and the test projects' `TargetFrameworks` | ci.yml `dotnet` jobs, `dotnet/tests/*/*.csproj` |
| November 2026 | PHP 8.6 joins `php:` | ci.yml `php` job |
| December 2026 | Ruby 4.1 joins `ruby:` | ci.yml `ruby` job |
| February 2027 | Go 1.28 joins `go:` | ci.yml `go` job |

Vendor ends that change nothing here, because floors stay: Java 17 at Oracle
on 2026-09-30, Python 3.10 on 2026-10-31, .NET 8 and 9 on 2026-11-10, PHP 8.2
on 2026-12-31.
