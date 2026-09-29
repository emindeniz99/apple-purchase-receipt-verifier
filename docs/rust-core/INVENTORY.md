# Baseline: where the repository stands at 0.7.0 (2026-09-28)

The migration starts from this snapshot: `rust-core` (then named
`plan/one-rust-core`) at
`1af140f`, which merges `main` with 0.7.0. 0.7.0 was released on
2026-09-28 (tags `v0.7.0` and `go/v0.7.0`, CHANGELOG.md). Registry states
come from each registry's public API on 2026-09-28, except Maven Central,
which was not re-queried; everything else comes from the files named.
Nothing was built to measure this page; "not re-measured" marks each
number that would need a build.

The first form of this page described 0.6.0 on 2026-09-25; git history
keeps it.

## What ships, and to whom

| Package | Registry | Live at 0.7.0? | Floor | Crypto | Runtime dependencies | Size |
|---|---|---|---|---|---|---|
| Java | Maven Central `io.github.emindeniz99:apple-purchase-receipt-verifier` | yes, per the release workflow and CHANGELOG (registry not re-queried) | Java 8 (`java-runtime-8`) | BouncyCastle 1.86, a private provider | `bcpkix-jdk18on` 1.86 (with `bcprov` and `bcutil`), `jackson-core` 2.22.2; `jspecify` optional | not re-measured; 0.6.0's jar was 71 KB, 11.8 MB with Bouncy Castle and Jackson ([rust-core spikes][spikes] row 18), and 0.7 dropped `jackson-databind` |
| Node | npm `apple-purchase-receipt-verifier` | yes, 0.7.0 | Node 20 | `node:crypto`; WebCrypto in `/web` | none | 291,820 B unpacked, 70 files (npm registry) |
| Python | PyPI `apple-purchase-receipt-verifier` | yes, 0.7.0 | 3.10 | `cryptography` + `asn1crypto` | `cryptography>=40`, `asn1crypto>=1.5,<2` | wheel 56,521 B, sdist 76,095 B (PyPI) |
| Go | Go proxy, module `.../go`, tags `go/v*` | yes: v0.4.0, v0.5.1, v0.6.0, v0.7.0 | Go 1.22 | stdlib | none | not re-measured |
| Swift | SwiftPM from the repository | yes, tag `v0.7.0` | tools 6.1, macOS 13 and Linux | swift-crypto (≥ 4.5.1), swift-certificates, swift-asn1 | 3 packages | not re-measured |
| Rust | crates.io | no (404) | 1.85.0 | RustCrypto `rsa`, `p256`, `p384`, `sha1`, `md-5`, `sha2` | 10 crates, direct | — |
| C ABI | none | source only | the Rust floor | the Rust core | none | — |
| Ruby | RubyGems | no (404) | 3.3 | the `openssl` default gem | none | — |
| PHP | Packagist, from the root `composer.json` | no (404) | 8.2 | `ext-openssl` | `psr/clock` | — |
| .NET | NuGet `ApplePurchaseReceiptVerifier` | no (404) | netstandard2.0, net8.0 | `System.Security.Cryptography.Pkcs` | 2 | — |

0.7.0 reached the same registries as 0.6.0. crates.io, RubyGems,
NuGet and Packagist still wait for the owner's bootstrap steps
(BOOTSTRAP.md).

## Size of what gets replaced

Lines of library source in each port at `1af140f`, from `wc -l` over the
language's files under the folder named, test files and test folders
excluded, generated root data included:

| Port | Folder | Lines | Fate in 0.8.0 |
|---|---|---:|---|
| Java | `java/src/main` | 3,200 | **stays**: the independent implementation (R33) |
| Node | `node/src` | 6,188 | replaced by a façade over `aprv.wasm` |
| Python | `python/apple_purchase_receipt_verifier` | 2,625 | replaced by a façade over wasmtime-py |
| Go | `go/` | 4,262 | replaced by a wrapper over wazero |
| Swift | `swift/Sources` | 2,979 | replaced by a wrapper over WasmKit |
| Ruby | `ruby/lib` | 3,755 | replaced by a wrapper over the `wasmtime` gem |
| PHP | `php/src` | 4,193 | replaced by a façade over `aprv-server` |
| .NET | `dotnet/src` | 5,580 | replaced by a wrapper over Wasmtime .NET |
| Rust | `rust/src` | 6,271 | becomes the core; its ASN.1, X.509, CMS, chain and crypto modules leave for OpenSSL (R21) |
| C ABI | `rust/ffi/src` | 1,048 | stays, over the surface and the wire |

## The Rust core today

- The 0.7 API: `Verifier::new(Config)`, `ReceiptPayload`, `JsonPayload`,
  `Failure` with the eight 0.7 reasons (CHANGELOG 0.7.0). The `endpoint`
  feature and its `serde_json` dependency are gone.
- `#![forbid(unsafe_code)]` (`rust/src/lib.rs:49`) and the lint wall
  denying `unwrap`, `expect`, indexing and `panic`.
- Its own ASN.1, X.509, CMS, chain and crypto modules over RustCrypto: the
  code R21 replaces with OpenSSL. `include_bytes!` embeds the three Apple
  roots from `rust/certs/`; no filesystem, environment or network access.
- Seven fuzz targets: `verify-receipt`, `verify-receipt-base64`,
  `verify-transaction`, `endpoint-json`, and the three parser targets
  `parse-der`, `parse-certificate` and `parse-cms` that leave with their
  modules.

## The C ABI today (`rust/ffi`)

- A `cdylib` and `staticlib`, unpublished, outside any workspace, with its
  own `Cargo.lock`, and a cbindgen header CI regenerates and diffs.
- 0.7 moved it to one verifier: `aprv_verifier_new`, `aprv_verifier_free`,
  `aprv_verify_receipt`, `aprv_verify_signed_data`,
  `aprv_verify_receipt_endpoint`, `aprv_string_free`, `aprv_version`;
  results are JSON documents, the receipt one exactly
  `ReceiptPayload.toJson()`.
- CI tests it on Ubuntu, macOS and Windows with C++17 and ctypes harnesses
  and an Elixir NIF example. The `decodeBase64` cases are not reachable
  through it, and it has no fuzz target of its own (PORTS.md).

## Tests that become host tests

Every port has a `fixtures/cases.json` runner, trust-isolation,
hostile-input and input-cap tests, and a fuzz target. `cases.json` is
schema v2 with 311 cases. After the migration the non-Java runners test a
host: loading, pooling, the clock read, trap recovery, conversions. They
stay; what they call changes.

## CI and release today

- `ci.yml` has 61 jobs; every action is pinned to a SHA; zizmor reports 0
  findings.
- `release.yml` has one publish job per registry (`publish-pypi`,
  `publish-npm`, `publish-maven`, `publish-rubygems`, `publish-crates`,
  `publish-nuget`), `tag-go-module` and a smoke job; it never caches and
  skips registries that are not bootstrapped. No build-provenance or
  attestation step exists yet.
- `post-publish-smoke.yml` installs from each real registry and verifies
  the genuine g5 receipt.
- Maven Central allows 7 releases, about 80 MB and about 1,000 files per
  calendar month (CLAUDE.md).

## Decisions on record that the migration touches

| Record | What it says today | What the migration does to it |
|---|---|---|
| PLAN.md D2 and the 0.7 floors | Java 8, Node 20, Python 3.10, Swift 6.1, Ruby 3.3, PHP 8.2, netstandard2.0 | Keeps them all except Swift, which rises to 6.3, macOS 15 and iOS 18 (R30) |
| PLAN.md D8, D16 | Minimal dependencies; hand-written readers per port on each ecosystem's crypto | Superseded for the eight non-Java ports: one Rust policy over OpenSSL (R21); the Java implementation keeps BouncyCastle |
| PLAN.md D15 | Three pinned Apple roots | Unchanged; pruning them is rejected (DECISIONS.md, rejected table) |
| CLAUDE.md "Behavior changes" | Nine implementations are one product | A behaviour change touches the Rust core, the Java implementation and `fixtures/` in one PR (R33) |
| CLAUDE.md certs copies | Seven ports keep a copy of `certs/`; Node, Ruby, PHP, .NET and Java inline the roots | `rust/certs` and Java's constants remain |
| CLAUDE.md "one version, many files" | Every manifest and version constant | Gains the new wrappers' constants and loses the deleted ones |
| ROADMAP.md "A shared Rust core compiled to WebAssembly" | A future idea | This plan, for 0.8.0 |
| ROADMAP.md "C ABI phase 2" | Prebuilt binaries undecided | Unchanged: the C ABI ships as source; the prebuilt native artifacts are `aprv-server`'s |
| Root THREAT-MODEL.md §5 | `asn1crypto`, Java ignoring host policy, the C ABI's `unsafe` | The first closes with the Python port; the others stay; the Wasm boundaries are in this folder's THREAT-MODEL.md |

[spikes]: ../evidence/2026-09-25-rust-core-spikes.md
