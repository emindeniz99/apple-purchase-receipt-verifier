# Phase 0: where the repository stands (2026-09-25)

The migration starts from this snapshot. Commit `80c6320`, version 0.6.0,
released 2026-09-24. Registry states come from each registry's API on
2026-09-25; everything else comes from the files named.

## What ships, and to whom

| Package | Registry | Live? | Floor | Crypto today | Runtime deps |
|---|---|---|---|---|---|
| Java | Maven Central `io.github.emindeniz99:apple-purchase-receipt-verifier` | yes, 0.6.0 | Java 8 (`java-runtime-8` CI job) | Bouncy Castle 1.86, private provider | bcpkix/bcprov/bcutil (about 9.4 MB), jackson-databind 2.22 (about 2.4 MB) |
| Node | npm `apple-purchase-receipt-verifier` | yes, 0.6.0 | Node 20 | `node:crypto` (default build), WebCrypto (`/web`) | none |
| Python | PyPI `apple-purchase-receipt-verifier` | yes, 0.6.0 | 3.10 | `cryptography` + `asn1crypto` | 2 (plus cffi, pycparser) |
| Swift | SwiftPM, repository URL | yes, tags | Swift 6.1, macOS 13 and Linux | swift-crypto, swift-certificates, swift-asn1 | 3 packages |
| Go | Go proxy, module `.../go`, tags `go/v*` | **yes**, v0.4.0, v0.5.1, v0.6.0 | Go 1.22 | stdlib | none |
| Rust | crates.io | **no** (404, first publish pending in BOOTSTRAP.md) | 1.85.0 | RustCrypto `rsa` 0.9, `p256`/`p384` 0.13 | 9 crates |
| C ABI | none | source only | the Rust MSRV | the Rust core | none |
| Ruby | RubyGems | no | 3.1 | openssl default gem | none |
| PHP | Packagist | no | 8.1, 64-bit | ext-openssl | `psr/clock` |
| .NET | NuGet `ApplePurchaseReceiptVerifier` | no | netstandard2.0, net8.0 | `System.Security.Cryptography.Pkcs` | 2 |

Downloads last month: npm 529, PyPI 698. Maven Central and the Go proxy
publish no counts.

Doc drift found on the way, to fix in the first migration PR:
- README.md:70, README.md:96-100 and BOOTSTRAP.md:130-157
  still describe Go as not installable.
- `rust/README.md:10` offers `cargo add` for a crate that is not published.
- `rust/ffi/README.md:160` and root `README.md:83` say twenty-one symbols,
  and `rust/ffi/src/lib.rs:6` says seven verification calls. The code has
  20 and 8 (`rust/ffi/README.md:53` already says so).
- CLAUDE.md says "one version, eight files". `release-please-config.json`
  bumps nine extra files plus `version.txt` and the CHANGELOG.
- SUPPORT-MATRIX.md:50 says the Node runtime jobs run on Node 24. `ci.yml`
  pins Node 22 for them.

## Size of what gets replaced

Line counts of library source (tests in brackets), from `wc -l`:

| Port | Source | Tests |
|---|---:|---:|
| Java | 3,612 | 10,018 |
| Node | 3,451 + 1,204 web | 5,679 |
| Python | 1,860 | 2,888 |
| Swift | 2,093 | 4,031 |
| Go | 3,580 | 7,732 |
| Ruby | 2,898 | 3,861 |
| PHP | 3,848 | 6,160 |
| .NET | 4,986 | 7,268 |
| **Rust core** | **5,358** | about 220 tests plus the 186-case conformance runner |
| Rust C ABI | 1,595 in `lib.rs` (tests included), 20 symbols | 25 unit tests, C++ and ctypes conformance |

About 28,000 lines of security code across eight ports duplicate what the
5,358 Rust lines do.

## The Rust core today

- `#![forbid(unsafe_code)]`. It also denies `unwrap`, `expect`, indexing,
  `panic`, `todo`, `unimplemented`, `unreachable` and `mem::forget`
  (`rust/src/lib.rs:65-82`).
- The core has no `build.rs`. `include_bytes!` embeds the three Apple roots
  from `rust/certs/`. It does no filesystem, environment or network access.
  `deny.toml` bans trust-store and network crates.
- Seven fuzz targets. `tests/hostile.rs` mutates 5,000 receipts and 2,000
  JWS under `catch_unwind`. The conformance runner covers all 186 cases.
- Public API: builder-based `JwsVerifier` and `ReceiptVerifier`, and
  `VerifyReceiptEndpoint` behind the default `endpoint` feature. Also
  `Reason` (13 tokens), `VerificationError`, `ConfigError`, `CoreError`,
  `Environment`, `TrustAnchor`, `Clock`, and the payload structs.
- The core reads the clock in four places: `jws.rs:455` and `receipt.rs:134`
  (chain-validity fallback when the payload carries no date), plus
  `clock.rs:32` and `endpoint.rs:525` (endpoint `request_date`).
- Shapes that do not cross a binding boundary as they are:
  - builders that consume `self`;
  - `impl IntoIterator`;
  - `Arc<dyn Clock>`;
  - `SystemTime` fields;
  - `serde_json::Map` claims;
  - `BTreeMap<u32, Vec<Vec<u8>>>`;
  - `#[non_exhaustive]` structs;
  - `u64` ids;
  - `Tlv<'a>` in the public `asn1` module.

## The C ABI today (`rust/ffi`)

- `cdylib` + `staticlib`, unpublished, not a workspace member, with its own
  `Cargo.lock`.
- 20 exported symbols, opaque handles, and JSON results through
  `AprvResult { int32_t status; char *json }`. Callers must free strings
  with `aprv_string_free`. Every export runs inside `catch_unwind`, and a
  test enforces that.
- The header comes from cbindgen 0.29.0. CI regenerates it and fails on a
  diff.
- CI tests it on Ubuntu (gcc), macOS (clang) and Windows (MSVC). The tests
  are C++17 conformance, Python ctypes conformance and an Elixir NIF
  example.
- Gaps against the ports (PORTS.md):
  - no `verified` flag and no re-render;
  - no `REQUEST_TOO_LARGE`;
  - no base64 decoder entry point;
  - no fuzz target of its own;
  - no prebuilt binaries (ROADMAP "C ABI phase 2", undecided).
- It already carries the "cross-port JSON view" of a receipt: ISO-8601
  dates, lowercase hex under `<name>Hex`, `unknownAttributes` keyed by
  string. The bindings can reuse it.

## Tests that become binding tests

Every port has a `fixtures/cases.json` runner, trust-store isolation tests,
hostile-input tests, input-cap tests and a fuzz target. After the migration
the per-port runners stop testing an algorithm and start testing a binding:
conversions, nullability, errors, lifetimes. They stay; only what they call
changes.

## CI and release today

- `ci.yml` has 53 jobs. Every action is pinned to a SHA and zizmor reports
  0 findings. Rust jobs use no cache.
- JS runtime legs:
  - Node 20/22/24/26 (`node`);
  - Bun, Deno and workerd ×3 (`node-runtimes`);
  - WebCrypto on Node, `@edge-runtime/vm` (Vercel Edge) and workerd with
    no flags (`node-runtimes-web`);
  - Fastly via js-compute-runtime and viceroy (`node-runtimes-fastly`).
- Akamai EdgeWorkers is claimed but untested (`node/README.md:96-108`).
- `release.yml` has one publish job per registry, never caches, and skips
  registries that are not bootstrapped. Java publishes with a token and GPG
  key; the rest use OIDC. Go publishes by creating the `go/vX.Y.Z` tag
  through the API. **No build provenance or attestation step exists.**
- `post-publish-smoke.yml` installs from each real registry and verifies the
  genuine g5 receipt.
- Maven Central allows 7 releases per calendar month, and every tag spends
  one.

## Decisions on record that the migration touches

| Record | What it says today | What the migration does to it |
|---|---|---|
| PLAN.md D2 | Floors: Java 8, Node 20, Python 3.10, Swift 6 | Keeps all of them except Swift on Linux (6.2, see R7). |
| PLAN.md D7 | Full type safety (strict TypeScript, `py.typed`); Node still zero runtime dependencies | Keeps it: the wasm glue ships inside the package. |
| PLAN.md D8 | Minimal dependencies, hand-rolled parsers | Reversed by R21 (2026-09-26): OpenSSL's parsers, under the Rust policy, become the only parsers, and the hand-rolled Rust ones are deleted. |
| PLAN.md D16 | Hand-written readers per port, per-ecosystem crypto; the Node web build must run WebCrypto-only on workerd and Fastly | **Superseded.** One Rust policy over OpenSSL everywhere (R21). The Fastly clause fails (R5). |
| CLAUDE.md "Behavior changes" | Nine implementations are one product | Becomes one implementation, many bindings. |
| CLAUDE.md certs copies | `go/`, `ruby/`, `rust/`, `php/` copy `certs/`; Node, Ruby, PHP and .NET inline the roots | Root `certs/` stays canonical, and `rust/certs` is the only copy. |
| ROADMAP "C ABI phase 2" | Prebuilt binaries undecided | Becomes mandatory: every binding ships prebuilt natives. |
| ROADMAP RHEL 9 SHA-1 | Per-port raw-RSA fix planned for Ruby, PHP, .NET, Python, Node | Moot: the Rust core does not read the host crypto policy. |
| THREAT-MODEL §5 | asn1crypto unmaintained; Java ignores host policy; C ABI `unsafe` | The first closes. The second becomes true for every package. The third grows: `unsafe` lives in the OpenSSL adapter (R21), `rust/ffi` and the `aprv.wasm` exports; the UniFFI adapter contains no hand-written `unsafe` (its scaffolding does). OpenSSL joins the trusted base. |
