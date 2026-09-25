# Rust core behind generated bindings: spike results

Measured 2026-09-25. This note is the evidence behind
[docs/rust-core/](../rust-core/README.md), the plan to make the Rust crate
the only verifier implementation and ship every other package as a thin
binding over it. The throwaway sources are in
[2026-09-25-rust-core-spikes/](./2026-09-25-rust-core-spikes/README.md).
None of them is built by CI.

## Result

| # | Question | Answer |
|---|---|---|
| 1 | Does the core build for `wasm32-unknown-unknown` as it stands? | **No.** `getrandom` 0.2 refuses the target. The `std` features on `rsa`, `p256` and `p384` enable `rand_core/std`, which pulls it in. |
| 2 | Does it build once those three `std` features go? | **Yes**, for native and wasm. `getrandom` leaves the dependency graph entirely. Verification needs no randomness. |
| 3 | Does it build for `wasm32-wasip1`? | **Yes**, unchanged. |
| 4 | What does `SystemTime::now()` do on `wasm32-unknown-unknown`? | It **traps** (`RuntimeError: unreachable`) on Node, Bun and Deno. Case `transaction/accept-payload-without-a-signed-date` reaches it through the chain-validity fallback in `rust/src/jws.rs:455`. |
| 5 | Does the UniFFI Python binding work? | **Yes.** Typed exceptions (`VerifyError.Verification` with `.reason` as an enum), keyword default arguments, and Rust doc comments as docstrings. |
| 6 | Can Java 8 use the UniFFI Kotlin binding? | **Yes, with one rule.** Any unsigned integer in a signature makes the method private to Java (Kotlin mangles value-class parameters), so the Java call does not compile. With `i64` instead, Java 8 gets try-with-resources (`AutoCloseable`), a checked exception via `@Throws`, a typed `Reason` enum and `List<byte[]>`. Kotlin default arguments are invisible to Java, so Java passes `null` explicitly. |
| 7 | What do JDK 24+ users see? | JDK 25 prints `WARNING: java.lang.System::load has been called by com.sun.jna.Native in an unnamed module` once. `--enable-native-access=ALL-UNNAMED` silences it. `--illegal-native-access=deny` fails at class init with `ExceptionInInitializerError`. |
| 8 | Does wasm-bindgen output run on every JS runtime we test today? | Node 22, Bun 1.3.11, Deno 2.9.7: **yes**. Cloudflare workerd (compat date 2024-09-23, no flags): **yes, when the `.wasm` arrives as a static module import.** workerd refuses `WebAssembly.compile(bytes)` with "Wasm code generation disallowed by embedder". |
| 9 | Can Go run the core without cgo? | **Yes**, through wazero v1.12.0 with `CGO_ENABLED=0`, on a `wasm32-wasip1` build with a pointer-and-length ABI and JSON out. |
| 10 | Do Rust doc comments reach Java users? | **Yes.** UniFFI copies every `///` comment into KDoc on the class, constructor and methods. Dokka 2.0.0 (`dokka:javadoc` with `javadoc-plugin` and `kotlin-as-java-plugin`) turns that into a Javadoc site. Two blemishes: the pages show Kotlin type names (`ByteArray`, `Unit`, `List<ByteArray>`) and no `throws` clause, and a comment that names a Rust parameter (`trusted_roots`) shows it verbatim. `javap` shows Java callers the right shapes (`verify(byte[]) throws VerifyException`, `getBundleId()`), but autocomplete also offers UniFFI plumbing: constructors taking `UniffiWithHandle`, `NoHandle` or `DefaultConstructorMarker`, and `callWithHandle$…`. |
| 11 | Does the verifyReceipt endpoint survive the binding, result object included? | **Yes, on Temurin 8.** `jvm/EndpointDemo.java` drives `VerifyReceiptEndpoint` and `VerifyReceiptResult` as UniFFI objects. The genuine g5 sandbox receipt sent to a Production endpoint answers `{"status":21007}` with `verified=true` and a typed receipt. `toJsonIn(SANDBOX)` re-renders the same result as `{"environment":"Sandbox","receipt":{...}}` without a second verification. A Sandbox endpoint answers 0. A body of `not json` answers 21002 / `MALFORMED_REQUEST` with no exception. |
| 12 | How do objects, records and maps behave across the boundary? | `jvm/ObjectsDemo.java` on Temurin 8. `VerifyReceiptResult` stays a handle to the Rust object: verification runs once, and each later `toJson()`/`toJsonIn()` is one FFI call rendering the stored result (about 99 µs, no re-verification). `receipt()` copies the nested record (`AppReceipt` with its `List<InAppPurchase>`) into plain Java objects. Kotlin generates `var` fields, so Java can edit its copy, and the Rust result stays unchanged (`toJsonIn` output byte-identical after the edit). `generate_immutable_records = true` would make the copies read-only. A Rust `HashMap` arrives as a read-only `java.util.Map` (`kotlin.collections.builders.MapBuilder`); `put` throws `UnsupportedOperationException`. |
| 13 | Can one endpoint be a long-lived shared field, and must results be closed? | `jvm/SharedDemo.java` on Temurin 8, 4 vCPUs: one `static final VerifyReceiptEndpoint`, never closed, served 16 threads × 200 calls. All 3,200 answered 21007, at 2,099 verifications/s. None of the 3,200 results was closed. After GC the heap held 19 MB and the process RSS was 147 MB, so the Cleaner freed them. |
| 14 | What does it cost? | See the timing table. Native Rust roughly matches the current ports. Wasm costs about 5.3 times the current `node:crypto` build (3.5 times `/web`). wazero costs about 30 times the current Go port. |

## Timings

One Linux x86_64 cloud container with shared vCPUs. Every row ran on the
same machine in the same hour, so compare the ratios rather than the
absolute numbers. "Receipt" is `receipt/verify-genuine-sandbox-g5-against-apple-roots`
(base64 in, pinned Apple roots). "JWS" is the generated
`fixtures/generated/transaction.jws` against `jws-root.der`. Every loop ran a
warm-up first.

| Path | Receipt µs/op | JWS µs/op |
|---|---:|---:|
| npm 0.6.0, default build (`node:crypto`), Node 22 | 683 | 732 |
| npm 0.6.0, `/web` build (WebCrypto), Node 22 | 1,001 | 1,134 |
| PyPI 0.6.0 (`cryptography` + `asn1crypto`), CPython 3.11 | 669 | 484 |
| Maven 0.6.0 (Bouncy Castle), JDK 21, 10k warm-up, mean of 3 × 10k | 781 | 1,253 |
| Maven 0.6.0 (Bouncy Castle), Temurin 8, same method | 821 | 1,373 |
| Rust core via UniFFI, Python | 742 | 1,053 |
| Rust core via UniFFI Kotlin, JDK 21, 10k warm-up, mean of 3 × 10k | 701 | 1,096 |
| Rust core via UniFFI Kotlin, Temurin 8, same method | 701 | 1,125 |
| Rust core via UniFFI Kotlin, Temurin 8 | 877 (short run) | not run |
| Rust core as wasm, Node 22, `opt-level=3` | 3,626 | 3,900 |
| Rust core as wasm, Bun, `opt-level="z"` | 2,960 | not run |
| Rust core as wasm, Deno, `opt-level="z"` | 2,933 | not run |
| Rust core as `wasm32-wasip1` in wazero (Go 1.25 toolchain) | 6,740 | not run |
| Rust core as `wasm32-wasip1` in Chicory 1.7.5, runtime compiler, JDK 21 | 18,546 | not run |
| Rust core as `wasm32-wasip1` in Chicory 1.7.5, interpreter, JDK 21 | 974,602 | not run |

The Go port was not timed here. BENCHMARKS.md records 207 µs for the same
receipt on a different machine.

Reading the table:

- **JVM:** the Rust core beats today's Maven artifact on both paths: by
  10% (receipt) and 13% (JWS) on JDK 21, and by 15% and 18% on Java 8.
  Those JVM rows use 10,000 warm-up calls and three rounds of 10,000
  (`jvm/Bench10kMaven.java`, `jvm/Bench10kUniffi.java`). The first
  measurement (500 to 2,000 warm-up calls, 880 against 668 µs) overstated
  the gap, because Bouncy Castle gains most from a longer JIT warm-up.
  The rounds varied by under 5%.
- **Python:** it matches on receipts. JWS takes twice as long, because
  `cryptography` runs ECDSA in OpenSSL.
- **JWS in Rust is the slow spot everywhere.** RustCrypto's pure-Rust
  P-256/P-384 costs about 1 ms per transaction where OpenSSL costs 0.5 to
  0.7 ms. Phase 1 of the plan profiles this before any number becomes a
  promise.
- **Wasm:** 64-bit multiplies dominate RSA and ECDSA, and wasm32 emulates
  the 128-bit products. `opt-level=3` barely helps (3,626 against about
  3,800 for `z`).
- wazero adds its own overhead on top of wasm.
- **Wasm on the JVM is not an option.** Chicory's compiler runs the core 28x
  slower than the UniFFI native build on the same JDK, and Chicory needs
  Java 11 (the floor is 8).

## Sizes

| Artifact | Bytes |
|---|---:|
| `aprv_wasm_bg.wasm`, `opt-level="z"`, LTO, no `wasm-opt` | 374,492 |
| the same, gzip -9 | 133,363 |
| `aprv_wasm_bg.wasm`, `opt-level=3` | 564,982 |
| `aprv_wasi.wasm` (Go spike), `opt-level=3` | 467,042 |
| `libaprv_uniffi.so`, release, x86_64 Linux | 1,163,848 |
| npm 0.6.0 unpacked, 56 files | 239,944 |

## Registries on 2026-09-25

Queried live from each registry's API.

| Registry | State |
|---|---|
| npm | 0.6.0, zero dependencies, `engines.node >=20`, 529 downloads 2026-08-23..09-21 |
| PyPI | 0.6.0, pure `py3-none-any` wheel, needs `cryptography>=40` and `asn1crypto`, 698 downloads last month |
| Maven Central | 0.6.0 |
| Go proxy | `go/v0.4.0`, `v0.5.1`, `v0.6.0`. **Live**, although README.md:70 and README.md:96-100 still say otherwise. |
| crates.io | 404, never published |
| RubyGems, NuGet, Packagist | 404, never published |

## Method

- Toolchains: rustc 1.94.1, uniffi 0.32.2, wasm-bindgen 0.2.129,
  kotlin-maven-plugin 2.2.20, JNA 5.17.0, Temurin 1.8.0_504, OpenJDK 21.0.10,
  Temurin 25.0.4.1, Node 22.22.2, Bun 1.3.11, Deno 2.9.7,
  workerd 1.20260903.1 (the version `node/package.json` pins), Go 1.24.7
  (wazero 1.12 fetched a 1.25.0 toolchain), CPython 3.11.15.
- The adapters wrap the core's public API and contain no verification
  logic. The one core change the wasm spikes needed is
  [core-no-std-features.diff](./2026-09-25-rust-core-spikes/core-no-std-features.diff).
  The UniFFI spikes used the core unchanged.
- The spikes checked verdicts and reasons on a handful of cases
  (genuine, wrong bundle id, wrong environment, bad root, missing
  `signedDate`), not the full 186-case suite. Running `fixtures/cases.json`
  through every binding is Phase 2 work in the plan.
- Not measured here: Swift (no toolchain in the container), Fastly Compute,
  Windows and macOS, musl, `wasm-opt`, and the Rust C ABI's own numbers.

## Findings from outside the container

The research behind these rows is in the plan's
[DECISIONS.md](../rust-core/DECISIONS.md) with source links. The rows that
change the plan:

- Fastly Compute's JavaScript runtime (StarlingMonkey) builds SpiderMonkey
  without a JIT and documents no `WebAssembly` object. Akamai EdgeWorkers
  lists WebAssembly as removed. Neither can load a wasm build.
- SwiftPM can link a prebuilt static library on Linux from Swift 6.2
  (SE-0482, artifact bundles). Swift 6.1 cannot.
- UniFFI 0.32 maps `&[u8]` arguments to a direct `java.nio.ByteBuffer`.
  Taking `Vec<u8>` keeps `byte[]` for Java callers.
- JNA picks native libraries by `linux-<arch>` with no glibc/musl split.
- 1Password's Go SDK ships its Rust core as wasm on wazero, a precedent for
  the Go option measured here.
