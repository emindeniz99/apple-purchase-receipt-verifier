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
| 14 | Does Swift on Linux link the Rust core as a prebuilt library? | **Yes, with Swift 6.2.4 and 6.4.** `swift/` is a SwiftPM package whose `binaryTarget` points at an SE-0482 artifact bundle (`staticLibrary`, `x86_64-unknown-linux-gnu`) holding the UniFFI static library plus the generated header and module map. `swift build -c release` needed no `unsafeFlags` and no Rust toolchain, and printed no dependency-audit warning. The smoke verified the g5 receipt, caught `VerifyError.Verification(wrongBundleId, ...)`, and ran the endpoint with `toJsonIn(environment: .sandbox)`. The unstripped static library is 50 MB, 44 MB after `strip --strip-debug`, 11 MB gzipped. Consumers do not ship that: the linker pulls in only what is used, and the stripped Swift executable with the Rust core inside is 1.4 MB. The JVM/Python shared library is 1.3 MB stripped, 0.6 MB gzipped. |
| 15 | Does the existing C ABI pass its own suites? | **Yes.** `cargo test` 25/25; C++17 conformance 153 passed, 0 failed; Python ctypes conformance 272 expected fields. 33 `decodeBase64` groups stay unreachable until the ABI gets a decoder (MIGRATION 1.6). |
| 16 | Is SWIG a good way to hand the C ABI to other languages? | **Yes, once the `.i` states ownership.** First attempt: A six-line `swig/aprv.i` over the cbindgen header produced 5,199 lines of C and a Python module that verified the g5 receipt. Out of the box it leaks every result: SWIG copies the Rust-owned `char*` into a Python string and drops the pointer that `aprv_string_free` needs. Second attempt, `swig/aprv.i` as committed: a `newfree` typemap that returns every string through `aprv_string_free`, plus one `%inline` helper that hides the `AprvResult` out-parameter and raises a Python exception on failure. Measured by `swig/leak.py` over 3,000 calls: the fixed interface grew max RSS by 0 KB, the raw call by 6,016 KB (about 2 KB per call). The same 26-line file, made language-neutral with `SWIG_exception`, generated working bindings for six languages without a single edit: Python, Java (JNI), Ruby, Perl, PHP 8.4 and Go (cgo). Each verified the g5 receipt and raised its own language's exception (`ValueError`, `IllegalArgumentException`, `ArgumentError`, Perl `die`, PHP `ValueError`, Go panic). Each language still compiles SWIG's generated C with its own headers. On 64-bit Linux SWIG needs `-DSWIGWORDSIZE64`, or `int64_t*` arguments get a pointer-type warning. |
| 17 | Does UniFFI's built-in Ruby backend work? | **Yes**, through the `ffi` gem on Ruby 3.3.6: receipt, typed error class `AprvUniffi::VerifyError::Verification`, endpoint and `to_json_in`. Weaker than the other three: the reason arrives as an integer (`reason=5`), and Ruby gets no default arguments. |
| 18 | How big is the Java package? | Today: the 71 KB jar plus Bouncy Castle and Jackson, **11.8 MB** in all. Rust-backed: generated classes 190 KB, plus about 0.63 MB compressed per native target. That makes about **5.2 MB** for eight targets (0.8 MB for one), plus `jna` 2.0 MB and `kotlin-stdlib` 1.8 MB: about **9 MB** in all. Per-platform classifier jars would take a single-platform install to about 4.6 MB. |
| 19 | What does the Rust core add to a Swift app? | Stripped Linux executables, Swift 6.4 release: an empty Foundation app is 12 KB; the same app with the Rust core is 1.39 MB (**+1.38 MB**); with today's pure-Swift package it is 5.27 MB (**+5.26 MB**, mostly swift-crypto's BoringSSL). `ldd` shows no Rust library at runtime: the core is linked into the executable. |
| 20 | How many platforms do Java libraries with native code ship? | One jar, native file per platform, picked at runtime: JNA 5.17.0 ships 28 platforms (AIX, BSDs, Solaris, Linux on arm/armel/ppc/ppc64le/s390x/riscv64/loongarch64/mips64el/x86, Windows x86/x64/arm64, macOS). sqlite-jdbc 3.50.3.0 ships 24 in a 14.3 MB jar, including separate `Linux-Musl` and `Linux-Android` folders. zstd-jni 1.5.7-4 ships 18 in 7.4 MB. Netty takes the other route: classifier jars (`linux-x86_64`, ...) the user picks. |
| 21 | What does it cost? | See the timing table. Native Rust roughly matches the current ports. Wasm costs about 5.3 times the current `node:crypto` build (3.5 times `/web`). wazero costs about 30 times the current Go port. |

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
| Maven 0.6.0 (Bouncy Castle), Temurin 17.0.20.1, same method | 762 | 1,261 |
| Rust core via UniFFI Kotlin, Temurin 17, same method | 707 | 1,081 |
| Rust core via hand-written JNI (`jni` 0.21), Temurin 17, same method | 626 | not built |
| Rust core via hand-written JNI, Temurin 8 / JDK 21 | 643 / 638 | not built |
| Rust core via UniFFI Kotlin, Temurin 8 | 877 (short run) | not run |
| Rust core as wasm, Node 22, `opt-level=3` | 3,626 | 3,900 |
| Rust core as wasm, Bun, `opt-level="z"` | 2,960 | not run |
| Rust core as wasm, Deno, `opt-level="z"` | 2,933 | not run |
| Rust core as `wasm32-wasip1` in wazero (Go 1.25 toolchain) | 6,740 | not run |
| Current pure-Swift port (swift-crypto, swift-certificates), Swift 6.4 release build | 718 | not run |
| Rust core via UniFFI Swift, Swift 6.4 / 6.2.4 release build | 713 / 687 | not run |
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
- **JNI against UniFFI:** the hand-written JNI spike (`jni/`) is about 11%
  faster per receipt, but it returns only the bundle id string while the
  UniFFI call serializes the whole `AppReceipt` with its purchases. Part of
  the gap is that extra work, not the calling mechanism.
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

## Usage of the binding tools on 2026-09-25

GitHub's API refused this container, so registry downloads stand in for
stars. They measure use, which is the better signal anyway.

| Tool | Registry | Downloads | Latest |
|---|---|---:|---|
| uniffi | crates.io, last 90 days | 4,307,544 | 0.32.2 |
| wasm-bindgen | crates.io, last 90 days | 135,956,563 | 0.2.129 |
| cbindgen | crates.io, last 90 days | 15,559,300 | 0.29.4 |
| jni | crates.io, last 90 days | 59,688,058 | 0.22.4 |
| pyo3 | crates.io, last 90 days | 60,961,888 | 0.29.2 |
| napi (napi-rs) | crates.io, last 90 days | 14,276,099 | 3.13.0 |
| uniffi-bindgen-java (IronCore) | crates.io, last 90 days | 77,073 | 0.5.2 |
| gobley-uniffi-bindgen (Kotlin Multiplatform) | crates.io, last 90 days | 9,051 | 0.3.7, last release 2025-10-08 |
| uniffi-bindgen-react-native | npm, last month | 1,659,584 | 0.31.0-5 |
| uniffi-bindgen-cs, -go, -cpp (NordSecurity), uniffi-dart | not on crates.io | installed from git | |

## GitHub stars on 2026-09-25

Read through a GitHub repository search (stars, archived flag) and each
repository's release feed (latest release). None is archived.

| Repository | Stars | Latest release |
|---|---:|---|
| PyO3/pyo3 | 16,175 | v0.29.2, 2026-08-05 |
| wasm-bindgen/wasm-bindgen | 9,158 | 0.2.129, 2026-09-25 |
| napi-rs/napi-rs | 7,946 | napi-v3.13.0, 2026-09-22 |
| wazero/wazero (moved from tetratelabs) | 6,387 | v1.12.0, 2026-05-29 |
| swig/swig | 6,326 | v4.5.1, 2026-09-04 |
| PyO3/maturin | 5,815 | v1.15.0, 2026-08-24 |
| mozilla/uniffi-rs | 4,987 | v0.32.2, 2026-09-23 |
| mozilla/cbindgen | 2,954 | 0.29.4, 2026-06-10 |
| jni-rs/jni-rs | 1,602 | v0.22.4, 2026-03-16 |
| dylibso/chicory | 1,136 | 1.7.5, 2026-03-24 |
| jhugman/uniffi-bindgen-react-native | 550 | v0.31.0-5, 2026-08-21 (targets uniffi 0.31) |
| gobley/gobley | 431 | 0.3.7, 2025-10-08 |
| NordSecurity/uniffi-bindgen-cs | 186 | v0.11.0+v0.31.0, 2026-06-23 |
| NordSecurity/uniffi-bindgen-go | 130 | v0.7.1+v0.31.0, 2026-04-16 |
| Uniffi-Dart/uniffi-dart | 43 | v0.2.1+v0.31.2, 2026-06-26 |
| NordSecurity/uniffi-bindgen-cpp | 38 | v0.9.0+v0.29.4, 2026-08-18 |
| IronCoreLabs/uniffi-bindgen-java | 27 | 0.5.2, 2026-09-24 |

Every third-party UniFFI generator trails UniFFI itself by one or more minor
versions (0.29 to 0.31 against 0.32). A package built on one of them has
to pin UniFFI to that generator's version.

## Java binding bake-off (2026-09-25)

Five ways to put the Rust core behind a Java API, built to one spec
([java-bakeoff/SPEC.md](./2026-09-25-rust-core-spikes/java-bakeoff/SPEC.md)):
the same classes, 20 checks (genuine and generated receipts, typed errors,
JWS, endpoint with `toJsonIn`, malformed body, bad root, 8 threads × 100
calls). Every entry passed every check on Temurin 8, 17 and 21.

Timing: µs per call, mean of three rounds of 10,000 after 10,000 warm-up
calls, run one approach at a time with nothing else on the machine. This
session's machine ran faster than the earlier JVM rows, so compare within
this table.

| Approach | JDK 8 receipt / JWS | JDK 17 receipt / JWS | JDK 21 receipt / JWS |
|---|---|---|---|
| Maven 0.6.0 (Bouncy Castle), today | 708 / 1,157 | 660 / 1,118 | 678 / 1,077 |
| UniFFI (generated Kotlin) | 604 / 972 | 611 / 922 | 629 / 964 |
| jni-rs + hand-written Java | 552 / 862 | 540 / 877 | 530 / 853 |
| flapigen | 593 / 892 | 603 / 877 | 583 / 873 |
| SWIG over the C ABI + Java JSON layer | 641 / 882 | 617 / 883 | 659 / 893 |
| Diplomat (generated Kotlin) | 641 / 863 | 649 / 900 | 654 / 891 |

| | UniFFI | jni-rs | flapigen | SWIG | Diplomat |
|---|---|---|---|---|---|
| Hand-written Rust (lines) | 263 | 314 | 126 + 299 interface | 0 (existing C ABI) | 424 |
| Hand-written Java (lines, library only) | 0 | 472 | 30 | 1,077 incl. a 200-line JSON parser | 0 |
| `unsafe` in hand-written code | 0 | 2 | 1 (plus 271 generated) | 0 (the C ABI's own) | 0 |
| Rust panic reaches Java as | exception | exception | **JVM abort** (no `catch_unwind`) | exception | not tested |
| Checked, typed exception | yes | yes | no: `throws Exception` everywhere | yes | no: errors are returned values |
| Lifetime | `AutoCloseable` + Cleaner | `AutoCloseable`, leaks if not closed | `finalize()` | `AutoCloseable` | `finalize()` only |
| `toJsonIn` without re-verifying | yes | yes | yes | **no**: the C ABI has no result handle | yes |
| Runtime jars | jna + kotlin-stdlib (3.8 MB) | none | none | none | jna + kotlin-stdlib |
| Native library, stripped | 1.30 MB | 1.14 MB | 0.91 MB | 0.89 MB (two files) | 0.86 MB |
| Same definitions serve Swift and Python | yes | no | no | through SWIG, JSON only | no production Swift |
| Build notes | none | jni 0.22 API churn | needs libclang; typemaps "experimental" | 35 lines of hand JNI in C | fails on Rust 1.94.1 (upstream MSRV bug), needs 1.95; config booleans must be strings |

All five bindings beat today's jar. The gap between them (about 10-15%)
comes mostly from how each builds result objects: jni-rs sends one packed
`byte[]`, UniFFI serializes every record field, including the claims JSON.

## IBM Power and IBM Z (2026-09-25)

Both finalists (UniFFI, jni-rs) cross-compiled with `cargo build --target
powerpc64le-unknown-linux-gnu` / `s390x-unknown-linux-gnu` and the Ubuntu
cross linkers, with no source or Cargo.toml change, and ran their full
check programs on real Temurin JVMs under QEMU user-mode emulation:

| Architecture | JVM | UniFFI (`spike.Smoke`) | jni-rs (`bakeoff.jni.Demo`) |
|---|---|---|---|
| ppc64le (IBM Power, little-endian) | Temurin 1.8.0_504 | ALL OK | ALL PASS |
| s390x (IBM Z, big-endian) | Temurin 17.0.20.1 | ALL OK | ALL PASS, 800/800 threaded |

JNA resolved `linux-ppc64le/` and `linux-s390x/` resources with no extra
property. The JIT ran under QEMU without `-Xint`. Adoptium has never
published Java 8 for s390x (the API answers 404 for HotSpot and OpenJ9);
Java 8 on IBM Z comes from IBM's own JDK, which this container could not
download, so the s390x row ran on 17. Emulated timings (7.9-10 ms per
receipt) say nothing about real hardware.

## Sidecar: the Rust core as a local verifyReceipt server (2026-09-25)

`sidecar/server` is a 145-line axum binary: `POST /verifyReceipt` answers
with exactly the core's `verify_receipt_json`, verification runs on
`spawn_blocking`, the port comes from the OS and is printed on stdout, and
the process exits on SIGTERM or when its stdin closes (so it dies with
the JVM that started it). `sidecar/java` extracts it from the classpath,
starts it and calls it, with no dependencies on Java 8.

- **Checks, Temurin 8 and JDK 21:** a Production sidecar answers 21007 for
  the genuine sandbox receipt, a Sandbox one answers 0 with the receipt,
  `not json` answers 21002. All pass.
- **Binary:** 1.43 MB glibc, 1.54 MB static musl (`ldd`: statically
  linked). Resident memory about 2 MB. Cold start to healthy: 43 ms.
- **`/tmp` mounted `noexec`:** starting the extracted binary fails with
  `error: 13 (Permission denied)`; pointing `-Daprv.sidecar.dir` at an
  exec-allowed directory fixes it.
- **Latency, JDK 21, Sandbox path (status 0 with the receipt JSON):**

| Path | µs per call |
|---|---:|
| In-process, UniFFI `verifyReceiptJson` (same body, same output) | 648 |
| Sidecar, `HttpURLConnection` client | 2,314 to 2,604 |
| Sidecar, one-write keep-alive socket client with `TCP_NODELAY` (`RawSocketClient.java`, Java 8) | **961** |
| Sidecar transport alone: `GET /health` / tiny `POST` with the one-write client | 53 / 77 |

`HttpURLConnection` writes a POST's headers and body separately; Nagle's
algorithm and delayed ACKs then hold the body back about 1.5 ms per
request. A client that sends each request in one write removes that, so
the sidecar costs about 310 µs over in-process (1.5x), mostly moving
7.5 KB in and 2 KB out as JSON. 8-thread throughput with the
`HttpURLConnection` client was 941 requests/s on 4 vCPUs.

### Sidecar throughput, re-measured (2026-09-25)

941 requests/s is far below what 4 vCPUs can verify, so the server was
measured again with a lean client: `sidecar/loadtest/`, Rust, one
keep-alive connection per thread, each request in one write with
`TCP_NODELAY`, response checked for `"status":0`. 4,000 calls per thread
after 200 warm-up calls, receipt `receipt-sandbox-g5`, release builds,
client and server on the same 4 vCPUs (Intel Xeon 2.1 GHz).

| Threads or connections | In-process core (verifications/s) | Sidecar over HTTP (requests/s) |
|---:|---:|---:|
| 1 | 1,890 | 1,117 |
| 2 | 3,502 | 2,042 |
| 4 | 6,444 | 3,296 |
| 8 | 6,956 | 4,123 |
| 16 | | 5,004 |

- The core scales linearly to 4 cores: about 1,600 to 1,900 per core.
- The server reaches 78% of the in-process ceiling at 16 connections, with
  the load generator taking CPU from the same 4 vCPUs.
- One HTTP call adds about 365 µs over in-process at one connection
  (895 against 529 µs): loopback, HTTP parsing, the `spawn_blocking`
  hand-off and copying 7.5 KB in and 2 KB out.
- The 941 figure measured the Java `HttpURLConnection` client (Nagle stall
  plus its own CPU on the shared cores), not the server. The Java
  one-write client's throughput was not measured.

## Enterprise deployment shapes (2026-09-25)

Both Java finalists, packaged as ordinary library jars with the native
library inside.

| Scenario | UniFFI (JNA) | jni-rs, loader extracts to a unique temp name | jni-rs, fixed temp name |
|---|---|---|---|
| Tomcat 10.1.60 / JDK 21, deploy + 3 hot redeploys | Works; **leaks per redeploy**: 2 more mapped native copies (`~/.cache/JNA/temp/jna*.tmp`) and 1 thread each; Tomcat logs `started a thread named [JNA Cleaner] but has failed to stop it` and a SEVERE ThreadLocal `com.sun.jna.Structure$2`; `findleaks` lists the old app 3 times | Works, no leak: mapped copies fall back to 1 after GC; `findleaks`: "No memory leaks found" | **Fails from redeploy 1**: `UnsatisfiedLinkError ... already loaded in another classloader`, then `NoClassDefFoundError` for good |
| Tomcat 10.1, two WARs + 3 redeploys each | Works, leaks (16 mapped copies, 6 old apps held) | Works, no leak | Fails on the second WAR's first request |
| Tomcat 9.0.122 / Temurin 8, deploy + 3 redeploys | Works, same leak | Works, no leak | Fails |
| Spring Boot 3.5.16 fat jar (`java -jar`, nested `BOOT-INF/lib`) | Works, no configuration | Works, no configuration | not run |
| Alpine (musl) chroot, apk `openjdk17-jre` | Works: JNA's bundled `libjnidispatch` loads on musl | Works | — |
| GraalVM native-image (Oracle GraalVM for JDK 21) | Works with the tracing agent's config, no hand edits | Works, same | — |

- Putting the jars in Tomcat's shared `lib/` instead of `WEB-INF/lib`
  makes both pass; UniFFI still pins the first webapp's classloader once,
  through the JNA Cleaner thread.
- A musl `cdylib` needs `RUSTFLAGS="-C target-feature=-crt-static"` plus a
  static unwinder: rustc links `-lgcc_s`, which musl lacks. Rust's own
  `self-contained/libunwind.a`, offered to the linker as `libgcc_s.a`,
  resolved it on stable; `-C link-self-contained=+unwind` needs nightly.
- The Alpine and native-image runs used synthetic inputs (bad root bytes,
  malformed base64), because this session's permission policy blocked
  copying the fixtures into the chroot. They prove loading, calls and
  error mapping; verifying a genuine receipt on those two platforms is
  left to CI.

### JNA 5.19.1 does not change the redeploy leak (2026-09-25)

Rerun of the Tomcat 10.1 / JDK 21 "deploy + 3 hot redeploys" case with
JNA 5.19.1, the latest release on Maven Central, everything else
identical:

| Setup | Result |
|---|---|
| UniFFI jar, JNA and kotlin-stdlib in `WEB-INF/lib` | Same leak as 5.17.0: mapped `jna*.tmp` copies 2→4→6→8, threads 18→21, three "[JNA Cleaner] ... failed to stop" warnings, one SEVERE `com.sun.jna.Structure$2` ThreadLocal, `findleaks` lists the old app three times |
| The same jars in Tomcat's shared `lib/` | No growth: 2 mapped copies and 18 threads throughout; one fixed "JNA Cleaner" warning |
| A cleanup call from `ServletContextListener.contextDestroyed` | Not possible: `javap` shows `Native.dispose()` is private and `com.sun.jna.internal.Cleaner` has no stop method in either version; the only public `dispose` is per `NativeLibrary` instance, which UniFFI's generated code does not expose |

The leak matches JNA issue #1521 (Cleaner thread holds the webapp
classloader after undeploy). No library-side fix exists; the mitigation
is installing the jars in the container's shared library directory.

## JVM native platforms against RocksDB and JNA (2026-09-25)

Native libraries inside `rocksdbjni` 10.10.1 (latest on Maven Central,
83.6 MB jar) and `jna` 5.19.1, against the R12 list:

| Platform | RocksDB | JNA | R12 |
|---|:-:|:-:|:-:|
| linux x86_64 glibc / musl | ✅ / ✅ | ✅ | ✅ / ✅ |
| linux aarch64 glibc / musl | ✅ / ✅ | ✅ | ✅ / ✅ |
| linux ppc64le glibc / musl | ✅ / ✅ | ✅ | tier 2 / ❌ |
| linux s390x glibc / musl | ✅ / ✅ | ✅ | tier 2 / ❌ |
| linux riscv64 glibc / musl | ✅ / ✅ | ✅ | tier 2 / ❌ |
| linux x86 (32-bit) glibc / musl | ✅ / ✅ | ✅ | tier 2 / ❌ |
| linux armv7 | ❌ | ✅ | tier 2 |
| macOS arm64 / x86_64 | ✅ / ✅ | ✅ | ✅ / ✅ |
| Windows x86_64 | ✅ | ✅ | ✅ |
| Windows arm64 | ❌ | ✅ | ✅ |
| Windows x86 | ❌ | ✅ | tier 2 |
| FreeBSD x86_64 | ❌ | ✅ | tier 2 |
| linux loongarch64 | ❌ | ✅ | ❌ |

JNA also ships AIX, Solaris, OpenBSD, DragonFly BSD, linux-ppc, armel and
mips64el. JNA's list is the outer bound for the UniFFI build: a native
library without a JNA dispatcher for that platform cannot load.

Rust side (rustup 1.94.1 target list): `powerpc64le-unknown-linux-musl`,
`riscv64gc-unknown-linux-musl`, `i686-unknown-linux-musl` and
`loongarch64-unknown-linux-gnu` have a prebuilt standard library.
`s390x-unknown-linux-musl` does not (tier 3): it needs nightly and
`-Z build-std`, which the release build's pinned stable toolchain rules
out.

### Which platforms have Java users: Temurin as the proxy (2026-09-25)

Maven Central download counts carry no platform, so there is no direct
usage data. The next best signal is where Eclipse Temurin, the most used
free OpenJDK build, ships a JDK (`api.adoptium.net/v3/assets/latest`):

| Platform | JDK 8 | JDK 17 | JDK 21 | JDK 25 |
|---|:-:|:-:|:-:|:-:|
| linux x64, linux aarch64 | ✅ | ✅ | ✅ | ✅ |
| Alpine (musl) x64 | ✅ | ✅ | ✅ | ✅ |
| Alpine (musl) aarch64 | | | ✅ | ✅ |
| Alpine (musl) ppc64le, s390x, riscv64, x86 | | | | |
| linux ppc64le | ✅ | ✅ | ✅ | ✅ |
| linux s390x, linux riscv64 | | ✅ | ✅ | ✅ |
| linux arm (armv7) | ✅ | ✅ | | |
| linux x86 (32-bit) | | | | |
| macOS x64 | ✅ | ✅ | ✅ | ✅ |
| macOS aarch64 | | ✅ | ✅ | ✅ |
| Windows x64 | ✅ | ✅ | ✅ | ✅ |
| Windows x86 (32-bit) | ✅ | ✅ | | |
| Windows aarch64 | | | ✅ | |
| AIX ppc64 | ✅ | ✅ | ✅ | ✅ |
| Solaris sparcv9, x64 | ✅ | | | |
| FreeBSD | | | | |

Temurin ships musl only for x64 and aarch64. The four extra musl builds
RocksDB carries have no Temurin JDK to run on. AIX has Temurin on every
line, but Rust's `powerpc64-ibm-aix` is tier 3 (nightly only).

### Which platforms other native libraries ship (2026-09-25)

Latest release of each, read from the registry:

| Library | Language | Platforms |
|---|---|---|
| pydantic-core 2.49.0 (PyPI) | Rust | manylinux x86_64, aarch64, armv7l, i686, ppc64le, s390x, riscv64; musllinux x86_64, aarch64, armv7l; win32, win_amd64, win_arm64; macOS x86_64, arm64 (15) |
| cryptography 50.0.1 (PyPI) | Rust | manylinux x86_64, aarch64, armv7l, ppc64le; musllinux x86_64, aarch64; win_amd64; macOS arm64 |
| orjson 3.12.0 (PyPI) | Rust | manylinux x86_64, aarch64, armv7l, i686; musllinux x86_64, aarch64; win32, win_amd64, win_arm64; macOS |
| @swc/core 1.16.2 (npm) | Rust | linux x64, arm64 (glibc and musl), arm-gnueabihf, ppc64, s390x; darwin x64, arm64; win32 x64, ia32, arm64 (12) |
| @biomejs/biome 2.5.14 (npm) | Rust | linux x64, arm64 (glibc and musl); darwin x64, arm64; win32 x64, arm64 (8) |
| sqlite-jdbc 3.53.4.0 (Maven) | C | Linux x86_64, x86, aarch64, arm, armv6, armv7, ppc64, riscv64; Linux musl x86_64, x86, aarch64; Mac x86_64, aarch64; Windows x86_64, x86, aarch64, armv7; FreeBSD x86_64, x86, aarch64 (20) |
| rocksdbjni 10.10.1 (Maven) | C++ | 15, see the RocksDB table above |
| jna 5.19.1 (Maven) | C | 27, see the RocksDB table above |
| esbuild 0.28.2 (npm) | Go | 25 incl. AIX, OpenBSD, NetBSD, SunOS, loong64, mips64el (Go's own target list, not Rust's) |

Stable Rust 1.98.1 (the latest on 2026-09-25, read from
`static.rust-lang.org/dist/channel-rust-stable.toml`) has a prebuilt
standard library for every server target in R12, and none for AIX,
OpenBSD, DragonFly BSD, mips64el or s390x musl. Against 1.94.1 it adds
`aarch64-unknown-freebsd` and `powerpc64-unknown-linux-musl`.

Other facts R12 relies on: FreeBSD 15.0's release notes retire i386,
armv6 and 32-bit powerpc; Alpine's latest-stable releases cover x86_64,
x86, aarch64, armhf, armv7, loongarch64, ppc64le, riscv64 and s390x.

