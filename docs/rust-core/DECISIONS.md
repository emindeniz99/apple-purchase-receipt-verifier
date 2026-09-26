# Decisions for the Rust-core migration

Each record lists the options, the evidence and a recommendation. Status is
one of:

- **Owner-stated**: the owner's brief already decided it.
- **Recommended**: technical, no product trade-off; proceeds unless the
  owner objects.
- **Owner call**: a real trade-off that the owner decides.

When a record is settled, its outcome moves into PLAN.md as the next
D-number (D17 onward) and this file keeps the history.

Evidence: [spike results](../evidence/2026-09-25-rust-core-spikes.md),
and the five substrate notes of 2026-09-26 listed under R21.

---

## R1. Rust is the only implementation

**Status: owner-stated** (brief of 2026-09-25).

Today nine implementations repeat one security algorithm: the Rust core
(5,358 lines) and eight ports (about 27,500 lines). A fix has to land nine times, and eight of the nine
had little human review. The owner reviews Java deeply and wants to learn
Rust and review exactly one implementation.

The existing Rust crate becomes the only place that parses, validates or
decides. Since R21 it does so on top of OpenSSL, which does the generic
ASN.1, CMS, X.509 and signature work. Every published package becomes a
binding. PLAN.md D16
(hand-written readers per port, each on its ecosystem's crypto) is
superseded.

Trade-off accepted with this: **monoculture.** Today a bug in one port
shows up as a disagreement on `fixtures/cases.json`. After the migration, a
bug in Rust ships to every language at once. R8 decides how much
independent checking survives.

---

## R2. Binding toolset

**Status: owner-stated, confirmed by the spikes.** The JavaScript row
changed on 2026-09-26 with R21: wasm-bindgen is dropped.

| Use | Tool | Why |
|---|---|---|
| Kotlin/JVM, Swift, Python | **UniFFI** 0.32 (Mozilla) | Built for one Rust core with many foreign bindings. Firefox ships it. First-party Kotlin, Swift and Python. Java 8 works (spike). Doc comments propagate. |
| JavaScript | **one plain wasm module**, `aprv.wasm`, with a hand-written JS façade (about 100 lines) and a hand-written `index.d.ts` | The core now links OpenSSL (R21). `wasm32-unknown-unknown`, the target wasm-bindgen needs, cannot build `openssl-sys`, so `aprv.wasm` is a `wasm32-wasip1` build that imports two functions (R21, [wasm bake-off §6](../evidence/2026-09-26-wasm-architecture-bakeoff.md)). Go runs the same file. |
| C and everything else | explicit `extern "C"` + **cbindgen** | Already exists, 20 symbols, tested on three OSes. |
| Go | wazero (R6) | cgo-free. 1Password's Go SDK runs its Rust core the same way. |
| Examples for other languages | each language's own C FFI (ctypes, JNA/FFM, P/Invoke, cgo, Ruby `ffi`, PHP FFI) over the C ABI; SWIG `.i` only as an extra | SWIG works once its `.i` declares ownership: a `newfree` typemap calling `aprv_string_free` took a 2 KB-per-call leak to zero (evidence row 16). Native FFI examples free explicitly and need no generated C; SWIG suits users who want one interface file for many languages. |

Rejected, with the trigger that would reopen each:

| Tool | Why not now | Reopen when |
|---|---|---|
| PyO3 + maturin (native module) | UniFFI Python passed the spike: typed exceptions, docstrings, defaults. PyO3 would be a second binding system. | UniFFI Python fails a concrete requirement: an API shape, a measured performance gap, or a packaging limit. |
| napi-rs (Node native addon) | It adds per-platform npm binaries; wasm already covers every JS runtime. | R4 picks the performance option. |
| wasm-bindgen (dropped 2026-09-26) | It needs `wasm32-unknown-unknown`. There `openssl-sys` 0.9.117 fails with 20 × E0432, because `libc` defines no `size_t`, `time_t` or `FILE` for that target ([OpenSSL CMS everywhere §3](../evidence/2026-09-26-openssl-cms-everywhere.md)). | The core stops linking a C library, or `libc` and `openssl-sys` gain that target. |
| Emscripten | It works: 1,179 of 1,179 rows on 7 hosts for OpenSSL. It needs legacy exceptions, starts with about 18 MB of linear memory, ships 12.8 to 78.9 KB of generated glue, and workerd needs a second web-only glue ([wasm bake-off §7](../evidence/2026-09-26-wasm-architecture-bakeoff.md)). | A host runs Emscripten output and not a plain wasm2 core module. |
| Component Model with jco, for npm | It works on 8 hosts, and adds 202,031 to 236,337 B of generated glue (`aprv.js`) to do what the 100-line façade does ([wasm bake-off §8, §20](../evidence/2026-09-26-wasm-architecture-bakeoff.md)). The WIT file stays in the evidence as a future option for native Component Model hosts such as Wasmtime. | A package targets a native Component Model host. |
| uniffi-bindgen-java (IronCore) | FFM API, needs Java 22+, "currently unstable". | The Java floor rises to 22. |
| Chicory (pure-Java wasm) | Java 11 floor. Measured 18.5 ms per receipt with its compiler (975 ms interpreted), against 0.70 ms for UniFFI on the same JDK. | The Java floor rises to 11 and a 28x slowdown becomes acceptable. |
| Wasm everywhere (one `.wasm` run by Chicory, wasmtime-py, WasmKit, wazero) | One artifact instead of a native matrix, but: JVM 28x slower and Java 11+; wasmtime-py is itself a native wheel, so Python gains nothing; Swift has only interpreters. Wasm stays where no native option exists (JS) or where native breaks the deployment model (Go, R6). | A JVM or Python wasm runtime reaches near-native speed without native code of its own. |
| GraalWasm | JDK 21 floor. Needs JVMCI for speed. | Never, for a library. |
| safer-ffi | Still alpha. Overlaps cbindgen, and our ABI is small. | The C ABI grows callbacks, foreign-owned buffers or many object types. |
| Diplomat (ICU4X) | No production Swift backend for our needs, and no Java 8. | It gains both. |
| BoltFFI, Alef, WeaveFFI | Young, little independent production use, benchmarks are self-reported. | Two years of independent adoption. |
| swift-bridge, CXX, flutter_rust_bridge, Rustler, Magnus, ext-php-rs | No supported package needs them. | Someone commits to supporting that language as a package. |
| uniffi-bindgen-go (NordSecurity) | Needs cgo. Lags UniFFI by one minor version. | R6 picks cgo. |

### R2 addendum: the JVM taken on its own (2026-09-25)

If the product were Java alone, the reviewed pure-Java implementation would
already be the one implementation, and a Rust core would add native
packaging for a 10-18% speed gain. The Rust core pays off because five
registries share it. For the JVM binding itself:

| Option | Floor | Java API | Runtime deps | Glue we maintain | Receipt µs (JDK 17) |
|---|---|---|---|---|---:|
| **UniFFI Kotlin + thin Java façade** | 8 | Façade in plain Java; generated Kotlin underneath | `kotlin-stdlib`, `jna` (about 3.7 MB) | none generated by hand; façade is delegation | 707 |
| Hand-written JNI (`jni` crate) + Java classes | 8 | Plain Java, hand-written Javadoc | none | Rust JNI glue with `unsafe` handles, plus Java-object construction by hand | 626 |
| C ABI + JNA wrapper by hand | 8 | Plain Java | `jna` | Java wrapper plus JSON mapping by hand | not built |
| FFM (Panama): uniffi-bindgen-java or jextract | **22** | Plain Java | none | none | not built |
| Wasm on Chicory | 11 | Plain Java | Chicory | wasi adapter | 18,546 |

Raising the floor to **Java 17** changes little: FFM only became final in
Java 22 (JEP 454), and Java 17 has it only as an incubator module. A 17
floor would let the façade use records and sealed exceptions, let UniFFI
use `java.lang.ref.Cleaner` without `disable_java_cleaner`, and allow a
`module-info`. The binding technology stays the same. Only a 22 floor
unlocks JNA-free and JNI-free bindings.

A five-way bake-off at one spec (evidence, "Java binding bake-off")
measured UniFFI, jni-rs, flapigen, SWIG and Diplomat. flapigen aborts the
JVM on a Rust panic and throws bare `Exception`; Diplomat returns errors
instead of throwing and has no `AutoCloseable`; SWIG needs a Java JSON
parser and re-verifies for `toJsonIn`. UniFFI and jni-rs are the two
viable choices: UniFFI with no hand-written Java and one definition for
Swift and Python, jni-rs with no runtime jars and about 12% less time per
receipt, at the price of 472 hand-written Java lines and two `unsafe`
blocks.

Enterprise shapes (evidence, "Enterprise deployment shapes") separate the
two: both work in Spring Boot fat jars, on Alpine and in native-image, but
under Tomcat hot redeploy UniFFI leaks a JNA Cleaner thread and two native
copies per redeploy, while jni-rs with a unique-name loader leaks nothing.

Decision: UniFFI on the Java 8 floor with a thin Java façade (R18). jni-rs
stays the fallback engine behind the same façade. Revisit FFM when the
floor reaches 22.

---

## R3. Where binding annotations live

**Status: recommended.**

| Option | For | Against |
|---|---|---|
| A. Annotate core types with `uniffi`, `wasm_bindgen`, ... | Least code | Couples the reviewed core to every generator. The core API drifts toward the lowest common denominator. The brief forbids it. |
| B. Each adapter defines its own mirror types | No shared crate | Four adapters convert dates, bytes and ids four ways, and that is exactly the drift we are removing. |
| **C. One `aprv-surface` crate, generator-free; adapters annotate it from outside (`#[uniffi::remote]`)** | One model. Neither core nor surface names a generator, so any adapter can be swapped. | Adapters restate field lists (compile-checked). |

Recommendation: **C.** Details in [ARCHITECTURE.md §2-3](./ARCHITECTURE.md).

---

## R4. npm on Node: accept the wasm cost, or add a native addon

**Status: accepted by the owner on 2026-09-25: option C.** Numbers
replaced on 2026-09-26: npm now runs the plain `aprv.wasm` module over
OpenSSL (R21). Speed is informational: the owner stated for R21 that it
does not matter.

µs per verification. The rows come from different runs and harnesses, so
treat the ratios as rough:

| | Receipt (g5) | JWS | Source |
|---|---:|---:|---|
| npm 0.6.0 today, `node:crypto` | 683 | 732 | [spikes of 2026-09-25](../evidence/2026-09-25-rust-core-spikes.md) |
| npm 0.6.0 today, `/web` (WebCrypto) | 1,001 | 1,134 | same |
| OpenSSL 4.0.2 C ABI, native, p50 | 399 | 479 | [substrate bake-off §9](../evidence/2026-09-26-security-substrate-bakeoff.md) |
| **OpenSSL 4.0.2 Route C module (`ossl-c`) in Node 22** | **1,395** | **4,550** | [wasm bake-off §13](../evidence/2026-09-26-wasm-architecture-bakeoff.md) |

The two OpenSSL rows used the PKCS7 path; the CMS path R21 picks was not
timed. The cost is per verification, not per HTTP request: a backend
verifies a receipt or transaction when a purchase or notification
arrives.

| Option | Speed on Node | Cost |
|---|---|---|
| **A. wasm everywhere** | About 2x `node:crypto` per receipt and about 6x per JWS on the numbers above. | Simplest. One artifact. Zero npm dependencies. No platform binaries. |
| B. wasm for edge and browsers, napi-rs native addon for Node | Native, close to today | A second binding tool, 6-8 platform packages (`@…/linux-x64-gnu` and so on) as optionalDependencies, a larger release matrix, and a native-module story for serverless bundlers. |
| C. A from day one, B written in as a trigger | A until the trigger fires | Only the trigger to agree on now. |

Recommendation: **C.** Ship wasm and publish the numbers in
BENCHMARKS.md. Add napi-rs only if wasm on Node is **more than 2x** the
0.6.0 `node:crypto` build on either path, or a user reports throughput
trouble. napi-rs would call the same core, so no security code gets added
either way.

**Open (2026-09-26):** on the Route C numbers the JWS path is above the
2x trigger from the start. The trigger was agreed when the pure-Rust core
was the plan; whether it still stands is the owner's call.

---

## R5. JS runtimes that cannot run WebAssembly

**Status: accepted by the owner on 2026-09-25: drop both claims** (the
brief: "platform compatibility must never force duplicated security
logic").

- **Fastly Compute JS:** StarlingMonkey builds SpiderMonkey without a JIT,
  and the JS reference lists no `WebAssembly` object. Today CI tests
  `/web` there through js-compute-runtime and viceroy.
- **Akamai EdgeWorkers:** V8 runs with WebAssembly removed. Claimed today,
  never tested.

Options: keep the pure-TypeScript `/web` implementation for these two (a
second implementation, rejected by R1), or drop both claims.

Recommendation: **drop both claims** in the npm README and SUPPORT-MATRIX,
and delete the `node-runtimes-fastly` job. Fastly users who write Rust can
depend on the Rust crate from a Fastly Rust service (a git dependency
until the crate is on crates.io, see R19); the core builds
for `wasm32-wasip1` (spike), with OpenSSL compiled by wasi-sdk and passed
through `OPENSSL_DIR` since R21 (`openssl-src` maps no `wasm32-wasip1`
target, [OpenSSL CMS everywhere §1](../evidence/2026-09-26-openssl-cms-everywhere.md)).
Record it in the CHANGELOG as a breaking change.

---

## R6. Go

**Status: accepted by the owner on 2026-09-25: option A, plus an on-demand fast path.**
The default stays pure Go on wazero. If a user needs native speed, an
opt-in `-tags aprv_native` build links the C ABI library from the GitHub
Release through cgo. Nothing gets committed for it, and it gets built only
when someone asks. Context: the module has been public since 2026-09-06, so
few users are affected by the change. The module is live (`go/v0.4.0` to `v0.6.0`).
Today's Go port is stdlib-only, cgo-free and the fastest port (207 µs per
receipt in BENCHMARKS.md).

Since R21 (2026-09-26) the Go module embeds the same `aprv.wasm` that npm
ships. Go supplies its two imports: `aprv.clock_now_ms` from the wall
clock and `aprv.random_get` from `crypto/rand`. The option A row below
carries the OpenSSL numbers; the pure-Rust module of 2026-09-25 took
6,740 µs per receipt, plus 177 ms once per process to compile, in a file of
about 470 KB.

| Option | Speed | What users lose | Our cost |
|---|---|---|---|
| **A. wazero** + embedded `aprv.wasm` (`wasm32-wasip1`, OpenSSL) | 2,495 µs per receipt and 8,110 µs per JWS on wazero 1.12.0 ([substrate bake-off §13](../evidence/2026-09-26-security-substrate-bakeoff.md), PKCS7 path; informational). Compile time for the larger module is unmeasured. | Stdlib-only (gains wazero + x/sys). Go floor 1.22 rises to 1.25. | About 3 MB of `.wasm` committed per release (2,973,532 B raw for the template-payload module, [ASN.1 payload note §3](../evidence/2026-09-26-openssl-asn1-payload.md)), and a small Go wrapper with JSON decode and an instance pool. |
| B. cgo + prebuilt static libraries in the module | Native (about 750 µs) | `CGO_ENABLED=0`, easy cross-compiling, `FROM scratch`. musl and Windows need extra work (automerge-go and wasmvm ship neither). | About 2-3 MB of `.a` per target per release, committed to git forever. `go mod vendor` quirks. |
| C. Keep the Go port as an independent implementation | Unchanged | Nothing | Breaks R1: two implementations to review and keep in step. |
| D. Deprecate the Go module; point Go users at the C ABI | n/a | The package | A `retract` plus a notice |

Recommendation: **A.** It keeps R1 and keeps Go's deployment model. The
speed cost is real but bounded: about 2.5 ms per receipt and 8.1 ms per
JWS on the numbers above. (Written before R8 was settled: had R8 chosen
the "published second implementation" route, option C would have been the
home for that role.)

---

## R7. Swift on Linux

**Status: accepted by the owner on 2026-09-25: option A, Swift 6.2 for
every platform.** Only Linux needs 6.2 (SE-0482); Apple's XCFramework works
from Swift 5.3. If a Swift 6.1 macOS user needs support, a second manifest
(`Package@swift-6.1.swift`, Apple-only XCFramework) can keep 6.1 there. Today the Swift package supports macOS 13 and
Linux, with Swift 6.1 as the floor, and CI runs 6.1/6.2/6.3 Linux
containers plus macOS. A backend verifier makes Linux the likely
deployment target.

| Option | For | Against |
|---|---|---|
| **A. Swift floor 6.2, SE-0482 artifact bundle for Linux plus XCFramework for Apple** | Keeps Linux with prebuilt binaries. swift-tokenizers ships the same shape with UniFFI 0.32. | Raises the floor by one minor version. glibc only (no musl). Needs a symbol-localization step. |
| B. Apple platforms only (XCFramework) | The mainstream UniFFI Swift shape (matrix-rust-sdk) | Drops Linux, the likely server platform. |
| C. Build Rust from source during `swift build` | No binary artifacts | SwiftPM has no build step. It would need a plugin, a Rust toolchain on every consumer, and unsafe flags that version-resolved packages forbid. |

Recommendation: **A.** The Linux spike has since run (evidence row 14): an
SE-0482 artifact bundle with the UniFFI static library built and ran on
Swift 6.2.4 and 6.4 with no `unsafeFlags` and no audit warning, at
687-713 µs per receipt against 718 µs for today's pure-Swift port.

---

## R8. What independent checking survives the migration

**Status: accepted by the owner on 2026-09-25: option B. Revised by the
owner on 2026-09-26: the reference is the published 0.7.x jar, not Java
source kept in the repository.** This is the monoculture trade-off from
R1.

| Option | What catches a Rust bug | Cost |
|---|---|---|
| A. Delete every other implementation after parity | `fixtures/cases.json`, the fuzzers, review | Lowest |
| **B. Compare against the published 0.7.x Java jar, test-only** | A, plus the differential harness: the same request corpus through the jar and through the Rust core, verdicts compared | No Java verifier source to maintain. The jar is frozen, so wherever the core changes on purpose the two answer differently; R20 records those rows. |
| C. Keep Go published as the second implementation | A, plus a real second implementation in production | Two published implementations to fix in step. It also answers R6. |

Decision: **B until 1.0**, then decide again with a year of differential
data. The harness downloads the 0.7.x jar from Maven Central, pinned by
version and checksum. No copy of the Java verifier's source stays in the
repository for this. The Java package itself still becomes the UniFFI
binding (R18). Java/Bouncy Castle is a reference, not the target: R20 says
what a difference means.

The first form of this record (2026-09-25) kept today's Java code under
`java/oracle/` as a test-only oracle; the 2026-09-26 revision replaces
that.

---

## R9. Unpublished ports: Ruby, PHP, .NET

**Status: owner-stated** (brief §22: "unpublished → remove"). The owner
accepted the recommendation below on 2026-09-25.

None has ever reached its registry (404 on RubyGems, Packagist and NuGet).

Recommendation:
1. Keep them through Phase 1 as extra differential oracles.
2. Delete them, their CI jobs, their `certs` copies and their
   release-please extra files in one commit per port.
3. Remove their pending entries from BOOTSTRAP.md.

A later demand for Ruby, PHP or .NET gets a binding over the C ABI
(Magnus, ext-php-rs or P/Invoke), not a port.

### R9 addendum: more languages from the same Rust definitions (2026-09-25)

- **Ruby:** UniFFI's built-in backend worked in the spike (evidence row
  17). Shipping it means a native gem per platform plus CI legs. The gem
  was never published, so no user is waiting: add it when someone asks.
- **Kotlin:** comes with the JVM package; the Maven artifact is Kotlin
  underneath.
- **React Native, Flutter, Kotlin Multiplatform:** out of scope. These are
  app frameworks, and INTENT.md puts on-device validation out of scope: an
  attacker controls the device, so the check belongs on a backend.
- **C#, Go (cgo), C++, Dart through third-party UniFFI generators:**
  community-maintained, installed from git, not on crates.io. Use one only
  after checking its activity and running the full conformance suite
  through it.

---

## R10. Clock source on wasm

**Status: recommended on 2026-09-25; revised by the owner on 2026-09-26:
option E.**

The core keeps one crate-private `system_now()` seam (SURFACE.md §4.1).
The wasm bake-off proved what the seam is for: the 58
`wasm32-unknown-unknown` rows that trapped were exactly the rows that read
the missing clock, and with a clock seam the same module answered all
1,179 rows as native did ([wasm bake-off §4](../evidence/2026-09-26-wasm-architecture-bakeoff.md)).

| Option | Verdict |
|---|---|
| A. Core-internal `system_now()` with `js_sys::Date::now()` behind a `js-clock` feature | First choice, replaced 2026-09-25: it puts a wasm-bindgen crate in the core's graph. |
| A2. A `platform::install_clock` hook that exists only on `wasm32-unknown-unknown`; the wasm adapter installs `Date.now()` | Chosen on 2026-09-25, replaced on 2026-09-26: wasm-bindgen and `wasm32-unknown-unknown` are gone (R21), and `aprv.wasm` has a clock import anyway. |
| B. `web-time` crate | The same idea through a dependency last released 2024-03-01. No gain. |
| C. Take `now` as a parameter on the verifiers | Breaks §3.5: a caller could accept an expired chain. |
| D. Leave it | Traps (spike). |
| **E. On wasm, `system_now()` reads the `aprv.clock_now_ms` import** | **Chosen** (SURFACE.md §4.1). The host supplies it: `Date.now()` in the JS façade, the wall clock in Go. Callers still cannot move the validity instant (THREAT-MODEL §3.5): the host's clock replaces the OS clock, the same trust level as `SystemTime::now()`. OpenSSL's own `time()` calls resolve to the same import through the link-time C file (wasm bake-off §4). |

---

## R11. Crypto dependencies and speed

**Status: superseded by R21 on 2026-09-26.** OpenSSL does the signature
arithmetic, so `crypto.rs` and the RustCrypto crates leave the core, and
with them the `std`-feature and `getrandom` work below. On wasm, OpenSSL
draws randomness through the `aprv.random_get` import (R21). The Marvin
advisory ignore goes with the `rsa` crate. The original record, kept as
history:

- Stay on stable RustCrypto: `rsa` 0.9.10, `p256`/`p384` 0.13. `rsa` 0.10 is
  still `0.10.0-rc.18`. `p256`/`p384` 0.14 are stable but need `digest`
  0.11, and `rsa` 0.9 uses 0.10.
- Drop the `std` features on `rsa`, `p256` and `p384` (evidence row 2). This
  removes `getrandom` from the graph and unblocks wasm.
- Phase 1 profiles JWS on native and wasm before anything else moves. JWS
  costs about 1 ms natively where OpenSSL costs 0.5 to 0.7 ms, and the gap
  sits on the modern path.
- Move to `rsa` 0.10 together with the 0.14 curve stack when 0.10 ships
  stable. ROADMAP measured 92 µs against 221 µs per RSA-2048 verify.
- Keep the `RUSTSEC-2023-0071` (Marvin) ignore with its note. The advisory
  covers private-key operations, and the core only verifies.

---

## R12. Native artifacts: targets and trust

**Status: accepted by the owner on 2026-09-25.** Evidence: "Which platforms other native
libraries ship" and the Temurin table in the spike notes.

**The rule.** A target is in when all three hold:
1. stable Rust ships a prebuilt standard library for it (checked against
   Rust 1.98.1, the latest stable on 2026-09-25); release builds pin a
   stable toolchain, so anything that needs nightly (`-Z build-std`) is out;
2. CI can run at least the C ABI smoke test on it: a real runner, QEMU
   user mode, or a VM. The repository's rule is that every claim is
   tested;
3. someone still runs it: a supported OS ships for it, or a popular
   library with native code ships a build for it. Old laptops count: a
   2010 netbook with a 32-bit Atom and a 32-bit OS is covered by i686.

musl builds follow Alpine, the only common musl distribution: one for
each Alpine architecture that stable Rust can build.

**Per package.** Only three packages carry natives. npm and Go run the
wasm build, which is the same file on every platform.

| Package | Targets | Count |
|---|---|---:|
| C ABI archives (GitHub Releases) | every target the rule admits | 26 |
| JVM jar | the C ABI targets JNA can load; musl x86_64 and aarch64, plus the Alpine OpenJDK musl targets that pass the QEMU gate (open item 2) | 18 to 22 |
| Python wheels | the C ABI targets PyPI accepts a wheel tag for; other platforms build the sdist with a Rust toolchain | 19 |
| Swift | Apple XCFramework, Linux x86_64 and aarch64 (R7), Windows x86_64 and aarch64 | 4 + Apple |
| npm, Go | wasm | 1 |

**Who runs each target.** No registry reports downloads by platform, so
"use" below is the known deployments, not a measurement. Packages: C = C
ABI archive, J = JVM jar, P = Python wheel, S = Swift.

| # | Target | Who runs it | Use | In |
|---:|---|---|---|---|
| 1 | Linux x86_64 (glibc) | most servers and cloud VMs, Linux desktops, CI runners | very high | C J P S |
| 2 | Linux aarch64 (glibc) | AWS Graviton, Google Axion, Azure Cobalt, Ampere servers; Docker on Apple silicon Macs; 64-bit Raspberry Pi OS | high, growing | C J P S |
| 3 | Linux x86_64 musl | Alpine container images (`eclipse-temurin:*-alpine`, `python:*-alpine`) | high in containers | C J P |
| 4 | Linux aarch64 musl | Alpine containers on Graviton and Apple silicon | medium | C J P |
| 5 | macOS aarch64 | every Mac since 2020; developer laptops, Mac mini CI hosts | very high for development | C J P S |
| 6 | macOS x86_64 | Intel Macs; macOS 26 is the last release for them | medium, falling | C J P S |
| 7 | Windows x86_64 | Windows PCs and Windows Server | very high | C J P S |
| 8 | Windows aarch64 | Snapdragon X laptops, Surface Pro, Azure Cobalt VMs | low, growing | C J P S |
| 9 | Windows x86 (32-bit) | 32-bit JVMs and Pythons still installed on 64-bit Windows by legacy enterprise apps; Windows 11 itself is 64-bit only | low | C J P |
| 10 | Linux x86 (32-bit, i686) | old PCs and 2008 to 2010 Atom netbooks on a 32-bit OS, some industrial PCs | low | C J P |
| 11 | Linux ppc64le | IBM Power servers (RHEL, SLES) at banks and insurers, SAP HANA on Power | niche, enterprise | C J P |
| 12 | Linux s390x | IBM Z and LinuxONE mainframes at banks, airlines, governments | niche, enterprise | C J P |
| 13 | Linux ARMv6 hard-float | Raspberry Pi Zero, Zero W and 1 on 32-bit Raspberry Pi OS | niche, hobby | C J P |
| 14 | Linux ARMv7 hard-float | Raspberry Pi 2 to 5 on a 32-bit OS, BeagleBone, IoT gateways | low, hobby and IoT | C P |
| 15 | Linux riscv64 | VisionFive 2, Milk-V and other boards, first RISC-V servers | niche, emerging | C J P |
| 16 | Linux loongarch64 | Loongson 3A5000 and 3A6000 PCs and servers, mostly Chinese government and enterprise (UOS, Kylin) | niche outside China | C J |
| 17 | FreeBSD x86_64 | FreeBSD servers (Netflix's CDN appliances), pfSense and OPNsense firewalls | low for Java and Python backends | C J |
| 18 | FreeBSD aarch64 | FreeBSD on Graviton, Ampere, Raspberry Pi 4 | niche | C J |
| 19 | illumos x86_64 | OmniOS, SmartOS (Triton clouds), Oxide Computer's racks | niche | C |
| 20 | Solaris x86_64 | Oracle Solaris 11.4 on x86 servers, still under Oracle support | niche, legacy enterprise | C J |
| 21 to 26 | Linux musl i686, ARMv6, ARMv7, loongarch64, ppc64le, riscv64 | Alpine on those architectures: routers, Raspberry Pi, boards, Alpine containers on Power | niche | C, and P for i686, ARMv7, ppc64le, riscv64 |
| | wasm (npm, Go) | Node, Bun, Deno, Cloudflare Workers, browsers; every platform Go builds for | very high | npm, Go |

**C ABI archives (26).**
- Linux glibc (9): x86_64, aarch64, i686, arm (ARMv6 hard-float: Raspberry
  Pi Zero and 1), armv7 (hard-float: 32-bit OS on Pi 2 to 5), loongarch64,
  powerpc64le, riscv64, s390x.
- Linux musl, Alpine's architectures (8): x86_64, aarch64, i686 (Alpine
  x86), arm (Alpine armhf), armv7, loongarch64, powerpc64le, riscv64.
  Alpine s390x is out (below).
- macOS (2): aarch64, x86_64.
- Windows, MSVC (3): x86_64, i686, aarch64.
- FreeBSD (2): x86_64, aarch64 (stable since Rust 1.98).
- illumos (1): x86_64 (OmniOS, SmartOS).
- Solaris (1): x86_64 (Oracle Solaris 11.4).

**JVM jar (18).** JNA's dispatcher decides where the jar can work at all:
linux x86-64, aarch64, x86, arm (the ARMv6 build, so one file covers every
32-bit Raspberry Pi), ppc64le, s390x, riscv64, loongarch64; musl x86-64
and aarch64; macOS aarch64, x86-64; Windows x86-64, x86, aarch64; FreeBSD
x86-64, aarch64; Solaris x86-64. At about 0.6 MB each the pure-Rust
natives added about 11 MB to the jar (sqlite-jdbc is about 14 MB,
rocksdbjni 84 MB). With OpenSSL linked (R21) the one library measured so
far, Linux x86_64 with vendored OpenSSL 4.0.2, is 6,336,528 B raw and
1,966,051 B stripped and gzipped
([OpenSSL CMS everywhere §2](../evidence/2026-09-26-openssl-cms-everywhere.md)),
so the jar grows by more. Maven Central caps a release at 80 MB
(CLAUDE.md).

**Python wheels (19).** manylinux x86_64, aarch64, armv7l, i686, ppc64le,
s390x, riscv64; `linux_armv6l`; musllinux x86_64, aarch64, armv7l, i686,
ppc64le, riscv64; Windows amd64, win32, arm64; macOS arm64, x86_64.
pydantic-core, the largest Rust-on-PyPI package, ships 15 of these.

**Why the jar and the wheels differ.**
- Jar only: loongarch64, FreeBSD x86_64 and aarch64, Solaris x86_64 glibc
  builds. PyPI refuses wheels for these platforms (its upload check,
  `warehouse/utils/wheel.py`, accepts only Windows, macOS, iOS, Android,
  manylinux, musllinux, `linux_armv6l` and `linux_armv7l`), so `pip` builds
  the sdist there with a Rust toolchain.
- Wheels only: musl i686, ARMv7, ppc64le and riscv64. Temurin ships no
  Alpine JDK for them, and JNA's dispatcher is one glibc build per CPU,
  tested on musl only for x86_64 and aarch64. Alpine's own OpenJDK
  packages do exist for ppc64le (11 to 25), riscv64 (21, 25),
  loongarch64 (11 to 25), s390x and x86 (11 only), none for ARM.
- ARMv6 and ARMv7: JNA has one `linux-arm` slot, so the jar's ARMv6 build
  serves every 32-bit Pi. The wheels carry ARMv7 as `manylinux armv7l`;
  PyPI also accepts `linux_armv6l`, and the wheels add it (item 1 below).

**Fallbacks where nothing is prebuilt.** Python: when no wheel matches,
`pip` downloads the sdist and builds it on the spot, which works only if
a Rust toolchain is installed and can take long on small boards. Java:
Maven has no build step at install time, so the only fallback is the
`libraryOverride` property pointed at a library the user built or took
from GitHub Releases. The jar therefore has to carry every platform it
claims; the wheels can lean on the sdist for platforms PyPI refuses.

**Out, and why.** The user-facing support page lists these too, so
nobody has to guess.

| Platform | Why it is out |
|---|---|
| AIX, OpenBSD, DragonFly BSD, Linux mips64el, Alpine s390x | Rust needs nightly for them (tier 3) |
| 32-bit Solaris (SPARC, x86) | no Rust target |
| Solaris SPARC 64-bit | CI cannot run it, so the claim could not be tested (owner, 2026-09-25) |
| i586 | CPUs without SSE2: the Pentium, Pentium II and III, or embedded Vortex86 and Geode chips. Every x86 PC since about 2003 has SSE2 and uses the i686 build. |
| ARMv5TE, soft-float ARMv6 and ARMv7 (Debian armel) | ARM9 boards and old NAS boxes. No Temurin JDK, no PyPI wheel tag, no popular Rust library ships it. Every Raspberry Pi uses hard-float. |
| 32-bit PowerPC | the last PowerPC Mac shipped in 2005; FreeBSD 15 retired the platform |
| 64-bit big-endian PowerPC Linux (glibc and musl) | IBM Power moved Linux to little-endian (ppc64le, which is in) |
| SPARC Linux | Debian Ports only, no supported distribution |
| FreeBSD 32-bit x86 | FreeBSD 15.0 retired i386 |
| NetBSD | no popular Rust library ships a NetBSD build |

A Java user on a platform outside the jar can still point
`uniffi.component.<namespace>.libraryOverride` at a library they built,
wherever JNA runs.

**Additions after the first list:**
1. Accepted by the owner on 2026-09-25: a `linux_armv6l` wheel
   (Raspberry Pi Zero and 1), built from the jar's ARMv6 library. 19
   wheels.
2. Accepted by the owner on 2026-09-25: the jar adds musl ppc64le,
   riscv64 and loongarch64 (and i686, where Alpine ships Java 11 only).
   Each stays only if a QEMU job running Alpine's own OpenJDK loads the
   library through JNA and verifies the g5 receipt; one that fails is
   dropped and listed under "Out" with the reason. Up to 22 natives.

**How each target is tested.** GitHub runners for linux x86_64 and
aarch64, macOS, Windows x86_64 and aarch64 (x86 under WOW64). QEMU user
mode for every other Linux target, glibc and musl. `vmactions` VMs for
FreeBSD, illumos (OmniOS) and Solaris x86_64. The JVM smoke test runs
where a JDK exists for that target (Temurin: x86-64, aarch64, arm,
ppc64le, s390x, riscv64, Windows x86); elsewhere only the C ABI smoke
test runs.

**What it costs:** about 30 native builds per release instead of 8 (the
jar and the wheels reuse them), run in parallel and without caches
(publish jobs never cache). Rust builds its tier 2 targets but does not
test them, so a Rust upgrade can break one; our CI catches that before a
release. Since R21 each build also compiles OpenSSL for its target, which
needs perl and a C compiler per target, and on Windows is expected to need
nasm or `no-asm` ([substrate bake-off §14](../evidence/2026-09-26-security-substrate-bakeoff.md)).

**OpenSSL on each target (R21, open item).** `openssl-src` maps all 26
C ABI triples in its target table (DOCUMENTED in the substrate bake-off
§14), but only Linux x86_64 has been built and run. The owner deferred
the rest on 2026-09-26: "for now it is enough that it works here; we'll
look at the platforms later". The 26-target list stays. Phase 1 or CI
must prove, before 0.8.0, that OpenSSL builds for each target and that at
least the C ABI smoke test passes there (rule 2 above); a target that fails leaves the list and goes under
"Out" with the reason, like any other.

**Licenses of the linked C code.** OpenSSL 4.0.2 is Apache-2.0
(`LICENSE.txt`). Every package that carries a native library or
`aprv.wasm` ships OpenSSL's license and NOTICE text. `aprv.wasm` also
links wasi-libc (Apache-2.0 WITH LLVM-exception, Apache-2.0 or MIT, plus
musl's MIT) and Rust's standard library, and ships their texts too
([wasm bake-off §16](../evidence/2026-09-26-wasm-architecture-bakeoff.md)).
None is copyleft. The library itself stays MIT.

**Unchanged from the first version of this record:**
- One fat jar, selected at runtime, like JNA and sqlite-jdbc: no
  classifier for users to choose. A platform without a bundled library
  gets a clear error that names the missing target and the
  `libraryOverride` property.
- Build on native runners where GitHub provides them; `cargo-zigbuild` or
  `cross` for the rest.
- Every artifact gets a SHA-256 and `actions/attest-build-provenance`.
  The repository has no attestation step today.
- Release builds pin the toolchain (`rust-toolchain.toml`) and remap
  paths, so a second build can reproduce the hash.

**Swift on Windows (accepted by the owner on 2026-09-25).** Today's
Swift package never claimed Windows (CI tests Linux and macOS). swift.org
ships official Windows toolchains for x86_64 and arm64 for every release
from 6.1 on (swift.org/install/windows, read 2026-09-25). SE-0482, the
proposal R7 relies on, covers Windows `.lib` static libraries by design,
and the C ABI builds a Windows `.lib` anyway. The Swift package adds
Windows x86_64 and aarch64, and keeps the claim only if the Phase 5 CI
leg (MIGRATION 5.6) proves SwiftPM on Windows links the bundle. This
Linux container could not test it.

---

## R13. How much of today's API survives

**Status: superseded by R18 on 2026-09-25** (Java gets a thin façade).
Kept for the record: accepted earlier the same day as "no Java façade to
start". Java uses the UniFFI-generated API directly: `null` for "use Apple's roots",
the generated package for imports (a breaking change the CHANGELOG lists),
and KDoc/Dokka for docs. Add the façade before 1.0 only if Java users
object. npm keeps its thin TypeScript layer, because Wasm trap recovery
(ARCHITECTURE §5) and the sync/async split need it. Original analysis:

- Keep the class names (`JwsVerifier`, `ReceiptVerifier`,
  `VerifyReceiptEndpoint`, `VerifyReceiptResult`), the `Reason` tokens,
  the package coordinates and the import paths. On the JVM that needs the
  Java façade, because UniFFI puts every generated class in one package
  while today's classes live in the root, `.jws` and `.receipt` packages
  (ARCHITECTURE §6.1).
- Accept generated shapes where they are idiomatic enough:
  - positional constructors in place of builders;
  - Java passing `null` for "use Apple's roots";
  - `AutoCloseable` verifiers.
- Allow a thin façade where a current signature is worth one file:
  - npm options objects;
  - a Java overload without the roots argument;
  - Python keyword arguments, which UniFFI already provides.
- List every break in the CHANGELOG, per package.

Keeping the shapes close lets the five published ports' test suites (about
30,000 lines) become the bindings' test suites with small edits.

---

## R14. Generated code: committed or built

**Status: recommended.**

| Output | Committed? | Why |
|---|---|---|
| C header | yes (already) | Consumers read it from the repo. CI diff gate already exists. |
| Swift sources + FFI modulemap | **yes** | SwiftPM builds from git and has no build step. |
| Go `aprv.wasm` | **yes** | The Go module is the git tree at a tag. npm ships the same module (R21). |
| Kotlin, Python glue | no | Built inside each package build from pinned tools, from a clean checkout. |
| npm JS façade and `index.d.ts` | yes, as source | Hand-written since R21; nothing generates them. |

Every generator and toolchain version is pinned in one place. The UniFFI
and cbindgen Dependabot groups, and bumps of the OpenSSL crates
(`openssl`, `openssl-sys`, `openssl-src`), must pass the full
cross-package conformance run before merging.

---

## R15. Order of migration

**Status: accepted by the owner on 2026-09-25.**

1. **Python** first: smallest package, lowest risk, maturin is mature, and
   it proves the release pipeline for native wheels.
2. **Java** second: the gate already passed. It carries the Maven Central
   budget, so batch it into one release.
3. **npm** third: the widest runtime matrix. Needs R4 and R5 settled.
4. **Swift** fourth: the hardest packaging (R7).
5. **Go** last: needs R6. (It was also the port most likely to become
   the R8 second implementation; R8 settled on the published Java jar
   instead.)

The phases run in this order, but all of them ship together in 0.8.0
(R19). See [MIGRATION.md](./MIGRATION.md).

---

## R16. aprv-surface is generator-neutral

**Status: accepted by the owner on 2026-09-25.**

The contract, the field-by-field mapping and the enforcement are in
[SURFACE.md](./SURFACE.md). Neither the core nor the surface depends on a
binding generator; UniFFI annotates the surface from its adapter crate
with `#[uniffi::remote]` (spike passed). This replaces R3's option C as
first written (derives behind a `uniffi` feature on the surface).

---

## R17. The sidecar: a verifyReceipt server, and a mode of the Java library

**Status: accepted by the owner on 2026-09-25: both.**

Evidence: "Sidecar" in the spike notes. A 1.5 MB static binary answers
`POST /verifyReceipt` with exactly the core's `verify_receipt_json`; with
a one-write client it costs 961 µs per receipt against 648 µs in-process.

1. **A product of its own:** `aprv-server`, a binary and a Docker image
   that stand in for Apple's retired `verifyReceipt` endpoint, offline.
   Any language switches by changing a URL. It is one more adapter over
   the surface and adds no verification logic.
2. **A mode of the Java library:** besides the in-process binding, the Java
   package can start the bundled server as a child process and talk to it
   over HTTP. That mode puts no native code in the JVM, which sidesteps
   classloader, native-image, JNA and Kotlin concerns at the price of a
   child process and about 310 µs per call.

Constraints the spike surfaced:
- The Java client must send each request in one write with `TCP_NODELAY`;
  `HttpURLConnection` costs about 1.5 ms extra per POST (Nagle plus
  delayed ACK).
- `/tmp` mounted `noexec` blocks the extracted binary; the launcher takes
  an exec-allowed directory setting, and the docs recommend a separate
  container where that is available.
- Executing from memory (`memfd_create` + `fexecve`) is rejected: pure Java
  cannot do it, and security tools treat fileless execution as malware
  behaviour.
- The server binds to `127.0.0.1` (or a Unix socket on Java 16+) and exits
  when its parent's stdin closes.

**Image registries (owner, 2026-09-25):** GitHub Container Registry and
Docker Hub. GHCR publishes from `release.yml` with the workflow token.
Docker Hub needs a stored access token and a namespace, so it gets a
BOOTSTRAP.md entry and publishes only after the owner creates both.

**Throughput, re-measured 2026-09-25** (evidence: "Sidecar throughput"):
the 941 requests/s above came from the Java `HttpURLConnection` client,
not from the server. With a lean keep-alive client, the same server on
the same 4 vCPUs answers 5,004 requests/s at 16 connections; the core
itself peaks at 6,444 verifications/s in-process on 4 threads.

---

## R18. The Java binding: UniFFI plus a thin Java façade

**Status: accepted by the owner on 2026-09-25.** Supersedes R13 ("no
façade to start").

The Java package keeps UniFFI's generated Kotlin as its engine and puts a
small hand-written Java layer in front of it: pure delegation, no parsing,
no policy, no caps.

**What `uniffi.toml` fixes without a façade** (spike, UniFFI 0.32.2,
`bindings.kotlin`): `package_name`, `generate_immutable_records = true`
(fields become `val`, no setters), `disable_java_cleaner = true` (no
`java.lang.ref.Cleaner` reference, so it compiles against Java 8 APIs),
and a `rename` table for types and record fields (`VerifyError` became
`VerificationException`; `AppReceipt.creation_date_ms` became
`createdAtMillis`). `custom_types` can map a surface `i64` to
`java.time.Instant` (not yet tried).

**What only the façade fixes:**
- default arguments for Java (`new ReceiptVerifier(bundleId)` without a
  `null`), since UniFFI emits no `@JvmOverloads`;
- today's import paths (`.jws.JwsVerifier`, `.receipt.ReceiptVerifier`),
  since UniFFI puts one crate in one package;
- a clean autocomplete: no `UniffiWithHandle`, `NoHandle`,
  `callWithHandle$...` or `Companion`;
- Javadoc in Java types (`byte[]`, `void`, `throws`) from `javac`/`javadoc`;
- `VerificationException.reason()` as today, instead of a nested
  `VerificationException.Verification`.

**Why the façade makes the engine replaceable:** Java users depend only on
the façade. The engine behind it can move from UniFFI over JNA to
UniFFI's JNI backend (unreleased on 2026-09-25) or to jni-rs without any
user-visible change. The JNI backend would remove JNA and with it the
known cost below.

**API compatibility:** breaking changes are allowed before 1.0 (owner,
2026-09-25). The façade does not have to reproduce today's class names or
import paths; it picks the best Java shape, and the CHANGELOG lists every
break.

**Known cost, accepted:** under Tomcat or another app server with hot
redeploy, JNA leaks a Cleaner thread and two native copies per redeploy
(evidence: "Enterprise deployment shapes", JNA 5.17.0 and 5.19.1; JNA
issue #1521; JNA offers no public API to stop the thread). The Java README
documents the mitigation: install the jars in the container's shared
`lib/`. Spring Boot, plain `java -jar`, containers and native-image are
unaffected.

**Rejected here:** jni-rs + hand-written Java (no dependencies and no
redeploy leak, but 472 lines of Java plus 2 `unsafe` to maintain, and a
second binding system beside UniFFI). It stays the fallback engine if the
redeploy leak becomes a real user problem before the JNI backend ships.

---

## R19. Versions and the crates.io debut

**Status: accepted by the owner on 2026-09-25.**

- The owner ships a fix as 0.7.0 from `main` first. That release is not
  part of the migration.
- Phase 1 changes only the Rust crate and the C ABI, neither of which is
  on a registry, so it cuts no release (CLAUDE.md release budget).
- Every package moves to the Rust core in one release, 0.8.0 (owner,
  2026-09-25). The phases (R15) still run one after another with their
  gates, but none of them cuts a release of its own. One release also
  spends one Maven Central slot instead of five.
- The phases land on a `rust-core` integration branch (below).
- Everything stays 0.x. 1.0 is a separate decision after the migration.
- The first crates.io publish waits until something needs it: a user
  asking for the crate, or a binding that has to depend on it from a
  registry. Until then Rust users take a git dependency.

**Where the phases land (accepted by the owner on 2026-09-25).** release-please opens a release PR for
whatever reaches `main`. If the phases merge into `main` one by one, an
urgent 0.7.x fix during the migration would ship half-migrated packages.
Decision: a long-lived `rust-core` integration branch. Each phase
merges there, `main` keeps taking 0.7.x fixes and is merged into
`rust-core` after each one, and `rust-core` merges into `main` once, when
every gate has passed. That merge produces 0.8.0.

---

## R20. Apple compatibility, the algorithm policy, and recorded divergences

**Status: accepted by the owner on 2026-09-26, and rewritten by the owner
the same day after the OpenSSL rounds (R21).**

**The goal (owner):** Apple compatibility and failing closed. Matching
Java is not the goal. `fixtures/cases.json` is the contract, and
Java/Bouncy Castle is a reference only (R8). No prescan or other check
gets added only to match Java.

The Native Image spike (evidence: `2026-09-25-java-native-image.md` §7)
ran one corpus through the JVM Java verifier and the Rust core and found
divergences that the shared fixtures never caught. The first form of this
record counted each one as a bug on one side. The rule below replaces
that.

**Algorithm policy (owner, option a), unchanged:** accept any signer and
chain signature algorithm that the pinned Apple chain vouches for. That is
Java's behavior since `2ba48bc` (2026-09-24), which changed Java alone and
so broke the one-product rule. There are no extra exclusions. Measured in
the spike, the JVM Java verifier accepts all 22 algorithm inputs,
including receipt signers using MD5, RIPEMD-160, SHA-224, SHA3-256,
RSA-PSS, P-521 and Ed25519, as long as the chain ends at a pinned Apple
root. Earlier on 2026-09-26 the owner chose to match Java rather than
exclude MD5. With OpenSSL's CMS API (R21) the core accepts all 22 too:
the algorithms corpus answers as Java does on 22 of 22 rows
([follow-up §3.2](../evidence/2026-09-26-substrate-followup.md)).
The remaining risk: only a key under a pinned Apple root can produce the
signature, so an attacker would need a collision attack against something
Apple itself signs.

**The rule (owner, 2026-09-26):** divergences are recorded. A divergence
that changes an Apple-signed input's verdict, or accepts something
unsigned, is a bug.

**Divergences the Native Image spike found** (owner, 2026-09-26: another
agent fixes them on `main`, one PR each). The last column says what the
OpenSSL switch does to each:

| # | Input | Java | Rust today | Direction | Under OpenSSL (R21) |
|---:|---|---|---|---|---|
| 1 | Signer or chain algorithm outside RSA SHA-1/SHA-256 and EC P-256/P-384 (14 of 22 algorithm inputs) | accepts | rejects (9, 5, 4 or 2) | Rust and the other ports follow Java (policy above) | **Resolved by the switch:** 22 of 22 algorithm rows answer as Java does |
| 2 | Unused embedded certificate whose `tbsCertificate.signature` OID disagrees with its outer `signatureAlgorithm` | accepts | 9 | decided in its fix PR | No longer diverges: it is not among the hostile rows the CMS build answers differently from Java, and §5 of the CMS note lists all of those. Read off the tallies, not checked row by row. The fix PR on `main` still decides the intended answer. |
| 3 | `verifyReceipt` body with bytes after the JSON object | status 0 (Jackson ignores trailing tokens) | 21002 | decided in its fix PR | Unchanged: the endpoint's JSON layer is Rust code that both builds share (CMS note §5, rows 4 and 5) |
| 4 | Non-UTF-8 JWS, base64 receipt or endpoint body at the C ABI | answers | 101 `INVALID_UTF8` | decided in its fix PR | Unchanged: the C ABI refuses these before the substrate runs |
| 5 | Comment at `rust/src/jws.rs:632-634` claims U+FFFD always makes the JSON invalid | | wrong | fix the comment | Unchanged: `jws.rs` stays |

Twenty more rows reject on both sides with a different reason; they are
listed in the spike's `results/java-vs-rust-hostile-explained.txt` and
need a case each where the reason is part of the contract.

**What stays different under OpenSSL.** Without a prescan, the CMS build
answers as Java does on 1,028 of the 1,048 rows the C ABI can express
([ASN.1 payload note §3](../evidence/2026-09-26-openssl-asn1-payload.md)).
The other 20:

- The 18 rows in §5 of the
  [CMS note](../evidence/2026-09-26-openssl-cms-everywhere.md), each with
  its reason, the RFC or X.690 section that takes a side, and whether
  Apple could produce it. One is an acceptance Java refuses:
  `substrate/cms/attributes-unsorted-signed-as-sent`, a signature the key
  holder made over signed attributes sent in non-DER order (RFC 5652 §5.3
  sides with Java). The other 17 reject either way, or sit in the shared
  JSON layer.
- `substrate/cms/unsigned-attribute-nesting-2000` and `-100000`: Java
  answers 9, OpenSSL 0. The nesting sits inside unsigned attributes, which
  no signature covers and which OpenSSL does not parse
  ([substrate bake-off §6](../evidence/2026-09-26-security-substrate-bakeoff.md),
  [follow-up §3.4](../evidence/2026-09-26-substrate-followup.md)). The
  prescan that aligned them left with `asn1.rs` (R21).

The payload reader's differences from today's `asn1.rs` fall into nine
classes, L1 to L5 and S1 to S4 (payload note §3). The CMS note checked
its 18 rows against the genuine receipts in `fixtures/`: none is a
forgery, and none could come from a genuine Apple receipt or JWS. No
genuine or fixture payload falls into any payload class.

**New Apple fields.** An attribute type the core does not model lands in
`unknownAttributes`, which `cases.json` already covers, so a new Apple
field stays visible without a second parser. The local drift check over
private production receipts (MIGRATION step 1.13) watches for new types;
one found there becomes a test built from a generated receipt of the same
shape.

**How the plan checks them:** the spike's differential harness runs the
same request corpus through the published 0.7.x jar (pinned by version and
checksum, R8) and through the Rust core, in MIGRATION step 1.8 and in the
final acceptance tests. Each difference it finds gets a row here with its
reason, and the rule above decides whether it is a bug.

---

## R21. Security substrate: OpenSSL 4 with the CMS API

**Status: accepted by the owner on 2026-09-26.**

Evidence, five notes of 2026-09-26, in the order they ran:

1. [Security substrate bake-off](../evidence/2026-09-26-security-substrate-bakeoff.md):
   OpenSSL, LibreSSL and AWS-LC under one rust-openssl adapter.
2. [Wasm architecture bake-off](../evidence/2026-09-26-wasm-architecture-bakeoff.md):
   four wasm routes for a C-backed core.
3. [Substrate follow-up](../evidence/2026-09-26-substrate-followup.md):
   the CMS API, the newest toolchains, the first fuzz campaigns.
4. [OpenSSL CMS everywhere](../evidence/2026-09-26-openssl-cms-everywhere.md):
   the CMS path on every route and host.
5. [ASN.1 payload](../evidence/2026-09-26-openssl-asn1-payload.md): the
   receipt payload through OpenSSL's ASN.1 templates, `asn1.rs` deleted.

**The owner's reasons**, as stated: the risk is code we write ourselves
for generic security protocols ("we can't trust ourselves writing it by
hand"), and speed does not matter.

### The decision

The core's generic security code moves onto OpenSSL 4.x through
rust-openssl (`openssl` 0.10.81, `openssl-sys` 0.9.117 in the evidence).
4.0.2 is the newest stable release today; 4.1.0-beta1 changed no verdict
(follow-up §2b).

- **CMS:** OpenSSL's CMS API with our own chain policy. The evidence build
  finds the signer with `CMS_SignerInfo_cert_cmp` and verifies with
  `CMS_SignerInfo_verify` and `CMS_SignerInfo_verify_content`. It never
  calls `CMS_verify` and never builds a store from anything but the pinned
  roots (follow-up §3.2).
- **Chain:** `X509_verify_cert` over a store that holds only the pinned
  Apple roots, `X509_V_FLAG_PARTIAL_CHAIN`, the check time set to the
  signing instant, and our historical-time verify callback (substrate
  bake-off §4, A2).
- **Receipt payload:** Apple's `ReceiptAttribute` SET and the nested
  in-app SETs are read with OpenSSL's declarative ASN.1 templates: a
  14-line C file of `ASN1_SEQUENCE`/`ASN1_ITEM` declarations, decoded with
  `ASN1_item_d2i` (payload note §2, option (a)). No hand-written tag or
  length parsing remains anywhere.
- **Isolation:** no config file and no default trust paths. The adapter
  calls `OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG)`; the substrate
  bake-off's negative control proved the check can see a leak
  (substrate bake-off §7).

### Options measured

| Option | What the evidence showed | Verdict |
|---|---|---|
| **OpenSSL 4.0.2, CMS API** | Same answers as its native build on 1,179 of 1,179 rows in 33 wasm runs across 9 hosts (CMS note §2). Java-equal on 1,028 of 1,048 rows without a prescan (payload note §3), and on 22 of 22 algorithm rows (follow-up §3.2). | **Chosen** |
| OpenSSL 4.0.2, PKCS7 API | Refuses Ed25519, RSA-PSS and SKI-identified SignerInfos that Java accepts (follow-up §3.1). | Replaced by the CMS API |
| AWS-LC 1.73.0 and 5.7.0 | Fastest natively (JWS 355 µs p50) and smaller (1,301,167 B stripped and gzipped C ABI), and draws no randomness on wasm (substrate bake-off §1, wasm bake-off §10). No CMS API (no `cms.h` in either version), so Ed25519, RSA-PSS and SKI-identified signers stay unsupported (follow-up §3.3). | Not chosen |
| LibreSSL 4.3.2 | Does not build for `wasm32-wasip1`, so no freestanding module (substrate bake-off §13). Its CMS API refuses the ECDSA-signed receipts `ec-p256-sha256`, `ec-p384-sha384` and `ec-p521-sha512` (follow-up §3.3). | Not chosen |
| Pure Rust, today's core | 0 `unsafe`, but 1,069 lines of our own ASN.1, CMS, X.509, path and crypto code (substrate bake-off §10). RustCrypto `der` cannot replace `asn1.rs`: it refuses BER spellings (substrate bake-off §6, payload note §5). | Not chosen: it is the hand-written code the owner wants gone |
| Emscripten packaging | Works (R2), with legacy exceptions, about 18 MB of initial memory and generated glue (wasm bake-off §7). | Not used |
| Component Model and jco as the npm route | Works, with 202 KB or more of generated glue (wasm bake-off §8). The WIT experiment stays in the evidence as a future option for native Component Model hosts. | Not used |
| BoringSSL, wolfSSL, Botan, Mbed TLS, NSS, GnuTLS | Research only: no PKCS#7 signature verification (BoringSSL), GPL (wolfSSL), no CMS SignedData verification (Botan), a DER-only `pkcs7` module (Mbed TLS), no maintained Rust binding (NSS), LGPL static-link terms (GnuTLS) (substrate bake-off §15, wasm bake-off §18). | Not built |
| Rust ASN.1 crates for the payload | `der` 0.8.2 refuses chunked OCTET STRINGs and long-form lengths. `rasn` and `bcder` read every BER spelling in the probe; `asn1-rs` documents BER support and was not probed (payload note §5). | Not used. If pure Rust is ever wanted, `rasn`, `bcder` and `asn1-rs` are the candidates. |

### What gets deleted

In Phase 1, on the `rust-core` branch, with no fallback kept (git history
keeps the old code):

- `rust/src/cms.rs`, `x509.rs`, `chain.rs`, `crypto.rs` and `asn1.rs`:
  1,067 code lines (payload note §6);
- the RustCrypto dependencies `rsa`, `p256`, `p384`, `sha1`, `sha2` and
  `digest` (payload note §3);
- the public modules `asn1`, `x509`, `cms`, `crypto` and `chain`, with
  `TrustAnchor::certificate()` and `From<x509::Certificate>`;
- the fuzz targets `parse-der`, `parse-certificate` and `parse-cms`.

`roots.rs` stops parsing anchors with `x509.rs`: a `TrustAnchor` holds the
DER after `d2i_X509` and the adapter's readability check. The owner
accepts the breaking changes before 1.0: "don't hesitate, pre-1.0 feel
free". Unknown receipt attribute types keep appearing in
`unknownAttributes` (R20).

### What our code still owns

| Piece | What it holds | `unsafe` |
|---|---|---|
| The core (policy) | Apple's rules: pinned roots, the top-down pre-check, the verify callback (historical time, the notAfter waiver, the anchor exemptions), marker OIDs, the critical-extension rule, the receipt attribute mapping, JWS, caps, the endpoint, reason codes | none: `#![forbid(unsafe_code)]` |
| The OpenSSL adapter crate | The FFI to OpenSSL's CMS, X.509, EVP and ASN.1 template APIs, and the declaration of the `aprv.clock_now_ms` import that the core's clock reads on wasm | the only crate below the bindings with `unsafe`: 402 lines inside `unsafe` in the evidence build (payload note §6) |
| `payload.c` | 14 lines of `ASN1_SEQUENCE`/`ASN1_ITEM` declarations, no logic | C |
| The wasm link-time C file | Defines the WASI functions inside `aprv.wasm`, so the module imports only `aprv.clock_now_ms` and `aprv.random_get` (`wasi-none.c` in the evidence, 74 code lines) | C |
| The npm JS façade | Loads `aprv.wasm`, passes bytes in and JSON out, supplies the two imports; about 100 lines plus `index.d.ts` | none |

The whole security path goes from 2,100 code lines with 0 `unsafe` and 0
C to 2,207 lines with 402 inside `unsafe` and 14 lines of C (payload note
§6). OpenSSL 4.0.2 joins the trusted base.

### Numbers that matter

- **Corpus:** 1,179 rows (`cases` 153, `substrate` 193, `hostile` 811,
  `algorithms` 22). The CMS build answered them identically in 33 wasm
  runs: Route C and WASIp1 on 9 hosts each, Emscripten on 7, the
  component on 8 (CMS note §2). The template payload build matched it on
  1,179 of 1,179 rows natively and in Route C on 9 hosts (payload note
  §3).
- **`cases.json`:** 153 passed through the C ABI, 272 fields checked
  (payload note §3).
- **Java-equal:** 1,028 of 1,048 (R20).
- **Fuzzing,** ASan and libFuzzer with OpenSSL instrumented, no crash,
  leak, timeout or OOM in any campaign:
  - 4 × 45 min over OpenSSL and AWS-LC, 28,983,241 executions (follow-up
    §4.2);
  - 2 × 45 min on the CMS path, 9.33 million executions (CMS note §4);
  - 45 min of `verify-receipt` without `asn1.rs`, 2,999,045 executions,
    alongside a differential payload target with 5,634,104 (payload note
    §4).
- **Sizes, Linux x86_64:** the native C ABI library is 8,532,952 B with
  `OPENSSL_DIR` (payload note §3) and 6,336,528 B raw, 1,966,051 B
  stripped and gzipped with vendored OpenSSL (CMS note §2), against
  1,068,760 and 408,286 B for today's pure-Rust library (substrate
  bake-off §9). `aprv.wasm` is 2,973,532 B raw and 975,767 B stripped and
  gzipped (payload note §3), against 620,669 and 186,728 B for the
  pure-Rust `wasm32-unknown-unknown` module (substrate bake-off §13).
- **Memory (owner, Q32 a):** OpenSSL builds one object per ASN.1 element,
  and nothing caps the node count. On a hostile 3 MiB payload of small
  attributes the template reader peaks at 92 MiB against 33 MiB for a
  tiny one (+58 MiB in the note's table); today's reader refuses that
  payload at its node budget. As a whole receipt through the native C ABI
  the peak is 122 MiB against 47 MiB today, and 145 MiB in Route C on
  Node against 67 MiB for a tiny receipt (payload note §2 and §3).
  Realistic receipts are unchanged. Accepted, bounded by the 3 MiB input
  cap. Phase 4 measures it in workerd, whose isolate limit is 128 MB.

### Build configuration

- **Native:** OpenSSL 4.0.2 vendored through `openssl-src` 400.x, or an
  `OPENSSL_DIR` build. `openssl-sys` 0.9.117 declares `openssl-src`
  `^300.2.0`, so a one-line `[patch.crates-io]` copy of its manifest is
  needed until upstream accepts 400.x; with it, the vendored build matched
  the `OPENSSL_DIR` build on 1,179 of 1,179 rows (CMS note §1). Builds set
  `OPENSSL_CONFIG_DIR` to a path that does not exist, so no config file on
  the host is read; `openssl-src` otherwise passes
  `--openssldir=/usr/local/ssl`.
- **Wasm:** `aprv.wasm` is built for `wasm32-wasip1` with wasi-sdk's libc,
  over OpenSSL 4.0.2 compiled by wasi-sdk and passed through
  `OPENSSL_DIR` (`openssl-src` maps `wasm32-wasi` but not
  `wasm32-wasip1`). The link-time C file and the two WASIp1 link fixes
  (`crt1-reactor.o`, the wasi-libc emulation libraries) come from the
  substrate bake-off §13 and the wasm bake-off §6. In the shipped build
  every stubbed WASI function other than the clock and random traps
  instead of returning an error.
- **Randomness on wasm:** OpenSSL draws random bytes only for EC blinding
  inside ECDSA verification. The host fills `aprv.random_get` from
  `crypto.getRandomValues` in JS (never `Math.random`) and from
  `crypto/rand` in Go. A failing RNG makes OpenSSL refuse ECDSA
  verification: 0 new acceptances over 1,179 rows (wasm bake-off §10).

### Open items

1. **R12's 26 targets.** Only Linux x86_64 is built. The owner deferred
   the rest (R12); Phase 1 or CI proves each target before 0.8.0.
2. **Memory in workerd** (above): Phase 4 measures it.
3. **`openssl-sys` and `openssl-src` 400.x.** A `[patch.crates-io]`
   applies only inside our own workspace. A crates.io user of the core
   (R19) builds `openssl-sys` as published: its `vendored` feature gives
   OpenSSL 3.x, and without it the build takes the OpenSSL it finds on
   the system. That holds until upstream widens the requirement.
4. **OpenSSL 4.1.0 final** needs its own corpus run; the beta changed
   nothing (follow-up §2b).

### Maintenance

OpenSSL's security advisories join RustSec (which covers rust-openssl). A
fix in OpenSSL means a rebuild on every target and of `aprv.wasm`, then a
release (substrate bake-off §11); MIGRATION's risks say how a release
picks one up. The drift check over private production receipts
(MIGRATION step 1.13) watches for new Apple attribute types.
