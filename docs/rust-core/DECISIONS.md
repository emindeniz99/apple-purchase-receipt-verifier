# Decisions for the Rust-core migration

Each record lists the options, the evidence and a recommendation. Status is
one of:

- **Owner-stated**: the owner's brief already decided it.
- **Recommended**: technical, no product trade-off; proceeds unless the
  owner objects.
- **Owner call**: a real trade-off that the owner decides.

When a record is settled, its outcome moves into PLAN.md as the next
D-number (D17 onward) and this file keeps the history.

Evidence: [spike results](../evidence/2026-09-25-rust-core-spikes.md).

---

## R1. Rust is the only implementation

**Status: owner-stated** (brief of 2026-09-25).

Today nine implementations repeat one security algorithm: the Rust core
(5,358 lines) and eight ports (about 27,500 lines). A fix has to land nine times, and eight of the nine
had little human review. The owner reviews Java deeply and wants to learn
Rust and review exactly one implementation.

The existing Rust crate becomes the only place that parses, validates or
decides. Every published package becomes a binding. PLAN.md D16
(hand-written readers per port, each on its ecosystem's crypto) is
superseded.

Trade-off accepted with this: **monoculture.** Today a bug in one port
shows up as a disagreement on `fixtures/cases.json`. After the migration, a
bug in Rust ships to every language at once. R8 decides how much
independent checking survives.

---

## R2. Binding toolset

**Status: owner-stated, confirmed by the spikes.**

| Use | Tool | Why |
|---|---|---|
| Kotlin/JVM, Swift, Python | **UniFFI** 0.32 (Mozilla) | Built for one Rust core with many foreign bindings. Firefox ships it. First-party Kotlin, Swift and Python. Java 8 works (spike). Doc comments propagate. |
| JavaScript | **wasm-bindgen** 0.2.129 | The standard Rust-to-JS tool, now at github.com/wasm-bindgen. Targets `nodejs`, `web`, `deno`, `bundler`, `experimental-nodejs-module`, `module`. |
| C and everything else | explicit `extern "C"` + **cbindgen** | Already exists, 20 symbols, tested on three OSes. |
| Go | wazero (R6) | cgo-free. 1Password's Go SDK runs its Rust core the same way. |
| Examples for other languages | each language's own C FFI (ctypes, JNA/FFM, P/Invoke, cgo, Ruby `ffi`, PHP FFI) over the C ABI; SWIG `.i` only as an extra | SWIG works once its `.i` declares ownership: a `newfree` typemap calling `aprv_string_free` took a 2 KB-per-call leak to zero (evidence row 16). Native FFI examples free explicitly and need no generated C; SWIG suits users who want one interface file for many languages. |

Rejected, with the trigger that would reopen each:

| Tool | Why not now | Reopen when |
|---|---|---|
| PyO3 + maturin (native module) | UniFFI Python passed the spike: typed exceptions, docstrings, defaults. PyO3 would be a second binding system. | UniFFI Python fails a concrete requirement: an API shape, a measured performance gap, or a packaging limit. |
| napi-rs (Node native addon) | It adds per-platform npm binaries; wasm already covers every JS runtime. | R4 picks the performance option. |
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

**Status: accepted by the owner on 2026-09-25: option C.**

Measured on one machine (µs per verification):

| | Receipt (g5) | JWS |
|---|---:|---:|
| npm 0.6.0 today, `node:crypto` | 683 | 732 |
| npm 0.6.0 today, `/web` (WebCrypto) | 1,001 | 1,134 |
| Rust core, native (via UniFFI) | 742 | 1,053 |
| **Rust core, wasm in Node 22** | **3,626** | **3,900** |

In capacity terms, one core verifies about 1,400 receipts a second today
and about 275 a second on wasm. The cost is per verification, not per HTTP
request: a backend verifies a receipt or transaction when a purchase or
notification arrives.

| Option | Speed on Node | Cost |
|---|---|---|
| **A. wasm everywhere, then shrink the gap** | About 5.3x slower than `node:crypto` today (3.5x against `/web`). Phase 1 profiling and the crypto work in R11 may cut it (unmeasured). | Simplest. One artifact family. Zero npm dependencies. No platform binaries. |
| B. wasm for edge and browsers, napi-rs native addon for Node | Native, close to today | A second binding tool, 6-8 platform packages (`@…/linux-x64-gnu` and so on) as optionalDependencies, a larger release matrix, and a native-module story for serverless bundlers. |
| C. A from day one, B written in as a trigger | A until the trigger fires | Only the trigger to agree on now. |

Recommendation: **C.** Ship wasm and publish the numbers in
BENCHMARKS.md. Add napi-rs only if, after R11's work, wasm on Node is still
**more than 2x** the 0.6.0 `node:crypto` build on either path, or a user
reports throughput trouble. napi-rs would call the same core, so no
security code gets added either way.

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
for `wasm32-wasip1` (spike). Record it in the CHANGELOG as a breaking
change.

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

| Option | Speed | What users lose | Our cost |
|---|---|---|---|
| **A. wazero** + embedded `wasm32-wasip1` core | 6,740 µs per receipt (about 30x slower), plus 177 ms once per process to compile | Stdlib-only (gains wazero + x/sys). Go floor 1.22 rises to 1.25. | About 470 KB `.wasm` committed per release, and a small Go wrapper with JSON decode and an instance pool. |
| B. cgo + prebuilt static libraries in the module | Native (about 750 µs) | `CGO_ENABLED=0`, easy cross-compiling, `FROM scratch`. musl and Windows need extra work (automerge-go and wasmvm ship neither). | About 2-3 MB of `.a` per target per release, committed to git forever. `go mod vendor` quirks. |
| C. Keep the Go port as an independent implementation | Unchanged | Nothing | Breaks R1: two implementations to review and keep in step. |
| D. Deprecate the Go module; point Go users at the C ABI | n/a | The package | A `retract` plus a notice |

Recommendation: **A.** It keeps R1 and keeps Go's deployment model. The
speed cost is real but bounded: 6.7 ms per receipt is about 150 receipts a
second per core. If R8 chooses the "published second implementation"
route, option C becomes the natural home for that role instead.

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

**Status: accepted by the owner on 2026-09-25: option B.** This is the monoculture trade-off from R1.

| Option | What catches a Rust bug | Cost |
|---|---|---|
| A. Delete every other implementation after parity | `fixtures/cases.json`, the fuzzers, review | Lowest |
| **B. Keep the Java port as a test-only oracle, unpublished** | A, plus differential fuzzing (Jazzer inputs through Java and through Rust, compare verdicts) and the reviewed Java code as a second reading of each rule | Every behaviour change lands twice: Rust, then the oracle. Java is the port the owner already reviews. |
| C. Keep Go published as the second implementation | A, plus a real second implementation in production | Two published implementations to fix in step. It also answers R6. |

Recommendation: **B until 1.0**, then decide again with a year of
differential-fuzzing data. Only the oracle lives under `java/oracle/`
(test scope). The published jar is the binding.

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

## R10. Clock source on `wasm32-unknown-unknown`

**Status: recommended.**

| Option | Verdict |
|---|---|
| A. Core-internal `system_now()` with `js_sys::Date::now()` behind a `js-clock` feature | First choice, replaced 2026-09-25: it puts a wasm-bindgen crate in the core's graph. |
| **A2. A `platform::install_clock` hook that exists only on `wasm32-unknown-unknown`; the wasm adapter installs `Date.now()`** | **Chosen** (SURFACE.md §4.1). No JS dependency in the core, and callers still cannot move the validity instant (THREAT-MODEL §3.5). |
| B. `web-time` crate | The same idea through a dependency last released 2024-03-01. No gain. |
| C. Take `now` as a parameter on the verifiers | Breaks §3.5: a caller could accept an expired chain. |
| D. Leave it | Traps (spike). |

---

## R11. Crypto dependencies and speed

**Status: recommended.**

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
x86-64, aarch64; Solaris x86-64. At about 0.6 MB each the natives add
about 11 MB to the jar (sqlite-jdbc is about 14 MB, rocksdbjni 84 MB).

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
release.

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
| Go `aprv.wasm` | **yes** | The Go module is the git tree at a tag. |
| Kotlin, Python, JS glue | no | Built inside each package build from pinned tools, from a clean checkout. |

Every generator version is pinned in one place. The UniFFI, wasm-bindgen
and cbindgen Dependabot groups must pass the full cross-package
conformance run before merging.

---

## R15. Order of migration

**Status: accepted by the owner on 2026-09-25.**

1. **Python** first: smallest package, lowest risk, maturin is mature, and
   it proves the release pipeline for native wheels.
2. **Java** second: the gate already passed. It carries the Maven Central
   budget, so batch it into one release.
3. **npm** third: the widest runtime matrix. Needs R4 and R5 settled.
4. **Swift** fourth: the hardest packaging (R7).
5. **Go** last: needs R6, and it is the port most likely to become the
   R8 oracle instead.

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
