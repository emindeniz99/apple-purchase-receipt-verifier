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

Decision: keep UniFFI on the Java 8 floor, without a façade to start (R13). Revisit JNI
if users object to the `kotlin-stdlib`/`jna` dependencies. Revisit FFM
when the floor reaches 22.

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

**Status: recommended** (the brief: "platform compatibility must never
force duplicated security logic").

- **Fastly Compute JS:** StarlingMonkey builds SpiderMonkey without a JIT,
  and the JS reference lists no `WebAssembly` object. Today CI tests
  `/web` there through js-compute-runtime and viceroy.
- **Akamai EdgeWorkers:** V8 runs with WebAssembly removed. Claimed today,
  never tested.

Options: keep the pure-TypeScript `/web` implementation for these two (a
second implementation, rejected by R1), or drop both claims.

Recommendation: **drop both claims** in the npm README and SUPPORT-MATRIX,
and delete the `node-runtimes-fastly` job. Fastly users who write Rust can
depend on the crates.io crate from a Fastly Rust service; the core builds
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

**Status: owner-stated** (brief §22: "unpublished → remove").

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

**Status: recommended.**

| Target | JVM | Python | Swift | C ABI | npm / Go |
|---|:-:|:-:|:-:|:-:|:-:|
| linux x86_64 glibc | ✅ | ✅ manylinux_2_17 | ✅ | ✅ | wasm, no native |
| linux aarch64 glibc | ✅ | ✅ | ✅ | ✅ | |
| linux x86_64/aarch64 musl | ✅ (override, see ARCHITECTURE §6.1) | ✅ musllinux_1_2 | ❌ | ✅ | |
| macOS arm64 / x86_64 | ✅ | ✅ | ✅ XCFramework | ✅ | |
| Windows x86_64 | ✅ | ✅ | n/a | ✅ | |
| Windows arm64 | ✅ | ✅ | n/a | ✅ | |

- **Tier 2 targets (added 2026-09-25).** Today's pure-Java jar runs on any
  JVM, including IBM Power and Z, where the eight targets above would stop
  working. JNA, sqlite-jdbc and zstd-jni ship 18 to 28 platforms in one
  jar (evidence row 20). The JVM jar and the C ABI archives add, as tier 2:
  `linux-ppc64le`, `linux-s390x`, `linux-riscv64`, `linux-arm` (armv7),
  `linux-x86`, `win32-x86` and `freebsd-x86-64`. Cross-compiled, smoke-tested
  under QEMU where a runner doesn't exist, about 0.6 MB each in the jar. A
  platform without a bundled library gets a clear error that names the
  missing target and the `uniffi.component.<namespace>.libraryOverride`
  property for a library the user built.
- One fat jar, selected at runtime, like JNA and sqlite-jdbc: no classifier
  for users to choose. Python wheels, the SwiftPM artifact bundle and npm
  (wasm) select automatically already.
- Build on native runners where GitHub provides them (ubuntu, ubuntu-arm,
  macos, windows, windows-arm). Use `cargo-zigbuild` only for musl and old
  glibc.
- Every artifact gets a SHA-256 and `actions/attest-build-provenance`. The
  repository has no attestation step today. Publish jobs keep the no-cache
  rule.
- Release builds pin the toolchain (`rust-toolchain.toml`) and remap paths,
  so a second build can reproduce the hash.

---

## R13. How much of today's API survives

**Status: accepted by the owner on 2026-09-25: no Java façade to start.**
Java uses the UniFFI-generated API directly: `null` for "use Apple's roots",
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

**Status: recommended.**

1. **Python** first: smallest package, lowest risk, maturin is mature, and
   it proves the release pipeline for native wheels.
2. **Java** second: the gate already passed. It carries the Maven Central
   budget, so batch it into one release.
3. **npm** third: the widest runtime matrix. Needs R4 and R5 settled.
4. **Swift** fourth: the hardest packaging (R7).
5. **Go** last: needs R6, and it is the port most likely to become the
   R8 oracle instead.

Each step is its own release. See [MIGRATION.md](./MIGRATION.md).

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
