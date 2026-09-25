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
| Optional examples | **SWIG** `.i` over the C ABI | A mature generator for users of languages we do not package. Not supported packages. |

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

---

## R3. Where binding annotations live

**Status: recommended.**

| Option | For | Against |
|---|---|---|
| A. Annotate core types with `uniffi`, `wasm_bindgen`, ... | Least code | Couples the reviewed core to every generator. The core API drifts toward the lowest common denominator. The brief forbids it. |
| B. Each adapter defines its own mirror types | No shared crate | Four adapters convert dates, bytes and ids four ways, and that is exactly the drift we are removing. |
| **C. One `aprv-surface` crate with binding-shaped types and `cfg_attr` derives** | One model, one JSON view. The core stays clean. | One more crate to review (mechanical). |

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

Recommendation: **A.** A Linux Swift spike (the container had no Swift) is
the first Phase 2 task for Swift, because the SE-0482 audit of Rust's
`libgcc_s`/unwind symbols is unconfirmed.

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

---

## R10. Clock source on `wasm32-unknown-unknown`

**Status: recommended.**

| Option | Verdict |
|---|---|
| **A. Core-internal `system_now()` with `js_sys::Date::now()` on that target, behind a `js-clock` feature** | Chosen. Callers still cannot inject the validity instant (THREAT-MODEL §3.5). One `cfg` in the core. |
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

**Status: recommended** (pre-1.0, so breaking changes are allowed).

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
