# The Route C verifier as JVM bytecode, via Endive's build-time compiler

Date: 2026-09-26. Code, scripts and raw results are in
`2026-09-26-endive-build-time-jvm/`; its `README.md` has the file table and
the commands to reproduce.

The question, from the owner's brief: can the current Rust + OpenSSL
verifier `.wasm` be compiled at build time by Endive into JVM bytecode,
shipped as a normal Java library, and used by a clean Java consumer without
loading native Rust or OpenSSL verifier code?

Labels: TESTED (ran here), DOCUMENTED (read in Endive's documentation, POMs
or Maven Central metadata), EXPECTED (inferred, not run). Nothing under
`rust/`, `java/` or any other production path changed. `DECISIONS.md` is
untouched. The public API is unchanged: the library drives the existing C
ABI (`rust/ffi`) inside the wasm module, as the Node, Go and browser runners
of the wasm bake-off do.

## 1. Verdict: PASS WITH CAVEATS

The whole route works (TESTED):

1. Round 4's Route C template build (`new-c.wasm`: OpenSSL 4.0.2, CMS path,
   the payload read by ASN.1 templates) goes into the
   `endive-compiler-maven-plugin`.
2. The plugin produces JVM bytecode.
3. The bytecode is packaged as a library jar and deployed to a Maven
   repository.
4. A separate Maven project with an empty local repository depends on the
   jar the ordinary way.
5. That project verifies receipts and JWS.

The results match the reference on every row: 1,179 of 1,179 corpus rows
and 5,000 of 5,000 mutants, on JDK 11, 17, 21 and 25. No native code of the
verifier is loaded into the JVM.

The caveats:

- **Java floor 11.** Endive requires Java 11, and the repository's Java
  package promises Java 8. JDK 8 refuses the class files.
- **Speed.** A JWS takes 20 to 29 ms warm, which is 34 to 50 per second on
  one core, below the brief's nice-to-have of 100. A receipt takes 5.9 to
  9.5 ms, 105 to 171 per second. That is 4.6 to 7.5 times slower than V8
  running the same module.
- **One instance per thread.** An instance must not be shared across
  threads. Sharing one corrupted the guest and hung it, without any
  exception.
- **Three jars, not one.** It is one Maven dependency but three jars: ours
  plus Endive's `runtime` and `wasm`.

## 2. Exact versions

`results/versions.txt` has the full list.

- **Repository:** `39c2469` on `plan/one-rust-core`.
- **Artifact:** round 4's `routec-new` build, 2,973,532 bytes, sha256
  `db31279e…919f`. It was built with rustc 1.98.1 for `wasm32-wasip1`,
  with wasi-sdk 34 and OpenSSL 4.0.2 (no-asm).
- **Endive:** `run.endive` 1.1.0, released 2026-09-03. That is the latest
  on Maven Central; the plugin and runtime share one version (DOCUMENTED,
  `results/endive-facts.txt`).
- **Build tools:** Maven 3.9.11, wasm-tools 1.259.0.
- **JDKs:** Temurin 11.0.32.1 (JRE), Temurin 17.0.20.1, OpenJDK 21.0.10
  (Ubuntu), Temurin 25.0.4.1, and Temurin 8u504 for the floor check.
- **Machine:** Linux 6.18, x86_64, 4 cores.

**What Endive is (DOCUMENTED).**

- **Origin:** Endive is the Bytecode Alliance fork of Chicory by Dylibso.
  Endive 1.0 came out on 2026-06-26 and 1.1.0 on 2026-09-03 (the blog on
  endive.run).
- **Coordinates:** they moved from `com.dylibso.chicory` to `run.endive`,
  and the packages from `com.dylibso.chicory.*` to `run.endive.*`. Chicory's
  last release is 1.7.5 (2026-03-24).
- **Java floor:** "Endive requires Java 11 or later" (docs, quick start).
  The POMs set `maven.compiler.release` 11.
- **Runtime modules:** `run.endive:runtime`, whose only non-test dependency
  is `run.endive:wasm`, which has none. Licence Apache-2.0.
- **Build-time modules:** the `endive-compiler-maven-plugin` (goal
  `compile`) depends on `build-time-compiler`, `compiler` and
  `redline-build-time-compiler-experimental`. Those stay on the build side.

## 3. Build architecture (TESTED)

```
Rust core + rust/ffi + OpenSSL 4.0.2 --(round 4 build.sh routec-new: rustc 1.98.1, wasi-sdk 34)--> new-c.wasm
new-c.wasm --(endive-compiler-maven-plugin 1.1.0, goal compile, mvn deploy)--> spike.aprv:aprv-endive:0.0.0-spike.jar
           --> file repository (stands in for Maven Central)
clean consumer (empty local repository) --(one <dependency>)--> aprv-endive + run.endive:runtime + run.endive:wasm
```

- **Library** (`lib/`). The plugin runs with `interpreterFallback` FAIL,
  the default, and `NameSectionMethodPrefixer`. The only hand-written class
  is `AprvWasm`, 160 lines with comments. It supplies the two imports, calls
  `_initialize` and `aprv_init`, and moves bytes in and out of guest
  memory.
- **Compile time.** The compile goal takes about 3 s: `mvn
  generate-sources` minus a bare `mvn validate`, 2.8 to 3.6 s over three
  runs on JDK 17 (`results/build-time.txt`). The whole `mvn deploy` takes
  6 to 16 s.
- **Consumer** (`consumer/`). It has one `<dependency>`, no plugins and no
  toolchain. `scripts/build.sh consumer` builds it with a fresh local
  repository. Its tree is exactly `aprv-endive → runtime → wasm`:
  - The runtime classpath is four jars: `aprv-endive` (1.76 MB),
    `runtime-1.1.0` (0.17 MB), `wasm-1.1.0` (0.21 MB), and the
    `trap-probe` test module.
  - The consumer's local repository holds no `compiler`, no
    `build-time-compiler`, no plugin and no redline artifact.
  - ASM is in that repository only because Maven's own plugins pull it
    (plexus-java, maven-dependency-analyzer). It is never on the
    classpath.
- **What the consumer needs.** It never needs Rust, clang, wasi-sdk,
  OpenSSL, the `.wasm`, the build tree, JNI, JNA or runtime compilation.

## 4. Artifact inspection (TESTED, `results/jar-inspection.txt`)

The jar is 1,762,214 bytes, 5.8 MB unpacked:

| Entry | Count | Bytes | What it is |
|---|---|---|---|
| `AprvModuleMachineFuncGroup_0.class` | 1 | 3,679,226 | every compiled wasm function: 16,959 static methods, one typed method per function (plus the two imports' stubs) and a `call_<index>` wrapper with boxed arguments for each, named after the wasm name section (`bn_mul_comba8_695`, `X509_verify_cert_4161`, the Rust mangled names) |
| `AprvModuleMachine.class` | 1 | 365,689 | the `Machine`: export dispatch and `call_indirect_N` per signature |
| `AprvModuleMachineDispatch_*`, `…Indirect_*` | 26 | about 1.0 MB | dispatch tables by function index, indirect-call tables |
| `AprvModuleMachineShaded.class` | 1 | 49,328 | memory, global and opcode helpers |
| `AprvModule.class` (+ holder) | 2 | 2,945 | generated from `AprvModule.java` (46 lines, the only generated source): `load()` and `create(Instance)` |
| `AprvModule.meta` | 1 | 728,138 | a stripped wasm module, see below |
| `AprvWasm.class` | 1 | 7,566 | our host glue |

- **`.meta` is the only wasm left.** It keeps the types, imports, exports,
  globals, table, element segment and the 673,717 bytes of data segments,
  which are the initial memory contents (OpenSSL's tables and constants).
- **No code survives in it.** Every one of the 8,479 function bodies is
  replaced by a single `unreachable`. The name, producers and
  target-features sections are dropped.
- **The original `.wasm` is not needed at run time.** Nothing reads it;
  `AprvModule.load()` parses `.meta` from the classpath.
- **Import and export adapters.** Only the `Machine` dispatch above is
  generated. The typed `_ModuleExports` and `_ModuleImports` wrappers are
  opt-in (`moduleInterface`) and were not used, because the C ABI is driven
  through `instance.export(name)`.
- **Class-file versions.** All 227 classes on the classpath are Java 11
  (major 55), the generated ones included (`results/java-floor.txt`).
- **No architecture-specific code.** No `.so`, `.dll`, `.dylib` or
  `.jnilib` is in any jar.
- **Portability (EXPECTED).** The same jar should run on Linux x86-64 and
  ARM64, macOS ARM64 and x86-64, and Windows on any Java 11+ JVM. Only
  Linux x86-64 was tested. Redline is the part of Endive that would add
  per-platform native code, and it is off.

**Build-time compilation really happened (TESTED):**

- **The build compiled every function.** The plugin logged "Compiling
  classes for spike.aprv.endive.AprvModule", and `interpreterFallback` FAIL
  did not trigger. No function exceeded the JVM's 64 KiB method limit; the
  largest generated method is 14,274 bytes (`results/method-sizes.txt`).
- **Only compiled code could produce these results.** The runtime has no
  other copy of the instructions: `.meta` bodies are `unreachable`, so an
  interpreter would trap on the first call. It verified 6,179 rows
  correctly.
- **No runtime compiler.** Neither `run.endive:compiler` nor ASM is on the
  consumer's classpath, and no `run.endive.compiler.*` class was loaded
  (`-verbose:class`, JDK 17, 21 and 25).
- **No interpreter.** The generated machine declares a
  `CompilerInterpreterMachine` field for the fallback, but its constructor
  never assigns it (0 `putfield`). `InterpreterMachine` was never loaded.
- **No Redline.** It is not enabled, and no redline artifact is on the
  classpath.

## 5. Correctness (TESTED, `results/parity.txt`, `results/java-tallies.txt`)

Every corpus row goes through the consumer on each JDK. The consumer's
driver is a port of the bake-off's `js/driver.mjs`, with the same row
format. The rows are compared three ways:

1. with round 4's native baseline by verdict (`py/same.py`);
2. byte for byte with round 4's native C ABI build of the same source
   (`new`);
3. byte for byte with round 4's Node run of this very `.wasm`.

Only the endpoint's `request_date*` values (the time of the request) are
masked.

| Run | cases 153 | hostile 811 | algorithms 22 | substrate 193 | 5,000 mutants | Traps |
|---|---|---|---|---|---|---|
| JDK 11, 17, 21, 25 (default memory) | identical | identical | identical | identical | 5,000 identical to native `new` | 0 |
| JDK 25, `ByteArrayMemory` | identical | identical | identical | identical | 5,000 identical | 0 |

- **The one verdict difference.** Against the round-4 baseline, the
  mutants show 4,999 same and 1 differs: `fuzz/1972`. That is round 4's
  known template-reader difference (an empty INTEGER refused), identical to
  the native and Node builds of the same source.
- **Java tallies.** Java-equal is 1,028 of 1,048 in every run, the same as
  the baseline.
- **Import calls.** They match Node exactly: `aprv.clock_now_ms` 463, 214,
  68 and 527 times per corpus, and `aprv.random_get` once per instance.
- **The rows the brief names** (all in `cases.jsonl`):
  - a genuine receipt: `receipt/verify-genuine-sandbox-g5-against-apple-roots`,
    `receipt/verify-genuine-legacy-sha1-chain`;
  - valid JWS: `transaction/verify-shared-sandbox`,
    `app-transaction/verify-shared-sandbox`;
  - bad signature or chain: `receipt/reject-empty-cms-signature` (5),
    `receipt/reject-chain-missing-the-intermediate` (4),
    `transaction/reject-fresh-payload-under-expired-chain` (4);
  - malformed input: `receipt/reject-signer-absent-beside-a-malformed-stranger`
    (9), `transaction/reject-signature-segment-noncanonical` (1).

  The Xcode-signed receipts and JWS, the size-cap rows (3 MiB DER and
  base64 receipts, 3 MiB endpoint bodies, one byte over each cap) and the
  byte-floor receipts (about 1 MB) are among the 1,179 rows, and all are
  identical.

**Host capabilities the instance receives.** Exactly the module's two
imports; no WASI, filesystem, environment, arguments or network:

- `aprv.clock_now_ms` returns `System.currentTimeMillis()` as an f64.
- `aprv.random_get(ptr, len)` bounds-checks the range, fills it from a
  default `SecureRandom` and returns 0.

## 6. Runtime dependencies and native code (TESTED, `results/native-check.txt`)

- **Classpath.** Our jar, `runtime-1.1.0` and `wasm-1.1.0` (plus the trap
  probe).
- **No native loading in the bytecode.** Across all 229 classes (`javap -c
  -p`) there are 0 references to `System.load`, `System.loadLibrary`,
  `Runtime.load`, `java.lang.foreign`, `jdk.internal.foreign`, JNA, jffi,
  jnr or `Unsafe`, and 0 `native` methods.
- **Mapped shared objects** (`/proc/self/maps`). Verifying all of
  `cases.jsonl` adds exactly one, `libzip.so`, and it comes from the JDK's
  own `lib/` directory. The same holds on JDK 17, 21 and 25.
- **`jdk.internal.foreign` classes.** On JDK 21 and 25, `-verbose:class`
  lists a few of them:
  - The four `jdk.internal.foreign.abi.*` classes also load in a JVM that
    never creates an instance, so they are JDK start-up.
  - `MemorySegment$Scope` and `MemorySessionImpl` come from `java.base`'s
    buffer internals.
  - None of them is an FFM call from Endive or from us.
- **What this does not claim.** It covers only the classic bytecode path.
  Endive's optional Redline runners (`redline-runner-experimental`,
  `…-jffi-experimental`) do load native code through FFM or jffi; they are
  not used and not on the classpath.

## 7. Trap test (TESTED, `results/trap.txt`)

A throwaway WAT module (`trap/src/main/wat/trap.wat`) goes through the same
plugin. It has one page of memory and no growth, and runs on JDK 11, 17,
21 and 25:

| Probe | What Java sees |
|---|---|
| `i32.load` at 65,533 | `WasmRuntimeException: out of bounds memory access` |
| `i32.load` at -1 | the same |
| `i32.store` of 4 bytes at 65,534 | the same, and no partial write (the last word still reads 0) |
| `memory.fill` 1,000 bytes at 65,000 | the same |
| `unreachable` | `TrapException: Trapped on unreachable instruction` |
| `i32.div_s` by 0 | `WasmRuntimeException: integer divide by zero` |
| unbounded recursion | `WasmEngineException: call stack exhausted` |

After each probe:

- **The JVM survives.** Every trap arrives as an ordinary Java exception.
- **The instance still answers.** Its memory is intact (`load(100)` still
  returns 42), and a verifier instance created afterwards in the same JVM
  works.
- **Reuse is still not recommended.** The spec allows it, but a trap in the
  verifier would leave Rust or OpenSSL state mid-operation. So the driver
  does what the JS driver does: it discards the instance and creates a new
  one, which costs 2 to 4 ms (§9).

One API wrinkle turned up in the harness. Calling an export with too few
arguments throws a raw `ArrayIndexOutOfBoundsException` rather than an
Endive exception.

## 8. Concurrency (TESTED, `results/concurrency.txt`; DOCUMENTED)

- **Endive's docs** say "`Instance` and `Store` are not thread-safe. Create
  separate instances per thread, or synchronize access externally."
- **Separate instances have separate memories.** Two instances of one
  compiled module allocated the same guest pointer, 1,728,624, and a write
  to one did not show in the other. They are distinct `Memory` objects.
- **One instance per thread works.** Four threads, each with its own
  instance, ran 3 rounds of `cases.jsonl` on JDK 17, 21 and 25, and 2
  rounds of `hostile.jsonl` on JDK 21. That is 1,836 and 6,488 rows, all
  identical to a single-threaded run. There was no shared-state
  interference.
- **One shared instance breaks.** Four threads on one instance, without a
  lock, produced no exception and no JVM crash. Instead the guest
  livelocked: three threads spun inside OpenSSL's `sk_reserve` and
  `dlmalloc` on the shared linear memory until the run was killed after
  8.5 minutes. A wrong answer was also possible.
- **Model:** one instance per worker thread, or a pool of instances used
  exclusively. Pooling is decided later. Creating an instance costs 2 to
  4 ms once the classes are loaded (§9).

## 9. Performance (TESTED, `results/bench.txt`, orientation only)

One thread, one instance, 1,000 warm-up calls, then 500 timed calls of the
same row:

| JDK | Memory | Receipt (g5) mean / median | per s | JWS (`verify-shared-sandbox`) mean / median | per s |
|---|---|---|---|---|---|
| 17 | default (`ByteBufferMemory`) | 9.07 / 9.05 ms | 110 | 28.6 / 27.7 ms | 35 |
| 17 | `ByteArrayMemory` | 6.97 / 6.85 ms | 144 | 23.3 / 22.5 ms | 43 |
| 21 | default | 9.52 / 9.06 ms | 105 | 27.9 / 27.7 ms | 36 |
| 21 | `ByteArrayMemory` | 6.52 / 6.08 ms | 153 | 22.0 / 20.5 ms | 46 |
| 25 | default | 8.71 / 8.54 ms | 115 | 29.4 / 28.1 ms | 34 |
| 25 | `ByteArrayMemory` | 5.86 / 5.69 ms | 171 | 19.9 / 19.2 ms | 50 |
| Node 22, same `.wasm` | V8 | 1.26 ms | 791 | 4.26 ms | 234 |

- **Start-up.** Creating the first instance takes 335 to 380 ms: loading a
  3.7 MB class, parsing `.meta`, `_initialize` and `aprv_init`. Each later
  instance takes 2 to 4 ms. The first verification takes 160 to 360 ms,
  most of it JIT warm-up.
- **Throughput across threads.** Four threads with an instance each ran
  about 900 `hostile` rows per second on four cores.
- **Where the time goes** (`results/profile-jws.txt`, JFR, JDK 21,
  `ByteArrayMemory`). 87% of a JWS is OpenSSL's ECDSA verification in
  generic bignum code (`bn_mul_comba8`, `bn_sub_words`, `bn_sqr_comba8`,
  `BN_nist_mod_256`), which is what a no-asm OpenSSL does. About 20% of
  samples end in Endive's memory accessors (`readInt`, `writeI32`,
  `memoryReadInt`); with the default `ByteBufferMemory` the same code is
  1.2 to 1.5 times slower (table above).
- **The JIT is not the limit.** Only 6 generated methods exceed HotSpot's
  8,000-byte JIT limit (`jws_call`, `printf_core`, serde_json and three
  more), and none of them shows up in the profile.
- **Nothing catastrophic.** Every row finishes, and the 3 MB receipts
  pass. Receipts reach the 100 per second target on every JDK; JWS does not
  (34 to 50 per second).
- **Profiling works.** Stack traces and JFR show the wasm function names
  (Rust mangled or C names with the function index, via
  `NameSectionMethodPrefixer`), without line numbers.

## 10. Problems and blockers

| # | Finding | Attributed to |
|---|---|---|
| 1 | Java 11 floor: the repository's Java package promises Java 8 (the `java-runtime-8` CI job); Endive classes and the generated classes are Java 11 class files, and JDK 8 refuses them | Java version (Endive's documented floor) |
| 2 | JWS 20 to 29 ms, below 100 per second per core; 4.6 to 7.5 times slower than V8 on the same module | Endive (bytecode translation, memory accessors) and our artifact (no-asm OpenSSL bignum code for ECDSA) |
| 3 | The default `ByteBufferMemory` is 1.2 to 1.5 times slower than `ByteArrayMemory`, which the docs recommend "for recent OpenJDK systems"; a library would have to choose one | Endive (default configuration) |
| 4 | A shared instance across threads livelocks silently rather than failing | Endive (documented as not thread-safe) and host usage; the library must enforce one instance per thread |
| 5 | JDK 17 and earlier run with Endive's workaround for a C2 miscompilation (the "JVM JIT bug" post; the upstream fix was integrated in JDK mainline on 2026-04-30); parity on JDK 11 and 17 is clean, but those JDKs depend on the workaround | Java version, Endive |
| 6 | 335 to 380 ms for the first instance in a JVM | Endive (class loading of the generated classes) |
| 7 | Too few export arguments give a raw `ArrayIndexOutOfBoundsException` | Endive (API), our harness |
| 8 | "One Maven dependency" holds; "one physical jar" does not: three jars; shading `runtime` and `wasm` (Apache-2.0) was not tried | Maven packaging |
| 9 | The plugin pulls Redline's experimental build-time artifacts into the build repository even when Redline is off; the consumer never sees them | Maven packaging (build side only) |
| 10 | Nothing needed changing in the `.wasm`, OpenSSL or the imports | none |

**Security model (DOCUMENTED).**

- **Trusted input only.** "The compiler translates Wasm to JVM bytecode
  without post-compilation verification. Only compile Wasm modules you
  trust." For maximum assurance with untrusted code the docs prefer the
  interpreter.
- **What the JVM still checks.** The JVM's own bytecode verifier checks
  type safety of the generated classes when they load. That is not a check
  that they match Wasm semantics.
- **Our case.** The module is built by our own CI from our own source, so
  the trusted-input assumption holds. The attack surface at run time is
  the receipt and JWS bytes, which the compiled code handles like any Wasm
  guest input.
- **Host functions** are the trust boundary. Ours validate the range
  before writing guest memory.
- **Other risks the docs list:** no CPU or memory limits by default, since
  memory can grow to the module's maximum (this module declares none). The
  large-module C2 bug is §10, row 5.

## 11. Reproduction

From a clean checkout, the commands are in the folder's `README.md`:

1. `facts.sh` records Endive's coordinates and documentation lines.
2. `build.sh lib`, `build.sh trap` and `build.sh consumer` build
   everything.
3. `run.sh parity` for JDK 11, 17, 21 and 25, then `java.sh`.
4. `inspect.sh jar`, `inspect.sh methods` and `inspect.sh native`.
5. The Java-floor, trap and concurrency runs.
6. `bench.sh build`, `bench.sh jvm`, `bench.sh node`, `bench.sh
   instances` and `bench.sh jfr`.

The `.wasm` comes from round 4's `scripts/build.sh routec-new`, which needs
the wasm bake-off's toolchains. The reference rows come from round 4's
`parity.sh` runs.
