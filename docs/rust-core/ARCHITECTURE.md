# Target architecture: one Rust core, one aprv.wasm, thin hosts

Status: **target design of the accepted plan, rewritten on 2026-09-28 on
the Wasm-first basis** (R22). The decisions it rests on are in
[DECISIONS.md](./DECISIONS.md), the public contract in
[SURFACE.md](./SURFACE.md), and the isolation argument in
[THREAT-MODEL.md](./THREAT-MODEL.md).

## 1. The shape

```text
                    SECURITY REVIEW BOUNDARY (deep human review)
┌─────────────────────────────────────────────────────────────────────┐
│ rust/          aprv-core: Apple's policy. Pinned roots, chain       │
│                policy, historical time, JWS, receipt attributes,    │
│                caps, base64 rules, JSON depth, Reason, endpoint.    │
│                #![forbid(unsafe_code)]. No ASN.1, CMS, X.509 code.  │
│   │ safe calls                                                      │
│ rust/openssl/  aprv-openssl: FFI to OpenSSL's CMS, X.509, EVP and   │
│                ASN.1 template APIs; payload.c. The only unsafe      │
│                crate below the boundary crates.                     │
│   │ static link                                                     │
│ OpenSSL 4.0.2, upstream C in the trusted base                       │
└───┬─────────────────────────────────────────────────────────────────┘
    │ plain Rust API
┌───▼──────────────────────────┐    ┌──────────────────────────────┐
│ aprv-surface: the 0.7 model  │───►│ aprv-wire: the 0.7 canonical │
│ (three operations, Reason,   │    │ JSON bytes, INIT config JSON │
│ payloads, Failure). No       │    └──────────────┬───────────────┘
│ generator, no serializer.    │                   │
└───┬──────────────────────────┘                   │
    ├──────────────────────────────┐               │
┌───▼──────────────────────────┐ ┌─▼───────────────▼──────────────┐
│ rust/ffi: the C ABI          │ │ aprv-abi → aprv.wasm           │
│ escape hatch, source only,   │ │ wasm32-wasip1, ABI v1,         │
│ class E (the user's choice)  │ │ imports only aprv.random_get   │
└──────────────────────────────┘ └─┬──────────────────────────────┘
                                   │ the same file, one SHA-256
     ┌───────────┬──────────┬──────┼───────────┬───────────┬──────────────┐
     ▼           ▼          ▼      ▼           ▼           ▼              ▼
  Endive      V8 / JSC /  wazero  wasmtime-  WasmKit    wasmtime gem,  aprv-server
  (build-     SpiderMonkey (Go)   py         (Swift)    Wasmtime .NET  (Wasmtime 49,
  time, JVM   (npm)               (Python)              (Ruby, .NET)   own process)
  bytecode)                                                            ├ Java 8 (-wasm)
  Java 11+                                                             ├ PHP (CLI/URL)
  (-wasm)                                                              └ HTTP, Docker

  Java 8+ main artifact: the 0.7 pure-Java BouncyCastle implementation,
  independent of all of the above, maintained, and the live oracle (R33).
```

A fix in `rust/` rebuilds one `aprv.wasm` and reaches every Wasm-hosted
package in the next release. No wrapper carries a parser, a signature
check or a trust decision. The Java implementation is the one deliberate
exception, kept as a second, independent implementation (R25, R33).

## 2. Crates and folders

```text
rust/                         aprv-core; the package keeps its published name,
                              apple-purchase-receipt-verifier (R19)
rust/Cargo.toml               gains [workspace]; exclude gains bindings/** and server/**
rust/openssl/                 aprv-openssl: the OpenSSL adapter (R21)
rust/openssl/payload.c        the receipt payload grammar as ASN.1 templates
rust/bindings/surface/        aprv-surface: the binding-neutral model of the 0.7 API
rust/bindings/wire/           aprv-wire: the 0.7 canonical JSON bytes
rust/bindings/abi/            aprv-abi: the ABI v1 exports, built as aprv.wasm
rust/bindings/abi/wasi-none.c the link-time C file: WASI answered inside the module
rust/server/                  aprv-server: the `aprv` binary (serve, CLI, precompile)
rust/ffi/                     the C ABI, rebased on aprv-surface and aprv-wire
rust/fuzz/                    verify-receipt, verify-transaction, the ABI entry
java/                         one Maven reactor: the main artifact and -wasm (§7.8)
node/ go/ python/ ruby/       thin wrappers over aprv.wasm
dotnet/ php/                  thin wrappers (PHP over aprv-server)
Package.swift, swift/         the Swift wrapper over WasmKit
```

- **aprv-core** is today's crate after R21: the OpenSSL adapter replaces
  `asn1.rs`, `x509.rs`, `cms.rs`, `chain.rs` and `crypto.rs`. Its public
  API is the Rust rendering of the 0.7 API that 0.7.0 already ships.
- **aprv-surface** is the semantic model every boundary shares: the
  three operations, the eight reasons, the payload records, the failure,
  the configuration (a list of DER roots). It depends on the core only,
  and never on a binding generator, a runtime or a wire format
  (SURFACE.md §4).
- **aprv-wire** turns surface values into the 0.7 canonical JSON bytes
  and reads the INIT configuration JSON. The C ABI and `aprv.wasm` both
  use it, so the two boundaries cannot drift apart.
- **aprv-abi** is the ABI v1 export list (§4). It is `unsafe` at the
  boundary only, like `rust/ffi`, and holds no security logic.
- **aprv-server** depends on `wasmtime`, not on the core. It runs the
  released `aprv.wasm` like any other host, so the server cannot
  disagree with the other packages about a verdict.
- One Cargo workspace replaces today's two lockfiles (`rust/` and
  `rust/ffi/`). `rust/fuzz` stays outside it, because it needs nightly.
  cargo-deny's bans for the core (no network, trust-store or generator
  crate) stay per crate, so the server's HTTP stack does not leak into
  the core's graph (§9).

## 3. `aprv.wasm`

**Build.** `aprv-abi` for `wasm32-wasip1`, linked with wasi-sdk's libc,
over OpenSSL 4.0.2 compiled by wasi-sdk with `no-asm` and passed through
`OPENSSL_DIR` (`openssl-src` maps `wasm32-wasi` but not `wasm32-wasip1`).
The two WASIp1 link fixes (`crt1-reactor.o`, wasi-libc's emulation
libraries) come from the substrate and wasm bake-offs
([wasm bake-off §6][wasmbake], [CMS everywhere §1][cms]). rustc, wasi-sdk
and the OpenSSL tarball are pinned by version and SHA-256. The release
builds the module **once**, with no cache, publishes its SHA-256 with the
release, and every package that carries it checks its copy against that
hash (§9).

**Size.** The ABI v1 spike module was 2,952,613 bytes
([ABI v1][abi]); the template-payload module it grew from was 2,973,532 B
raw and 975,767 B stripped and gzipped ([ASN.1 payload §3][payload]).
`wasm-opt` stays out: it saved 25% raw and 12% gzipped, changed no speed
beyond noise, and adds a second optimiser whose output would need
re-proving each release ([wasm speed §4][speed]).

**One import.** The module imports exactly `aprv.random_get(ptr, len)`.
OpenSSL draws random bytes only for EC blinding inside ECDSA verification;
the host fills them from its CSPRNG and bounds-checks the range before it
writes guest memory. A failing `random_get` makes OpenSSL refuse ECDSA
verification: 0 new acceptances over 1,179 rows
([wasm bake-off §10][wasmbake]). The measured modules also imported
`aprv.clock_now_ms`; ABI v1 as planned drops it (§6, R24).

**The link-time C file** (`wasi-none.c`, 74 code lines in the evidence)
defines every WASI function wasi-libc would import, inside the module. In
the shipped build every one of them **traps**, except two:
`random_get`, which forwards to `aprv.random_get`, and `clock_time_get`,
which answers from the `now_ms` of the call in progress (§6). An
unexpected call to a file, directory, environment, argument or exit
function stops the verification instead of taking a path nobody measured;
on the evidence corpus no run called any of them
([wasm bake-off §5][wasmbake]).

**Features.** Core Wasm 2.0 (`lime1`) only: no SIMD, no threads, no
Component Model ([CMS everywhere §2][cms]). Endive's build-time compiler
has no SIMD support ([wasm speed §5][speed]), and one module serves every
host.

## 4. ABI v1

Measured as the four-operation spike of 2026-09-26 ([ABI v1][abi]); the
plan adds INIT and `now_ms` (R23, R24).

```text
_initialize()                                 WASI reactor start, once per instance
aprv_abi_version() -> i32                     == 1
aprv_alloc(len) -> ptr                        0 when impossible
aprv_dealloc(ptr, len)
aprv_call(abi_version, op, ptr, len) -> handle
aprv_result_ptr(handle) -> ptr
aprv_result_len(handle) -> len
aprv_result_free(handle)
```

**Operations.** Numbers are stable and never reused. 0 and every number
not in the table trap.

| Op | Name | Input | Output (UTF-8 JSON, aprv-wire) |
|---:|---|---|---|
| 1 | VERIFY_RECEIPT | `now_ms`, then the `receipt-data` string (standard base64) | `{"verified":true,"payload":<ReceiptPayload JSON>}` or a failure |
| 2 | VERIFY_SIGNED_DATA | `now_ms`, then the compact JWS | `{"verified":true,"payload":"<the signed payload JSON, exactly>"}` or a failure |
| 3 | VERIFY_RECEIPT_ENDPOINT_PRODUCTION | `now_ms`, then the verifyReceipt request body | Apple's response JSON, byte for byte |
| 4 | VERIFY_RECEIPT_ENDPOINT_SANDBOX | as 3 | as 3 |
| 5 | INIT | `{"roots":["<base64 DER>", ...]}` | `{"ok":true}` or `{"ok":false,"message":"..."}` |

A failure is `{"verified":false,"reason":"<0.7 Reason>","message":"..."}`.
Ops 1 to 4 keep the spike's numbers; INIT is new.

- **`now_ms`** is the first eight bytes of every verify op's input: epoch
  milliseconds as a little-endian signed 64-bit integer, followed by the
  UTF-8 text. A prefix keeps a 3 MiB receipt out of a JSON string that
  would have to be escaped and copied again. This layout is the plan's;
  Phase 1 fixes it with the ABI tests.
- **INIT** parses the roots once per instance. An empty list means the
  three Apple roots compiled into the module. A wrapper never sends an
  empty list for a caller's own empty root set: 0.7's `Verifier.create`
  refuses that before INIT (SURFACE.md §2). A root that does not parse is
  `{"ok":false}`, which the wrapper turns into its language's
  configuration error at `create`. A second INIT on one instance traps.
- **A verify op before INIT** is a programmer error and traps. Wrappers
  cannot reach it: they INIT every instance they create.
- **Order of checks in `aprv_call`**: the ABI version first, before any
  other argument is read and before any host import runs; then the
  operation; then the input range. A mismatch branches straight to
  `unreachable` ([ABI v1][abi]).
- **No policy.** No bundle id, environment, app Apple id or device id
  crosses the boundary. The environment in ops 3 and 4 is which of
  Apple's two URLs the endpoint imitates, as in 0.7.
- **Base64 only.** Receipts cross as the `receipt-data` string, decoded
  in the module by the core's strict rule. The 3,145,728-byte cap applies
  to that string, so the largest receipt ABI v1 takes is 2,359,296 bytes
  of DER, as Apple's own endpoint takes base64 ([ABI v1][abi]).

**Lifecycle of one call**, the same in every wrapper:

1. `aprv_alloc(len)`;
2. copy the input into guest memory;
3. `aprv_call(1, op, ptr, len)`;
4. check `aprv_result_ptr`/`aprv_result_len` against the memory size;
5. copy the result out into host memory;
6. `aprv_result_free(handle)`;
7. `aprv_dealloc(ptr, len)`;
8. decode the JSON.

No guest pointer leaves a public call. After a trap the wrapper runs
nothing more in that instance and discards it. The spike's bridges did
exactly this on Node and Endive, and linear memory stayed at 2,097,152
bytes over 2,000 further calls ([ABI v1][abi]).

**Six outcomes, kept distinct.** A wrapper never folds one into another:

| Outcome | Where it comes from | What the caller sees |
|---|---|---|
| Verified | the module's result | the payload (0.7) |
| Verification failure | the module's result | a result with the 0.7 `Reason` |
| Caller misuse | the wrapper's own checks (a null `Config` or `Environment`, an empty root set, a root INIT refuses) | the language's programmer error at `create` or at the call, as in 0.7 |
| ABI mismatch | `aprv_abi_version()` ≠ the wrapper's version, or a trap in `aprv_call` before anything ran | a hard failure at `create` naming both versions ("APRV Wasm ABI mismatch: module=1, caller=N"); never a verdict |
| Trap or internal failure | a guest trap, a runtime error, an out-of-range result pointer, malformed result JSON | `INTERNAL_ERROR` (21009 at the endpoint); the instance is discarded; the cause names the trap |
| Server process failure | `aprv-server` did not answer: start failed, the child died, the connection broke, HTTP 5xx | `INTERNAL_ERROR` (21009 at the endpoint) with a cause of its own type, so it is never mistaken for a trap |

The 0.7 contract holds: the verify methods never throw for any input
(0.7-api.md, Setup). Both failure rows answer `INTERNAL_ERROR` and keep
their category in the cause.

## 5. The instance model (R23, owner Q49 d)

- `Verifier.create(config)` owns a small pool of instances of one
  compiled module. Each instance is INITed once, when it is created, so
  the roots are parsed once per instance.
- One instance serves one call at a time. A shared Endive instance
  livelocked inside OpenSSL's allocator in the spike, with no exception
  ([Endive §8][endive]); the other runtimes' stores are single-threaded
  too.
- A trapped instance is discarded with everything in it. The next call
  takes or creates another.
- Instances die with the `Verifier`. There are no handles in the public
  API and nothing for the caller to free or close.
- **Node:** one instance. JavaScript runs one call at a time per isolate.
- **aprv-server:** a fresh instance and INIT per request by default, so
  nothing from one hostile input reaches the next request. Phase 1
  measures INIT; if it costs more than 10% of a call, the default flips to
  the existing `--lifecycle pool` flag (R31). The spike's fresh lifecycle
  cost about 1.6 ms more per receipt than the pool, which it attributed to
  the guest initialising OpenSSL and its roots on an instance's first call
  ([aprv-server §3][server]); INIT separates that cost from the call.

What an instance costs to create, measured: Endive 335 to 380 ms for the
first, 2 to 4 ms after ([Endive §9][endive]); wasmtime-py 0.4 to 0.6 ms
after the compile ([Python wasmtime][pywt]); WasmKit about 3 ms
([Swift][swift]); Wasmtime .NET 14 to 18 ms for the first and about
0.7 ms after ([.NET][dotnet]); the wasmtime gem 0.1 ms after the compile
([Ruby][ruby]).

## 6. Time (R24, owner Q51 b)

- The wrapper reads the `Config` clock **once per call**, before it looks
  at the input, and passes the value as `now_ms`. The core uses it for
  two things, the 0.7 rule: the chain-validity instant when the receipt
  or JWS carries no usable date, and `request_date` in the endpoint
  response.
- A clock that throws is `INTERNAL_ERROR` (21009 at the endpoint), read
  outside any guard that reports unexpected exceptions on unverified input
  as `MALFORMED`, exactly as Java 0.7's `DefaultVerifier` does.
- The module has **no clock import**. The measured modules imported
  `aprv.clock_now_ms` and called it 463, 214, 68 and 527 times per corpus
  ([Endive §5][endive]); passing `now_ms` in removes that callback and one
  host capability.
- OpenSSL's own `time()` calls come from its DRBG, not from certificate
  checks: the core sets the check time explicitly to the signing instant
  (R21). The link-time C file answers `clock_time_get` from the `now_ms`
  of the call in progress, and with 0 during INIT. Whether OpenSSL's DRBG
  reads the clock during INIT at all is unmeasured; Phase 1's gate is
  that the module imports only `aprv.random_get` and answers the corpus
  as before.
- No public API takes a per-call time. 0.7 dropped it; ABI v1 carries
  `now_ms` per call anyway, so a per-call override later is additive.
- Callers still cannot move the validity instant of an input that
  carries its own date, which is THREAT-MODEL §3.5 of the root threat
  model.

## 7. Hosts

Each host chapter names the runtime, how it holds the instance model,
what it supplies for `aprv.random_get`, and what was measured. Every host
ran the 6,179 rows byte-identically to Node and passed 37 of 37 ABI and
facade tests unless a line says otherwise.

### 7.1 Endive: Java 11+ in the `-wasm` artifact

- Endive 1.1.0 (`run.endive`, Apache-2.0, the Bytecode Alliance fork of
  Chicory) compiles `aprv.wasm` into JVM bytecode **at build time**
  through `endive-compiler-maven-plugin`, with `interpreterFallback`
  FAIL. The consumer's classpath holds our jar plus `run.endive:runtime`
  (0.17 MB) and `run.endive:wasm` (0.21 MB); no compiler, no interpreter,
  no native code: 0 native-loading calls across 229 classes
  ([Endive §3, §4, §6][endive]).
- The spike's library jar was 1,762,214 bytes. It keeps a stripped
  `.meta` module with the data segments and every function body replaced
  by `unreachable` ([Endive §4][endive]).
- Memory: `ByteArrayMemory`, 24 to 42% faster than the default with
  byte-identical output ([wasm speed][speed]).
- `aprv.random_get` from `SecureRandom`, range-checked before it writes.
- A trap reaches Java as `WasmRuntimeException`, `TrapException` or
  `WasmEngineException`; the JVM survives ([Endive §7][endive]). The
  wrapper discards the instance.
- Speed through ABI v1 on JDK 21: 154.7, 323.0 and 482.2 g5 receipts and
  52.6, 101.9 and 166.8 JWS per second at 1, 2 and 4 threads
  ([ABI v1][abi]). The first instance takes 335 to 380 ms.
- Endive's compiler does no post-compilation verification ([Endive
  §10][endive]). The guard is CI: the corpus through the built jar, byte
  for byte against native, on every change (§9).
- JDK 17 and earlier run with Endive's workaround for a C2 miscompilation;
  parity there was clean ([Endive §10, row 5][endive]).

### 7.2 wasmtime-py: Python

- wasmtime-py at or above the current major, with no pin to one major
  (R27). 49.0.0 installed 32.2 MB ([final Python round][pyfinal]).
- **The plain `.wasm`, compiled at start.** The first `Verifier` in a
  process compiles the module with Cranelift: 934 ms on 4 CPUs and
  2,923 ms on one ([runtime options][pyopt]); every later `Verifier` takes
  0.4 to 0.6 ms ([Python wasmtime][pywt]).
- **Wasmtime's `Config.cache` is on by default.** A warm start takes 95 ms
  on 4 CPUs ([runtime options][pyopt]). The rules (THREAT-MODEL.md §8):
  - the default directory is the user's own cache directory;
  - an environment variable overrides the path (its name is fixed in
    Phase 5);
  - a directory that is read-only, or not the user's own, turns the cache
    off silently, and the process compiles at start.
- **AWS Lambda and other fresh containers** pay the compile on every new
  container, about 3 s on one vCPU (2,923 ms, [runtime options][pyopt]).
  The Python README says so on its first screen.
- **Winch** halves the compile (468 ms on 4 CPUs, 834 ms on one) and halves
  the speed; wasmtime-py 49 reaches it only through a private call. It is
  a later improvement once wasmtime-py exposes it
  ([runtime options][pyopt]).
- The host functions are defined once, on a process-wide `Linker`. That
  avoids the handle-table race of wasmtime-py 49.0.0, which returned
  another function's value 2 times in 190 rounds when host functions were
  created per store; upstream fixed it after 49.0.0 (wasmtime-py#344)
  ([Python wasmtime][pywt]).
- **Threads do not scale** past two in wasmtime-py: 583, 946 and 566 g5
  per second at 1, 2 and 4 threads, against 595, 1,123 and 2,259 with
  processes ([Python wasmtime][pywt]). Python deployments use worker
  processes (gunicorn, uvicorn) with one `Verifier` each. The pool still
  gives each thread its own instance.
- `aprv.random_get` from `os.urandom`/`secrets`.
- **Platforms without a wasmtime-py wheel** fail at install with a
  message that points to `aprv-server` or the C ABI (R28). Today the
  failure would come at import: pip picks wasmtime-py's `py3-none-any`
  wheel, which holds only the Windows x86_64 DLL
  ([Python wasmtime][pywt]). Phase 5 moves it to install time
  (SUPPORT-MATRIX.md §3).

### 7.3 wazero: Go

- The module path and package stay. `aprv.wasm` is embedded with
  `//go:embed`; the Go module is published from a git tag, so the file is
  committed under `go/`, and CI rebuilds it and fails when its SHA-256
  differs from the release build.
- One compiled module per process (`sync.Once`), a `sync.Pool` of
  instances, `aprv.random_get` from `crypto/rand`. Any other import is
  refused at instantiation.
- It stays cgo-free, so `CGO_ENABLED=0`, cross-compilation and `FROM
  scratch` keep working. The CMS module answered 1,179 of 1,179 rows on
  wazero 1.12.0 ([CMS everywhere §2][cms]); an OpenSSL module took
  2,495 µs per receipt and 8,110 µs per JWS there on the PKCS7 path
  ([substrate bake-off §13][substrate]). ABI v1 on wazero is measured in
  Phase 4.
- The floor stays as today (R30) if the wazero release we need builds on
  it; wazero 1.12.0 fetched a Go 1.25 toolchain in the spikes
  ([rust-core spikes, Method][spikes]). Phase 4 checks, and raises the
  floor to wazero's requirement if it must.
- An opt-in `-tags aprv_native` build over the C ABI stays possible on
  request (R6). It is class E, the user's choice, and nothing is built for
  it until someone asks.

### 7.4 JavaScript: native WebAssembly

- One npm package, zero runtime `dependencies`. It carries `aprv.wasm`, a
  hand-written façade and a hand-written `index.d.ts`: no wasm-bindgen,
  no Emscripten glue, no jco output. The Route C package of this shape was
  1,001,740 bytes and passed on Node, Bun, Deno, Chromium, Firefox,
  WebKitGTK, a `node --permission` run and `wrangler dev --local`
  ([CMS everywhere §2][cms]).
- One instance per module load. The façade supplies `aprv.random_get`
  from `crypto.getRandomValues` in 65,536-byte chunks, never
  `Math.random`, and refuses any other import. It decodes strings with
  `TextDecoder` and `ignoreBOM: true` ([wasm bake-off §8][wasmbake]).
- A trap (`WebAssembly.RuntimeError`) drops the instance, the next call
  instantiates a fresh one, and the call answers `INTERNAL_ERROR`.
- `exports` conditions load the module the way each runtime needs:
  workerd and Vercel Edge import the `.wasm` as a static module (workerd
  refuses `WebAssembly.compile(bytes)`, [rust-core spikes][spikes] row 8);
  Node reads it from disk and compiles it synchronously; browsers and Deno
  load it with top-level `await`. The `.` export stays synchronous and
  `./web` keeps returning Promises, as in 0.7.
- 64-bit ids stay strings, as the 0.7 Node port has them.
- Speed through ABI v1 on Node 22: 1,343 µs per g5 and 4,819 µs per JWS
  ([ABI v1][abi]).
- Memory: a hostile 3 MiB receipt of tiny attributes peaked at 145 MiB in
  Node against 67 MiB for a tiny one ([ASN.1 payload §3][payload]).
  Phase 4 measures it in workerd, whose isolate limit is 128 MB.
- Runtimes kept: Node 20/22/24/26, Bun, Deno, workerd, Vercel Edge through
  `@edge-runtime/vm`, Chromium, Firefox and WebKit. Fastly Compute JS and
  Akamai EdgeWorkers are dropped: neither runs WebAssembly (R5).

### 7.5 WasmKit: Swift

- WasmKit 0.4.0, an interpreter with no JIT, lazy translation on first
  call ([Swift][swift]). It declares `swift-tools-version:6.3` and
  `platforms: [.macOS(.v15), .iOS(.v18)]`, which sets the Swift floors
  (R30).
- `Engine` and `Module` are `Sendable` and shared; stores and instances
  are per thread. `aprv.random_get` from `SystemRandomNumberGenerator`.
- **Every range is checked before memory is touched.** WasmKit's
  `Memory.withUnsafe*BufferPointer` stops the whole process with a
  precondition failure on an out-of-range access instead of throwing, so
  the wrapper checks each pointer and length against `byteCount` first
  ([Swift][swift]). A trap surfaces as a Swift `Trap` error.
- Speed: 13.3 ms per g5 (75 per second) and 54.7 ms per JWS (18.3 per
  second) on one thread; four threads reach 308 and 67 per second
  ([Swift][swift]). The JWS is 1.7 to 1.9 times the floor per core, the
  thinnest margin of any host.
- `aprv.wasm` ships as a package resource. SwiftPM builds from git, so
  the file is committed and CI checks its hash like Go's.
- iOS: declared by WasmKit and expected to work without JIT entitlements;
  not built. Linux and macOS are the tested targets.

### 7.6 Ruby and .NET: Wasmtime bindings

**Ruby** runs the `wasmtime` gem (48.0.1 in the evidence, prebuilt for
Ruby ≥ 3.3 on Linux glibc and musl, macOS and Windows, x86_64 and
aarch64).

- The facade gem was 977 KB, pure Ruby plus `aprv.wasm`; RubyGems picked
  the prebuilt native gem, so no Rust toolchain was needed
  ([Ruby][ruby]).
- Every export is wrapped with `to_func(gvl: false)`, each thread using
  its own store. With the GVL held, threads do not scale at all (716, 666
  and 699 g5 per second at 1, 2 and 4 threads); released, 4 threads reach
  2,358 g5 and 746 JWS per second ([Ruby][ruby]).
- Instances are handed out through a pool or a thread-local, never
  through a variable a closure can capture: the spike's first harness
  shared one verifier across threads that way by accident.
- Compile at start 1.22 to 1.35 s; later verifiers 0.1 ms.
  `aprv.random_get` from `SecureRandom`.

**.NET** runs the `Wasmtime` NuGet package (48.0.2 in the evidence).

- The facade multi-targets netstandard2.0 and net8.0; it ran on .NET 8
  and .NET 10. netstandard2.0 compiles; .NET Framework loading the native
  library is untested ([.NET][dotnet]).
- `Engine`, `Module` and a `Linker` holding the host function are
  process-wide; `Store` and `Instance` are per thread. Four threads reach
  2,475 g5 and 669 JWS per second.
- The package ships no `linux-musl-*` library; on Alpine the `linux-x64`
  library needs glibc and is expected to fail without `gcompat`
  ([.NET][dotnet]). Alpine .NET users take `aprv-server`.
- Compile at start 0.92 to 0.98 s. `aprv.random_get` from
  `RandomNumberGenerator`.

### 7.7 aprv-server

One Rust binary, `aprv`, built on axum and tokio with Wasmtime 49
**runtime-only**: Cranelift, Winch, the cache, the Component Model and
every other optional feature are off. The release precompiles
`aprv.wasm` to a Cranelift `.cwasm` for an **explicit baseline target**
per platform and embeds it ([aprv-server §2][server]). The binary has no
base64, CMS, JWS, certificate or policy code: a route or command picks
the operation and passes the bytes through the ABI lifecycle (§4).

- **Why a precompiled module here.** Runtime-only Wasmtime starts in
  9.8 ms instead of 900 ms, idles at 20.7 MiB instead of 115.6 MiB, and
  is 3.58 MB gzipped instead of 5.07 MB, at the same verification speed
  ([aprv-server §2][server]). `Module::deserialize` runs native code
  without validating it, so the binary deserializes only the bytes
  embedded at build time; the runtime-only build refuses a `.wasm`
  outright.
- **Modes.**
  - `aprv serve`: `POST /v1/receipt/verify`, `/v1/signed-data/verify`,
    `/v1/verify-receipt/production`, `/v1/verify-receipt/sandbox`,
    `GET /healthz`, `GET /readyz`. Every verification result is HTTP 200
    with the module's JSON. A trap is 500 `WASM_TRAP`, an ABI fault 500
    `ABI_ERROR`, a lost worker 500 `INTERNAL_ERROR`, a body over
    3,145,728 bytes 413, a missing or wrong `X-Aprv-Token` 401 when a token
    is configured.
  - `aprv serve --managed`: the child of a JVM (§7.8). It binds
    `127.0.0.1:0` whatever `APRV_LISTEN` says, reports its port as one
    stdout line, reads a 256-bit token as its first stdin line, and exits
    on stdin EOF ([aprv-server §6][server]).
  - The one-shot CLI: `aprv verify-receipt`, `aprv verify-signed-data`,
    `aprv verify-receipt-endpoint <production|sandbox>`. It reads stdin
    (up to 3 MiB), runs one operation in one fresh instance, writes the
    JSON and exits: 0 for any result, 3 for input too large, 70 for a
    trap, ABI fault or load failure. About 12 ms per process
    ([aprv-server §5][server]).
- **Binding.** `127.0.0.1` unless `APRV_LISTEN` says otherwise, in and out
  of Docker.
- **Limits.** 256 MiB of linear memory and one instance per store
  (`StoreLimits`, `trap_on_grow_failure`); a worker semaphore of N
  concurrent verifications, N = CPU count; the 3 MiB body cap. A guest time
  limit (epoch interruption) is open (THREAT-MODEL.md §5).
- **Lifecycle.** A fresh store and instance, INITed, per request; `--lifecycle
  pool` keeps instances and destroys one on any trap or ABI error, never
  sharing one between two requests (§5).
- **The configuration a host passes.** The `Config` of a Java or PHP
  caller travels with the call: the per-call `now_ms` in a request header
  or CLI argument, and the roots once, at start (the managed child reads
  them after the token; a standalone server takes them from its own
  configuration and serves their fingerprints so a client can refuse a
  mismatch). The names are fixed in Phase 2.
- **Linux: fully static musl** for x86_64 (static-pie) and aarch64, with
  musl's own malloc. Neither has an INTERP header or a NEEDED entry; both
  run from an empty chroot and inside Alpine. They are 1.3% larger
  stripped than glibc and 6 to 8% slower per server CPU-second; the corpus
  matches the glibc server row for row ([static musl][musl]).
- **`cli-fast-exit`.** Wasmtime deregisters the module's unwind info one
  FDE at a time under LLVM libunwind, which a static musl binary links,
  and libunwind makes that quadratic in the 13,093 FDEs: 55 ms of teardown
  after the verdict. Wrapping the runtime in `ManuallyDrop` in the
  one-shot path brings the musl CLI's exit to 15.2 ms on 4 CPUs
  ([static musl §3][musl]). macOS is expected to show the same delay.
- **macOS and Windows** binaries ship on GitHub Releases for x86_64 and
  arm64; they have not been built yet (MIGRATION.md, Phase 2).
- **Docker.** A multi-stage build: the first stage checks the module's
  SHA-256, precompiles and builds the binary; the second is a distroless,
  non-root image pinned by digest, entrypoint `aprv serve`. Inside the
  container the server listens on `127.0.0.1:8080` until `APRV_LISTEN` is
  set, so a published port reaches nothing by accident. Published to GHCR
  and, once the owner creates the namespace and token, Docker Hub. The
  image has not been built yet ([aprv-server §8][server]).
- **Exotic CPUs** where Wasmtime has no compiler (ppc64le, loongarch64,
  32-bit): open. Pulley ran 4.6 JWS per second and Wasmi 2.0 12.5 on the
  same machine ([execution modes][modes]); nothing is decided.

### 7.8 Java: two artifacts

**`io.github.emindeniz99:apple-purchase-receipt-verifier`** (main): the
0.7 pure-Java implementation over BouncyCastle, Java 8+, unchanged in API
and kept maintained. It is the independent implementation and the live
oracle (R33). Its deprecation is decided later.

**`io.github.emindeniz99:apple-purchase-receipt-verifier-wasm`**: Java 8+,
the same package and class names as the main artifact, the same `Config`
(exactly 0.7's), and two engines.

```java
Verifier v1 = Verifier.create(config);                    // Endive on Java 11+, the server on Java 8
Verifier v2 = Verifier.create(config, Engine.endive());
Verifier v3 = Verifier.create(config,
        Engine.server(ServerSource.url(uri, token),
                      ServerSource.maven(),
                      ServerSource.github())
              .cacheDirectory(path));
```

- **Engine choice is programmatic and explicit.** The artifact reads no
  system property and no environment variable of ours. Java 11+ may choose
  the server engine too. `Engine.endive()` on Java 8 fails at `create`.
- **Class files.** The façade, the engine API and the server client are
  Java 8 bytecode. Endive's generated classes and its runtime are Java 11
  bytecode (major 55, [Endive §4][endive]) and load only when the Endive
  engine is chosen.
- **`ServerSource`**, tried in the order the user gives; the first that
  works wins:

| Source | What it does |
|---|---|
| `url(uri, token)` | an `aprv serve` the user runs (a sidecar, a Docker service); the JVM starts nothing and needs no writable or executable directory |
| `executable(path)` | starts that binary as `aprv serve --managed` and supervises it; nothing is extracted |
| `maven()` | the platform classifier jar on the classpath (R26); the expected SHA-256 is inside the `-wasm` jar |
| `github()` | downloads our release asset for this platform over HTTPS; the SHA-256 is inside the jar |
| `download(url, sha256)` | the user's mirror, checked against the given hash |

  `Engine.server()` with no sources means `[maven, github]`. A binary
  whose hash differs from the pin is never made executable; the source
  fails and the next is tried. When none works, `create` throws with each
  source's reason. Extracted and downloaded binaries live in the cache
  directory: owner-only, written as a temporary file, hashed while it
  streams, made executable and renamed to `aprv-<sha256>` only on a
  match, and hashed again before every start, one download per machine
  under a file lock ([aprv-server §6][server]). The default directory is
  fixed in Phase 3.
- **Managed mode**, tested on Temurin 8: loopback `127.0.0.1:0`, a fresh
  256-bit `SecureRandom` token on the child's stdin (never argv or the
  environment), supervision, restart after a crash (the next call pays
  18.7 ms), no restart after 10 deaths within a minute, and no orphan:
  `close()`, `System.exit` and `kill -9` of the JVM all end the child
  ([aprv-server §6][server]). A host whose cache directory is mounted
  `noexec` uses `url` or `executable`.
- **The client** sends each request in one write with `TCP_NODELAY`;
  `HttpURLConnection` costs about 1.5 ms extra per POST
  ([rust-core spikes, Sidecar][spikes]). A g5 call from Java 8 took
  3.87 ms mean and 3.71 ms p50; 258 per second on one thread, 719 on four
  ([aprv-server §6][server]).
- **Classpath guard.** Both artifacts ship a marker resource; each façade
  fails fast at startup when it finds both. The Gradle module metadata
  declares a capability conflict between them, and the READMEs say to
  depend on exactly one.
- **Maven Central** carries two classifier jars of the static musl
  server, `linux-x86_64` and `linux-aarch64`, attached to the `-wasm`
  artifact (R26). A classifier cannot replace the main jar: it shares the
  artifact's POM and dependencies, which is why the two implementations
  have two artifactIds. macOS and Windows binaries come from GitHub
  Releases.
- `Config.runtimeProbe` stays in the API. What the `-wasm` artifact probes
  at `create` (the engine instantiating and INITing one instance) is fixed
  in Phase 3.

### 7.9 PHP

- A PHP 8.2 façade (`verifyReceipt`, `verifySignedData`,
  `verifyReceiptEndpoint`) over two transports: the one-shot `aprv` CLI
  per call by default, through `proc_open` with an argv array and no
  shell; or a server URL the user configures, over one keep-alive curl
  handle ([aprv-server §7][server]).
- Measured: 11.6 ms per g5 through the CLI and 3.56 ms over HTTP; a
  200-row slice of the corpus matched Node on both.
- **`aprv install`**, a command the Composer package ships, downloads the
  binary for this platform from GitHub Releases, checks it against the
  SHA-256 pinned in the package, and installs it where the façade looks.
  Nothing downloads at request time.
- Published from the root `composer.json` to Packagist once the owner
  submits the repository (BOOTSTRAP.md).

### 7.10 The C ABI

`rust/ffi` stays: a `cdylib` and `staticlib` with a cbindgen header, now
over `aprv-surface` and `aprv-wire`, so its JSON is the same bytes
`aprv.wasm` returns. It is the escape hatch for a language with no host
above: C, C++, Elixir, or a platform no Wasm runtime reaches. It runs
OpenSSL and the core as native code in the caller's process (class E),
which is the caller's choice. 0.8.0 ships it as source, as today;
prebuilt archives stay ROADMAP's "C ABI phase 2" decision. OpenSSL is
linked statically, `OPENSSL_CONFIG_DIR` points at a path that does not
exist, and the adapter never loads a config file or a default trust path
([substrate bake-off §7][substrate]).

### 7.11 crates.io

The core gets its first publish when something needs it (R19). The
adapter crate publishes first. Until `openssl-sys` accepts `openssl-src`
400.x, a crates.io user gets OpenSSL 3.x from the vendored feature or the
system's OpenSSL, since our `[patch.crates-io]` applies only inside this
workspace ([CMS everywhere §1][cms]).

## 8. Documentation

- Each package README keeps install, a quick start and the 0.7 checklist,
  plus what is particular to its host: the Python compile and cache, the
  Java engine choice and `noexec` directories, PHP's `aprv install`,
  workerd's static import.
- Doc comments on `aprv-surface` are the reference text; each wrapper's
  API docs are written from it by hand and reviewed with the wrapper.

## 9. Invariants and how CI holds them

| Invariant | Enforced by |
|---|---|
| One Rust implementation under eight languages | A CI job greps the non-Java wrappers for crypto, X.509 and ASN.1 APIs (`node:crypto`, `crypto.subtle`, `cryptography`, `crypto/x509`, `System.Security.Cryptography.Pkcs`, `openssl_*`, `OpenSSL::`, swift-crypto, ...) and fails on a hit outside tests |
| The Java implementation stays independent | The main artifact depends on no Rust artifact; the `-wasm` module shares its API, not its code (R33) |
| No hand-written ASN.1, CMS or X.509 in the core (R21) | `tools/check-layering.mjs` fails on a module named `asn1`, `x509`, `cms`, `chain` or `crypto` in `rust/src`, an ASN.1, X.509 or signature crate in the core's graph, or a call to `ASN1_get_object` in the adapter |
| `unsafe` only at the edges | `#![forbid(unsafe_code)]` in the core, the surface and the wire crate; `unsafe` only in `aprv-openssl`, `aprv-abi`, `rust/ffi` and `aprv-server` (for `Module::deserialize`), each block with a `// SAFETY:` comment |
| `aprv.wasm` imports exactly `aprv.random_get` | CI lists the module's imports with `wasm-tools` and fails on anything else |
| `aprv.wasm` takes no unmeasured path | Every change runs the corpus through a host whose import object traps on anything unexpected, with the module's own WASI stubs trapping; any trap or any row that differs from native fails |
| One `aprv.wasm` everywhere | The release builds it once; every package's copy (npm, Go, Swift, PyPI, RubyGems, NuGet, the Endive input, the server's `.cwasm` input) is checked against its published SHA-256; the committed Go and Swift copies are rebuilt in CI and diffed |
| ABI v1 holds | The 33 mandatory ABI tests plus each facade's own run on every host on every change |
| Same verdicts everywhere | Every host runs all 311 `fixtures/cases.json` cases as one test each; the `-wasm` artifact runs them once per engine; the main Java artifact runs them too (SURFACE.md §6) |
| Endive answers as native | The corpus (1,179 rows plus 5,000 mutants) through the built `-wasm` jar on every change, byte for byte against native, on Linux x64 and arm64, macOS arm64, Windows x64 and arm64; s390x under QEMU before each release |
| One Java artifact per classpath | A test puts both jars on one classpath and asserts the guard's failure; a Gradle build that requests both fails at resolution |
| No ambient OpenSSL state | The isolation test plants a root in `SSL_CERT_FILE` and `SSL_CERT_DIR` and a hostile `OPENSSL_CONF`, and asserts they are ignored ([substrate bake-off §7][substrate]) |
| Pinned roots only | Root `certs/` stays canonical; `rust/certs` is the copy compiled into the core; the Java artifact keeps its constants. `check-cert-copies.mjs` checks what remains |
| Caps in one place | The core owns every bound of the 0.7 table; wrappers add none. `aprv-server` adds only the HTTP body cap, equal to the receipt cap |
| Precompiled code is only what we built | `aprv-server` deserializes only its embedded `.cwasm`; no host loads a `.cwasm` from anywhere else; wasmtime-py's cache follows THREAT-MODEL.md §8 |
| Artifacts are what CI built | Publish jobs never cache. `aprv.wasm`, every server binary and every classifier jar get a SHA-256 and a build-provenance attestation. Post-publish smoke installs from the real registries |
| Licences ship with the code | Every package that carries `aprv.wasm` or a server binary ships OpenSSL's licence and NOTICE, wasi-libc's and Rust std's texts; the server adds Wasmtime's |
| Floors are tested | Each floor in SUPPORT-MATRIX.md keeps a CI leg, the Java 8 server engine on a real Java 8 JVM |

[wasmbake]: ../evidence/2026-09-26-wasm-architecture-bakeoff.md
[cms]: ../evidence/2026-09-26-openssl-cms-everywhere.md
[abi]: ../evidence/2026-09-26-wasm-abi-v1.md
[payload]: ../evidence/2026-09-26-openssl-asn1-payload.md
[speed]: ../evidence/2026-09-26-wasm-speed.md
[endive]: ../evidence/2026-09-26-endive-build-time-jvm.md
[server]: ../evidence/2026-09-26-aprv-server.md
[musl]: ../evidence/2026-09-27-static-musl-server.md
[pywt]: ../evidence/2026-09-26-python-wasmtime.md
[pyopt]: ../evidence/2026-09-27-python-runtime-options.md
[pyfinal]: ../evidence/2026-09-27-python-runtime-final.md
[modes]: ../evidence/2026-09-27-wasm-execution-modes.md
[swift]: ../evidence/2026-09-26-swift-wasmkit.md
[ruby]: ../evidence/2026-09-26-ruby-wasmtime.md
[dotnet]: ../evidence/2026-09-26-dotnet-wasmtime.md
[substrate]: ../evidence/2026-09-26-security-substrate-bakeoff.md
[spikes]: ../evidence/2026-09-25-rust-core-spikes.md
