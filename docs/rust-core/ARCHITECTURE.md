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
│ (three operations, Reason,   │    │ JSON bytes, init config JSON │
│ payloads, Failure). No       │    └──────────────┬───────────────┘
│ generator, no serializer.    │                   │
└───┬──────────────────────────┘                   │
    ├──────────────────────────────┐               │
┌───▼──────────────────────────┐ ┌─▼───────────────▼──────────────┐
│ rust/ffi: the C ABI          │ │ aprv-abi → aprv.wasm           │
│ escape hatch, source only,   │ │ wasm32-wasip1, canonical ABI   │
│ class E (the user's choice)  │ │ (WIT), imports only random-get │
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
rust/bindings/abi/            aprv-abi: the canonical-ABI exports, built as aprv.wasm
rust/bindings/abi/wit/aprv.wit the interface: the contract every host binds (§4)
rust/bindings/abi/wasi-none.c the link-time C file: WASI answered inside the module
rust/bindings/wire/schema/    JSON Schema 2020-12 for the wire shapes (§4, R34)
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
  and reads `init`'s configuration JSON. The C ABI and `aprv.wasm` both
  use it, so the two boundaries cannot drift apart. Its three shapes are
  described by JSON Schema 2020-12 files that CI validates every corpus
  answer against (R34).
- **aprv-abi** is the guest side of the canonical ABI (§4): the WIT file,
  wit-bindgen's generated glue, and four function bodies that call the
  surface. It is `unsafe` at the boundary only, like `rust/ffi`, and holds
  no security logic.
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

**Size.** The canonical-ABI core module of the final round was
2,967,116 bytes raw, 2,713,063 stripped and 905,373 stripped and gzipped
([canonical ABI final][cabifinal]); the ABI v1 spike module was 2,952,613
bytes ([ABI v1][abi]) and the template-payload module it grew from was
2,973,532 B raw and 975,767 B stripped and gzipped
([ASN.1 payload §3][payload]).
`wasm-opt` stays out: it saved 25% raw and 12% gzipped, changed no speed
beyond noise, and adds a second optimiser whose output would need
re-proving each release ([wasm speed §4][speed]).

**One import.** The module imports exactly one function, the WIT import
`random-get: func(len: u32) -> list<u8>` (§4). OpenSSL draws random bytes
only for EC blinding inside ECDSA verification; the host answers from its
CSPRNG, and the guest traps when the answer is not exactly `len` bytes
([canonical ABI final][cabifinal]). A failing `random_get` makes OpenSSL
refuse ECDSA verification: 0 new acceptances over 1,179 rows
([wasm bake-off §10][wasmbake]). The measured modules of the earlier
rounds also imported `aprv.clock_now_ms`; `now-ms` is an argument now, so
that import is gone (§6, R24). Phase 1 checks whether the import can be
the standard `wasi:random/random@0.2` `get-random-bytes` instead of our
own interface, so a WASI 0.2 host supplies it without any code of ours;
either way it stays the module's only import (R34).

**The link-time C file** (`wasi-none.c`, 74 code lines in the evidence)
defines every WASI function wasi-libc would import, inside the module. In
the shipped build every one of them **traps**, except two:
`random_get`, which forwards to the `random-get` import, and `clock_time_get`,
which answers from the `now_ms` of the call in progress (§6). An
unexpected call to a file, directory, environment, argument or exit
function stops the verification instead of taking a path nobody measured;
on the evidence corpus no run called any of them
([wasm bake-off §5][wasmbake]).

**Features.** Core Wasm 2.0 (`lime1`) only: no SIMD, no threads
([CMS everywhere §2][cms]). Endive's build-time compiler has no SIMD
support ([wasm speed §5][speed]), and one module serves every host.
The canonical ABI needs no Wasm feature: it is a calling convention over
plain core exports (§4). The release also publishes the same core module
wrapped as a component by `wasm-tools component new`, 2,442 bytes larger,
for the hosts that bind components (jco, Wasmtime `bindgen!`); the
component adds no code, and `wasm-tools component unbundle` would give the
core back ([canonical ABI final][cabifinal]).

## 4. The ABI: the canonical ABI over a WIT interface (R23)

`aprv.wasm` exposes its four operations through the **canonical ABI**,
the Component Model's calling convention, described once in a WIT file
and generated on the guest side by wit-bindgen. It was measured in two
rounds on the same `wasm32-wasip1` core module as ABI v1
([canonical ABI][cabi], [canonical ABI final][cabifinal]).

```wit
package aprv:verifier@1.0.0;

interface verify {
  /// Once per instance. `{"roots":["<base64 DER>", ...]}`; empty or {} = the built-in Apple roots.
  /// Answers {"ok":true} or {"ok":false,"message":"..."}; a second call after {"ok":true} traps.
  init: func(config-json: list<u8>) -> string;
  verify-receipt: func(now-ms: u64, receipt-base64: list<u8>) -> string;
  verify-signed-data: func(now-ms: u64, jws: list<u8>) -> string;
  /// env: 0 production, 1 sandbox; anything else traps.
  verify-receipt-endpoint: func(env: u32, now-ms: u64, request-json: list<u8>) -> string;
}

interface host {
  random-get: func(len: u32) -> list<u8>;
}

world aprv {
  import host;
  export verify;
}
```

The WIT file is the contract. It lives in `rust/bindings/abi/wit/`, and
CI diffs it against what `wasm-tools component wit` reads back from the
built module (§9). The version in the package name is the ABI version:
export names carry it (`aprv:verifier/verify@1.0.0#init`), so a wrapper
built for one version finds no export on a module of another and fails at
`create` instead of misreading arguments.

**What the core module exports** (the canonical ABI's flattening of the
WIT; `list<u8>` and `string` become `(ptr, len)`, `u64` becomes `i64`,
`u32` becomes `i32`, and a returned string comes back through a return
area):

```text
import  "aprv:verifier/host@1.0.0" "random-get"                     (len i32, retptr i32) -> ()
export  "aprv:verifier/verify@1.0.0#init"                            (ptr, len) -> retptr
export  "aprv:verifier/verify@1.0.0#verify-receipt"                  (now i64, ptr, len) -> retptr
export  "aprv:verifier/verify@1.0.0#verify-signed-data"              (now i64, ptr, len) -> retptr
export  "aprv:verifier/verify@1.0.0#verify-receipt-endpoint"         (env i32, now i64, ptr, len) -> retptr
export  "cabi_post_aprv:verifier/verify@1.0.0#<each of the four>"   (retptr) -> ()
export  "cabi_realloc"                                                (old, old_size, align, new_size) -> ptr
export  memory, _initialize
```

| Operation | Input | Output (UTF-8 JSON, aprv-wire) |
|---|---|---|
| `init` | the configuration JSON, roots as base64 DER | `{"ok":true}` or `{"ok":false,"message":"..."}` |
| `verify-receipt` | `now-ms`, the `receipt-data` string's bytes (standard base64) | `{"verified":true,"payload":<ReceiptPayload JSON>}` or a failure |
| `verify-signed-data` | `now-ms`, the compact JWS's bytes | `{"verified":true,"payload":"<the signed payload JSON, exactly>"}` or a failure |
| `verify-receipt-endpoint` | `env`, `now-ms`, the verifyReceipt request body | Apple's response JSON, byte for byte |

A failure is `{"verified":false,"reason":"<0.7 Reason>","message":"..."}`.

- **Inputs are bytes, outputs are strings.** A WIT `string` must be UTF-8
  and the lift is unchecked in release builds of wit-bindgen, so the three
  payloads and the configuration cross as `list<u8>`: any bytes reach the
  core, which answers a non-UTF-8 JWS with `MALFORMED` as a value (the
  0.6 core's `INVALID_JWS_FORMAT`), the same 243 rows ABI v1 answered ([canonical ABI final][cabifinal]).
  Every output is JSON text the guest produced, so `string` is safe there.
- **`env` is a `u32`, not a WIT enum.** An enum lifts with an unchecked
  `transmute` in release builds; the `u32` is matched in the guest, which
  traps on anything but 0 and 1 (2, 255 and 2^32-1 all trapped on every
  host). Generated bindings do not range-check it: jco applies ToUint32
  (`2**32 + 1` becomes 1) and wasmtime-py wraps through ctypes, so the
  wrapper's own `Environment` type is what keeps a caller on 0 or 1
  ([canonical ABI final][cabifinal], finding 2).
- **`now-ms` is a `u64` argument** on every verify call (§6). The core's
  chain instant takes at most `i64::MAX`.
- **`init`** parses the roots once per instance. An empty list means the
  three Apple roots compiled into the module. A wrapper never sends an
  empty list for a caller's own empty root set: 0.7's `Verifier.create`
  refuses that before `init` (SURFACE.md §2). A root that does not parse is
  `{"ok":false}`, which the wrapper turns into its language's
  configuration error at `create`; `init` may then be retried on the same
  instance. A second `init` after `{"ok":true}` traps.
- **A verify before `init`** is a programmer error and traps. Wrappers
  cannot reach it: they `init` every instance they create.
- **No policy.** No bundle id, environment filter, app Apple id or device
  id crosses the boundary. `env` is which of Apple's two URLs the endpoint
  imitates, as in 0.7.
- **Base64 only.** Receipts cross as the `receipt-data` string, decoded
  in the module by the core's strict rule. The 3,145,728-byte cap applies
  to that string, so the largest receipt the ABI takes is 2,359,296 bytes
  of DER, as Apple's own endpoint takes base64 ([ABI v1][abi]).
- **Traps** are `core::arch::wasm32::unreachable()`: no panic path, no
  message formatting.

**Two ways to call it.** A host with a component runtime binds the WIT
and writes no ABI code: jco on Node, Deno and Bun (a generated `aprv.js`),
Wasmtime `bindgen!` in `aprv-server`, wasmtime-py's typed component API.
A host without one calls the four core exports by hand, in 35 to 66 lines
including the `random-get` import: Endive (35), WasmKit (37), wazero (66)
([canonical ABI final][cabifinal]). Both kinds answered all 6,179 rows
identically.

**Lifecycle of one hand-rolled call**, the same in every such wrapper:

1. `cabi_realloc(0, 0, 1, len)` for the input, then copy it in; the guest
   owns and frees that buffer;
2. call the export with the scalars in declaration order, then `(ptr, len)`;
3. read the return area, `ptr` then `len` as little-endian `u32`, at the
   returned address, bounds-check
   both against the memory size, and copy the result out;
4. call `cabi_post_<export>(retptr)`, which frees the result;
5. decode the JSON.

No guest pointer leaves a public call, and one call runs at a time per
instance: the return area is one static slot. Component runtimes do all
of this in their generated code. After a trap a component runtime refuses
the instance ("cannot enter component instance"); a hand-rolled host must
discard it itself, since wazero, Endive and WasmKit let a trapped
instance keep answering ([canonical ABI final][cabifinal], finding 4).
The same applies to heap discipline: a double post-return does not trap
on a hand-rolled host (finding 5), so a wrapper never exposes a result
pointer or calls post-return twice. On wazero, 2,000 calls left linear
memory the same size.

**Six outcomes, kept distinct.** A wrapper never folds one into another:

| Outcome | Where it comes from | What the caller sees |
|---|---|---|
| Verified | the module's result | the payload (0.7) |
| Verification failure | the module's result | a result with the 0.7 `Reason` |
| Caller misuse | the wrapper's own checks (a null `Config` or `Environment`, an empty root set, a root `init` refuses) | the language's programmer error at `create` or at the call, as in 0.7 |
| ABI mismatch | the module lacks the `@1.0.0` exports the wrapper binds, or the runtime rejects the imports | a hard failure at `create` naming the version the wrapper expects and the export names the module has; never a verdict |
| Trap or internal failure | a guest trap, a runtime error, an out-of-range result pointer, malformed result JSON | `INTERNAL_ERROR` (21009 at the endpoint); the instance is discarded; the cause names the trap |
| Server process failure | `aprv-server` did not answer: start failed, the child died, the connection broke, HTTP 5xx | `INTERNAL_ERROR` (21009 at the endpoint) with a cause of its own type, so it is never mistaken for a trap |

The 0.7 contract holds: the verify methods never throw for any input
(0.7-api.md, Setup). Both failure rows answer `INTERNAL_ERROR` and keep
their category in the cause.

**Cost against ABI v1**, measured: the stripped core module is +0.47%
(2,713,063 bytes against 2,700,240) and the component +0.53%; wazero's
first result +3.2% with equal throughput; Endive, WasmKit and Bun within
noise; jco on Node and Deno +8%, which is loading the generated glue
([canonical ABI final][cabifinal]).

## 5. The instance model (R23, owner Q49 d)

- `Verifier.create(config)` owns a small pool of instances of one
  compiled module. Each instance gets `init` once, when it is created, so
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
- **aprv-server:** a fresh instance and `init` per request by default, so
  nothing from one hostile input reaches the next request. Phase 1
  measures `init`; if it costs more than 10% of a call, the default flips
  to the existing `--lifecycle pool` flag (R31). The spike's fresh
  lifecycle cost about 1.6 ms more per receipt than the pool, which it
  attributed to the guest initialising OpenSSL and its roots on an
  instance's first call ([aprv-server §3][server]); `init` separates that
  cost from the call.

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
  of the call in progress, and with 0 during `init`. Whether OpenSSL's
  DRBG reads the clock during `init` at all is unmeasured; Phase 1's gate
  is that the module imports only `random-get` and answers the corpus as
  before.
- No public API takes a per-call time. 0.7 dropped it; the ABI carries
  `now-ms` per call anyway, so a per-call override later is additive.
- Callers still cannot move the validity instant of an input that
  carries its own date, which is THREAT-MODEL §3.5 of the root threat
  model.

## 7. Hosts

Each host chapter names the runtime, how it holds the instance model,
what it supplies for `random-get`, and what was measured. Every host
ran the 6,179 rows byte-identically to Node and passed 37 of 37 ABI and
facade tests unless a line says otherwise. Which hosts bind the WIT and
which call the core exports by hand is fixed in §4; the line counts are
the hand-written ABI code of the final round
([canonical ABI final][cabifinal]).

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
- **Hand-rolled canonical ABI, 35 lines**: a four-entry signature table
  (`u32`, `u64`, `list<u8>`), `cabi_realloc` for the input, the export by
  its `@1.0.0` name, the return area read, `cabi_post_*`. A wrong Java
  type or argument count is a host error before any call. `random-get`
  from `SecureRandom`, written through `cabi_realloc` into guest memory.
- A trap reaches Java as `WasmRuntimeException`, `TrapException` or
  `WasmEngineException`; the JVM survives ([Endive §7][endive]). The
  wrapper discards the instance.
- Speed through ABI v1 on JDK 21: 154.7, 323.0 and 482.2 g5 receipts and
  52.6, 101.9 and 166.8 JWS per second at 1, 2 and 4 threads
  ([ABI v1][abi]). The canonical ABI's first result is within noise of
  that ([canonical ABI final][cabifinal]). The first instance takes 335
  to 380 ms.
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
- **The call path is the hand-rolled one over the core module**, as
  Endive's, not wasmtime-py's typed component API. That API lowers a
  `list<u8>` one element at a time in Python (`ListType.convert_to_c` in
  49.0.0): about 1.1 µs per input byte, 226 s for the corpus against 17 s
  with strings ([canonical ABI final][cabifinal], finding 3). Writing the
  bytes into guest memory with `Memory.write` costs nothing of the kind.
  Phase 5 reopens the component API only if upstream adds a bytes fast
  path.
- `random-get` from `os.urandom`/`secrets`.
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
  instances, `random-get` from `crypto/rand`. Any other import is
  refused at instantiation. wazero has no Component Model, so the
  canonical ABI is called by hand: 66 lines, the largest of the three
  hand-rolled hosts because of Go's error checks
  ([canonical ABI final][cabifinal]).
- It stays cgo-free, so `CGO_ENABLED=0`, cross-compilation and `FROM
  scratch` keep working. The CMS module answered 1,179 of 1,179 rows on
  wazero 1.12.0 ([CMS everywhere §2][cms]); an OpenSSL module took
  2,495 µs per receipt and 8,110 µs per JWS there on the PKCS7 path
  ([substrate bake-off §13][substrate]). Through the canonical ABI on
  wazero 1.12.0: 238.5 g5 and 77.0 JWS per second steady, the corpus in
  23 s, first result 1,279 ms including runtime and compile
  ([canonical ABI final][cabifinal]).
- The floor stays as today (R30) if the wazero release we need builds on
  it; wazero 1.12.0 fetched a Go 1.25 toolchain in the spikes
  ([rust-core spikes, Method][spikes]). Phase 4 checks, and raises the
  floor to wazero's requirement if it must.
- An opt-in `-tags aprv_native` build over the C ABI stays possible on
  request (R6). It is class E, the user's choice, and nothing is built for
  it until someone asks.

### 7.4 JavaScript: native WebAssembly

- One npm package, zero runtime `dependencies`. It carries the core
  module, **jco's transpiled bindings** of the component (`aprv.js`,
  132,241 bytes as generated, 63,523 minified, 0 hand-written ABI lines)
  and a thin façade with a hand-written `index.d.ts` over them: no
  wasm-bindgen, no Emscripten glue. jco 1.35.0 answered the corpus
  identically on Node 22, Deno 2.9 and Bun 1.3; its glue costs 8 to 11 ms
  at start on Node and Deno ([canonical ABI final][cabifinal]). The Route
  C package of the earlier shape was 1,001,740 bytes and passed on Node,
  Bun, Deno, Chromium, Firefox, WebKitGTK, a `node --permission` run and
  `wrangler dev --local` ([CMS everywhere §2][cms]); Phase 4 repeats that
  list with jco's output, and falls back to a hand-rolled façade over the
  core exports (Endive's 35 lines in JavaScript) on any runtime where the
  glue does not load.
- Two quirks of the glue to carry: jco reads `process.env.JCO_DEBUG` on
  every call, so Deno needs `--allow-env=JCO_DEBUG` (documented; Phase 4
  checks whether a build flag removes the read); and jco coerces a JS
  string passed where the WIT says `list<u8>`, so the façade converts
  with `TextEncoder` itself and never passes a caller's value through
  ([canonical ABI final][cabifinal], findings 2 and 6).
- One instance per module load. The façade supplies `random-get` from
  `crypto.getRandomValues` in 65,536-byte chunks, never `Math.random`,
  and refuses any other import. It decodes strings with `TextDecoder`
  and `ignoreBOM: true` ([wasm bake-off §8][wasmbake]).
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
  Node against 67 MiB for a tiny one ([ASN.1 payload §3][payload]) before
  the core's header walk; after it the unsigned and signerless forms are
  refused before the payload is read and linear memory peaks near 16 MiB
  ([core review fixes][corefix]). Phase 4 measures it in workerd, whose
  isolate limit is 128 MB.
- Runtimes kept: Node 20/22/24/26, Bun, Deno, workerd, Vercel Edge through
  `@edge-runtime/vm`, Chromium, Firefox and WebKit. Fastly Compute JS and
  Akamai EdgeWorkers are dropped: neither runs WebAssembly (R5).

### 7.5 WasmKit: Swift

- WasmKit 0.4.0, an interpreter with no JIT, lazy translation on first
  call ([Swift][swift]). It declares `swift-tools-version:6.3` and
  `platforms: [.macOS(.v15), .iOS(.v18)]`, which sets the Swift floors
  (R30).
- `Engine` and `Module` are `Sendable` and shared; stores and instances
  are per thread. `random-get` from `SystemRandomNumberGenerator`. The
  canonical ABI is called by hand, 37 lines, with the bounds-checked
  read and write helpers below ([canonical ABI final][cabifinal]);
  WasmKit 0.4.0's opt-in `ComponentModel` trait is untested and not
  used.
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
  `random-get` from `SecureRandom`. The canonical ABI is called by hand
  over the core exports, as on Endive; neither the gem's nor Wasmtime
  .NET's component support was measured, and Phase 5 keeps the
  hand-rolled call unless a binding's component API costs nothing.

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
- Compile at start 0.92 to 0.98 s. `random-get` from
  `RandomNumberGenerator`.

### 7.7 aprv-server

One Rust binary, `aprv`, built on axum and tokio with Wasmtime 49
**runtime-only** plus `component-model`: Cranelift, Winch, the cache and
every other optional feature are off. The release precompiles the
component to a Cranelift `.ccwasm` for an **explicit baseline target**
per platform and embeds it; `bindgen!` over the WIT gives the typed
calls, with 0 hand-written ABI lines ([aprv-server §2][server],
[canonical ABI final][cabifinal]). The binary has no base64, CMS, JWS,
certificate or policy code: a route or command picks the operation and
calls the binding.

- **The component costs** +328,528 bytes of engine (+143,633 gzipped,
  about 30% of the runtime-only engine) and +34,072 bytes of precompiled
  file; time to the first result stays 14 ms in process, the same as the
  core `.cwasm` ([canonical ABI final][cabifinal]).
- **Precompile and runtime must agree on Wasm features.** A precompiled
  file records the features of the engine that wrote it, and Wasmtime
  refuses a mismatch at load time ("compiled with support for WebAssembly
  feature component_model but it is not enabled for the host"). The
  `precompile` step therefore runs with the same Wasmtime features as the
  serving binary, in the same build, and `info` reports both the module
  hash and the feature set ([canonical ABI final][cabifinal], finding 1).

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
  concurrent verifications, N = CPU count; the 3 MiB body cap; a guest time
  limit of 10 s per call by default, by epoch interruption
  (`--time-limit-ms`, rust/server/README.md).
- **Lifecycle.** A fresh store and instance, with `init`, per request;
  `--lifecycle pool` keeps instances and destroys one on any trap or ABI
  error, never sharing one between two requests (§5).
- **The HTTP contract is an OpenAPI 3.1 document** (`rust/server/openapi.yaml`),
  the wire shapes referenced from the JSON Schema 2020-12 files of
  `aprv-wire`; Spectral lints it and Schemathesis runs it against the
  server in CI. Errors that are not verification results (401, 413, 500
  `WASM_TRAP`, `ABI_ERROR`, `INTERNAL_ERROR`) are RFC 9457 Problem Details
  (`application/problem+json`) with the existing code in a `code` member;
  a verification result stays HTTP 200 with the module's JSON (R34).
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
  and, once the owner creates the namespace and token, Docker Hub, with
  the `org.opencontainers.image.*` labels (source, revision, version,
  licenses, description) and a CycloneDX SBOM attached (R34). The image
  has not been built yet ([aprv-server §8][server]).
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
  at `create` (the engine instantiating one instance and calling `init`)
  is fixed in Phase 3.

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

`rust/ffi` stays: a `cdylib` and `staticlib` with a header cbindgen
generates from the source and CI diffs against the committed copy, now
over `aprv-surface` and `aprv-wire`, so its JSON is the same bytes
`aprv.wasm` returns and validates against the same schemas. It is the escape hatch for a language with no host
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
| No hand-written ASN.1, CMS or X.509 in the core (R21) | `tools/check-layering.mjs` fails on a module named `asn1`, `x509`, `cms`, `chain` or `crypto` in `rust/src`, an ASN.1, X.509 or signature crate in the core's graph, `ASN1_get_object` anywhere in `rust/src`, or `ASN1_get_object` in the adapter outside its documented header walk (`rust/openssl/src/walk.rs`, which reads headers and decodes no value; rule 6) |
| `unsafe` only at the edges | `#![forbid(unsafe_code)]` in the core, the surface and the wire crate; `unsafe` only in `aprv-openssl`, `aprv-abi`, `rust/ffi` and `aprv-server` (for `Module::deserialize`), each block with a `// SAFETY:` comment |
| `aprv.wasm` imports exactly `random-get` | CI lists the module's imports with `wasm-tools` and fails on anything else |
| The WIT is the contract | CI reads the interface back from the built module with `wasm-tools component wit` and diffs it against `rust/bindings/abi/wit/aprv.wit`; a change to the file is a change to the ABI version |
| `aprv.wasm` takes no unmeasured path | Every change runs the corpus through a host whose import object traps on anything unexpected, with the module's own WASI stubs trapping; any trap or any row that differs from native fails |
| One `aprv.wasm` everywhere | The release builds it once; every package's copy (npm, Go, Swift, PyPI, RubyGems, NuGet, the Endive input, the server's `.cwasm` input) is checked against its published SHA-256; the committed Go and Swift copies are rebuilt in CI and diffed |
| The canonical ABI holds | The ABI tests of the final round (env 2, 255 and 2^32-1 trap; verify before `init` and a second `init` trap; a wrong-length `random-get` traps; a trap in one instance leaves another verifying; 2,000 calls leave memory the same size) plus each facade's own run on every host on every change |
| The wire shapes match their schemas | Every corpus answer and every `init` configuration and answer validates against the JSON Schema 2020-12 files in `rust/bindings/wire/schema/`, from the core, the C ABI and `aprv.wasm` |
| The server's HTTP contract is its OpenAPI document | Spectral lints `rust/server/openapi.yaml`; Schemathesis runs it against the server in the `aprv-server` job; non-result errors are RFC 9457 |
| Same verdicts everywhere | Every host runs all 311 `fixtures/cases.json` cases as one test each; the `-wasm` artifact runs them once per engine; the main Java artifact runs them too (SURFACE.md §6) |
| Endive answers as native | The corpus (1,179 rows plus 5,000 mutants) through the built `-wasm` jar on every change, byte for byte against native, on Linux x64 and arm64, macOS arm64, Windows x64 and arm64; s390x under QEMU before each release |
| One Java artifact per classpath | A test puts both jars on one classpath and asserts the guard's failure; a Gradle build that requests both fails at resolution |
| No ambient OpenSSL state | The isolation test plants a root in `SSL_CERT_FILE` and `SSL_CERT_DIR` and a hostile `OPENSSL_CONF`, and asserts they are ignored ([substrate bake-off §7][substrate]) |
| Pinned roots only | Root `certs/` stays canonical; `rust/certs` is the copy compiled into the core; the Java artifact keeps its constants. `check-cert-copies.mjs` checks what remains |
| Caps in one place | The core owns every bound of the 0.7 table; wrappers add none. `aprv-server` adds only the HTTP body cap, equal to the receipt cap |
| Precompiled code is only what we built | `aprv-server` deserializes only its embedded `.cwasm`; no host loads a `.cwasm` from anywhere else; wasmtime-py's cache follows THREAT-MODEL.md §8 |
| Artifacts are what CI built | Publish jobs never cache. `aprv.wasm`, the component, every server binary, every classifier jar and the image get a SHA-256, a SLSA build-provenance attestation and a CycloneDX SBOM that names the OpenSSL, wasi-sdk, rustc and Wasmtime versions inside them. Post-publish smoke installs from the real registries |
| `aprv.wasm` is reproducible | `tools/reproduce-wasm.sh` rebuilds the module from a tag in the pinned toolchain and compares the hash; the release job runs it once against its own artifact |
| Licences ship with the code | Every package that carries `aprv.wasm` or a server binary ships OpenSSL's licence and NOTICE, wasi-libc's and Rust std's texts; the server adds Wasmtime's |
| Floors are tested | Each floor in SUPPORT-MATRIX.md keeps a CI leg, the Java 8 server engine on a real Java 8 JVM |

[wasmbake]: ../evidence/2026-09-26-wasm-architecture-bakeoff.md
[cms]: ../evidence/2026-09-26-openssl-cms-everywhere.md
[abi]: ../evidence/2026-09-26-wasm-abi-v1.md
[cabi]: ../evidence/2026-09-29-canonical-abi-spike.md
[cabifinal]: ../evidence/2026-09-29-canonical-abi-final.md
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
[corefix]: ../evidence/2026-09-29-core-review-fixes.md
