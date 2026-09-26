# Target architecture: one Rust verifier, thin bindings

Status: **target design of the accepted plan.** The decisions it rests on
are in [DECISIONS.md](./DECISIONS.md); R21 (2026-09-26) put the core on
OpenSSL 4 and replaced wasm-bindgen with one plain wasm module.

## 1. The shape

```text
                 SECURITY REVIEW BOUNDARY (deep human review)
┌──────────────────────────────────────────────────────────────────────┐
│ rust/  crate apple-purchase-receipt-verifier  (the policy)           │
│   Apple's rules: pinned roots, chain policy and historical time,     │
│   JWS, receipt attributes, caps, base64 rules, JSON depth, Reason    │
│   vocabulary, verifyReceipt endpoint.                                │
│   #![forbid(unsafe_code)], no panics. No ASN.1, CMS or X.509 parser. │
│        │ safe Rust calls                                             │
│ ┌──────▼───────────────────────────────────────────────────────────┐ │
│ │ rust/openssl/  crate aprv-openssl  (the adapter)                 │ │
│ │   FFI to OpenSSL's CMS, X.509, EVP and ASN.1 template APIs;      │ │
│ │   payload.c (14 lines of ASN1_SEQUENCE/ASN1_ITEM declarations);  │ │
│ │   the wasm clock import. The only unsafe below the bindings.     │ │
│ └──────┬───────────────────────────────────────────────────────────┘ │
│        │ static link                                                 │
│   OpenSSL 4.0.2, upstream C in the trusted base                      │
└──────────────────────────────┬───────────────────────────────────────┘
                               │ plain Rust API
┌──────────────────────────────▼───────────────────────────────────────┐
│ rust/bindings/surface/  crate aprv-surface  (unpublished)            │
│   binding-neutral records and errors, checked conversions.           │
│   #![forbid(unsafe_code)]. Mechanical review.                        │
└─────┬─────────────────────────────┬──────────────────────────┬───────┘
      │                             │                          │
┌─────▼─────┐              ┌────────▼────────┐          ┌──────▼──────┐
│ uniffi/   │              │ wasm/           │          │ rust/ffi/   │
│ UniFFI    │              │ aprv.wasm: the  │◄─────────┤ C ABI       │
│ cdylib +  │              │ C ABI built for │          │ cdylib +    │
│ staticlib │              │ wasm32-wasip1,  │          │ staticlib + │
│           │              │ imports 2 funcs │          │ cbindgen .h │
└──┬──┬──┬──┘              └──────┬──────┬───┘          └──────┬──────┘
   │  │  │                        │      │                     │
 Kotlin Swift Python      JS façade    Go via wazero      C, C++, SWIG,
   │                          │                           Elixir NIF,
 Java (JVM)           one npm package                     anything else
```

A fix in `rust/` reaches every package on the next release. No package
carries a parser, a signature check or a trust decision of its own.

## 2. Crates and folders

```text
rust/                          core crate (the policy), unchanged name, published to crates.io
rust/Cargo.toml                gains [workspace] members = ["openssl", "ffi", "bindings/*"]
rust/openssl/                  aprv-openssl: the OpenSSL adapter, the one unsafe crate below the bindings
rust/openssl/payload.c         the receipt payload grammar as OpenSSL ASN.1 templates (14 lines)
rust/bindings/surface/         aprv-surface: the cross-language API model
rust/bindings/uniffi/          aprv-uniffi: #[uniffi::export] over aprv-surface
rust/bindings/uniffi/uniffi.toml   per-language names, packages, disable_java_cleaner
rust/bindings/wasm/            aprv-wasm: the C ABI as aprv.wasm (wasm32-wasip1), plus alloc/dealloc exports
rust/bindings/wasm/wasi-none.c link-time WASI definitions: the module imports only aprv.clock_now_ms, aprv.random_get
rust/bindings/wire/            aprv-wire: the JSON view (C ABI, aprv.wasm), see SURFACE.md §4.2
rust/ffi/                      existing C ABI, rebased on aprv-surface + aprv-wire
rust/ffi/swig/                 apple_purchase_receipt_verifier.i and examples
rust/fuzz/                     verify-receipt, verify-transaction, plus targets for the JSON view
node/                          aprv.wasm's JS façade (about 100 lines) and index.d.ts, hand-written
java/  python/  swift/  go/    package builds, façades, binding tests
```

Gone from `rust/src/` (R21): `asn1.rs`, `x509.rs`, `cms.rs`, `chain.rs` and
`crypto.rs`, with the public modules of the same names and
`TrustAnchor::certificate()`. `rust/fuzz` loses `parse-der`,
`parse-certificate` and `parse-cms`, which fuzzed those modules.

The core depends on `aprv-openssl`. A crates.io publish of the core (R19)
therefore publishes the adapter crate first. The file names above are the
plan's; the evidence calls the adapter `security-openssl` and the C file
`c/wasi-none.c`.

One Cargo workspace replaces today's two independent lockfiles (`rust/` and
`rust/ffi/`), so every adapter builds against the same resolved core.
`rust/fuzz` stays outside the workspace because it needs nightly.
`rust/Cargo.toml`'s `exclude` (today `ffi/**` and `fuzz/**`) gains
`bindings/**`, or the crates.io tarball would ship the adapters.

Why a separate `aprv-surface` crate:

- The core's public API stays idiomatic Rust (builders, `SystemTime`,
  `serde_json::Map`). crates.io users keep it.
- Every adapter needs the same binding-friendly model: `i64` instead of
  `u64`, `Vec<u8>` instead of `&[u8]`, records instead of `#[non_exhaustive]`
  structs, epoch milliseconds or a timestamp instead of `Option<SystemTime>`
  in JSON. Writing it once in `aprv-surface` stops four adapters from
  converting four slightly different ways.
- Neither the core nor the surface carries a binding annotation. The UniFFI
  adapter annotates the surface types from outside with `#[uniffi::remote]`
  (spike passed). The full contract, and why the surface also holds no
  serializer, is [SURFACE.md](./SURFACE.md).
- The C ABI's cross-port JSON view (today in `rust/ffi/src/lib.rs:391-534`)
  moves to a separate `aprv-wire` crate, shared by the C ABI and
  `aprv.wasm`, which is the C ABI built for wasm (SURFACE.md §4.2).

Why a separate adapter crate: the core keeps `#![forbid(unsafe_code)]`,
and every line that crosses into C sits in one crate a reviewer can read
end to end. The core calls it through safe functions only.

## 3. The cross-language API

One API, named once in Rust, rendered idiomatically by each generator. The
names below are the Kotlin/Java rendering; Python gets snake_case and Swift
gets Swift conventions from the same definitions.

```text
JwsVerifier(bundleId: String,
            environments: List<Environment>,
            appAppleId: Long?,             // i64 in Rust: Java cannot call ULong
            trustedRoots: List<byte[]>?)   // null = Apple's pinned roots
  verifyTransaction(jws: String): TransactionPayload
  verifyAppTransaction(jws: String): AppTransactionPayload
  verifyRaw(jws: String): String           // every claim, as JSON text

ReceiptVerifier(bundleId: String, trustedRoots: List<byte[]>?)
  verify(receipt: byte[]): AppReceipt
  verifyBase64(receipt: String): AppReceipt
  verifyWithDeviceGuid(receipt: byte[], deviceGuid: byte[]): AppReceipt
  verifyBase64WithDeviceGuid(receipt: String, deviceGuid: byte[]): AppReceipt

VerifyReceiptEndpoint(environment: Environment, trustedRoots: List<byte[]>?)
  verifyReceiptResult(requestBody: String): VerifyReceiptResult       // core: verify_receipt_result_from_json
  verifyReceiptResultAt(requestBody: String, requestDateMillis: Long) // core: verify_receipt_result_from_json_at
  verifyReceiptData(base64: String): VerifyReceiptResult              // core: verify_receipt_data
  verifyReceiptDataAt(base64: String, requestDateMillis: Long)        // core: verify_receipt_data_at
  verifyReceiptJson(requestBody: String): String                      // core: verify_receipt_json

VerifyReceiptResult: status, verified, receipt?, failureReason?, failureCause?,
                     requestDateMillis, toJson(),
                     toJsonIn(Environment) throws ConfigurationException   // core: to_json_in -> Result<_, ConfigError>

AppReceipt, InAppPurchase, TransactionPayload, AppTransactionPayload: records
Environment, Reason: enums with the existing tokens
VerificationException(reason: Reason, detail: String)   // checked in Java
ConfigurationException(detail: String)
```

Rules that came out of the spikes:

1. **No unsigned integers** anywhere on the surface. Kotlin turns `ULong`
   parameters into methods that Java cannot call (measured, compile error).
2. **`Vec<u8>` for byte input.** UniFFI 0.32 maps `&[u8]` to a direct
   `ByteBuffer` in Kotlin.
3. **No callbacks.** The endpoint takes `requestDateMillis` per call instead
   of a clock object, mirroring the core's `verify_receipt_*_at` methods and
   today's Java and Node `verifyReceiptResult(body, requestDate)`. (The C ABI
   pins its clock per endpoint instead, through the `fixed_clock_unix_millis`
   argument of `aprv_endpoint_new_with_roots_and_clock`.) A language façade that wants to accept
   `java.time.Clock`, a Python callable or a Swift closure reads it and
   passes the millis. The verifiers take no clock at all, as today
   (THREAT-MODEL §3.5).
4. **Receipt dates:** UniFFI's timestamp type renders as `java.time.Instant`,
   Swift `Date` and Python `datetime`, which is what the Java, Swift and
   Python ports return today. The JSON view and wasm carry ISO-8601 strings,
   and the npm façade turns them into `Date`. **JWS dates stay epoch-ms
   integers** in every language: that contract is in `jws.rs:104-111`.
5. **Unknown attributes** become `List<UnknownAttribute(type: Long, values:
   List<byte[]>)>`. The type is `i64` because a type above 2^31-1 is a
   pinned divergence case.
6. **Errors:** the spike's two-variant error enum rendered as
   `VerifyException.Verification(reason, detail)` in Kotlin and
   `VerifyError.Verification` in Python, and worked in both. The Phase 2
   PoC picks the final naming, so Java keeps today's `VerificationException`
   with its `reason()` accessor and the nested `VerificationException.Reason`
   enum. `toJsonIn` throws `ConfigurationException` for an environment other
   than Production or Sandbox, as `to_json_in` returns a `ConfigError`.
   Today's ports spell it `toJson(environment)`; the façade keeps that name.

Generated APIs cover roughly 90% of what users call today. A **façade** is
allowed only for:
- keeping a current signature (the npm options objects, a Java overload
  that restores default arguments);
- idiomatic time and clock types;
- `AutoCloseable`/`with`-style lifetime helpers.

A façade holds no parsing, no crypto, no policy and no caps. CI enforces
that per package (section 8).

## 4. Time

The core reads the clock only in the chain-validity fallback (`jws.rs:455`,
`receipt.rs:134`) and for the endpoint's `request_date`.

On wasm the core needs a clock it can reach without WASI. The spikes
measured what happens without one: on `wasm32-unknown-unknown` the standard
library's `SystemTime::now()` panics, and the 58 corpus rows that trapped
there were exactly the rows that read the clock
([wasm bake-off §4](../evidence/2026-09-26-wasm-architecture-bakeoff.md)).
The fix keeps the core free of any JavaScript or WASI dependency (R10,
SURFACE.md §4.1):

- The core gets one crate-private `fn system_now() -> SystemTime`. The
  three fallbacks (`receipt.rs:134`, `jws.rs:455`, `endpoint.rs:525`) and
  `SystemClock::now` all go through it.
- It uses `std::time::SystemTime::now()` on every native target.
- In `aprv.wasm` it reads the import `aprv.clock_now_ms`, epoch
  milliseconds from the host: `Date.now()` in the JS façade, the wall
  clock in Go. The adapter crate declares the import and hands the core a
  safe function, so the core keeps `#![forbid(unsafe_code)]`.
- A host answer that is not a finite instant after 1970 maps to 1970,
  where no Apple chain is valid, so the failure is closed (the evidence
  shim's rule, wasm bake-off §4).
- OpenSSL's own `time()` calls, from its DRBG, resolve to the same import
  through the link-time C file. No WASI clock import remains.
- Callers still cannot move the validity instant. The host's clock replaces
  the OS clock, which is the same trust level as `SystemTime::now()`.
- Cloudflare Workers and Akamai freeze `Date.now()` at the last I/O or at
  request start. For a certificate-validity fallback that is harmless:
  seconds of drift against a validity window measured in years.

## 5. Panics and traps

| Binding | What happens on a Rust panic | Containment |
|---|---|---|
| UniFFI (Kotlin, Swift, Python) | UniFFI's scaffolding catches the unwind and raises its internal error type | Build with `panic = "unwind"` (the default). A binding test forces an `INTERNAL_ERROR` path and asserts a language exception, not a crash. |
| C ABI | `guard`/`guard_ptr` wrap every export in `catch_unwind` (existing) | Keep. The source-scanning test that enforces it stays. |
| `aprv.wasm` in JS (npm) | `panic = "abort"`: the instance **traps**, and its memory may be left inconsistent | The JS façade catches `WebAssembly.RuntimeError`, drops the instance, instantiates a fresh one on the next call, and throws `VerificationError(INTERNAL_ERROR)`. |
| `aprv.wasm` in Go (wazero) | wazero returns an error from the call and the module is unusable | Same pattern in Go: the pool discards the instance and the call returns `INTERNAL_ERROR`. |

The endpoint's "never fails" promise rests on `catch_unwind` at
`endpoint.rs:510`, which does nothing under `panic = "abort"`. On wasm the
façade provides that promise instead.

**Trap policy of `aprv.wasm`.** The link-time C file answers every WASI
function wasi-libc would import. In the shipped build, every one of them
other than the clock and random bytes **traps** instead of returning an
error, so an unexpected call to a file, directory, environment, argument
or exit function stops the verification rather than taking a code path
nobody measured. On the evidence corpus no run called any of them (wasm
bake-off §5). CI runs the full corpus on every change through a host whose
import object also traps on anything unexpected, and fails on any trap or
any row that differs from native. A failing `aprv.random_get` fails
closed: OpenSSL then refuses ECDSA verification, with 0 new acceptances
over 1,179 rows (wasm bake-off §10).

The core's lint wall (`unwrap`, `expect`, indexing, `panic` all denied)
remains the first line of defence. Every row above only covers the case
where that wall fails.

## 6. Packages

### 6.1 Maven Central (Java, Kotlin)

- Coordinates stay `io.github.emindeniz99:apple-purchase-receipt-verifier`.
  Today's classes sit in three packages: the root, `.jws` and `.receipt`.
  UniFFI's `package_name` puts every generated class in one package, so the
  generated code goes to `...applepurchasereceiptverifier.internal`. The owner chose
  no Java façade to start (R13), so the migration release moves the import
  paths into that one package and the CHANGELOG lists the break. A façade
  that restores `.jws` and `.receipt` stays possible before 1.0.
- Contents: the compiled generated Kotlin (`jvmTarget = 1.8`), a small Java
  façade if the PoC needs one, and natives at JNA's resource paths:
  `linux-x86-64`, `linux-aarch64`, `darwin-x86-64`, `darwin-aarch64`,
  `win32-x86-64`, `win32-aarch64`.
- Runtime dependencies change from Bouncy Castle and Jackson (about
  11.8 MB) to `kotlin-stdlib` (Java 8 bytecode) and `jna` 5.x (Java 8
  bytecode). The jar grows by the natives. With OpenSSL linked (R21) the
  one library measured so far, Linux x86_64 with vendored OpenSSL, is
  6,336,528 B raw and 1,966,051 B stripped and gzipped
  ([OpenSSL CMS everywhere §2](../evidence/2026-09-26-openssl-cms-everywhere.md));
  the pure-Rust estimate was about 1.2 MB per target.
- `uniffi.toml` sets `disable_java_cleaner = true`, so the generated code
  compiles against JDK 8 APIs.
- Docs: Maven Central requires `-sources.jar` and `-javadoc.jar`. The sources
  jar carries the generated Kotlin with its KDoc, which IntelliJ shows on
  hover in Java code. Dokka (`dokka:javadoc`) builds the javadoc jar from
  the same KDoc; the spike showed the Rust text arriving, but under Kotlin
  type names (`ByteArray`, `Unit`). If Java readers need `byte[]` and
  `throws` in the pages, the Java façade (compiled by `javac`, documented
  by the standard `javadoc` tool) becomes the documented surface, and the
  generated classes move to an internal package. Phase 3 decides by looking
  at both outputs.
- Doc comments on the surface are written language-neutrally: "the trusted
  roots", never `trusted_roots`, because every generator copies the text
  verbatim.
- Native access: JDK 24+ warns once per process until the application adds
  `--enable-native-access=ALL-UNNAMED`, or `Enable-Native-Access:
  ALL-UNNAMED` in an executable jar's manifest. The README says so on its
  first screen.
- musl (Alpine): JNA resolves `linux-<arch>` with no libc split. The jar
  carries glibc builds there, plus musl builds under `linux-musl-<arch>`.
  The façade selects the musl build by setting
  `uniffi.component.<namespace>.libraryOverride` when it detects musl. A CI
  leg on an Alpine image proves it, including JNA's own `jnidispatch`
  (unconfirmed today, see MIGRATION.md risks).

### 6.2 PyPI (Python)

- The build is maturin with `bindings = "uniffi"`. The import name stays
  `apple_purchase_receipt_verifier`. The generated module becomes a private
  submodule, and a short `__init__.py` re-exports it and adds the
  `py.typed` marker.
- Wheels are tagged `py3-none-<platform>`: one wheel per platform covers
  every CPython 3.x. Platforms:
  - `manylinux_2_17` x86_64 and aarch64;
  - `musllinux_1_2` x86_64 and aarch64;
  - `macosx` x86_64 and arm64;
  - `win_amd64` and `win_arm64`.
- The sdist builds from source with a Rust toolchain. That is the fallback
  for any other platform.
- `cryptography` and `asn1crypto` drop out of the dependency list, and the
  asn1crypto residual risk (THREAT-MODEL §5) closes.

### 6.3 SwiftPM (Swift)

- The generated Swift source is committed under
  `swift/Sources/ApplePurchaseReceiptVerifier/`. SwiftPM compiles consumers
  from git and has no build step, so the generated file must live in the
  repository. CI regenerates it and fails on a diff.
- A `binaryTarget` carries the Rust static library as an artifact bundle on
  the GitHub Release:
  - XCFramework slices for macOS arm64/x86_64 (plus iOS if the owner wants
    it);
  - SE-0482 static-library slices for `x86_64` and `aarch64-unknown-linux-gnu`.
- The swift-tools version rises to 6.2 (R7).
- Release sequencing: the artifact's URL and checksum must be in
  `Package.swift` inside the tagged commit.
  1. `release-please.yml` already commits lockfiles onto the release PR
     branch.
  2. It also builds the bundle and commits the checksum.
  3. `release.yml` uploads that exact file, kept as a workflow artifact,
     to the Release.
- Symbol hygiene: a consumer that links two Rust static libraries can
  collide on Rust's non-FFI globals (swift-tokenizers hit this). The build
  localizes every non-`uniffi_`/`ffi_` symbol, OpenSSL's included, and a
  CI check lists the exported symbols. A static archive that kept
  OpenSSL's symbols global could collide with a consumer's own OpenSSL
  (unmeasured).

### 6.4 npm (JavaScript, TypeScript)

- There is one package, `apple-purchase-receipt-verifier`, still with zero
  runtime `dependencies`. It carries `aprv.wasm` (R21), a hand-written JS
  façade of about 100 lines and a hand-written `index.d.ts`. No
  wasm-bindgen, no Emscripten glue, no jco output: the wasm bake-off's
  Route C package had this shape and passed on Node, Bun, Deno,
  Chromium, Firefox, WebKitGTK, a `node --permission` run and `wrangler dev
  --local` ([wasm bake-off §14](../evidence/2026-09-26-wasm-architecture-bakeoff.md),
  [OpenSSL CMS everywhere §2](../evidence/2026-09-26-openssl-cms-everywhere.md)).
- What the façade does, and nothing more: instantiate the module with an
  import object that holds exactly `aprv.clock_now_ms` (`Date.now()`) and
  `aprv.random_get` (`crypto.getRandomValues` in 65,536-byte chunks, never
  `Math.random`); call `_initialize` before `aprv_init`; copy bytes in
  through `aprv_alloc`/`aprv_dealloc`; call the C ABI exports; decode the
  JSON out. It decodes strings with `TextDecoder` and `ignoreBOM: true`,
  because the default strips a UTF-8 BOM and changes what the core sees
  (wasm bake-off §8).
- `exports` conditions choose how the wasm gets loaded, because the
  runtimes differ:

```jsonc
"exports": {
  ".": {
    "types":      "./dist/index.d.ts",
    "workerd":    "./dist/static/index.js",  // imports the .wasm as a module (required)
    "edge-light": "./dist/static/index.js",  // Vercel Edge: same rule
    "deno":       "./dist/web/index.js",
    "browser":    "./dist/web/index.js",
    "node":       "./dist/node/index.js",    // reads the .wasm from disk, compiles it synchronously
    "default":    "./dist/web/index.js"
  },
  "./web": "./dist/web/index.js"             // kept: 0.x users import it today
}
```

- Sync or async: today's `.` build is **synchronous** (`node/src/jws.ts:62`,
  `receipt.ts:284`, `verify-receipt-endpoint.ts:101`), and `/web` is
  **async** (`web/jws.ts:58`, `web/receipt.ts:173`). Both contracts stay:
  - `.` stays synchronous on every runtime. A wasm call is synchronous once
    the module is loaded. Node compiles it synchronously and workerd
    imports it as a module; browsers and Deno load it with top-level
    `await` at import, so the calls after the import are synchronous. Deno
    users of `.` today keep sync calls.
  - `./web` keeps returning Promises. It is a thin async wrapper over the
    same module, so no 0.x caller of `/web` changes a line.
- The façade keeps the rest of today's API: the options objects, the
  `Reason` const, `VerificationError extends Error` with `.reason`, `Date`
  for receipt dates, and `bigint` ids. It also owns trap recovery
  (section 5).
- Runtimes kept and tested: Node 20/22/24/26, Bun, Deno, workerd (three
  compatibility dates), Vercel Edge via `@edge-runtime/vm`, and Chromium,
  Firefox and WebKit (new). Safari itself is expected, not tested: the
  evidence ran WebKitGTK.
- Runtimes dropped: Fastly Compute JS and Akamai EdgeWorkers. Neither can
  run WebAssembly (R5).
- Size: `aprv.wasm` over OpenSSL with the template payload reader is
  2,973,532 B raw and 975,767 B stripped and gzipped
  ([ASN.1 payload note §3](../evidence/2026-09-26-openssl-asn1-payload.md));
  the spike tarball of the same shape was 1,001,740 B. `wasm-opt -Oz` saved
  20 to 27% raw in the wasm bake-off and kept parity on Node. CI sets a budget at the
  measured value plus 10% once the real build exists.
- Memory: a hostile 3 MiB receipt of tiny attributes peaks at 145 MiB in
  Node against 67 MiB for a tiny one (payload note §3). Phase 4 measures it
  in workerd, whose isolate limit is 128 MB (R21).
- Performance: see R4. Informational: the OpenSSL module took 1,395 µs per
  receipt and 4,550 µs per JWS in Node 22 (wasm bake-off §13).

### 6.5 Go (R6: wazero)

- The module path and package `applereceipt` stay. The public Go API stays
  as it is: the options structs, `Reason`, `errors.Is`, and
  `VerifyReceiptResult`.
- Inside, the module embeds the same `aprv.wasm` as npm (about 3 MB raw,
  R21) with `//go:embed` and runs it with wazero. Go supplies the two
  imports: `aprv.clock_now_ms` from the wall clock and `aprv.random_get`
  from `crypto/rand`. JSON crosses the boundary and decodes into the
  existing Go types. The Go module is published from a git tag, so the
  `.wasm` is committed. CI rebuilds it with the pinned toolchain (wasi-sdk,
  OpenSSL) and fails when the hash differs.
- Concurrency: a wasm instance is single-threaded. The package compiles
  the module once (`sync.Once`) and keeps a `sync.Pool` of instances.
- Floor: wazero v1.9.x declares Go 1.22 and v1.12 declares Go 1.25. The
  Go team supports only 1.26 and 1.27 today, so the plan raises the floor
  to wazero's current requirement.
- It stays cgo-free, so `CGO_ENABLED=0`, cross-compilation and `FROM
  scratch` images keep working.

### 6.6 C ABI and everything else

- `rust/ffi` stays the universal escape hatch. The migration closes its
  PORTS.md gaps:
  - `verified` flag and re-render;
  - `REQUEST_TOO_LARGE`;
  - a base64 decode entry point for the `decodeBase64` cases;
  - its own fuzz target.
- Prebuilt archives go on each GitHub Release, one per target: `.so`,
  `.dylib`, `.dll` + `.lib`, `.a`, the header, `SHA256SUMS`, build
  provenance attestations, and OpenSSL's license and NOTICE text (R12).
- OpenSSL 4.0.2 is linked statically into every library, so a consumer
  needs no OpenSSL of its own. The evidence's Linux x86_64 library needed
  only libgcc_s, libc and ld-linux, and exported only its 20 `aprv_*`
  symbols ([substrate bake-off §9](../evidence/2026-09-26-security-substrate-bakeoff.md)).
  Builds set `OPENSSL_CONFIG_DIR` to a path that does not exist, and the
  adapter never loads a config file or a default trust path (R21).
- cbindgen stays at its narrow job: it writes the header from the explicit
  `extern "C"` declarations. rustc and cargo produce the libraries.
- Examples for unpackaged languages use each language's own C FFI with
  explicit `aprv_string_free` calls: the existing Python ctypes and C++
  examples, plus C# P/Invoke and Ruby `ffi`. They are documented as
  "possible through the C ABI", never as supported packages. A SWIG `.i`
  ships as well, with the ownership typemaps from the spike
  (`newfree` → `aprv_string_free`): without them SWIG leaks every result,
  and with them the spike measured no growth over 3,000 calls.

### 6.7 crates.io (Rust)

The core crate gets its first publish when something needs it (R19;
BOOTSTRAP.md already has the steps). Rust users then get the reviewed
implementation directly, with the same version as every package. The
adapter crate `aprv-openssl` publishes first, because the core depends on
it. Until `openssl-sys` accepts `openssl-src` 400.x, a crates.io user gets
OpenSSL 3.x from the vendored feature or the system's OpenSSL, since our
`[patch.crates-io]` applies only inside this workspace (R21 open item 3).

## 7. Documentation

- Rust doc comments on `aprv-surface` are the API reference. UniFFI copies
  them into KDoc, Swift doc comments and Python docstrings; the Python spike
  showed the docstring arriving. The npm `index.d.ts` is hand-written
  (R21), so its JSDoc is written by hand from the same text and reviewed
  with the façade.
- Each package README keeps install, a quick start, runtime notes and links
  to THREAT-MODEL.md. The long per-language manuals shrink to the parts
  that are about that ecosystem: native access, musl, JNA, workerd imports.

## 8. Invariants and how CI holds them

| Invariant | Enforced by |
|---|---|
| One implementation | A CI job greps the package folders for crypto and ASN.1 imports (`java.security.Signature`, `node:crypto`, `crypto.subtle`, `cryptography`, `Security`, `crypto/x509`, `CertificateFactory`, ...) and fails on any hit outside tests. |
| No hand-written ASN.1, CMS or X.509 (R21) | `tools/check-layering.mjs` fails if `rust/src` gains a module named `asn1`, `x509`, `cms`, `chain` or `crypto`, if the core's graph gains an ASN.1, X.509 or signature crate (`der`, `rasn`, `bcder`, `asn1-rs`, `x509-*`, `cms`, `rsa`, `p256`, `p384`, ...), or if the adapter calls `ASN1_get_object`, which is hand TLV walking. The payload grammar lives only in `payload.c`'s templates. |
| The adapter is the only `unsafe` crate below the bindings | `#![forbid(unsafe_code)]` in the core and the surface, checked by the layering script (SURFACE.md §7.1). The boundary crates (`rust/ffi`, `aprv-wasm`) keep the `unsafe` their ABIs need and hold no security logic. Every `unsafe` block carries a `// SAFETY:` comment (Clippy `undocumented_unsafe_blocks`). |
| `aprv.wasm` imports exactly two functions | CI lists the module's imports (`wasm-tools`) and fails on anything other than `aprv.clock_now_ms` and `aprv.random_get`. |
| `aprv.wasm` takes no unmeasured path | Every change runs the full corpus through a host that traps on any unexpected import call, with the shipped module's own WASI stubs trapping too (section 5); any trap or any row that differs from native fails the job. |
| No ambient OpenSSL state | `OPENSSL_CONFIG_DIR` points at a path that does not exist; the adapter uses `OPENSSL_INIT_NO_LOAD_CONFIG` and no default trust paths. An isolation test plants a root in `SSL_CERT_FILE` and `SSL_CERT_DIR` and a hostile `OPENSSL_CONF`, and asserts they are ignored and never opened ([substrate bake-off §7](../evidence/2026-09-26-security-substrate-bakeoff.md)). |
| Pinned roots only | Root `certs/` stays canonical (`apple-root-watch.yml` diffs it against apple.com). `rust/certs` is the one copy, compiled in with `include_bytes!`; `check-cert-copies.mjs` checks that single copy. No binding ships or reads roots of its own. Trust-isolation tests run per binding. |
| No panic crosses a boundary | UniFFI scaffolding, C ABI `catch_unwind`, and wasm trap recovery in the JS façade and the Go pool (section 5), each with a forced-failure test. |
| Caps in one place | The core owns `MAX_RECEIPT_BYTES`, `MAX_JWS_BYTES`, `MAX_REQUEST_BYTES`, the JSON depth and the certificate caps. The bindings add none. |
| Generated code is reproducible | Pinned uniffi and cbindgen versions, and a pinned wasi-sdk and OpenSSL tarball, each checked by SHA-256. Committed outputs (Swift sources, the C header, Go `aprv.wasm`) are regenerated in CI with `git diff --exit-code`. |
| Same verdicts everywhere | Every package runs all 186 `fixtures/cases.json` cases through its binding. |
| Artifacts are what CI built | Publish jobs never cache. Every native and wasm artifact gets a SHA-256 and a build-provenance attestation. Post-publish smoke installs from the real registry. |
| Licenses ship with the code | Every package that carries OpenSSL, natively or in `aprv.wasm`, ships OpenSSL's license and NOTICE text; `aprv.wasm` also ships wasi-libc's and Rust std's (R12). A package-content check in release fails when one is missing. |
| Floors are tested | Java 8 on Temurin 8, Node 20, Python 3.10, Swift 6.2 (Linux) and the Go floor all keep their CI legs, now against the binding. |
