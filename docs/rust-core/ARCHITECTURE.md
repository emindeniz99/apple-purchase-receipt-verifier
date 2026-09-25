# Target architecture: one Rust verifier, thin bindings

Status: **proposal**, waiting on the owner decisions listed in
[DECISIONS.md](./DECISIONS.md). Where a section depends on an open
decision, it names the decision (R-number) and describes the recommended
option.

## 1. The shape

```text
                 SECURITY REVIEW BOUNDARY (deep human review)
┌──────────────────────────────────────────────────────────────────────┐
│ rust/  crate apple-purchase-receipt-verifier  (crates.io)            │
│   ASN.1/DER, X.509, CMS, JWS, chain policy, pinned roots, caps,      │
│   base64 rules, JSON depth, Apple semantics, Reason vocabulary,      │
│   verifyReceipt endpoint.  #![forbid(unsafe_code)], no panics.       │
└──────────────────────────────┬───────────────────────────────────────┘
                               │ plain Rust API
┌──────────────────────────────▼───────────────────────────────────────┐
│ rust/bindings/surface/  crate aprv-surface  (unpublished)            │
│   binding-shaped records and errors, conversions, the JSON view.     │
│   #![forbid(unsafe_code)]. Mechanical review.                        │
└─────┬───────────────────┬──────────────────┬──────────────────┬──────┘
      │                   │                  │                  │
┌─────▼─────┐     ┌───────▼──────┐    ┌──────▼──────┐    ┌──────▼──────┐
│ uniffi/   │     │ wasm/        │    │ wasi/       │    │ rust/ffi/   │
│ UniFFI    │     │ wasm-bindgen │    │ ptr+len ABI │    │ C ABI       │
│ cdylib +  │     │ wasm32-      │    │ wasm32-     │    │ cdylib +    │
│ staticlib │     │ unknown-     │    │ wasip1      │    │ staticlib + │
│           │     │ unknown      │    │ (R6)        │    │ cbindgen .h │
└──┬──┬──┬──┘     └──────┬───────┘    └──────┬──────┘    └──────┬──────┘
   │  │  │               │                   │                  │
 Kotlin Swift Python   JS glue            Go via wazero      C, C++, SWIG,
   │                     │                                    Elixir NIF,
 Java (JVM)         one npm package                          anything else
```

A fix in `rust/` reaches every package on the next release. No package
carries a parser, a signature check or a trust decision of its own.

## 2. Crates and folders

```text
rust/                          core crate, unchanged name, published to crates.io
rust/Cargo.toml                gains [workspace] members = ["ffi", "bindings/*"]
rust/bindings/surface/         aprv-surface: the cross-language API model
rust/bindings/uniffi/          aprv-uniffi: #[uniffi::export] over aprv-surface
rust/bindings/uniffi/uniffi.toml   per-language names, packages, disable_java_cleaner
rust/bindings/wasm/            aprv-wasm: #[wasm_bindgen] over aprv-surface
rust/bindings/wasi/            aprv-wasi: exports for wazero (only if R6 = wazero)
rust/ffi/                      existing C ABI, rebased on aprv-surface's JSON view
rust/ffi/swig/                 apple_purchase_receipt_verifier.i and examples
rust/fuzz/                     unchanged, plus targets for the JSON view
java/  node/  python/  swift/  go/   package builds, façades, binding tests
```

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
- The UniFFI derives go on the surface types behind
  `#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]`. The core
  carries no binding annotation at all, which is the brief's rule.
- The C ABI's cross-port JSON view (today in `rust/ffi/src/lib.rs:391-534`)
  moves here as a serde model. The C ABI, the wasi adapter and the npm
  façade then share one serializer.

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

On `wasm32-unknown-unknown` the standard library's `SystemTime::now()`
panics, and the spikes measured that trap. The fix stays inside the core:

- The core gets one crate-private `fn system_now() -> SystemTime`.
- It uses `std::time::SystemTime::now()` on every target except
  `all(target_arch = "wasm32", target_os = "unknown")`.
- On that target it uses `js_sys::Date::now()`, behind an optional `js-clock`
  feature. The wasm adapter enables the feature.
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
| wasm-bindgen | `panic = "abort"`: the instance **traps**, and its memory may be left inconsistent | The JS façade catches `WebAssembly.RuntimeError`, drops the instance, instantiates a fresh one on the next call, and throws `VerificationError(INTERNAL_ERROR)`. CI replays the hostile corpora through the wasm build and fails on any trap. |
| wasi (Go) | wazero returns an error from the call and the module is unusable | Same pattern in Go: the pool discards the instance and the call returns `INTERNAL_ERROR`. |

The endpoint's "never fails" promise rests on `catch_unwind` at
`endpoint.rs:510`, which does nothing under `panic = "abort"`. On wasm the
façade provides that promise instead.

The core's lint wall (`unwrap`, `expect`, indexing, `panic` all denied)
remains the first line of defence. Every row above only covers the case
where that wall fails.

## 6. Packages

### 6.1 Maven Central (Java, Kotlin)

- Coordinates stay `io.github.emindeniz99:apple-purchase-receipt-verifier`.
  Today's classes sit in three packages: the root, `.jws` and `.receipt`.
  UniFFI's `package_name` puts every generated class in one package, so the
  generated code goes to `...applepurchasereceiptverifier.internal`. The Java
  façade (option B in the spike notes) keeps today's classes and import paths
  (`.jws.JwsVerifier`, `.receipt.ReceiptVerifier`, ...). Without the façade,
  the import paths break, and R13 would have to list that.
- Contents: the compiled generated Kotlin (`jvmTarget = 1.8`), a small Java
  façade if the PoC needs one, and natives at JNA's resource paths:
  `linux-x86-64`, `linux-aarch64`, `darwin-x86-64`, `darwin-aarch64`,
  `win32-x86-64`, `win32-aarch64`.
- Runtime dependencies change from Bouncy Castle and Jackson (about
  11.8 MB) to `kotlin-stdlib` (Java 8 bytecode) and `jna` 5.x (Java 8
  bytecode). The jar grows by the natives: about 1.2 MB per target before
  stripping and compression.
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
  localizes every non-`uniffi_`/`ffi_` symbol, and a CI check lists the
  exported symbols.

### 6.4 npm (JavaScript, TypeScript)

- There is one package, `apple-purchase-receipt-verifier`, still with zero
  runtime `dependencies`. The generated glue and the `.wasm` ship inside it.
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
    "node":       "./dist/node/index.js",    // reads the .wasm from disk, initSync
    "default":    "./dist/web/index.js"
  },
  "./web": "./dist/web/index.js"             // kept: 0.x users import it today
}
```

- Sync or async: today's `.` build is **synchronous** (`node/src/jws.ts:62`,
  `receipt.ts:284`, `verify-receipt-endpoint.ts:101`), and `/web` is
  **async** (`web/jws.ts:58`, `web/receipt.ts:173`). Both contracts stay:
  - `.` stays synchronous on every runtime. A wasm call is synchronous once
    the module is loaded. Node and workerd load it synchronously
    (`initSync`); browsers and Deno load it with top-level `await` at
    import, so the calls after the import are synchronous. Deno users of
    `.` today keep sync calls.
  - `./web` keeps returning Promises. It is a thin async wrapper over the
    same module, so no 0.x caller of `/web` changes a line.
- The TypeScript façade keeps the rest of today's API: the options objects,
  the `Reason` const, `VerificationError extends Error` with `.reason`,
  `Date` for receipt dates, and `bigint` ids. It also owns trap recovery
  (section 5).
- Runtimes kept and tested: Node 20/22/24/26, Bun, Deno, workerd (three
  compatibility dates), Vercel Edge via `@edge-runtime/vm`, and a browser
  (new, cheap once the code is wasm).
- Runtimes dropped: Fastly Compute JS and Akamai EdgeWorkers. Neither can
  run WebAssembly (R5).
- Size: the wasm is 374 KB raw and 133 KB gzip before `wasm-opt`. CI sets a
  budget at the measured value plus 10% once the real build exists.
- Performance: see R4. The wasm build costs about 5.3 times the current
  `node:crypto` build per verification, and 3.4 to 3.6 times the `/web`
  build.

### 6.5 Go (R6, recommended: wazero)

- The module path and package `applereceipt` stay. The public Go API stays
  as it is: the options structs, `Reason`, `errors.Is`, and
  `VerifyReceiptResult`.
- Inside, the module embeds `aprv.wasm` (a `wasm32-wasip1` build of
  `aprv-wasi`, about 470 KB) with `//go:embed` and runs it with wazero.
  JSON crosses the boundary and decodes into the existing Go types. The Go
  module is published from a git tag, so the `.wasm` is committed. CI
  rebuilds it with the pinned toolchain and fails when the hash differs.
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
  `.dylib`, `.dll` + `.lib`, `.a`, the header, `SHA256SUMS`, and build
  provenance attestations.
- cbindgen stays at its narrow job: it writes the header from the explicit
  `extern "C"` declarations. rustc and cargo produce the libraries.
- `rust/ffi/swig/apple_purchase_receipt_verifier.i` with Java, Python and
  C# examples, documented as "possible through the C ABI", never as
  supported packages.

### 6.7 crates.io (Rust)

The core crate gets its first publish before any binding ships (BOOTSTRAP.md
already has the steps). Rust users then get the reviewed implementation
directly, with the same version as every package.

## 7. Documentation

- Rust doc comments on `aprv-surface` are the API reference. UniFFI copies
  them into KDoc, Swift doc comments and Python docstrings; the Python spike
  showed the docstring arriving. wasm-bindgen copies them into the `.d.ts`
  as JSDoc.
- Each package README keeps install, a quick start, runtime notes and links
  to THREAT-MODEL.md. The long per-language manuals shrink to the parts
  that are about that ecosystem: native access, musl, JNA, workerd imports.

## 8. Invariants and how CI holds them

| Invariant | Enforced by |
|---|---|
| One implementation | A CI job greps the package folders for crypto and ASN.1 imports (`java.security.Signature`, `node:crypto`, `crypto.subtle`, `cryptography`, `Security`, `crypto/x509`, `CertificateFactory`, ...) and fails on any hit outside tests. |
| Pinned roots only | Root `certs/` stays canonical (`apple-root-watch.yml` diffs it against apple.com). `rust/certs` is the one copy, compiled in with `include_bytes!`; `check-cert-copies.mjs` checks that single copy. No binding ships or reads roots of its own. Trust-isolation tests run per binding. |
| No panic crosses a boundary | UniFFI scaffolding, C ABI `catch_unwind`, and wasm trap recovery (section 5), each with a forced-failure test. |
| Caps in one place | The core owns `MAX_RECEIPT_BYTES`, `MAX_JWS_BYTES`, `MAX_REQUEST_BYTES`, the JSON depth and the certificate caps. The bindings add none. |
| Generated code is reproducible | Pinned uniffi, wasm-bindgen and cbindgen versions. Committed outputs (Swift sources, the C header, Go `aprv.wasm`) are regenerated in CI with `git diff --exit-code`. |
| Same verdicts everywhere | Every package runs all 186 `fixtures/cases.json` cases through its binding. |
| Artifacts are what CI built | Publish jobs never cache. Every native and wasm artifact gets a SHA-256 and a build-provenance attestation. Post-publish smoke installs from the real registry. |
| Floors are tested | Java 8 on Temurin 8, Node 20, Python 3.10, Swift 6.2 (Linux) and the Go floor all keep their CI legs, now against the binding. |
