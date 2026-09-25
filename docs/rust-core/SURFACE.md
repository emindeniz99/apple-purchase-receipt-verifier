# aprv-surface: the binding-neutral contract

Status: **proposal, 2026-09-25.** It refines ARCHITECTURE.md §2-§4 and
DECISIONS.md R3 and R10. The owner raised the rule it rests on:

> The binding generator must never become the architecture.

## 1. Three layers, one direction

```text
adapter crates      aprv-uniffi, aprv-wasm, rust/ffi (C ABI), aprv-wasi, [future: jni, pyo3, ...]
      │  may depend on a generator; own presentation, loading, ergonomics
      ▼
aprv-surface        portable semantic model + checked conversions
      │  depends on the core only; no generator, no runtime, no wire format
      ▼
core                apple-purchase-receipt-verifier: every security decision
                    depends on no binding technology
```

- **Core:** parses, verifies and decides. It stays idiomatic Rust
  (builders, `SystemTime`, `serde_json::Map`, `#[non_exhaustive]`, `Arc`)
  and never bends toward a generator.
- **Surface:** turns core values into boring portable values and back,
  with checked conversions. It holds no crypto, no parsing, no policy, and
  no language or runtime concept.
- **Adapters:** present the surface in one language. Allowed: names,
  overloads, options objects, `Date`/`Instant`/`datetime`, `AutoCloseable`,
  wasm loading, trap recovery. Not allowed: a capability or a security rule
  of their own.

Reviewing security means reviewing the core. Reviewing an adapter is
mechanical: convert input, call the surface, convert output, map the error.

## 2. How the current plan measures up

| # | Question | Finding | Change |
|---|---|---|---|
| 1 | Is the core coupled to a binding technology today? | **No.** The core has 9 dependencies and none is a generator; `deny.toml` bans network and trust-store crates. **But the plan would couple it:** ARCHITECTURE §4 adds an optional `js-sys` dependency to the core for the wasm clock. | Section 4.1: the clock seam moves to an adapter-installed hook, so the core never depends on `js-sys`. |
| 2 | Duplicated semantic models? | **Yes, four copies:** the C ABI's `AprvReason` codes and receipt JSON view (`rust/ffi/src/lib.rs:72-118`, `391-534`), and each spike's mirror types (UniFFI, wasm, jni-rs, Diplomat), each with its own token-to-enum table. | The surface owns `Reason`, `Environment`, the records and the error types once. Adapters map from them. |
| 3 | Security logic proposed for the surface? | **No,** with two watch items. The `u64` → `i64` app-apple-id check is a conversion (it rejects, never clamps). The base64 entry points must call the core's `verify_base64`; an adapter decoding base64 itself would duplicate the core's strict-base64 rules (THREAT-MODEL §3.8). | Section 5 lists what must stay in the core. |
| 4 | Language concerns leaking into the surface? | **Yes, two:** ARCHITECTURE §2 puts `#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]` on surface types, and it moves the C ABI's JSON view into the surface. That view is a wire format, which the surface is not. | Section 3.1 (UniFFI "remote" types; spike passed) and section 4.2 (`aprv-wire` crate). |
| 5 | Can the portable types carry every public capability without loss? | **Yes,** with the table in section 6. Two items need a decision: claims as JSON text, and the endpoint clock as `*_at(ms)` instead of a callback. | Section 6. |
| 6 | Java 8 | Unsigned integers are uncallable from Java through UniFFI Kotlin (measured); `&[u8]` becomes `ByteBuffer` in UniFFI 0.32. | Surface rule: no unsigned integers; bytes are `Vec<u8>`. |
| 7 | Python | `i64` → `int`, `Vec<u8>` → `bytes`, `Option` → `None`: no loss. | None. |
| 8 | JS / wasm | wasm-bindgen turns `i64` into `bigint`. Epoch-ms dates fit a double exactly; `download_id` and `app_item_id` can exceed 2^53 (the core says so). Claims JSON parsed with plain `JSON.parse` loses digits above 2^53. | The JS adapter keeps ids as `bigint`, converts dates to `Date`, and parses claims losslessly. |
| 9 | Is the C ABI independent of the generators? | **Yes, today.** It depends only on the core, and must stay that way. It lacks the FFI-safety lints (section 7.2). | It moves onto the surface and `aprv-wire`, and gains the lints. |
| 10 | Automated checks | None exist for layering. | Section 7. |

## 3. What the surface is

### 3.1 The generator stays out, measured

The 2026-09-25 spike (`neutral/` in the spike notes) built a surface crate
whose only dependency is the core. `cargo tree` found no `uniffi`,
`wasm-bindgen`, `js-sys` or `serde`. A separate adapter crate annotated the
surface's `Reason` enum and `AppReceipt` record with
`#[uniffi::remote(Enum)]` and `#[uniffi::remote(Record)]`. The generated
Python verified the genuine receipt and raised
`VerifyError.Verification(reason=Reason.WRONG_BUNDLE_ID)`.

The price: the adapter restates each type's fields. The remote macro
refers to the real type, so a field that drifts fails to compile. It never
drifts silently.

The alternative (derives behind a `uniffi` feature on the surface) saves
that restatement. It also makes the surface's source mention UniFFI, and a
future generator would need its own feature. The owner's rule favours the
remote form.

### 3.2 Type rules

| Allowed at the surface | Instead of |
|---|---|
| `bool`, `i32`, `i64`, `String` | `u8`..`u64`, `usize` (Java cannot call unsigned; JS gets `bigint`) |
| `Vec<u8>` | `&[u8]`, base64 text (except the explicit base64 entry points) |
| `Vec<T>`, `Option<T>` | iterators, `BTreeMap`, `HashMap` (a list of records keeps order and works everywhere) |
| plain records, plain enums | traits, generics, `impl Trait`, `Box<dyn ...>`, lifetimes, `#[non_exhaustive]` |
| epoch milliseconds as `i64` | `SystemTime`, generator timestamp types (each adapter picks `Instant`, `Date`, `datetime`) |
| verified claims as JSON text | `serde_json::Value` in the public surface |
| one error enum: `Verification { reason, detail }`, `Configuration { detail }` | the core's `CoreError` hierarchy |

### 3.3 Conversion rules

- `TryFrom` wherever a value can fail to fit, `From` only when it is
  provably total. No `as` casts; `clippy::cast_*` lints denied in the crate.
- Dates go through the core's own `datetime::unix_millis_of`. The core
  builds every date from epoch milliseconds, negatives included
  (`datetime.rs:22-33`), so the round trip is exact.
- Any core value that fails conversion becomes `Reason::InternalError`.
  **A conversion failure can never turn into a success.**
- A core field left out of the surface is listed in section 6 with the
  reason.

## 4. Changes to the plan

### 4.1 The wasm clock moves out of the core

- **Current state:** ARCHITECTURE §4 and R10 give the core an optional
  `js-clock` feature that calls `js_sys::Date::now()` on
  `wasm32-unknown-unknown`.
- **Problem:** the core would depend on the wasm-bindgen ecosystem.
- **Proposed state:** the core exposes one platform hook that exists only
  on that target. On every other target it does not exist, so native users
  cannot move the clock.
  ```rust
  #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
  pub mod platform {
      /// Installs the host's wall clock once. Only the wasm adapter calls it.
      pub fn install_clock(now: fn() -> std::time::SystemTime) -> Result<(), AlreadyInstalled>;
  }
  ```
  Until a clock is installed, a verification that needs "now" fails with
  `InternalError` instead of trapping. The wasm adapter installs
  `Date.now()` in its init function.
- **Why it is better:** the core stays free of `js-sys`, and THREAT-MODEL
  §3.5 still holds: no verifier API takes a caller clock.
- **Alternatives:** `web-time` (still wasm-bindgen underneath); passing
  `now` into the verifiers (breaks §3.5).
- **Migration and compatibility:** internal only; nothing public changes on
  native targets.
- **CI:** the layering check in section 7 fails if the core's graph ever
  contains `js-sys` or `wasm-bindgen`.

### 4.2 The JSON view gets its own crate

- **Current state:** the plan moves the C ABI's receipt JSON view into the
  surface.
- **Problem:** that view is a wire format (camelCase names, `...Hex`
  mirrors, ISO dates). The surface would become a serialization protocol,
  and every adapter would inherit one adapter's naming choices.
- **Proposed state:** a small `aprv-wire` crate converts surface values to
  JSON. The C ABI and the Go `wasi` adapter use it; UniFFI and jni-rs never
  see it. The wasm adapter uses it only if it returns JSON to its
  TypeScript layer.
- **Why it is better:** one serializer, and it is never mistaken for the
  contract.
- **Migration:** code moves out of `rust/ffi` unchanged in behaviour;
  the C ABI's C++ and ctypes conformance runs prove it.
- **CI:** `aprv-surface` may not depend on `serde` or `serde_json`
  (section 7).

### 4.3 Adapters reach the core only through the surface

- **Current state:** the spikes call the core directly.
- **Proposed state:** adapters depend on `aprv-surface` and not on the core
  crate. The one exception is the C ABI, which must return the core's own
  verifyReceipt JSON bytes; it reaches them through the surface's endpoint
  result (`to_json`), so it needs no direct edge either.
- **CI:** section 7, rule 3.

### 4.4 Capability parity becomes a checked list

- **Current state:** parity lives in PORTS.md, checked by hand.
- **Proposed state:** `rust/bindings/surface/CAPABILITIES.toml` names every
  operation the surface offers. Each adapter's test suite carries a test
  that calls each named operation once, and CI fails when an operation has
  no test in an adapter.
- **Why it is better:** "Java has it, Python does not" becomes a failing
  build rather than a README row.

### 4.5 Where the current plan is already right, and stays

- The core stays at `rust/` (the published crate path), not `rust/core/`.
  A workspace with the core as root package plus members gives the same
  boundary without moving the crate.
- One shared `fixtures/cases.json` replayed by every package (MIGRATION
  acceptance test 3).
- No callbacks across the boundary: the endpoint takes `request_date_ms`
  per call, so no adapter needs a clock object.
- cbindgen and an explicit, small C ABI, not safer-ffi.

## 5. Things that stay in the core, whatever an adapter wants

Certificate-chain verification, root selection and pinning, Apple marker
OIDs, signature algorithms, receipt parsing, strict base64, JWS parsing
and validation, environment acceptance, bundle-id and app-apple-id checks,
signed-date and validity-window policy, device-hash comparison, input
caps, JSON depth, unknown-attribute handling, verifyReceipt status and
routing (21007/21008), and the reason vocabulary.

An adapter that implements any of these has failed the architecture, even
when its output agrees.

## 6. The surface, field by field

Core types in the left column, surface types in the right. "Exact" means
the conversion loses nothing.

| Core | Surface | Conversion |
|---|---|---|
| `Reason` (13, `#[non_exhaustive]`) | `Reason` (13) plus `token()` | By token. A test walks `Reason::all()` plus the two endpoint-only reasons and fails on a missing or duplicate mapping. **Exact.** |
| `Environment` (4) | `Environment` (4) | Both directions. **Exact.** |
| `VerificationError { reason, detail }` | `Error::Verification { reason, detail }` | **Exact.** |
| `ConfigError { detail }` | `Error::Configuration { detail }` | **Exact.** |
| `TrustAnchor` | input `Vec<u8>` (DER) or `String` (PEM) | Parsed by the core's `from_der` / `from_pem`, never by an adapter. |
| `AppReceipt` | `AppReceipt` | Strings and bytes 1:1 (`bundle_id_bytes` included); three dates (`creation_date`, `original_purchase_date`, `expiration_date`) to `Option<i64>` ms; `app_item_id`, `download_id`, `version_external_identifier` stay `i64`; `in_app_purchases` to `Vec<InAppPurchase>`. **Exact.** |
| `BTreeMap<u32, Vec<Vec<u8>>>` unknown attributes | `Vec<UnknownAttribute { attribute_type: i64, values: Vec<Vec<u8>> }>`, sorted by type | `u32` → `i64` is total. **Exact** (the order is the map's own). |
| `InAppPurchase` (11 fields + unknown attributes; four dates) | `InAppPurchase` | As above. **Exact.** |
| `TransactionPayload` (23 modelled fields + `claims`) | same fields + `claims_json: String` | Modelled fields 1:1 (all `Option<String>` / `Option<i64>`). Claims re-serialised by `serde_json` from the map the core verified. **Exact** for what the core holds. |
| `AppTransactionPayload` (12 + `claims`) | same | As above. |
| `verify_raw` → `Claims` | `claims_json: String` | As above. |
| `ReceiptVerifier` + builder | `ReceiptVerifier::new(bundle_id, roots: Option<...>)`; `verify`, `verify_base64`, `verify_with_device_guid`, `verify_base64_with_device_guid` | The builder stays in the core; the surface constructor calls it. |
| free `verify_receipt_core` | `verify_receipt_core(bytes, roots)` | Present in every port today, so kept for parity. |
| `JwsVerifier` + builder (`app_apple_id: u64`) | `JwsVerifier::new(bundle_id, environments: Vec<Environment>, app_apple_id: Option<i64>, roots)` | `i64` → `u64` by `TryFrom`; a negative id is a `Configuration` error, never a clamp. |
| `VerifyReceiptEndpoint` + builder (`clock: Arc<dyn Clock>`) | `VerifyReceiptEndpoint::new(environment, roots)` with `*_at(request_date_ms)` variants | The clock only feeds `request_date`, so a per-call value covers every use, the conformance cases' pinned clocks included. **Decision recorded:** no callback crosses the boundary. |
| `VerifyReceiptRequest { receipt_data, password, exclude_old_transactions }` | same record | Kept: Java's `Map` overload and Go's struct entry point exist today. |
| `VerifyReceiptResult` | object: `status`, `verified`, `receipt`, `failure_reason`, `failure_cause`, `request_date_ms`, `to_json`, `to_json_in(env)` | The core renders the JSON; the surface holds the core value, so `to_json_in` never verifies again. |
| `VerifyReceiptResponse` (typed response) | not exposed; `to_json` carries it | Every port can parse the JSON into its own map if it wants one. |
| `MAX_RECEIPT_BYTES`, `MAX_JWS_BYTES`, `MAX_REQUEST_BYTES`, `MAX_JSON_NESTING_DEPTH` | `limits()` → record of `i64` | Exact. |
| Public low-level modules (`asn1`, `x509`, `cms`, `crypto`, `datetime`), `Clock`, `Tlv<'a>` | **not exposed** | Rust-only building blocks. Foreign packages get verdicts, not parsers. |

## 7. Enforcement

### 7.1 Layering, checked from `cargo metadata`

A `tools/check-layering.mjs` (Node, no dependencies, like the other tools)
reads `cargo metadata --format-version 1` for the workspace and fails when:

1. **The core's dependency graph** (normal and build, every target) contains
   any of `uniffi*`, `wasm-bindgen*`, `js-sys`, `web-sys`, `pyo3*`, `jni*`,
   `diplomat*`, `napi*`, `cbindgen`, `safer-ffi`, `serde_derive`.
2. **The surface's graph** contains anything outside the core's own graph,
   or any crate from rule 1.
3. **An adapter** depends on the core directly instead of through the
   surface.
4. **`unsafe`** appears outside `rust/ffi` and `rust/bindings/wasi`
   (checked by `#![forbid(unsafe_code)]` in every other crate, and the
   script verifies the attribute is present).

cargo-deny adds a second, independent guard on rule 1: the core's
`deny.toml` bans list gains the generator crates.

### 7.2 The C ABI

- Crate attributes: `#![deny(improper_ctypes, improper_ctypes_definitions,
  unsafe_op_in_unsafe_fn, ffi_unwind_calls)]`, Clippy
  `not_unsafe_ptr_arg_deref` and `missing_safety_doc` as errors. Today the
  crate has only `warn(clippy::pedantic)` (`rust/ffi/src/lib.rs:40-42`).
- Every export keeps its `catch_unwind` guard. The existing source-scanning
  test stays, and stays the enforcement.
- Every `unsafe` block carries a `// SAFETY:` comment (Clippy
  `undocumented_unsafe_blocks`).
- New CI: compile the header as C99 with gcc and clang, and C++ with MSVC
  (C++ already runs on three OSes); an exported-symbol allowlist diffed
  against `nm`/`dumpbin`; ASan and UBSan runs of the C++ conformance on
  Linux; a fuzz target that enters through the `extern "C"` functions; a
  repeated allocate/free loop under a leak checker.

### 7.3 Parity and meaning

- Reason parity: every adapter's test lists its reason names and compares
  them with the surface's; one test per language.
- Capability parity: `CAPABILITIES.toml` (section 4.4).
- Verdict parity: all 186 `fixtures/cases.json` cases through every
  adapter.
- Conversion tests on the surface: a property test that round-trips
  generated core values through the surface and back, including negative
  and pre-1970 dates, `u32::MAX` attribute types, `i64::MAX` ids, and
  `None` against empty string and empty bytes.
- Failure-mapping test: every forced conversion failure and every caught
  panic yields `InternalError`, never a verified result.

## 8. Adapter replaceability, as a table

| Package | Today's adapter | Can become, without touching core or surface |
|---|---|---|
| JVM | UniFFI Kotlin (JNA) | jni-rs + plain Java; UniFFI's JNI backend once released; Diplomat; FFM when the floor reaches 22 |
| Python | UniFFI | PyO3 |
| JS | wasm-bindgen | another wasm toolchain |
| Swift | UniFFI | swift-bridge, or a C-ABI module |
| Go | wazero + wasi | cgo + C ABI (the on-demand fast path) |
| Everything else | C ABI + cbindgen | unchanged |
| HTTP (under evaluation) | sidecar server | a spike is running; it would be one more adapter over the surface |
