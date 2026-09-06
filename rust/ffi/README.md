# apple-purchase-receipt-verifier — the C ABI

Offline verification of Apple App Store JWS payloads and legacy PKCS#7 app
receipts, exposed as a C ABI so that C, C++ and any FFI-capable runtime —
Elixir NIFs, Lua, Python ctypes, .NET P/Invoke, Java FFM — can call the Rust
implementation directly. The pattern is AWS's: one C library under the
language SDKs rather than one reimplementation per language.

It is a thin wrapper. Every verification decision, every parser and every
trust rule is the Rust library's, unchanged; this crate adds a calling
convention, a JSON encoding and a panic boundary, and nothing else.

## Build

```bash
cargo build --locked --manifest-path rust/ffi/Cargo.toml            # debug
cargo build --locked --release --manifest-path rust/ffi/Cargo.toml  # release
```

That produces both a `cdylib` and a `staticlib` in `rust/ffi/target/<profile>`:

| Platform | Shared | Static |
|---|---|---|
| Linux | `libapple_purchase_receipt_verifier_ffi.so` | `libapple_purchase_receipt_verifier_ffi.a` |
| macOS | `libapple_purchase_receipt_verifier_ffi.dylib` | `libapple_purchase_receipt_verifier_ffi.a` |
| Windows | `apple_purchase_receipt_verifier_ffi.dll` (+ `.dll.lib`) | `apple_purchase_receipt_verifier_ffi.lib` |

The header is `include/apple_purchase_receipt_verifier.h`. cbindgen generates
it from `src/lib.rs`; it is committed, and CI regenerates it and fails on any
diff, so it cannot drift from the symbols the library exports. Regenerate it
with the pinned version:

```bash
cargo install cbindgen --locked --version 0.29.0
cd rust/ffi && cbindgen --config cbindgen.toml \
  --crate apple-purchase-receipt-verifier-ffi \
  --output include/apple_purchase_receipt_verifier.h
```

The crate builds on the same Rust 1.74.0 floor as the library, from a
committed `Cargo.lock` resolved for that floor:

```bash
CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback cargo +stable generate-lockfile
```

**Phase 2 — prebuilt binaries — does not exist yet.** There is no
`.so`/`.dylib`/`.dll` attached to a release and no package on any registry.
Building from source is the only supported path today; see `ROADMAP.md`.

## The surface

Nineteen symbols. Three opaque handles, seven verification calls, one result
struct, one free function.

```c
const char *aprv_version(void);

AprvJwsVerifier     *aprv_verifier_new_jws(bundle_id, environments, app_apple_id, max_age_secs);
AprvJwsVerifier     *aprv_verifier_new_jws_with_roots(..., ders, lens, count);
void                 aprv_verifier_free_jws(AprvJwsVerifier *);

AprvReceiptVerifier *aprv_verifier_new_receipt(bundle_id);
AprvReceiptVerifier *aprv_verifier_new_receipt_with_roots(bundle_id, ders, lens, count);
void                 aprv_verifier_free_receipt(AprvReceiptVerifier *);

AprvReceiptEndpoint *aprv_endpoint_new(environment);
AprvReceiptEndpoint *aprv_endpoint_new_with_roots(environment, ders, lens, count);
void                 aprv_endpoint_free(AprvReceiptEndpoint *);

int32_t aprv_verify_transaction(v, const char *jws, AprvResult *out);
int32_t aprv_verify_app_transaction(v, const char *jws, AprvResult *out);
int32_t aprv_verify_raw(v, const char *jws, AprvResult *out);
int32_t aprv_verify_receipt_der(v, const uint8_t *der, size_t len, AprvResult *out);
int32_t aprv_verify_receipt_base64(v, const char *b64, AprvResult *out);
int32_t aprv_verify_receipt_der_with_device_guid(v, der, len, guid, guid_len, AprvResult *out);
int32_t aprv_verify_receipt_base64_with_device_guid(v, b64, guid, guid_len, AprvResult *out);
int32_t aprv_verify_receipt_endpoint_json(e, const char *request, char **response);

void aprv_string_free(char *);
```

Trust anchors default to the three Apple roots the Rust library embeds. The
`_with_roots` variants take DER certificates the caller owns, for tests and
for a deployment that pins its own; the bytes are parsed during the call and
never retained. Passing no anchors is not a way to disable pinning — there is
no code path to an operating-system trust store to disable.

`accepted_environments` is a bitmask of `AprvEnvironment` values. An unknown
bit is refused rather than ignored, because silently dropping one builds a
verifier that accepts less than the caller asked for and reports the
difference as `WRONG_ENVIRONMENT` on a genuine payload.

### Why JSON is the interchange

`AprvResult.json` carries the answer: the claim object for the JWS calls, a
normalised receipt object for the receipt calls, Apple's own response body
for the endpoint call.

A verified transaction is an open-ended JSON claim set and a verified receipt
is a tree with repeated groups and raw byte attributes. Modelling either as C
structs would put every field of a wire format Apple extends at will into the
ABI, and every field Apple added would then be a breaking change for every
consumer in every language. One UTF-8 JSON document instead keeps the ABI at
nineteen symbols and moves the schema question into a parser the caller
already has.

The receipt encoding is the shared cross-port view the conformance vectors
are written against: dates as ISO-8601 UTC strings, byte attributes as
lowercase hex (mirrored under `<name>Hex`), `unknownAttributes` as an object
keyed by the attribute number. JWS claims are passed through exactly as Apple
ships them, epoch-millisecond dates included.

### Status codes are stable and append-only

`AprvResult.status` — also the return value — has two bands, and the split is
the point.

* **`1`–`11`** is a verdict about the input: the canonical `Reason`
  vocabulary every port of this library shares, in the order that vocabulary
  declares it. These numbers never change and are never reused. Adding a
  twelfth is a deliberate change to `fixtures/cases.schema.json`, `PLAN.md`
  and all nine ports at once, and it would be `12`.
* **`100`+** is a mistake in the call itself — a null pointer, a non-UTF-8
  string, a rejected configuration, a caught panic — and means *nothing about
  the input was checked*. A caller that treats `APRV_REASON_NULL_POINTER` as
  "the receipt is forged" is reporting its own bug as an attack.

`reason_codes_mirror_the_library` in `src/lib.rs` asserts the first band
against the library's own `Reason::all()`, so the promise is mechanical
rather than written down.

On any non-zero status, `json` is `{"reason":"<token>","message":"<detail>"}`.
The token is the `SCREAMING_SNAKE` spelling; the message is short,
non-sensitive, and never contains receipt bytes, claims or key material.
Match on the status or the token — never parse the message.

### Ownership

* `aprv_version()` returns a static string. **Never free it.**
* Every `aprv_*_new*()` returns a handle the caller owns, or `NULL` if an
  argument was rejected. Release it with the matching `aprv_*_free()`.
  Freeing `NULL` is a no-op; freeing twice is undefined behaviour.
* `AprvResult.json` and the endpoint's `*response_json` are owned by the
  caller. Release each with `aprv_string_free()` — **never** with the C
  runtime's `free()`, because the allocator is Rust's.
* Every input pointer is borrowed for the duration of the call. Nothing
  retains it and nothing is written through it.

### Panic safety

Unwinding out of an `extern "C"` function is undefined behaviour. Every
exported function is a single call to an internal guard that runs the real
body inside `std::panic::catch_unwind` and reports a caught panic as
`APRV_REASON_PANIC` (or a `NULL` handle). This is not a convention anyone has
to remember: `every_exported_function_is_guarded` reads `src/lib.rs` and
fails if a `#[no_mangle]` function is ever added that does not do it.

Nothing is expected to panic — the library target denies `unwrap`, `expect`,
slice indexing and `panic!` — so `APRV_REASON_PANIC` is a bug report, not a
verdict.

### Thread safety

A handle is immutable once built and safe to share: any number of threads may
verify through the same handle at the same time. Freeing a handle while
another thread is inside a call on it is not allowed. Strings the ABI hands
out belong to whoever received them and are not shared.

## Tests

Three layers, all of them driving the same shared vectors the other nine
ports answer.

```bash
# 1. the ABI's own edge cases: null, non-UTF-8, refused configs, the guard
cargo test --locked --manifest-path rust/ffi/Cargo.toml

# 2. fixtures/cases.json from C++17 — the primary harness
cargo build --locked --manifest-path rust/ffi/Cargo.toml
node tools/gen-cases-manifest.mjs rust/ffi/target/manifest
cmake -S rust/ffi/examples/cpp -B rust/ffi/target/cppbuild
cmake --build rust/ffi/target/cppbuild --config Debug
rust/ffi/target/cppbuild/bin/aprv_conformance rust/ffi/target/manifest

# 3. the same vectors from a language with no compiler in the loop
python3 rust/ffi/tests/conformance.py rust/ffi/target/debug
```

**Layer 2 is the primary evidence.** A passing C++ run says the header
compiles as C++, the symbols link, and the answers match the vectors — the
whole compiled-toolchain path, on all three operating systems in CI.
`tools/gen-cases-manifest.mjs` flattens `cases.json` into a line-oriented
manifest first, because a dependency-free C++17 program cannot parse JSON,
base64-decode a fixture or check its SHA-256; the generator does all three
and hands over plain files.

**Layer 3 is what "any FFI-capable language" means, tested.** ctypes reads
`cases.json` itself and calls the same symbols, and it checks the nested
field paths the C++ harness cannot reach — `receipt.bundle_id`,
`inAppPurchases[productId=…].expiresDate`, `unknownAttributes[9999][0]`.

Both harnesses run 92 of the 104 cases and skip the same 12, for the same
stated reason: those cases pin a clock, and the ABI has no clock argument —
injecting a `dyn Clock` across a C boundary would mean a callback, and this
surface is deliberately callback-free. The skip is asserted, not assumed: a
case that becomes unrunnable for any *other* reason fails the run. The
staleness rule those cases exercise is covered instead by a unit test that
does not need a clock, because a one-second maximum against a 2024 fixture is
stale on any real one.

## Example

`examples/cpp/example.cpp` is the whole ABI on one page: a StoreKit 2
transaction verified against the fixture root that signed it, and the genuine
sandbox receipt verified against the bundled Apple roots.

```bash
rust/ffi/target/cppbuild/bin/aprv_example \
  fixtures/generated/jws-root.der \
  fixtures/generated/transaction.jws \
  fixtures/generated/receipt-b64/01-genuine.txt
```

```
apple-purchase-receipt-verifier 0.4.0

transaction: status 0
{"bundleId":"com.example.app","environment":"Sandbox","inAppOwnershipType":"PURCHASED", …}

receipt: status 0
{"appVersion":"2","bundleId":"dev.bonzer.weeka.app","creationDate":"2025-12-26T18:39:47Z", …}
```

`examples/python/example.py` is the same page from Python, with nothing but
the standard library. ctypes opens the shared library at run time and calls
the exported symbols by name, so there is no compiler and no package in the
loop; the conformance harness in `tests/` is built the same way.

```bash
python3 rust/ffi/examples/python/example.py rust/ffi/target/release
```

## Elixir

`examples/elixir/` is a third consumer, in a language that cannot call C at
all. The BEAM has no foreign function interface: a native call from Elixir is
a NIF, a C function the emulator loads and calls directly. So an Elixir
application that wants this library writes one piece of C against the header
above, and `examples/elixir/c_src/aprv_nif.c` is that piece, with a Mix
project and the shared vectors on top of it.

It is an example rather than a tenth port. Nothing is published to Hex, the
Mix project has no Hex dependencies, and `SUPPORT-MATRIX.md` has no row for
it. If you want Elixir, you build the shim.

```bash
cargo build --locked --release --manifest-path rust/ffi/Cargo.toml
node tools/gen-cases-manifest.mjs rust/ffi/target/manifest
cd rust/ffi/examples/elixir && mix compile && mix test && mix run example.exs
```

```
apple-purchase-receipt-verifier 0.4.0 — C ABI conformance over NIFs
92 passed, 0 failed, 12 not runnable through the C ABI (no clock argument)
```

The same 92 cases and the same 12 clock skips as the C++ harness, which is
the point of running it: two consumers, one manifest, identical counts.

Two things the shim does that a C caller does not have to think about.

**Handles are released by the garbage collector.** Each handle from
`aprv_*_new*` lives in an `ErlNifResourceType` whose destructor calls the
matching `aprv_*_free`, so dropping the last Elixir reference frees it.
Strings are copied into Erlang binaries and released with `aprv_string_free`
before the NIF returns, so no Rust allocation outlives a call.

**Verification runs on a dirty scheduler.** A NIF that does not return within
about a millisecond delays every process on its scheduler thread, and
verifying a chain takes longer than that. Every call that parses or verifies
carries `ERL_NIF_DIRTY_JOB_CPU_BOUND`.

`examples/elixir/README.md` covers the rest, including why the example reads
JSON with a decoder of its own instead of depending on Jason.
