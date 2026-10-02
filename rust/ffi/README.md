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

That produces both a `cdylib` and a `staticlib` in `rust/target/<profile>`
(the crate is a member of the `rust/` workspace, whose target directory that
is):

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

The crate builds on the same Rust 1.85.0 floor as the library, from the
`rust/` workspace's one committed `Cargo.lock`, resolved for that floor
(run in `rust/`):

```bash
CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback cargo +stable generate-lockfile
```

It reaches the library through `aprv-surface` (the calls) and `aprv-wire`
(the JSON), the boundary `aprv.wasm` is built on too, so the C ABI and the
Wasm module hand out the same bytes.

**Phase 2 — prebuilt binaries — does not exist yet.** There is no
`.so`/`.dylib`/`.dll` attached to a release and no package on any registry.
Building from source is the only supported path today; see `ROADMAP.md`.

## The surface

Ten symbols, all functions: the version string, a constructor and a
destructor for the opaque `AprvVerifier` handle, three verification calls
in two forms each (two fill an `AprvResult` struct, the endpoint call
returns a string), and one function that frees those strings.

```c
const char *aprv_version(void);

AprvVerifier *aprv_verifier_new(const uint8_t *const *ders, const size_t *lens, size_t count,
                                const int64_t *fixed_clock_unix_millis);
void          aprv_verifier_free(AprvVerifier *);

/* Bytes in, aprv.wasm's documents out: use these. */
int32_t aprv_verify_receipt_bytes(const AprvVerifier *, const uint8_t *receipt_base64, size_t len,
                                  AprvResult *out);
int32_t aprv_verify_signed_data_bytes(const AprvVerifier *, const uint8_t *jws, size_t len, AprvResult *out);
int32_t aprv_verify_receipt_endpoint_bytes(const AprvVerifier *, uint32_t environment,
                                           const uint8_t *request_json, size_t len, char **response_json);

/* The 0.7 C-string forms, kept for 0.7 callers. */
int32_t aprv_verify_receipt(const AprvVerifier *, const char *receipt_base64, AprvResult *out);
int32_t aprv_verify_signed_data(const AprvVerifier *, const char *jws, AprvResult *out);
int32_t aprv_verify_receipt_endpoint(const AprvVerifier *, uint32_t environment,
                                     const char *request_json, char **response_json);

void aprv_string_free(char *);
```

The `_bytes` calls take a pointer and a length, as `aprv.wasm` takes a
`list<u8>`, and answer what `aprv.wasm` answers for the same bytes: every
input is a verdict, an embedded NUL and bytes that are not UTF-8 included.
The C-string forms read up to the first NUL, so a genuine receipt followed
by a NUL and anything verifies through `aprv_verify_receipt` and is
`MALFORMED` everywhere else, and they answer bytes that are not UTF-8 with
`APRV_REASON_INVALID_UTF8` rather than a verdict.

`NULL`, `NULL`, `0` for the anchors selects the three Apple roots the Rust
library embeds. Otherwise `ders` and `lens` describe roots the caller owns,
for tests and for a deployment that pins its own: each entry is DER or PEM
bytes, which the library tells apart by the bytes, and a PEM entry may hold
several certificates. The bytes are parsed during the call and never
retained. Passing no anchors is not a way to
disable pinning: there is no code path to an operating-system trust store to
disable.

Nothing takes a bundle id, an environment set or a device id: a verified
payload comes back whole and the caller judges it, as in every 0.7 port.

### Which call to use

| You have | Call | You get |
|---|---|---|
| the base64 receipt an app sends | `aprv_verify_receipt_bytes` | the reason as `status`, and aprv.wasm's document in `json` |
| any Apple-signed JWS (transaction, renewal info, app transaction, notification) | `aprv_verify_signed_data_bytes` | the reason as `status`, and aprv.wasm's document in `json` |
| a drop-in for Apple's `verifyReceipt` | `aprv_verify_receipt_endpoint_bytes` | Apple's response body, verdict in its `status` field |

`environment` is `APRV_ENVIRONMENT_PRODUCTION` or `APRV_ENVIRONMENT_SANDBOX`;
it drives the 21007/21008 routing. The endpoint call takes Apple's request
JSON. If you hold only the base64 receipt, build `{"receipt-data":"<base64>"}`
yourself: base64 without line breaks needs no JSON escaping. Like Apple's
endpoint, it does not check the bundle id. Compare `receipt.bundle_id` in the
response before granting anything.

A request body over 3,145,728 UTF-8 bytes, the size at which Apple's own
endpoint answers HTTP 413, gets `{"status":21002}` without being parsed. To
answer 413 as Apple does, check the body's length in bytes before the call.

### The clock

`aprv_verifier_new` takes `const int64_t *fixed_clock_unix_millis`: one
instant, in milliseconds since the Unix epoch. `NULL` reads the system clock
on every call. A pointer rather than a sentinel value because every `int64_t`
names a real instant, `0` included.

It is an instant and not a callback on purpose. The Rust `Config` takes a
closure, but a function pointer the library calls back into would have to be
thread-safe, outlive the handle and never unwind, and getting any of that
wrong is a crash rather than a rejected argument. This surface is
deliberately callback-free.

**Pinning a clock is for conformance vectors and tests.** The clock is read
in two places, as in every 0.7 port: the certificate-validity instant when
the input states no usable signing date (a receipt without a readable
creation date, a JWS without a usable `signedDate`), and the endpoint's
`request_date` triple. No verifier rejects a payload for its age: how old a
signed payload may be is the caller's decision, made on the `signedDate` in
the JSON.

### Why JSON is the interchange

`AprvResult.json` carries the answer. From the `_bytes` calls it is the
document `aprv.wasm` answers, byte for byte, which validates against
`rust/bindings/wire/schema/`: `{"verified":true,"payload":...}` (the
receipt payload is 0.7's `ReceiptPayload.toJson()` value; a JWS payload is
a JSON string holding the signed text) or
`{"verified":false,"reason":"<token>","message":"<detail>"}`. From the 0.7
calls it is the bare payload (the receipt value, or the signed JSON text).
The endpoint calls hand back Apple's own response body.

A verified transaction is an open-ended JSON claim set and a verified receipt
is a tree with repeated groups and raw byte attributes. Modelling either as C
structs would put every field of a wire format Apple extends at will into the
ABI, and every field Apple added would then be a breaking change for every
consumer in every language. One UTF-8 JSON document instead keeps the ABI at
ten symbols and moves the schema question into a parser the caller already
has.

The receipt encoding is the JSON value every 0.7 port shares and the
conformance vectors pin (the value, not the bytes): snake_case keys, dates as `*_ms` epoch
milliseconds, 64-bit ids as strings, bytes as standard base64,
`unknown_attributes` keyed by the attribute number. JWS claims are passed
through exactly as Apple signed them. `rust/bindings/wire/schema/` describes
the receipt value as JSON Schema 2020-12.

### Status codes are stable and append-only

`AprvResult.status`, also the return value, has two bands, and the split is
the point.

* **`1`-`99`** is a verdict about the input: the eight canonical 0.7 reasons
  every port of this library shares. `2` `INVALID_CERTIFICATE`, `3`
  `INVALID_CERTIFICATE_PURPOSE`, `5` `INVALID_SIGNATURE` and `12`
  `INTERNAL_ERROR` kept their numbers; `13` `MALFORMED`, `14` `TOO_LARGE`,
  `15` `UNTRUSTED_CHAIN` and `16` `UNREADABLE_PAYLOAD` are new in 0.7. The
  0.6 codes `1`, `4` and `6` to `11` are retired and never reused.
  `UNREADABLE_PAYLOAD` and `INTERNAL_ERROR` are not the caller's fault: alert
  and reconcile rather than deny.
* **`100`+** is a mistake in the call itself (a null pointer, a non-UTF-8
  string, a rejected configuration, a caught panic) and means *nothing about
  the input was checked*. A caller that treats `APRV_REASON_NULL_POINTER` as
  "the receipt is forged" is reporting its own bug as an attack.

`reason_codes_mirror_the_library` in `src/lib.rs` asserts the first band
against the library's own `Reason::all()`, so the promise is mechanical
rather than written down.

From the `_bytes` calls, a verdict (`1`-`99`) comes with the wire document
above and a call mistake (`100`+) with `json` `NULL`. From the 0.7 calls,
any non-zero status comes with `{"reason":"<token>","message":"<detail>"}`.
The token is the `SCREAMING_SNAKE` spelling; the message is short,
non-sensitive, and never contains receipt bytes, claims or key material.
Match on the status or the token; never parse the message.

### Ownership

* `aprv_version()` returns a static string. **Never free it.**
* `aprv_verifier_new()` returns a handle the caller owns, or `NULL` if an
  argument was rejected. Release it with `aprv_verifier_free()`. Freeing
  `NULL` is a no-op; freeing twice is undefined behaviour.
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

### What else holds the surface

* The crate denies `unsafe_op_in_unsafe_fn`, `improper_ctypes`,
  `improper_ctypes_definitions` and `ffi_unwind_calls`, and Clippy's
  `undocumented_unsafe_blocks`: every `unsafe` block says why it is sound.
* `exported-symbols.txt` is the allowlist of what the shared library
  exports; `tests/exported_symbols.rs` reads the built library with `nm`
  (Linux and macOS) and fails on any other symbol, so no Rust, OpenSSL or
  libc symbol reaches a caller's namespace.
* `check-header.sh` regenerates the header with cbindgen 0.29.0 and fails
  on any difference from the committed one; the unit test
  `the_committed_header_declares_exactly_the_exports` checks the names and
  parameter counts without cbindgen.
* `rust/fuzz`'s `ffi` target drives the `_bytes` calls with arbitrary bytes
  and checks each answer against the surface's own.

Nothing is expected to panic — the library target denies `unwrap`, `expect`,
slice indexing and `panic!` — so `APRV_REASON_PANIC` is a bug report, not a
verdict.

### Thread safety

A handle is immutable once built and safe to share: any number of threads may
verify through the same handle at the same time. Freeing a handle while
another thread is inside a call on it is not allowed. Strings the ABI hands
out belong to whoever received them and are not shared.

## Tests

Three layers, all of them driving the same shared vectors,
`fixtures/cases.json`, the other ports answer.

```bash
# 1. the ABI's own edge cases: null, non-UTF-8, refused configs, the guard
cargo test --locked --manifest-path rust/ffi/Cargo.toml

# 2. fixtures/cases.json from C++17: the primary harness
cargo build --locked --manifest-path rust/ffi/Cargo.toml
node tools/gen-cases-manifest.mjs rust/ffi/target/manifest
cmake -S rust/ffi/examples/cpp -B rust/ffi/target/cppbuild
cmake --build rust/ffi/target/cppbuild --config Debug
rust/ffi/target/cppbuild/bin/aprv_conformance rust/ffi/target/manifest

# 3. the same vectors from a language with no compiler in the loop
python3 rust/ffi/tests/conformance.py rust/target/debug
```

**Layer 2 is the primary evidence.** A passing C++ run says the header
compiles as C++, the symbols link, and the answers match the vectors: the
whole compiled-toolchain path, on all three operating systems in CI.
`tools/gen-cases-manifest.mjs` flattens the vector file into a line-oriented
manifest first, because a dependency-free C++17 program cannot parse JSON,
base64-encode a fixture or check its SHA-256; the generator does all three
and hands over plain files. The C++ harness skips the `toJson` value
comparison, which needs a JSON parser, and counts it; ctypes checks it.

**Layer 3 is what "any FFI-capable language" means, tested.** ctypes reads
`cases.json` itself and calls the same symbols, and it checks the nested
pointers the C++ harness cannot reach: `/receipt/bundle_id`,
`/in_app/[product_id=...]/expires_date_ms`, `/unknown_attributes/9999/0`,
and every `toJson` value.

Both harnesses drive the `_bytes` calls and run every case in the file,
skipping none. A `decodeBase64` group reaches its decoder through a verify
call, as `tools/wasm-trap-host.mjs` does: a receipt-data text as the input
of `aprv_verify_receipt_bytes`, an x5c text as the three x5c entries of a
JWS header, and a text lands on the refusing side of the base64 rule when
the answer is its group's reason and the message names base64. Both check
that each document is the wire shape and agrees with its status; ctypes
writes them with `--answers <dir>` for `tools/validate-wire.mjs`. A case
that pins a clock passes the instant to `aprv_verifier_new`. A case with a
`maxMillis` budget (the denial-of-service cases) runs once to warm up and
fails if the second run takes longer. After the run every case id must have
run. The Elixir example still drives the 0.7 C-string calls and counts the
`decodeBase64` groups as not reachable.

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
apple-purchase-receipt-verifier <version>

transaction: status 0
{"bundleId":"com.example.app","environment":"Sandbox","signedDate":1722945600000, ...}

receipt: status 0
{"receipt_type":"ProductionSandbox","app_item_id":"0","bundle_id":"...", ...}
```

`examples/python/example.py` is the same page from Python, with nothing but
the standard library. ctypes opens the shared library at run time and calls
the exported symbols by name, so there is no compiler and no package in the
loop; the conformance harness in `tests/` is built the same way.

```bash
python3 rust/ffi/examples/python/example.py rust/target/release
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

It needs Elixir 1.18 on OTP 27 or newer. CI runs that floor and a current
pair; `examples/elixir/README.md` says what each proves.

```
apple-purchase-receipt-verifier <version> — C ABI conformance over NIFs
<N> passed, 0 failed, 0 skipped (<C> pin a clock, and every one of them ran)
```

The same cases as the C++ harness, which is the point of running it: two
consumers, one manifest, identical counts.

Two things the shim does that a C caller does not have to think about.

**Handles are released by the garbage collector.** The handle from
`aprv_verifier_new` lives in an `ErlNifResourceType` whose destructor calls
`aprv_verifier_free`, so dropping the last Elixir reference frees it.
Strings are copied into Erlang binaries and released with `aprv_string_free`
before the NIF returns, so no Rust allocation outlives a call.

**Verification runs on a dirty scheduler.** A NIF that does not return within
about a millisecond delays every process on its scheduler thread, and
verifying a chain takes longer than that. Every call that parses or verifies
carries `ERL_NIF_DIRTY_JOB_CPU_BOUND`.

`examples/elixir/README.md` covers the rest. The example has no Hex
dependencies: it decodes the ABI's documents with Elixir 1.18's built-in
`JSON` module, which is the floor `mix.exs` claims.
