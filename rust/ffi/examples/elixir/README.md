# The C ABI from Elixir

An example, not a package. It shows what an Elixir application has to do to
verify Apple receipts with this library, and it runs the shared conformance
vectors through that path so the answer is checked rather than asserted.

Nothing here is published to Hex, and the example has no Hex dependencies at
all. `mix compile` fetches nothing.

## Why there is C in an Elixir directory

The BEAM has no foreign function interface. A native call from Elixir is a
NIF: a C function the emulator loads and calls directly. So the Elixir side
of this library is a shim in C, `c_src/aprv_nif.c`, written against the
committed header in `../../include`. It converts Erlang terms to the
arguments the ABI takes and back, and holds no verification logic.

The shim is 9 NIFs over the ABI's 19 exports. An empty roots list means the
bundled Apple roots, so one NIF covers both `aprv_verifier_new_jws` and
`aprv_verifier_new_jws_with_roots`; an empty device GUID means no device hash
check, so one NIF covers each receipt call and its `_with_device_guid`
variant. Every export is still reached.

## Build and run

Build the shared library first. The NIF links against it and finds it again
at load time through an rpath, so nothing has to be installed:

```bash
cargo build --locked --release --manifest-path rust/ffi/Cargo.toml
node tools/gen-cases-manifest.mjs rust/ffi/target/manifest
cd rust/ffi/examples/elixir
mix compile
mix test
mix run example.exs
```

`mix compile` runs the `Makefile` through a small Mix compiler in `mix.exs`.
The Makefile asks the running Erlang for its include directory
(`code:root_dir()`) rather than hard-coding a path, so it compiles against
whatever OTP is installed. `APRV_LIB_DIR` overrides where it looks for the
cdylib, for a debug build or a relocated `CARGO_TARGET_DIR`.

## What the code does

`AppleReceiptExample.Native` is the raw NIF surface, one function per entry
point in the shim. `AppleReceiptExample` is the layer a real application
would write: environments as atoms, status codes as reason atoms, and the
JSON decoded into a map.

```elixir
{:ok, verifier} = AppleReceiptExample.jws_verifier("com.example.app", [:sandbox])

case AppleReceiptExample.verify_transaction(verifier, jws) do
  {:ok, claims} -> claims["productId"]
  {:error, :wrong_bundle_id, _body} -> :rejected
end
```

### Handles are released by the garbage collector

Each handle from `aprv_*_new*` lives in an `ErlNifResourceType` whose
destructor calls the matching `aprv_*_free`. When the last Elixir reference
to a verifier is dropped, the destructor runs. A caller cannot leak a handle
and cannot free one twice, so the API has no close function.

Strings are the other owned thing crossing the boundary. Each
`AprvResult.json` is copied into an Erlang binary and freed with
`aprv_string_free` before the NIF returns, so no Rust allocation outlives the
call.

### Verification runs on a dirty scheduler

A NIF that does not return within about a millisecond delays every process on
its scheduler thread. Verifying a chain takes longer than that, so every call
that parses or verifies is flagged `ERL_NIF_DIRTY_JOB_CPU_BOUND` and the
emulator runs it on a dirty scheduler instead.

### JSON

Elixir 1.14 on OTP 25 has no JSON reader in its standard library: `JSON`
arrived in Elixir 1.18 and `:json` in OTP 27. Rather than depend on Jason,
`AppleReceiptExample.Json` reads the documents this ABI emits, which keeps
the dependency count at zero. Your application should use Jason or a current
runtime.

## The conformance run

`test/conformance_test.exs` reads the same flat manifest
`tools/gen-cases-manifest.mjs` writes for the C++ harness, and drives all 104
cases through the NIF:

```
apple-purchase-receipt-verifier 0.4.0 — C ABI conformance over NIFs
92 passed, 0 failed, 12 not runnable through the C ABI (no clock argument)
157 expected fields checked here, nested paths left to conformance.py
```

The 12 skipped cases pin a clock, and the ABI has no clock argument. That is
the only sanctioned reason: a case marked unsupported for anything else fails
the run. The counts match `examples/cpp/conformance.cpp` exactly, because
both read the same manifest.
