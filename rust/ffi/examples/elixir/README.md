# The C ABI from Elixir

An example, not a package. It shows what an Elixir application has to do to
verify Apple receipts with this library, and it runs the shared conformance
vectors through that path so the answer is checked rather than asserted.

Nothing here is published to Hex, and the example has no Hex dependencies at
all. `mix compile` fetches nothing.

It needs **Elixir 1.18 on OTP 27** or newer, which is what `mix.exs` claims
and what CI's floor leg runs; the other leg runs a current pair.

## Why there is C in an Elixir directory

The BEAM has no foreign function interface. A native call from Elixir is a
NIF: a C function the emulator loads and calls directly. So the Elixir side
of this library is a shim in C, `c_src/aprv_nif.c`, written against the
committed header in `../../include`. It converts Erlang terms to the
arguments the ABI takes and back, and holds no verification logic.

The shim is 5 NIFs, one per export that takes arguments, plus `version`.
An empty roots list means the bundled Apple roots and a `nil` clock means the
system clock, the same two sentinels the ABI itself takes.

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
JSON decoded into a map. The library checks the chain and the signature and
hands back the whole payload; the caller judges the claims.

```elixir
{:ok, verifier} = AppleReceiptExample.verifier()

case AppleReceiptExample.verify_signed_data(verifier, jws) do
  {:ok, %{"bundleId" => "com.example.app"} = claims} -> claims["productId"]
  {:ok, _other_app} -> :rejected
  {:error, :untrusted_chain, _body} -> :rejected
end
```

### Handles are released by the garbage collector

The handle from `aprv_verifier_new` lives in an `ErlNifResourceType` whose
destructor calls `aprv_verifier_free`. When the last Elixir reference
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

The ABI hands back one UTF-8 JSON document per call, and `JSON.decode!/1`
from Elixir's own standard library reads it. That is why `mix.exs` claims
Elixir 1.18: `JSON` arrived there, and taking it as the floor keeps the
example's dependency count at zero without a hand-written reader.

### The clock

`verifier/1` takes a `:clock_unix_millis` option, which becomes the ABI's
`fixed_clock_unix_millis` pointer; leaving it out passes `nil`, the NULL that
means the system clock. It exists for tests and the conformance vectors that
pin one. The clock is read where every 0.7 port reads it: the
certificate-validity instant when the input states no usable signing date,
and the endpoint's `request_date`. No payload is rejected for its age.

## The conformance run

`test/conformance_test.exs` reads the same flat manifest
`tools/gen-cases-manifest.mjs` writes for the C++ harness, and drives every
case in it through the NIF:

```
apple-purchase-receipt-verifier <version>: C ABI conformance over NIFs
<N> passed, 0 failed, 0 skipped (<C> pin a clock, and every one of them ran)
<F> expected fields checked here, nested paths left to conformance.py
```

`<N>` is the number of cases in `cases-0.7.json` the ABI can reach (every
one but the `decodeBase64` groups), `<C>` the ones among them that pin a
clock, and `<F>` the expected fields and lengths this harness checks.

Nothing is skipped: a case that pins a clock passes the instant to
`aprv_verifier_new`, and a case with a `maxMillis` budget runs once to warm
up and fails if the second run takes longer. A case the manifest marks
unsupported fails the run rather than shrinking it. The counts match
`examples/cpp/conformance.cpp` exactly, because both read the same manifest.
