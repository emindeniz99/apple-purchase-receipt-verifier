# aprv-abi: aprv.wasm

The guest side of the canonical ABI (docs/rust-core/ARCHITECTURE.md §3 and
§4). `wit/aprv.wit` is the contract every host binds; wit-bindgen 0.62.0
generates the exports from it, and four bodies in `src/lib.rs` call
`aprv-surface` and answer `aprv-wire`'s JSON. Nothing here parses,
verifies or decides.

## Build

```sh
eval "$(tools/wasm-toolchain.sh "$HOME/.cache/aprv-wasm-toolchain")"
rust/bindings/abi/build.sh <out-dir>
```

`build.sh` reads `WASI_SDK_DIR`, `OPENSSL_WASM_DIR` and `PATH` (wasm-tools,
wit-bindgen, and the cargo of `rust/rust-toolchain.toml` with
`wasm32-wasip1`), and `CARGO_TARGET_DIR` if set. It builds the crate with
`--profile wasm` (release, one codegen unit, LTO, `panic = "abort"`), the
reactor start file, wasi-libc's four emulation libraries and
`wasi-none.c`, then wraps the module with `wasm-tools component new` (no
adapter). It writes `aprv.wasm`, `aprv.component.wasm`, `aprv.wit` and
`SHA256SUMS` into `<out-dir>`, and fails when:

- the module imports anything but `aprv:verifier/host@1.0.0` `random-get`;
- it exports anything but the four `@1.0.0` operations, their
  `cabi_post_` functions, `cabi_realloc` (and wit-bindgen's versioned
  alias of it), `memory` and `_initialize`;
- the interface read back from the component with `wasm-tools component
  wit` differs from `wit/aprv.wit` rendered the same way (names and
  types; wit-bindgen 0.62.0 embeds no doc comments, so neither side
  carries them);
- the module carries a path of the machine that built it.

The `aprv.wit` it writes is the committed file, once the read-back has
shown the component's interface is that file's. Every path that could
reach the module (the source tree, the cargo home, the target directory)
is remapped, so a build in another directory gives the same bytes
(`tools/reproduce-wasm.sh`).

No build output is committed on a lane branch: packages read the module
from their own ignored path, or from `APRV_WASM` (`APRV_COMPONENT` for the
component).

## What the module does with its host

| Call | Behaviour |
|---|---|
| `init(config-json)` | `{"roots":["<base64 DER>", ...]}`; no bytes, `{}` or an empty list mean the three Apple roots. Answers `{"ok":true}` or `{"ok":false,"message":...}`; after a refusal it may be called again, after `{"ok":true}` it traps |
| `verify-receipt(now-ms, receipt-base64)` | `aprv-wire`'s answer (`../wire/schema/verify-receipt-result.schema.json`) |
| `verify-signed-data(now-ms, jws)` | `aprv-wire`'s answer (`../wire/schema/verify-signed-data-result.schema.json`) |
| `verify-receipt-endpoint(env, now-ms, request-json)` | Apple's response JSON; `env` 0 is production, 1 sandbox, anything else traps |
| `random-get(len)`, the one import | OpenSSL's randomness (EC blinding, its DRBG); an answer that is not exactly `len` bytes traps |

A verify call before a successful `init` traps. A `now-ms` above `i64::MAX`
is `INTERNAL_ERROR` (`{"status":21009}` at the endpoint), as a clock that
throws is in 0.7. Traps are `unreachable`, reached directly. The module is
built with `panic = "abort"`: std's panic handler is still linked on stable
Rust (bounds and borrow checks in std and the dependencies can reach it),
and every such path ends in a trap: the hook's write to stderr traps in
`wasi-none.c`, and the abort is `unreachable`.

A `list<u8>` argument is the host's to place: the canonical ABI requires
the range to come from `cabi_realloc`, and the module does not check it.
The core reads its input front to back and decides as early as it can: a
length over the input cap (3,145,728 bytes for a receipt or an endpoint
body, 262,144 for a JWS) is `TOO_LARGE` before any byte is read, and base64
that goes wrong early is `MALFORMED` without the rest being read. So a raw
call whose range runs past the end of linear memory answers a value when
those rules decide before the first byte outside memory, and traps
(out-of-bounds access) when a byte outside memory is read; a range whose
length overflows 32 bits traps in the lift. No read outside linear memory
can happen without a trap. The list is also freed with the module's
allocator after the call, so a range the host did not allocate corrupts
that instance's heap, as it would for any canonical-ABI guest; hosts built
on a bindings generator cannot make such a call.

`_initialize` need not be called: each export runs the module's one
constructor on its first call. Calling it first is harmless; calling it
twice traps.

`wasi-none.c` defines every WASI function wasi-libc references, inside the
module: `random_get` forwards to the Rust side, `clock_time_get` answers
the `now-ms` of the call in progress (0 during `init`), and every other one
traps. The Rust side hands both over through two C setters, so no Rust
symbol needs exporting.
