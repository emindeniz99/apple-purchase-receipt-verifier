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
`SHA256SUMS` into `<out-dir>`, first removing those four files there, so a
build that stops at any check leaves none of an earlier run's behind. It
refuses to start when the compiler cargo would run is not the channel
`rust/rust-toolchain.toml` pins: that compiler is `RUSTC` or
`CARGO_BUILD_RUSTC` when set, and `rustc` on `PATH` otherwise, and cargo is
handed it by path, so a `build.rustc` in a cargo configuration cannot swap
it. A compiler wrapper (`RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER` or their
`CARGO_BUILD_` forms) is refused, since it may run any compiler, and cargo
runs with none. `tools/test/build-sh.test.mjs` holds the pin and the
cleanup without building anything. It fails when:

- the module imports anything but `aprv:verifier/host@0.1.0` `random-get`;
- it exports anything but the four `@0.1.0` operations, their
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

The module ships without its `name` section (review round 2, F11). On the
2026-09-29 build that section was 256,982 of 3,013,162 bytes (8.5%; 71 KB
of 990 KB gzipped); the stripped module passed `tools/check-wasm.sh`, all
360 shared cases and the ABI tests of `tools/wasm-trap-host.mjs`, and
answered 811 hostile-corpus calls byte for byte as the named one. What the
section bought was trap stack frames with Rust names: without it a frame
reads `wasm-function[33]:0xa956` instead of
`aprv_abi.wasm.aprv:verifier/verify@0.1.0#verify-receipt`, and the Java
engine's stack traces and JFR recordings carry the index too (Endive can
name its compiled methods only from this section). Stripping moves no
code, so the index and offset are the same in the named module cargo
leaves at `$CARGO_TARGET_DIR/wasm32-wasip1/wasm/aprv_abi.wasm`, and
`wasm-tools print` of it names the function; the build is reproducible, so
rebuilding a release's commit gives that module back. `producers` and
`target_features` (322 bytes) stay, and `component-type` must: `wasm-tools
component new` reads the interface from it.

No build output is committed on a lane branch: packages read the module
from their own ignored path, or from `APRV_WASM` (`APRV_COMPONENT` for the
component).

## What the module does with its host

| Call | Behaviour |
|---|---|
| `init(config-json)` | `{"roots":["<base64>", ...]}`, each root DER or PEM bytes, which the core tells apart (a PEM bundle is one entry); no bytes or `{}` mean the three Apple roots, and an empty list is refused (`roots must not be empty`). Answers `{"ok":true,"max_input_bytes":N}` or `{"ok":false,"message":...}`; after a refusal it may be called again, after an `ok` answer it traps. `N` is the most bytes of one input a host needs to hand the module, one over its largest cap (3,145,729): a longer input may be cut to `N`, and the module answers `TOO_LARGE` for it (DECISIONS.md R42) |
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
the range to come from `cabi_realloc`. Every cap is decided on the input's
length before a byte of it is read (a length over the input cap, 3,145,728
bytes for a receipt or an endpoint body and 262,144 for a JWS, is
`TOO_LARGE` or `{"status":21002}`), so a host may lower at most the
`max_input_bytes` `init` answered (3,145,729) of any input and get the
answer the whole input would get, without copying the rest into linear
memory. A host reads the number from `init` and keeps no copy of it.

A range that did not come from `cabi_realloc` is the host's bug. One that
runs past the end of linear memory, or wraps 32 bits, traps as each export
starts, before a byte is read and before the list is freed; the same holds
for the answer to `random-get`, whose length is also checked (any length
but the one asked traps). Without that check the length alone would have
decided the answer (`TOO_LARGE` for a length of `0xFFFFFFF8`), and freeing
a pointer the allocator never returned corrupts the instance's heap. A
range inside memory that `cabi_realloc` never returned is not caught: the
list is read and freed as if it had been, which may corrupt the heap.
`cabi_realloc` itself accepts any old pointer and alignment. Component
runtimes check ranges, and every wrapper in this repository lowers through
`cabi_realloc`; a hand-rolled host that cannot vouch for a call discards
the instance after it.

`_initialize` need not be called: each export runs the module's one
constructor on its first call. Calling it first is harmless; calling it
twice traps.

`wasi-none.c` defines every WASI function wasi-libc references, inside the
module: `random_get` forwards to the Rust side, `clock_time_get` answers
the `now-ms` of the call in progress (0 during `init`), and every other one
traps. The Rust side hands both over through two C setters, so no Rust
symbol needs exporting.
