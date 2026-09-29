# CI notes for the bindings (lane A2)

What `.github/` needs for the workspace, `aprv-surface`, `aprv-wire`,
`aprv-abi` and the C ABI's move. None of it is applied here. Lane D's
`rust-wasm` job and `.github/CI-NOTES.md` on `rust-core` already call the
contracts below; each item says whether that job changes.

## `rust-wasm` (lane D's job; the gate flips)

1. **The gate flips as written.** `rust/bindings/abi/build.sh <out-dir>`
   exists and keeps lane D's contract: it reads `WASI_SDK_DIR`,
   `OPENSSL_WASM_DIR` and `PATH` from `tools/wasm-toolchain.sh`, uses the
   rustc of `rust/rust-toolchain.toml` (lane D's file, unchanged), remaps
   the source tree, `CARGO_HOME` and the target directory, and writes
   `aprv.wasm`, `aprv.component.wasm`, `aprv.wit` and `SHA256SUMS`.
   `CARGO_TARGET_DIR` is honoured when set (default `rust/target`).
   The compiler pin holds from any working directory (review round 2,
   F1): the jobs run build.sh from the repository root, where rustup does
   not see `rust/rust-toolchain.toml`, so build.sh reads the channel from
   that file, exports `RUSTUP_TOOLCHAIN` and stops unless `rustc
   --version` names it. The job must have installed that toolchain with
   the `wasm32-wasip1` target (`rustup toolchain install` in `rust/`, as
   today); it need not make it the default. A failed check leaves no
   `aprv.wasm`, component, `aprv.wit` or `SHA256SUMS` in the output
   directory (F6), so a later step that copies the module without reading
   the exit status finds nothing to copy.
   The module is now built without its `name` section (F11: 8.5% smaller;
   the measurement is in `rust/bindings/abi/README.md`), so its hash
   differs from every build before this change; any recorded hash moves
   with it.
2. **`aprv.wit` in the output is the committed file**, written only after
   the component's interface, read back with `wasm-tools component wit`,
   matched it. That is what `tools/check-wasm.sh` check 5 compares byte for
   byte. The raw read-back (`package root:component; ...`) is not shipped.
3. **Doc comments are not part of the read-back.** wit-bindgen 0.62.0
   embeds none in the component, and `wasm-tools component embed --dummy`
   renders none from the committed file either, so `check-wasm.sh` check 4
   compares names and types. Its header comment says doc comments count;
   they do not, today.
4. **The exports are exactly the contract**, wit-bindgen's
   `cabi_realloc_wit_bindgen_0_62_0` alias included; the two internal
   symbols of the round-13 stand-in are gone (`check-wasm.sh` check 3
   passes as written).
5. **The corpus** (`wasm-trap-host.mjs calls`) needs the spike's call
   files, which are not in the repository (lane D's note). The evidence
   note `docs/evidence/2026-09-29-aprv-wasm-parity.md` has the run.

Add to the job, after the build:

6. **The Wasmtime ABI tests** (a package outside the workspace, with its
   own lockfile):

   ```sh
   APRV_WASM="$RUNNER_TEMP/aprv/aprv.wasm" \
   APRV_COMPONENT="$RUNNER_TEMP/aprv/aprv.component.wasm" \
     cargo test --locked --manifest-path rust/bindings/abi/tests/Cargo.toml
   ```

   It builds Wasmtime 49.0.1 with Cranelift (about 4 minutes on two cores
   cold); cache its target directory in this test job only.

## `rust` (tests, lints, the floor)

7. `cargo test --locked --workspace` from `rust/` now covers the core, the
   adapter, `aprv-surface`, `aprv-wire` (its `tests/schema.rs` validates
   every shared case's answer against `bindings/wire/schema/`), the C ABI
   and a native build of `aprv-abi` (no tests; it checks the crate
   compiles). `cargo clippy --locked --workspace --all-targets -- -D warnings`
   likewise. For the `cfg(target_arch = "wasm32")` code, also run
   `cargo clippy --locked -p aprv-abi --target wasm32-wasip1 -- -D warnings`
   with the environment `build.sh` sets (the `CC_wasm32_wasip1`,
   `CFLAGS_wasm32_wasip1`, `AR_wasm32_wasip1` and `OPENSSL_DIR` lines).
8. **The 1.85.0 floor leg must exclude `aprv-abi`**: wit-bindgen 0.62's
   generator crates (wit-parser, wasm-encoder, wasmparser 0.259) declare
   Rust 1.88, and `aprv-abi` says so (`rust-version = "1.88.0"`). The
   module is built with the pinned 1.98.1 only. Use
   `cargo +1.85.0 test --locked --workspace --exclude aprv-abi`. Not run in
   this lane (no 1.85 toolchain here), as A1 noted for the core.
9. **The layering check** (MIGRATION.md step 1.3): `node
   tools/check-layering.mjs` from the repository root, with cargo on PATH,
   in any job that has the Rust toolchain; and its own test, `node --test
   tools/test/check-layering.test.mjs` (lane D's `npm --prefix tools test`
   runs it too, since it matches `test/*.test.mjs`). Both call `cargo
   metadata` and `cargo tree` on `rust/`, so they fetch the crates once.
10. **cargo-deny** over the workspace now sees the dev-dependency
    `jsonschema` 0.58.2 (no network features) and `wit-bindgen` 0.62.0 with
    its generator crates: `bans licenses sources` pass with `deny.toml` as
    it is (checked with cargo-deny 0.18.9; `advisories` not run, the
    database could not be fetched). Do not run it over
    `rust/bindings/abi/tests`: Wasmtime is `Apache-2.0 WITH LLVM-exception`,
    which `deny.toml` does not list, as for `rust/server`.

## `rust-ffi` (Linux, macOS, Windows)

11. **`rust/ffi` is a member of the `rust/` workspace.** Its own
    `Cargo.lock`, `[workspace]` table and `[patch.crates-io]` are gone; the
    lockfile is `rust/Cargo.lock`. The library now lands in
    `rust/target/<profile>`, not `rust/ffi/target/<profile>`: the CMake
    harness defaults `APRV_LIB_DIR` to `rust/target/debug` and the Elixir
    Makefile to `rust/target/release`; the Python harness takes the
    directory as its argument (`rust/target/debug`). The manifest and
    `cppbuild` directories under `rust/ffi/target/` are only output paths
    the job names, and can stay.
12. The header changed only in two doc comments (a receipt's JSON is now
    `aprv-wire`'s bytes, the same value in the 0.7 key order); regenerated
    with cbindgen 0.29.0, as the job pins.
13. `cargo deny --manifest-path ffi/Cargo.toml` now reads the workspace's
    graph; `--manifest-path Cargo.toml` from `rust/` covers it.

Lane A3 (MIGRATION.md 1.13, review round 2 F3 and F4) adds:

13a. **The header check** on one OS (Linux): `rust/ffi/check-header.sh`
     with cbindgen 0.29.0 on PATH (`cargo install cbindgen --locked
     --version 0.29.0`); it refuses another version rather than diffing.
     It replaces any step that regenerates the header and diffs by hand.
13b. **The exported-symbol test** (`rust/ffi/tests/exported_symbols.rs`)
     runs inside `cargo test` on Linux and macOS and needs `nm` on PATH
     (binutils; the Xcode command-line tools on macOS). It reads the
     cdylib `cargo test` builds into `target/<profile>/deps/`, so no
     `cargo build` needs to come first. On Windows it compiles to nothing.
13c. **The harnesses now call the ten-symbol ABI**: both drive the
     `_bytes` calls and run the `decodeBase64` groups. The C++ harness
     reads the manifest `tools/gen-cases-manifest.mjs` writes, which now
     carries `probe=` lines; regenerate it in the job (it already does).
     Add, after the ctypes run on Linux:

     ```sh
     A="$RUNNER_TEMP/ffi-answers"
     python3 rust/ffi/tests/conformance.py rust/target/debug --answers "$A"
     for op in verify-receipt verify-signed-data; do
       node tools/validate-wire.mjs \
         "rust/bindings/wire/schema/$op-result.schema.json" "$A/$op.jsonl"
     done
     ```

     so the C ABI's documents are held to the wire schema as the
     module's are.
13d. **The Elixir NIF example** still drives the 0.7 C-string calls and
     was not built in this lane (no Elixir toolchain); its job step is
     unchanged.

## Dependabot

14. Drop the cargo entry for `/rust/ffi` (it has no lockfile of its own
    now); `/rust` covers it.
15. Add a cargo entry for `/rust/bindings/abi/tests`, and pin `wasmtime`
    there to move with `rust/server`'s (the ABI is tested on the runtime the
    server ships). Keep `wit-bindgen` in `/rust` on an exact pin that moves
    only together with `tools/wasm-toolchain.sh`'s CLI version: the
    generated glue is part of the released module's bytes.

## `release-please-config.json`

16. Nothing: `aprv-surface`, `aprv-wire`, `aprv-abi` and `aprv-abi-tests`
    are `publish = false` at `0.0.0` and carry no version constant.

## `release-please.yml`

17. The lock step after release-please: `cargo update --workspace` in
    `rust/` now covers the C ABI too; drop any `rust/ffi` lock update (A1's
    item 13 in `rust/openssl/CI-NOTES.md` named one).
