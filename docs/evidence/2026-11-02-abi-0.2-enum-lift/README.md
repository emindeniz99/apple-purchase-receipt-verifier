# ABI 0.2.0: the checked enum lift, sources

The note is [../2026-11-02-abi-0.2-enum-lift.md](../2026-11-02-abi-0.2-enum-lift.md).

| File | Question it answered |
|---|---|
| `toy/` (`Cargo.toml`, `Cargo.lock`, `src/lib.rs`, `wit/aprv.wit`) | A one-export guest with the same pins and profile as `aprv.wasm`: does wit-bindgen 0.63.0's enum lift check the discriminant, with and without debug assertions? |
| `toy/run.mjs` | Calls the toy's `verify-receipt-endpoint` by hand with env 0, 1, 2, 255 and 2^32-1; every WASI import throws, naming itself |
| `toy/results.txt` | Its output for the `wasm` and `wasmchecked` profiles |
| `real/run-real.mjs` | The same calls on the real `aprv.wasm` on V8, with `random-get` supplied, plus `now-ms` -1, `i64::MIN` and `i64::MAX`. The endpoint gets the sandbox G5 receipt, so its status names the environment the guest used (0 sandbox, 21007 production) |
| `real/wazero/` | The env calls on wazero v1.12.0, as the Go package makes them |
| `real/EndiveTrapProbe.java` | The env calls on Endive, through the `-wasm` artifact's own `EndiveGuest` |
| `real/results.txt` | Sizes and hashes of the four builds and every probe's output, with the Wasmtime ABI-test result, cargo's flags and the reproduce run |

The four builds of the real module, all with `rust/bindings/abi/build.sh`:

| Name | Tree |
|---|---|
| `base` | `main` at 04bc1f4 (ABI 0.1.0) |
| `u` | ABI 0.2.0 with `debug-assertions = false` in `[profile.wasm.package.aprv-abi]`: the unchecked lift |
| `a` | ABI 0.2.0 as committed (`debug-assertions = true`) |
| `h` | `a` plus `std::panic::set_hook(Box::new(\|_\| trap()));` as the first line of `init`'s closure in `rust/bindings/abi/src/lib.rs` |

## Reproduce

```sh
eval "$($REPO/tools/wasm-toolchain.sh $SCRATCH/toolchain)"

# the toy
CARGO_TARGET_DIR=$SCRATCH/toy cargo build --manifest-path toy/Cargo.toml \
  --target wasm32-wasip1 --profile wasm
CARGO_TARGET_DIR=$SCRATCH/toy cargo build --manifest-path toy/Cargo.toml \
  --target wasm32-wasip1 --profile wasmchecked
node toy/run.mjs $SCRATCH/toy/wasm32-wasip1/wasm/spike_enum.wasm
node toy/run.mjs $SCRATCH/toy/wasm32-wasip1/wasmchecked/spike_enum.wasm

# the real module (edit the tree for u or h first, as above)
CARGO_TARGET_DIR=$SCRATCH/target $REPO/rust/bindings/abi/build.sh $SCRATCH/out-a
node real/run-real.mjs $SCRATCH/out-a/aprv.wasm $REPO
go -C real/wazero run . $SCRATCH/out-a/aprv.wasm $REPO      # Go 1.25 or later

# Wasmtime: the ABI tests, whose is_trap is Trap::UnreachableCodeReached
APRV_WASM=$SCRATCH/out-a/aprv.wasm APRV_COMPONENT=$SCRATCH/out-a/aprv.component.wasm \
  cargo test --manifest-path $REPO/rust/bindings/abi/tests/Cargo.toml

# Endive: copy the probe into the -wasm test tree, place the module, run it
cp real/EndiveTrapProbe.java $REPO/java-wasm/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/
$REPO/.github/scripts/place-module.sh $SCRATCH/out-a java
mvn -f $REPO/java-wasm test -Dtest=EndiveTrapProbe -DexcludedGroups=server

# reproducibility
$REPO/tools/reproduce-wasm.sh <commit> <sha256 of out-a/aprv.wasm>
```

Delete the copied probe and run `git checkout java-wasm/src/main/wasm/aprv.wasm.sha256`
afterwards: `place-module.sh` rewrites that pin in the checkout.
