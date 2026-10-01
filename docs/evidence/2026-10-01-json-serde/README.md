# 2026-10-01 json-serde spike

| Path | Question it answered |
|---|---|
| `proto-value/` | `rust/src/json.rs`, `jws.rs`, `endpoint.rs` with the documents read into `serde_json::Map<String, Value>` (variant A). |
| `proto-raw/` | The same three files reading into `BTreeMap<String, &RawValue>`, values read from their raw text (variant B); `Cargo.toml.diff` turns on serde_json's `raw_value` feature. |
| `cost/` | Time and peak heap of the old reader, variant A and variant B on the worst inputs built within the caps. `cost/src/old_json.rs` is `rust/src/json.rs` at the base commit without its tests. |
| `cost-results.md` | The table `cost/` printed. |

## Reproduce

Base commit: `7f2ea42`. `$REPO` is the repository root, `$SCRATCH` any
directory outside it; every build goes to `$SCRATCH`.

```sh
# a scratch copy of the tracked files
mkdir -p "$SCRATCH/tree"
git -C "$REPO" ls-files -z rust fixtures certs | tar -C "$REPO" --null -T - -cf - | tar -x -C "$SCRATCH/tree"

# shared cases and unit tests: base, then a variant
cargo +1.98.1 test --workspace --manifest-path "$SCRATCH/tree/rust/Cargo.toml" --no-fail-fast
cp proto-raw/{json,jws,endpoint}.rs "$SCRATCH/tree/rust/src/"
git -C "$SCRATCH/tree" apply "$PWD/proto-raw/Cargo.toml.diff"   # variant B only
cargo +1.98.1 test --workspace --manifest-path "$SCRATCH/tree/rust/Cargo.toml" --no-fail-fast

# module size: with tools/wasm-toolchain.sh's environment
"$SCRATCH/tree/rust/bindings/abi/build.sh" "$SCRATCH/out"

# cost table
cargo +1.98.1 run --release --manifest-path cost/Cargo.toml --target-dir "$SCRATCH/json-cost"
```
