# aprv.wasm parity (2026-09-29)

The code behind [`../2026-09-29-aprv-wasm-parity.md`](../2026-09-29-aprv-wasm-parity.md).

| Path | Question it answers |
|---|---|
| `runner/` | What does the module's own code answer natively? The four bodies of `rust/bindings/abi/src/lib.rs` over `aprv-surface` and `aprv-wire`, reading round 13's call rows (`Cargo.toml.in` is filled in by `scripts/parity.sh`) |
| `scripts/pin-now.py` | Pins every call without a clock to one instant, so both sides judge dateless inputs alike |
| `scripts/same.py` | Are the module's rows and the native twin's identical, byte for byte? |
| `scripts/against_a1.py` | Does the module answer as the OpenSSL core's 0.7 text API (`../2026-09-29-openssl-core-parity`'s rows), and which rows could that API not take? |
| `scripts/split.py` | Every corpus answer by wire shape, for `tools/validate-wire.mjs` |
| `scripts/parity.sh` | All of the above over the five corpora, plus the verdict comparison with the ABI v1 Node rows (that note's `scripts/compare.py ref`) |
| `scripts/facts.sh` | Sizes, hashes, imports, exports, custom sections, the read-back interface, where a panic ends, the start function |
| `wasi-random/` | Can the one import be WASI 0.2's `get-random-bytes`? (`run.sh`, the WIT variant, the upstream interface) |
| `results/` | The outputs quoted in the note |

Inputs outside the repository: ABI v1's call files `$CALLS_V1/<corpus>.jsonl`
and Node rows `$NODEROWS/node-<corpus>.jsonl`
(`../2026-09-26-wasm-abi-v1/`), the OpenSSL core note's rows
`$A1ROWS/{openssl-dir,old}-<corpus>.jsonl`, and rust-core's
`tools/wasm-trap-host.mjs`, `tools/validate-wire.mjs` and
`tools/check-wasm.sh` (lane D) with `npm ci --prefix tools`.

```sh
eval "$(tools/wasm-toolchain.sh "$SCRATCH/toolchain")"
rust/bindings/abi/build.sh "$SCRATCH/out"                       # results/build.txt's first line
sh docs/evidence/2026-09-29-aprv-wasm-parity/scripts/facts.sh "$SCRATCH/out" # results/build.txt
tools/check-wasm.sh "$SCRATCH/out" rust/bindings/abi/wit/aprv.wit           # results/check-wasm.txt
node tools/wasm-trap-host.mjs cases "$SCRATCH/out/aprv.wasm" fixtures/cases.json --answers "$SCRATCH/answers"
node tools/wasm-trap-host.mjs abi-tests "$SCRATCH/out/aprv.wasm" fixtures/cases.json
# results/no-initialize.txt: the trap host with its _initialize call removed
sed 's/if (typeof this.exports._initialize === .function.) this.exports._initialize();//' \
  tools/wasm-trap-host.mjs > tools/trap-noinit.mjs
APRV_WASM="$SCRATCH/out/aprv.wasm" APRV_COMPONENT="$SCRATCH/out/aprv.component.wasm" \
  cargo test --locked --manifest-path rust/bindings/abi/tests/Cargo.toml   # results/abi-tests-wasmtime.txt
# results/cases-schemas.txt
for p in "init-config init-config" "init-result init" "verify-receipt-result verify-receipt" \
         "verify-signed-data-result verify-signed-data"; do set -- $p
  node tools/validate-wire.mjs "rust/bindings/wire/schema/$1.schema.json" "$SCRATCH/answers/$2.jsonl"; done
# results/parity.txt (a native OpenSSL 4.0.2 in OPENSSL_DIR for the twin)
REPO=$PWD MODULE="$SCRATCH/out/aprv.wasm" TRAPHOST=tools/wasm-trap-host.mjs \
  VALIDATOR=tools/validate-wire.mjs CALLS_V1=... A1ROWS=... NODEROWS=... \
  sh docs/evidence/2026-09-29-aprv-wasm-parity/scripts/parity.sh
# results/wasi-random.txt (after parity.sh, whose pinned calls it reuses)
REPO=$PWD MODULE="$SCRATCH/out/aprv.wasm" TRAPHOST=tools/wasm-trap-host.mjs \
  sh docs/evidence/2026-09-29-aprv-wasm-parity/wasi-random/run.sh
# results/standin-case-differences.txt: the cases on round 13's stand-in module
node tools/wasm-trap-host.mjs cases "$SCRATCH/r13/art/aprv-cabi.core.wasm" fixtures/cases.json
```

`results/reproduce.txt` is the module rebuilt by `build.sh` from a fresh
clone in another directory; `tools/reproduce-wasm.sh` does the same from a
tag.
