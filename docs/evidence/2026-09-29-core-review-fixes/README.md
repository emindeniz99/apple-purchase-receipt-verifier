# Core review fixes: sources

The note is [`../2026-09-29-core-review-fixes.md`](../2026-09-29-core-review-fixes.md).

| File | Question it answered |
|---|---|
| `gen_fixtures.py` | Which shared cases do the findings become? Writes `fixtures/generated-0.7/core-review-*.der` and their 27 cases into `fixtures/cases.json` |
| `wasm_cost.mjs` | What does a hostile receipt cost through `aprv.wasm`, in time and linear memory? `hostile` builds the Node lane's `flat-max`; `files` runs DER receipts |
| `against_a2.py` | Which corpus rows of the rebuilt module differ from lane A2's module, and is it the verdict or only the message? |
| `results/` | The output of each command below, local paths replaced by `$REPO` and `$SCRATCH` |

## Reproduce

From `$REPO`, with the toolchain of `tools/wasm-toolchain.sh`, a native
OpenSSL 4.0.2 in `OPENSSL_DIR` for the native runs, and `npm ci --prefix
tools`. `$SCRATCH/a2` holds A2's module (05b4ad9) and `$SCRATCH/a2rows` its
`module-<corpus>.jsonl` rows from the same parity run.

```sh
python3 docs/evidence/2026-09-29-core-review-fixes/gen_fixtures.py     # needs cryptography >= 41
node tools/lint-cases.mjs
rust/bindings/abi/build.sh "$SCRATCH/out2"
tools/check-wasm.sh "$SCRATCH/out2" rust/bindings/abi/wit/aprv.wit     # results/check-wasm.txt, imports.txt
node tools/wasm-trap-host.mjs cases "$SCRATCH/out2/aprv.wasm" fixtures/cases.json \
  --answers "$SCRATCH/answers"                                          # results/cases-trap-host.txt
node tools/wasm-trap-host.mjs abi-tests "$SCRATCH/out2/aprv.wasm" fixtures/cases.json  # results/abi-tests-node.txt
# results/no-initialize.txt and results/cases-schemas.txt: as in 2026-09-29-aprv-wasm-parity/README.md
APRV_WASM="$SCRATCH/out2/aprv.wasm" APRV_COMPONENT="$SCRATCH/out2/aprv.component.wasm" \
  cargo test --locked --manifest-path rust/bindings/abi/tests/Cargo.toml  # results/abi-tests-wasmtime.txt
REPO=$PWD MODULE="$SCRATCH/out2/aprv.wasm" TRAPHOST=tools/wasm-trap-host.mjs \
  VALIDATOR=tools/validate-wire.mjs CALLS_V1=... A1ROWS=... NODEROWS=... \
  sh docs/evidence/2026-09-29-aprv-wasm-parity/scripts/parity.sh        # results/parity.txt
python3 docs/evidence/2026-09-29-core-review-fixes/against_a2.py \
  "$SCRATCH/a2rows" "$SCRATCH/parity/rows"                              # results/against-a2.txt
for m in a2 out2; do
  node docs/evidence/2026-09-29-core-review-fixes/wasm_cost.mjs hostile "$SCRATCH/$m/aprv.wasm"
done                                                                    # results/hostile-memory.txt
for m in a2 out2; do
  node docs/evidence/2026-09-29-core-review-fixes/wasm_cost.mjs files "$SCRATCH/$m/aprv.wasm" \
    "$SCRATCH/review/root.der" "$SCRATCH"/review/*.der
done                                                                    # results/review-inputs-wasm.txt
(cd rust && cargo test --locked --workspace && \
  cargo clippy --locked --workspace --all-targets -- -D warnings && \
  cargo deny check bans licenses sources)                               # results/deny.txt
node tools/check-layering.mjs                                           # results/check-layering.txt
node --test tools/test/check-layering.test.mjs
mvn -B -f java -Dtest=ConformanceCasesTest test                         # Java's answers on the new cases
```

`$SCRATCH/review/*.der` are the reviewers' inputs, made by their probe
scripts, which stay outside the repository; each shape is rebuilt in code by
`rust/tests/envelope_bounds.rs`, `rust/tests/hostile.rs` or the unit tests
of `rust/src/receipt_payload.rs`. In `review-inputs-wasm.txt`, `out` is A2's
module and `out2` this lane's.
