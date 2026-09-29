# init cost (2026-09-29)

The code behind [`../2026-09-29-init-cost.md`](../2026-09-29-init-cost.md).

| Path | Question it answers |
|---|---|
| `node-init-cost.mjs` | What do instantiation, `init` and a verify call cost in Node, calling the core module's exports by hand? |
| `wasmtime/` | The same on Wasmtime 49, through the ABI tests' two hosts (`rust/bindings/abi/tests`): the core module called by hand, and the component through Wasmtime's component runtime, as `aprv-server` binds it (`Cargo.toml.in` is filled in by `run.sh`) |
| `summarize.py` | Medians of the seven runs, and `init` against a pooled call |
| `run.sh` | Builds the Wasmtime bench and runs both, pinned to one CPU |
| `results/` | The rows (`wasmtime.jsonl`, `node.jsonl`), the machine's load before and after (`load.txt`), Wasmtime's compile time (`wasmtime-compile.txt`) and the table (`summary.md`) |

```sh
rust/bindings/abi/build.sh "$SCRATCH/out"
REPO=$PWD OUT="$SCRATCH/out" WORK="$SCRATCH/init-cost" sh docs/evidence/2026-09-29-init-cost/run.sh
```

Each run is 20 iterations after one warm-up run; each iteration times a
fresh instance (instantiate, `init`, one verify call) and one call on a
pooled instance that had `init` once. The inputs are the sandbox G5 receipt
under Apple's roots and `fixtures/generated/transaction.jws` under its
fixture root, at the pinned instant 2026-09-29T00:00:00Z.
