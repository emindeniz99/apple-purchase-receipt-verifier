# aprv.wasm on Ruby with wasmtime-rb (2026-09-26)

Sources for `../2026-09-26-ruby-wasmtime.md`. The ABI v1 module from
`../2026-09-26-wasm-abi-v1/` runs here on the official Bytecode Alliance
`wasmtime` gem (48.0.1), through a minimal facade gem that is installed
into an empty `GEM_HOME`.

Placeholders:

| Name | Meaning |
|---|---|
| `$REPO` | the repository root |
| `$SCRATCH` | the wasm bake-off's scratch directory; this round writes under `$SCRATCH/rb7` (gems included) and reads the ABI v1 module and calls files from `$SCRATCH/abi` |
| `$CORPORA` | the substrate bake-off's request corpora |

Ruby 3.3.6 must be on `PATH`. No gem is installed outside `$SCRATCH/rb7`.

## Files

| File | What it is for |
|---|---|
| `gem/aprv_wasm_spike.gemspec`, `gem/lib/aprv_wasm.rb` | The facade gem: pure Ruby plus `aprv.wasm`, depending on `wasmtime = 48.0.1` |
| `rb/common.rb` | Shared helpers, including a JSON string writer spelled like `JSON.stringify` |
| `rb/run_calls.rb` | Runs a calls file; rows in the Node runner's exact format |
| `rb/abi_tests.rb` | The 33 ABI tests, plus 4 tests of the facade's contract |
| `rb/concurrency.rb` | Warm benchmark; 1/2/4 threads; 1/2/4 forked processes; independent instances and traps under concurrency |
| `rb/startup.rb` | Start-up in a fresh process |
| `scripts/env.sh`, `scripts/build.sh`, `scripts/run.sh`, `scripts/facts.sh` | Settings; gem build plus clean install and smoke test; runs; primary sources |
| `results/*.txt` | One file per `run.sh` mode, plus `build.txt` and `facts.txt` |

## Reproduce

Run the ABI v1 round's `scripts/build.sh` and `scripts/node.sh` first.

```sh
export REPO=... SCRATCH=... CORPORA=...
RW=$REPO/docs/evidence/2026-09-26-ruby-wasmtime
sh $RW/scripts/facts.sh > $RW/results/facts.txt
sh $RW/scripts/build.sh > $RW/results/build.txt
sh $RW/scripts/run.sh tests > $RW/results/abi-tests.txt
for m in calls startup bench threads processes isolation; do sh $RW/scripts/run.sh $m > $RW/results/$m.txt; done
```

Run the timing modes on an otherwise idle machine, one at a time.
