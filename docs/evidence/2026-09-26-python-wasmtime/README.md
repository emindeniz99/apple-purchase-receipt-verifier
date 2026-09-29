# aprv.wasm on Python with wasmtime-py (2026-09-26)

Sources for `../2026-09-26-python-wasmtime.md`. The ABI v1 module from
`../2026-09-26-wasm-abi-v1/` runs here on the official Bytecode Alliance
`wasmtime` package (49.0.0), through a minimal facade package, from a clean
consumer install.

Placeholders:

| Name | Meaning |
|---|---|
| `$REPO` | the repository root |
| `$SCRATCH` | the wasm bake-off's scratch directory; this round writes under `$SCRATCH/py7` and reads the ABI v1 module and calls files from `$SCRATCH/abi` |
| `$CORPORA` | the substrate bake-off's request corpora (1,179 rows, plus 5,000 mutants) |

## Files

| File | What it is for |
|---|---|
| `facade/pyproject.toml`, `facade/src/aprv_wasm/__init__.py` | The facade package `aprv-wasm-spike`: pure Python plus `aprv.wasm`, depending on `wasmtime==49.0.0` |
| `py/run_calls.py` | Runs a calls file; rows in the Node runner's exact format |
| `py/abi_tests.py` | The 33 ABI tests, plus 4 tests of the facade's contract |
| `py/concurrency.py` | Warm benchmark; 1/2/4 threads; 1/2/4 processes; independent instances and traps under concurrency |
| `py/startup.py` | Start-up in a fresh process |
| `py/slab_race.py` | The wasmtime-py 49.0.0 callback-table race: the per-Store pattern the facade avoids, and the facade's pattern |
| `scripts/env.sh` | Shared settings |
| `scripts/build.sh` | Builds the sdist and wheel, installs each into a new venv from PyPI (wheel on Python 3.12, sdist on 3.10), runs a smoke test |
| `scripts/run.sh` | `tests`, `calls`, `startup`, `bench`, `threads`, `processes`, `isolation`, `slab` |
| `scripts/facts.sh` | Primary sources: PyPI's API, the upstream git log, the wheels' contents and glibc floor, pip's choice where no wheel exists |
| `results/*.txt` | One file per `run.sh` mode, plus `build.txt` and `facts.txt` |

## Reproduce

Run the ABI v1 round's `scripts/build.sh` and `scripts/node.sh` first. They
build the module and the calls files and the Node rows this round compares
against.

```sh
export REPO=... SCRATCH=... CORPORA=...
PW=$REPO/docs/evidence/2026-09-26-python-wasmtime
sh $PW/scripts/facts.sh > $PW/results/facts.txt
sh $PW/scripts/build.sh > $PW/results/build.txt
for m in tests calls startup bench threads processes isolation; do
  n=$m; [ $m = tests ] && n=abi-tests
  sh $PW/scripts/run.sh $m > $PW/results/$n.txt
done
sh $PW/scripts/run.sh slab > $PW/results/slab-race.txt
```

Run the timing modes on an otherwise idle machine, one at a time.
