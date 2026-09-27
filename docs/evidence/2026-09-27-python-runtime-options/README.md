# Python start-up options for aprv.wasm (2026-09-27)

Sources for `../2026-09-27-python-runtime-options.md`. The question is
whether the roughly 0.9 s Cranelift compile that each Python process pays
before its first verification (round 7) can be avoided.

- **What runs.** The same ABI v1 module (sha256 `b14e14b2…`) goes through
  wasmtime-py 49.0.0 with each compiler (Cranelift at two opt levels, Winch,
  Pulley) and each way of getting compiled code into a process: compile at
  start, Wasmtime's disk cache, a per-machine file cache, and a module
  precompiled into the wheel.
- **How.** Round 7's harness (`../2026-09-26-python-wasmtime/py/`) runs
  unchanged. This folder's `py/aprv_wasm` comes first on `PYTHONPATH`: it is
  round 7's facade with the engine and module source selectable through
  `APRV_*` variables.
- **WAMR and the others.** They were researched, not measured, per the
  owner's instruction to measure only mature options. `scripts/build-wamr.sh`
  records the one WAMR build that ran.

Placeholders:

| Name | Meaning |
|---|---|
| `$REPO` | the repository root |
| `$SCRATCH` | the wasm bake-off's scratch directory; this round writes under `$SCRATCH/r8` and reads the ABI v1 module, calls files and Node rows from `$SCRATCH/abi`, and round 7's venv from `$SCRATCH/py7` |
| `$CORPORA` | the substrate bake-off's request corpora (1,179 rows, plus 5,000 mutants) |

## Files

| File | What it is for |
|---|---|
| `py/aprv_wasm/__init__.py` | Round 7's facade with `APRV_ENGINE` (cranelift, cranelift-none, winch, pulley), `APRV_BASELINE`, `APRV_MODULE` (.wasm or .cwasm), `APRV_PARALLEL` (0: compile on one thread), `APRV_CACHE` (Config.cache) and `APRV_FILECACHE` (serialize on a miss, deserialize on a hit) |
| `py/precompile.py` | Precompiles the module for one setting and reports its size raw, deflated as a wheel stores it, and xz |
| `py/first_result.py`, `py/startup.py` | One cold process to its first verified g5, with its breakdown; the parent-side timing of 7 such processes, optionally pinned to one CPU |
| `py/pinning.py` | Which precompiled files each engine setting, and another wasmtime version, will load |
| `scripts/env.sh` | Shared settings |
| `scripts/run.sh` | `precompile`, `tests OPT`, `calls OPT`, `bench OPT`, `processes OPT`, `startup`, `startup-serial`, `cross` |
| `scripts/build-wamr.sh` | `fetch`, `libs`, `aot`: libiwasm from WAMR-2.4.5 and the release's wamrc (only `fetch` and `libs` ran) |
| `scripts/facts.sh` | Primary sources: PyPI, upstream git activity, WAMR's binding and release assets, Wasmtime's tier document |
| `results/abi-tests-*.txt`, `results/calls-*.txt` | ABI tests and full-corpus parity per option |
| `results/startup.txt`, `results/bench.txt`, `results/processes.txt` | Cold start, one-thread speed, and 1/2/4 processes |
| `results/precompile.txt`, `results/pinning.txt`, `results/cross.txt` | Precompiled sizes, what a precompiled module pins, and cross-compiling for other wheel targets |
| `results/wamr-build.txt`, `results/facts.txt`, `results/versions.txt` | The libiwasm build, primary sources, versions |

Options (`scripts/run.sh`): `cranelift` (the default), `cranelift-none`,
`winch`, `pulley`. Each is compiled at start. `cranelift-baseline` and
`winch-baseline` are precompiled for the baseline x86-64 target and loaded
from `.cwasm`; `pulley-cwasm` is `pulley64` loaded from `.cwasm`;
`cranelift-serial` is Cranelift at start with parallel compilation off.
`cross` needs the Wasmtime 49.0.1 CLI that
`../2026-09-26-wasm-architecture-bakeoff/scripts/fetch-tools.sh` puts in
`$SCRATCH/tools`.

## Reproduce

Round 7's `scripts/build.sh` (the venv) and the ABI v1 round's
`scripts/build.sh` and `scripts/node.sh` come first.

```sh
export REPO=... SCRATCH=... CORPORA=...
RO=$REPO/docs/evidence/2026-09-27-python-runtime-options
sh $RO/scripts/facts.sh > $RO/results/facts.txt
sh $RO/scripts/run.sh precompile > $RO/results/precompile.txt
for o in cranelift cranelift-none winch pulley cranelift-baseline winch-baseline; do
  sh $RO/scripts/run.sh tests $o > $RO/results/abi-tests-$o.txt
  sh $RO/scripts/run.sh calls $o > $RO/results/calls-$o.txt
done
sh $RO/scripts/run.sh startup > $RO/results/startup.txt          # idle machine
sh $RO/scripts/run.sh startup-serial >> $RO/results/startup.txt  # idle machine
for o in cranelift cranelift-none winch cranelift-baseline winch-baseline pulley; do
  sh $RO/scripts/run.sh bench $o >> $RO/results/bench.txt          # idle machine
done
for o in cranelift cranelift-none winch cranelift-baseline winch-baseline pulley; do
  sh $RO/scripts/run.sh processes $o >> $RO/results/processes.txt  # idle machine
done
$SCRATCH/py7/venv-wheel/bin/python $RO/py/pinning.py $SCRATCH/r8/cwasm > $RO/results/pinning.txt
python3.12 -m venv $SCRATCH/r8/venv48 && $SCRATCH/r8/venv48/bin/pip install wasmtime==48.0.0
$SCRATCH/r8/venv48/bin/python $RO/py/pinning.py $SCRATCH/r8/cwasm >> $RO/results/pinning.txt
sh $RO/scripts/run.sh cross > $RO/results/cross.txt
sh $RO/scripts/build-wamr.sh fetch; sh $RO/scripts/build-wamr.sh libs  > $RO/results/wamr-build.txt
```
