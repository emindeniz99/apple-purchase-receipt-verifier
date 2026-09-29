# Final Python runtime round (2026-09-27, round 11)

Sources for `../2026-09-27-python-runtime-final.md`. The round measures the
two Python routes the earlier rounds had not: pure-Python pywasm 2.2.3, and
Wasmi 2.0.0 as a small shared library behind a ctypes facade. It measures
Wasmi both through its official C API and through a narrow APRV-specific
Rust cdylib. It then runs resource-exhaustion cases against both, checks
cross-builds for eight wheel targets, and runs an aarch64 correctness smoke
under QEMU. Round 9's harness
(`../2026-09-27-wasm-execution-modes/py`: `driver.py`, `startup.py`,
`procs.py`) runs unchanged, so every row is measured the way the WAMR and
wasmtime-py rows were.

The security desk review of Wasmi 2.0.0 is a separate note
(`../2026-09-27-wasmi-security-review.md`), written by another agent.
Nothing here writes to it.

Placeholders:

| Name | Meaning |
|---|---|
| `$REPO` | the repository root |
| `$SCRATCH` | the wasm bake-off's scratch directory. This round writes under `$SCRATCH/r11`. It reads the module, calls files and Node rows from `$SCRATCH/abi`, round 4's native rows from `$SCRATCH/asn1`, the Rust toolchains from `$SCRATCH/rustup`, wasm-tools from `$SCRATCH/tools`, and round 9's native Wasmi host from `$SCRATCH/r9/bin` |
| `$CORPORA` | the substrate bake-off's request corpora (1,179 rows, plus 5,000 mutants) |

## Files

| File | What it is for |
|---|---|
| `py/aprv_pywasm/__init__.py` | The APRV facade over pywasm 2.2.3 (pure Python): the two host imports, the ABI v1 lifecycle, a fresh instance after a trap |
| `py/pywasm_probe.py` | The early-stop probe: import, parse, instantiate, g5 #1..#N, JWS #1..#N, with RSS |
| `py/pywasm_asserts.py` | Three trap cases under `python` and `python -O` (pywasm's traps are `assert`s) |
| `wasmi-capi/Cargo.toml`, `Cargo.lock`, `src/lib.rs` | Wasmi's official C API (`wasmi_c_api_impl` 2.0.0) re-exported as one `libwasmi.so` |
| `py/aprv_wasmi_capi/__init__.py` | ctypes facade over that C API (`wasm.h` plus the `wasmi.h` config setters). Its docstring lists every C function it calls |
| `wasmi-cdylib/Cargo.toml`, `Cargo.lock`, `src/lib.rs` | The narrow alternative: 10 `extern "C"` functions around Wasmi 2.0.0's safe Rust API. The host imports are in Rust, with per-call fuel, `StoreLimits` (64 MiB memory cap, 1 instance/memory/table), and `catch_unwind` at every entry. Feature `extra-checks` turns on Wasmi's `extra-checks` |
| `py/aprv_wasmi_rs/__init__.py` | ctypes facade over `libaprv_wasmi.so` |
| `py/driver.py` | Round 9's `driver.py` with one addition: `-- inproc:<facade module>` for any facade |
| `py/first.py`, `py/bench.py` | Round 9's `wamr_first.py` / `wamr_bench.py` for any facade (`APRV_FACADE`). Same JSON, so round 9's `startup.py` and `procs.py` run them unchanged |
| `py/threads.py` | N threads in one process, one `Verifier` each |
| `py/fuel.py` | Fuel and linear-memory envelope of every corpus row |
| `py/fuel_heaviest.py` | The heaviest rows timed with metering on; the margin a 5e9 budget leaves |
| `py/exhaust.py` | 19 resource-exhaustion and trap cases × 4 configurations, each case in its own child process, killed as a group on timeout |
| `py/ab_summary.py` | Medians of the interleaved A/B runs |
| `wat/hostile.wat`, `two-tables.wat`, `big-memory.wat` | The hostile guests `exhaust.py` loads (aprv.wasm's import and lifecycle shape) |
| `scripts/env.sh` | Shared settings |
| `scripts/pywasm.sh` | pywasm: install, PyPI metadata, Python floor, sizes, the probe, the `-O` check. It states the stop rule |
| `scripts/build.sh` | The three Wasmi libraries, clean, one at a time: sizes, exported surface, `unsafe` count, crate versions |
| `scripts/run.sh` | `tests`, `calls`, `startup`, `procs`, `all` for one Python row |
| `scripts/ab.sh`, `scripts/ab-extra-checks.sh`, `scripts/startup-ab.sh` | Interleaved A/B runs: native Wasmi against the two facades and fuel off/on; `extra-checks` off/on; start-up of native Wasmi and of the cdylib with limits off/on |
| `scripts/cross.sh` | Cross-build feasibility of the cdylib for the wheel targets (cargo-zigbuild) |
| `scripts/qemu-smoke.sh` | aarch64 correctness smoke under QEMU (not performance) |
| `scripts/arm64-native.sh` | Self-contained script for the owner to run on Linux AArch64 or an Apple Silicon Mac |
| `scripts/versions.sh` | Machine, tool versions, module hash |
| `results/pywasm.txt` | pywasm facts, the probe and the `-O` check |
| `results/build.txt`, `results/versions.txt` | Builds and versions |
| `results/tests-ROW.txt`, `results/calls-ROW.txt` | ABI tests and corpus parity per row |
| `results/startup.txt`, `results/procs.txt` | Cold start and throughput, one JSON line per row and CPU count |
| `results/ab.txt`, `ab-summary.txt`, `ab-extra-checks*.txt`, `startup-ab.txt` | The A/B runs |
| `results/threads.txt` | Thread scaling |
| `results/fuel-envelope.txt`, `results/fuel-heaviest.txt` | Fuel and memory over the corpus; the heaviest rows timed |
| `results/exhaust.txt` | The exhaustion matrix |
| `results/cross.txt`, `results/qemu-smoke.txt` | Cross-builds; the QEMU smoke |
| `results/disk.txt` | Disk use |

Rows (`scripts/run.sh`):

| Row | Facade and setting |
|---|---|
| `py-wasmi-rs-lazytr`, `py-wasmi-rs-lazy` | `aprv_wasmi_rs`, `CompilationMode::{LazyTranslation,Lazy}`, no fuel, no memory cap |
| `py-wasmi-rs-lazytr-fuel` | the same with fuel 5e9 per call and a 64 MiB memory cap (the recommended configuration). Start-up and throughput ran at 10e9 and no cap; a budget is a counter value, and the limiter runs only on `memory.grow` |
| `py-wasmi-rs-lazytr-fuel-xc` | the recommended configuration on the `extra-checks` build |
| `py-wasmi-capi-lazytr`, `py-wasmi-capi-lazy` | `aprv_wasmi_capi`, the official C API; no fuel (see the note), no limits (the C API has none) |

## Reproduce

```sh
export REPO=... SCRATCH=... CORPORA=... PYTHONDONTWRITEBYTECODE=1
F=$REPO/docs/evidence/2026-09-27-python-runtime-final
sh $F/scripts/versions.sh > $F/results/versions.txt
sh $F/scripts/pywasm.sh > $F/results/pywasm.txt          # about 6 minutes; stop rule inside
sh $F/scripts/build.sh > $F/results/build.txt
for r in py-wasmi-rs-lazytr py-wasmi-capi-lazytr; do sh $F/scripts/run.sh all $r; done
FUEL=10000000000 MAXMEM=0 sh $F/scripts/run.sh startup py-wasmi-rs-lazytr-fuel
FUEL=10000000000 MAXMEM=0 sh $F/scripts/run.sh procs py-wasmi-rs-lazytr-fuel
sh $F/scripts/run.sh tests py-wasmi-rs-lazytr-fuel; sh $F/scripts/run.sh calls py-wasmi-rs-lazytr-fuel
sh $F/scripts/run.sh tests py-wasmi-rs-lazytr-fuel-xc; sh $F/scripts/run.sh calls py-wasmi-rs-lazytr-fuel-xc
for r in py-wasmi-rs-lazy py-wasmi-capi-lazy; do sh $F/scripts/run.sh startup $r; sh $F/scripts/run.sh procs $r; done
sh $F/scripts/ab.sh 5 > $F/results/ab.txt && python3 $F/py/ab_summary.py $F/results/ab.txt > $F/results/ab-summary.txt
sh $F/scripts/ab-extra-checks.sh 5 > $F/results/ab-extra-checks.txt   # summary: py/ab_summary.py
sh $F/scripts/startup-ab.sh 3 > $F/results/startup-ab.txt
# threads, fuel, exhaustion (env as in scripts/run.sh: APRV_MODULE, PYTHONPATH=$F/py, APRV_LIB*, APRV_FACADE)
python3.12 $F/py/threads.py G5 JWS 5 1 2 4 >> $F/results/threads.txt
APRV_WASMI_FUEL=4611686018427387904 python3.12 $F/py/fuel.py $SCRATCH/abi/calls > $F/results/fuel-envelope.txt
APRV_WASMI_FUEL=5000000000 python3.12 $F/py/fuel_heaviest.py $SCRATCH/abi/calls/cases.jsonl > $F/results/fuel-heaviest.txt
python3.12 $F/py/exhaust.py rs-bounded|rs-unbounded|capi|capi-fuel $SCRATCH/r11/wat MODULE >> $F/results/exhaust.txt
#   (plus APRV_EXHAUST_FUEL=10000000000 for rs-bounded's infinite-loop line at 10e9)
#   (wat/*.wat compiled first: wasm-tools parse wat/X.wat -o $SCRATCH/r11/wat/X.wasm)
sh $F/scripts/cross.sh > $F/results/cross.txt          # after: rustup target add ...; pip install ziglang cargo-zigbuild
sh $F/scripts/build.sh > $F/results/build.txt          # (re-run last: cross.sh and qemu-smoke.sh share the target dir)
sh $F/scripts/qemu-smoke.sh > $F/results/qemu-smoke.txt
```

On an ARM64 machine, from a checkout, with the module and the cases calls
file copied over:

```sh
sh docs/evidence/2026-09-27-python-runtime-final/scripts/arm64-native.sh aprv-abi1.wasm cases.jsonl
```
