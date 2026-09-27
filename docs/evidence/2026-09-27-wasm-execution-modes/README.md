# Wasm execution modes for aprv.wasm (2026-09-27, round 9)

Sources for `../2026-09-27-wasm-execution-modes.md`. The round measures
every execution mode that Wasmi (1.1.0, 2.0.0) and WAMR (2.4.5) expose for
the canonical ABI v1 module, beside Wasmtime 49.0.1's Cranelift, Winch and
Pulley in the same native host, and then a minimal Python ctypes facade
over the WAMR library.

- **What runs.** The ABI v1 module (`aprv-abi1.wasm`, sha256
  `b14e14b2…87b636b3`), the 6,179-row corpus of the ABI v1 round, its 33
  ABI tests plus round 7's 4 facade tests, and two isolation checks.
- **How.** Each engine gets a native host with one interface
  (`serve`, `first`, `bench`): `wasmi-host/` in Rust (Wasmi and, for the
  comparison rows, Wasmtime), `wamr-host/` in C over `wasm_export.h`.
  Timing happens inside the host. `py/driver.py` drives `serve` over a
  small binary protocol, so one corpus runner and one test suite cover
  every engine; `abi_compare.py` of the ABI v1 round checks the rows
  against Node byte for byte.
- **Python.** `py/aprv_wamr/` is the APRV-specific ctypes facade over a
  `libiwasm.so`; the same driver runs its tests and corpus in process.

Placeholders:

| Name | Meaning |
|---|---|
| `$REPO` | the repository root |
| `$SCRATCH` | the wasm bake-off's scratch directory; this round writes under `$SCRATCH/r9`, reads the module, calls files and Node rows from `$SCRATCH/abi`, round 4's native rows from `$SCRATCH/asn1`, the Rust toolchains from `$SCRATCH/rustup`, and round 8's WAMR clone from `$SCRATCH/r8/wamr-git` |
| `$CORPORA` | the substrate bake-off's request corpora (1,179 rows, plus 5,000 mutants) |

## Files

| File | What it is for |
|---|---|
| `wasmi-host/Cargo.toml`, `Cargo.lock`, `src/main.rs` | The Rust host. One engine per build: feature `v1` (Wasmi 1.1.0), `v2-auto`, `v2-tail`, `v2-tail-indirect`, `v2-loop`, `v2-loop-indirect`, `v2-unstable` (Wasmi 2.0.0 dispatch variants), `wt` (Wasmtime 49.0.1). `--mode` picks the Wasmi `CompilationMode` or the Wasmtime compiler |
| `wamr-host/CMakeLists.txt`, `host.c` | `libiwasm.so` from WAMR 2.4.5 with the flags the script passes, and the C host linked to it |
| `py/driver.py` | The protocol client: `calls` (corpus rows in the Node runner's format) and `tests` (37 ABI and facade tests, 2 isolation checks); `-- inproc:aprv_wamr` runs the same over the Python facade |
| `py/startup.py` | Fresh process to first verified g5, from the parent's CLOCK_MONOTONIC to the child's, 7 runs, optionally pinned to one CPU |
| `py/procs.py` | The hosts' `bench` mode on 1 CPU, or 4 copies on 4 CPUs at once |
| `py/aprv_wamr/__init__.py` | The ctypes facade over `libiwasm.so` |
| `py/wamr_first.py`, `py/wamr_bench.py` | `first` and `bench` for the facade, same output as the native hosts |
| `py/wasmtime_first.py` | Round 8's wasmtime-py facade (its folder on `PYTHONPATH`) re-timed on this machine with the same keys |
| `py/summarize.py` | The note's tables, generated from `results/` |
| `scripts/env.sh` | Shared settings |
| `scripts/facts.sh` | Primary sources: crates.io, docs.rs, Wasmi's changelog and usage guide, the dispatch `cfg`, WAMR's build rules |
| `scripts/build-wasmi.sh` | One Rust host per row; prints features, toolchain, sizes |
| `scripts/build-wamr.sh` | `llvm`: distro LLVM 18 dev files, extracted, not installed; then one `libiwasm.so` + host per WAMR row with its flags, WAMR's CMake report and the compiler's `WASM_ENABLE_*` definitions |
| `scripts/run.sh` | `tests`, `calls`, `startup`, `procs`, `all` for one row |
| `scripts/timing.sh` | The timing runs in the order they ran: native rows, `py ROW...` for facade rows, `wasmtime-py` for round 8's facade |
| `results/facts.txt`, `results/build-wasmi.txt`, `results/build-wamr.txt`, `results/wamr-llvm.txt` | Sources, builds, the LLVM extraction |
| `results/tests-ROW.txt`, `results/calls-ROW.txt` | ABI tests and corpus parity per row |
| `results/startup.txt`, `results/procs.txt` | Cold start and throughput, one JSON line per row and CPU count |
| `results/summary.txt` | `py/summarize.py`'s tables |
| `results/versions.txt`, `results/disk.txt` | Versions and hashes; disk use before and after |

Rows (`scripts/run.sh`):

| Row | Engine and setting |
|---|---|
| `wasmi1-{eager,lazytr,lazy}` | Wasmi 1.1.0, `CompilationMode::{Eager,LazyTranslation,Lazy}` |
| `wasmi2-auto-{eager,lazytr,lazy}` | Wasmi 2.0.0, default dispatch (`auto-dispatch`) |
| `wasmi2-{tail,tail-ind,loop,loop-ind,unstable}-MODE` | Wasmi 2.0.0 with that dispatch build |
| `wamr-{classic,fast}` | WAMR classic or fast interpreter |
| `wamr-{fastjit,llvmjit,multitier}-{lazy,eager}` | WAMR Fast JIT, LLVM JIT, both (multi-tier), lazy or eager |
| `wasmtime-{cranelift,winch,pulley}` | Wasmtime 49.0.1 in the same Rust host |
| `py-wamr-ROW` | The Python ctypes facade over that WAMR row's library |
| `py-wasmtime-{cranelift,winch,cranelift-cwasm}` | Round 8's wasmtime-py facade, start-up only |

## Reproduce

The ABI v1 round (`../2026-09-26-wasm-abi-v1`) comes first: its
`scripts/build.sh` and `scripts/node.sh` make the module, the calls files
and the Node rows. Round 8's `scripts/build-wamr.sh fetch` makes the WAMR
clone. Run the timing steps on an idle machine, one at a time.

```sh
export REPO=... SCRATCH=... CORPORA=...
EM=$REPO/docs/evidence/2026-09-27-wasm-execution-modes
sh $EM/scripts/facts.sh > $EM/results/facts.txt
sh $EM/scripts/build-wasmi.sh wasmi1 wasmi2-auto wasmi2-tail wasmi2-tail-ind wasmi2-loop wasmi2-loop-ind wasmi2-unstable wasmtime
sh $EM/scripts/build-wamr.sh llvm > $EM/results/wamr-llvm.txt
sh $EM/scripts/build-wamr.sh > $EM/results/build-wamr.txt
for r in wasmi1-eager wasmi1-lazytr wasmi1-lazy wasmi2-auto-eager wasmi2-auto-lazytr wasmi2-auto-lazy \
         wasmi2-tail-lazytr wasmi2-tail-ind-lazytr wasmi2-loop-lazytr wasmi2-loop-ind-lazytr wasmi2-unstable-lazytr \
         wamr-classic wamr-fast wamr-fastjit-lazy wamr-fastjit-eager wamr-multitier-lazy wamr-multitier-eager \
         wamr-llvmjit-lazy wamr-llvmjit-eager wasmtime-cranelift wasmtime-winch wasmtime-pulley \
         py-wamr-fast py-wamr-fastjit-eager; do
  sh $EM/scripts/run.sh tests $r; sh $EM/scripts/run.sh calls $r
done
# timing: an otherwise idle machine, nothing else running
sh $EM/scripts/timing.sh
sh $EM/scripts/timing.sh py py-wamr-fast py-wamr-fastjit-eager
sh $EM/scripts/timing.sh wasmtime-py
python3 $EM/py/summarize.py $EM/results > $EM/results/summary.txt
```

`results/build-wasmi.txt` holds that script's output, a header, and a check
that the binaries the first correctness runs used differ from the final
ones only in their build-id note.
