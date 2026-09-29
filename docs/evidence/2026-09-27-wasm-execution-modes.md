# Wasm execution modes for aprv.wasm: Wasmi, WAMR and Wasmtime

Date: 2026-09-27 (round 9). Code, scripts and raw results are in
`2026-09-27-wasm-execution-modes/`. Its `README.md` has the file table and
the commands to reproduce.

**Question.** Round 8 (`2026-09-27-python-runtime-options.md`) found that
Wasmtime compiles `aprv.wasm` for about 1 s per process, and 3 s on one
CPU, unless a precompiled module ships with it. This round maps the whole
start-up against throughput landscape for the same module. It covers every
execution mode that Wasmi 1.1.0, Wasmi 2.0.0 and WAMR 2.4.5 expose, next to
Wasmtime's Cranelift, Winch and Pulley in the same native host. It then
tests a minimal Python ctypes facade over the most useful WAMR modes. The
owner's frame is that cold start matters more than peak speed, and that 10
to 20 verifications per second per core is already usable. This note
records evidence and observations. It does not change the plan.

Labels: TESTED (ran here), DOCUMENTED (read in a primary source), EXPECTED
(inferred, not run). Nothing under `python/`, `rust/`, `docs/rust-core` or
any other production path changed. No AOT or precompiled guest artifact
was used, except in round 8's wasmtime-py `.cwasm` row, which is marked.

**Environment** (`results/versions.txt`):

- Ubuntu 24.04 x86-64, 4 vCPUs (Intel Xeon 2.80 GHz), 16 GB RAM.
- Rust 1.98.1 (nightly 1.100.0 for one row), with Wasmi's recommended
  profile: `lto = "fat"`, `codegen-units = 1`.
- gcc 13.3, Ubuntu's LLVM 18.1.3, CPython 3.12.3 for the Python rows.
- **A different CPU from round 8's** (2.10 GHz). Every number in this note
  was measured on this machine, including a re-timing of round 8's
  wasmtime-py start-up rows. No round 8 figure enters a table.

**What each measurement is:**

- **Start-up (first result).** The parent reads CLOCK_MONOTONIC and spawns
  the host. The host stamps the same clock when its first verified g5
  returns. The span covers exec, dynamic loading, runtime init, reading
  and loading the module, instantiation with `_initialize`, and the first
  call. Each figure is the median of 7 runs. A row whose run took over
  60 s ran once.
- **1 CPU** means `taskset -c 0` on the whole process, compiler threads
  included. That is the Lambda-like case.
- **Throughput.** One instance times calls #1, #2, #5, #10 and #100 of g5,
  then a steady loop of at least 20 calls and 2 s. It then does the same
  for the shared-sandbox JWS in the same instance.
  - "1 CPU" is one process on CPU 0.
  - "4 CPUs" is four processes at once, one per CPU. The table shows their
    mean, per CPU.

## Observations

- **Every mode gives the same answers (TESTED).** Each of the 24 rows that
  ran the corpus gave 6,179 of 6,179 rows byte-identical to Node, 0
  DIFFERENT and 0 traps. That is 22 native rows and the 2 Python facade
  rows. Each also passed the 37 ABI and facade tests and 2 isolation
  checks. The Wasmi dispatch builds ran the corpus in LazyTranslation
  mode. Their other modes were timed only.
- **Wasmi 2.0.0 with lazy compilation gives the fastest cold start of all
  (TESTED).** A fresh process has its first verified g5 in 54 ms on one
  CPU and 58 to 62 ms on four. Only the precompiled wasmtime-py module
  comes close, at 72 ms from Python. After that Wasmi runs 64 g5 and
  12.5 to 13 JWS per second per core. That is inside the owner's "usable"
  band of 10 to 20, not far above it.
- **Wasmi's lazy mode is Endive-like in the sense the owner asked
  (TESTED).** Load takes 5 ms, because nothing is validated or translated
  up front. The first call translates only what g5 touches and takes
  44 ms. The second call, at 15 ms, is already steady state. Details are
  below.
- **WAMR's Fast JIT gives the best balance in this set (TESTED).** First
  result in 156 to 195 ms on four CPUs and about 450 ms on one, then 274
  to 277 g5 and 68 JWS per second per core. That is 4 to 5 times Wasmi
  2.0 and half of Cranelift.
  - WAMR's "lazy" JIT is not on-demand. It starts compiler threads at load
    that translate the whole module in the background, so on one CPU lazy
    and eager both take about 450 ms.
- **WAMR's LLVM JIT is fast once warm and unusable cold (TESTED).**
  - Warm, the eager build reaches 604 g5/s and 183 JWS/s, at or above
    Cranelift's 575 and 143.
  - Cold, it takes 106 s on four CPUs and 153 s on one before the first
    result, and holds about 1 GB of RSS. This is with Ubuntu's LLVM 18 at
    iwasm's default opt level 3.
  - The lazy build reaches its first result after 85 s, then 111 s on one
    CPU.
  - Multi-tier (Fast JIT, then LLVM in the background) starts like the
    Fast JIT: 356 ms on four CPUs, 698 ms on one. The LLVM compile it runs
    in the background peaks at 476 MiB.
- **The interpreters fall around the floor (TESTED).**
  - WAMR's fast interpreter: 134 ms to first result, 41 g5/s, 9.4 JWS/s
    (just under 10).
  - WAMR's classic interpreter: 368 ms, 8.5 g5/s, 2.6 JWS/s.
  - Wasmi 1.1.0: 78 ms lazy, 29.5 g5/s, 7.5 JWS/s.
  - Wasmtime's Pulley: 3.3 s on one CPU (it compiles to bytecode first),
    22 g5/s, 4.6 JWS/s.
- **Wasmi 2.0's dispatch choice matters, and the default is the fastest
  (TESTED).** The default tail-call dispatch, the same dispatch forced,
  and nightly `become` all run 63 to 64 g5/s. Against that:
  - indirect dispatch costs 12% on g5 and 20% on JWS;
  - the portable switch loop is 1.7 times slower;
  - the portable call loop is 2.6 times slower (5.8 JWS/s).
- **The Python ctypes facade over WAMR adds about 30 ms to start-up and
  nothing measurable to steady speed (TESTED).**
  - Fast interpreter: 165 ms on one CPU, 41 g5/s, 9.4 JWS/s.
  - Fast JIT: 486 ms on one CPU, 272 g5/s, 66 JWS/s.
  - wasmtime-py re-timed here: 3,260 ms (Cranelift at start), 1,018 ms
    (Winch at start) and 72 ms (precompiled `.cwasm`), all on one CPU.
- **Size and memory spread by two orders of magnitude (TESTED).** Stripped:
  - the whole Wasmi host is 1.6 to 1.7 MB;
  - WAMR's `libiwasm.so` is 0.30 MB (classic), 0.32 MB (fast) and 0.69 MB
    (Fast JIT); with LLVM linked in, it is 49.5 MB;
  - the Wasmtime host with Cranelift, Winch and Pulley is 12.0 MB.

  Peak RSS is 13 to 19 MiB for Wasmi, 17 to 31 MiB for WAMR without LLVM,
  104 to 124 MiB for Wasmtime, and about 1 GB for the LLVM JIT.

## What ran

### Wasmi (DOCUMENTED from crates.io and docs.rs, `results/facts.txt`)

**Versions.** Wasmi 2.0.0 is a final release. crates.io lists it on
2026-09-01, not yanked, after `2.0.0-beta.0` to `beta.10`. Wasmi 1.1.0
(2026-06-12) is the newest 1.x.

**Compilation modes.** The docs.rs pages of both exact versions define
`pub enum CompilationMode { Eager, LazyTranslation, Lazy }`:

- `Eager`: "The Wasm code is compiled eagerly to Wasmi bytecode."
- `LazyTranslation`: "The Wasm code is validated eagerly and translated
  lazily on first use."
- `Lazy`: "The Wasm code is validated and translated lazily on first use.
  […] This mode must not be used if the result of Wasm execution must be
  deterministic amongst multiple Wasm implementations."

`Config::compilation_mode(&mut self, mode: CompilationMode)` sets it: "By
default CompilationMode::LazyTranslation is used." The host passes it at
run time (`--mode`). Every other `Config` value is the default: no fuel,
default stack limits.

**Cargo features, 2.0.0.** The defaults are `stable`, `std`, `wat`,
`validate`, `memory64` and `auto-dispatch`. Every row keeps `std`,
`validate` and `memory64`, and drops `wat`, which only lets `Module::new`
accept text. The rows add:

| Row | Features added | Dispatch compiled (from `dispatch/mod.rs` and `build.rs` of the 2.0.0 crate) |
|---|---|---|
| `wasmi2-auto` (default) | `stable`, `auto-dispatch` | tail-call backend with handler pointers in the IR: `build.rs` sets `wasmi_use_tail_calls` on x86_64 at opt level 2, 3, s or z |
| `wasmi2-tail` | `stable` | the same backend, chosen because `auto-dispatch` is off and `portable-dispatch` is off; on x86-64 at opt level 3 it compiles the same code path as the default |
| `wasmi2-tail-ind` | `stable`, `indirect-dispatch` | tail-call backend; the IR stores op codes, and a table maps them to handlers |
| `wasmi2-loop-ind` | `stable`, `portable-dispatch`, `indirect-dispatch` | loop backend running a `match` over op codes: a switch loop |
| `wasmi2-loop` | `stable`, `portable-dispatch` | loop backend calling the handler pointer stored in the IR: a call loop |
| `wasmi2-unstable` | `unstable` (no `stable`), nightly Rust | tail-call backend with `become`, which forces tail calls |

The owner's names map onto these by reading `backend/tail.rs` and
`backend/loop.rs`. Wasmi's documentation does not use the names
"direct-threaded", "switch-loop" or "call-loop".

- "Direct-threaded / fastest supported" is `wasmi2-auto`, equal to
  `wasmi2-tail` on this target.
- "Indirect-threaded" is `wasmi2-tail-ind`.
- "Portable switch-loop" is `wasmi2-loop-ind`.
- "Call-loop" is `wasmi2-loop`.

What upstream says about these features (DOCUMENTED):

- The docs.rs feature table describes `portable-dispatch` as "Allows to
  compile Wasmi universally at the cost of execution performance".
- It describes `indirect-dispatch` as "Uses a slightly more compact IR
  encoding at the cost of execution performance".
- The changelog adds that portable dispatch "may significantly reduce
  execution performance".
- I found no upstream sentence about the call loop in particular.

**Wasmi 1.1.0** has no dispatch features. Its only row uses `std`.

### WAMR 2.4.5 (TESTED, `results/build-wamr.txt`)

Each row is its own `libiwasm.so`, built from WAMR-2.4.5 (`25bd7eb6`)
with every switch explicit:

- Release, no AOT loader, no WASI, no libc-builtin, no multi-module, no
  debug interpreter (`WAMR_BUILD_DEBUG_INTERP=0`), no threads, no SIMD
  (the module has none);
- bulk memory and reference types on (the module uses both);
- iwasm's own defaults for the JIT settings: LLVM opt and size level 3,
  Fast JIT code cache 10 MiB;
- a 1 MiB exec-env stack, and no host-managed heap.

**WAMR switches to the classic interpreter whenever a JIT is on (TESTED).**

- Every JIT row asked for `-DWAMR_BUILD_FAST_INTERP=1`.
- WAMR's CMake answered "Fast interpreter disabled".
- The compiler received `-DWASM_ENABLE_FAST_INTERP=0`.
- The rule is in `runtime_lib.cmake` lines 51-54: "Enable classic
  interpreter if Fast JIT or LLVM JIT is enabled", then
  `set (WAMR_BUILD_FAST_INTERP 0)`.
- The LLVM rows also compile with `-DWASM_ENABLE_AOT=1` even though
  `WAMR_BUILD_AOT=0`. WAMR's LLVM JIT runs on its AOT runtime internally.
  No AOT file was made or loaded.

| Row | Flags beyond the common set | CMake said | Running mode the host saw |
|---|---|---|---|
| `wamr-classic` | `FAST_INTERP=0` | Fast interpreter disabled | interp |
| `wamr-fast` | `FAST_INTERP=1` | Fast interpreter enabled | interp |
| `wamr-fastjit-lazy` | `FAST_JIT=1 LAZY_JIT=1` | Fast interpreter disabled; Fast JIT enabled with Lazy Compilation | fast-jit |
| `wamr-fastjit-eager` | `FAST_JIT=1 LAZY_JIT=0` | … with Eager Compilation | fast-jit |
| `wamr-llvmjit-lazy` | `JIT=1 LAZY_JIT=1` | LLVM ORC JIT enabled with Lazy Compilation | llvm-jit |
| `wamr-llvmjit-eager` | `JIT=1 LAZY_JIT=0` | … with Eager Compilation | llvm-jit |
| `wamr-multitier-lazy` | `FAST_JIT=1 JIT=1 LAZY_JIT=1` | both lazy; "Multi-tier JIT enabled" | multi-tier |
| `wamr-multitier-eager` | `FAST_JIT=1 JIT=1 LAZY_JIT=0` | both eager; no multi-tier line | llvm-jit |

The last row is the one distinct lazy/eager multi-tier setting WAMR
builds. WAMR reports `Mode_Multi_Tier_JIT` as supported only with
`LAZY_JIT` (`wasm_runtime_common.c` lines 860-863). The eager build
therefore compiles both tiers up front and then runs the LLVM code.

**LLVM without building LLVM (TESTED, `results/wamr-llvm.txt`).**

- WAMR 2.4.5's own `build_llvm.py` pins LLVM `release/18.x`. Ubuntu
  already ships LLVM 18.1.3's runtime library.
- `build-wamr.sh llvm` downloads the matching `llvm-18-dev`, plus
  `libzstd-dev`, `libxml2-dev` and `libpfm4-dev`, and unpacks them into
  scratch with `dpkg-deb -x`. That takes 335 MB, and nothing is
  installed.
- Ubuntu's `LLVMExports.cmake` will not load unless every file of every
  exported target exists. The script links 75 of those files to the
  installed llvm-18 and puts empty placeholders for 27 that exist nowhere
  (MLIR, OpenMP, Polly, test tools).
- The CMake project defines empty `LibEdit::LibEdit` and `CURL::libcurl`
  targets.
- WAMR links neither of those, and `libiwasm.so` links the LLVM archives
  statically. Each LLVM row built in 23 to 36 s.

### Wasmtime and Python

- **Wasmtime 49.0.1 in the same Rust host** (feature `wt`: `runtime`,
  `std`, `cranelift`, `winch`, `pulley`, `parallel-compilation`).
  `--mode` sets `Strategy::Cranelift`, `Strategy::Winch` or
  `target("pulley64")`. These rows are new, not reused from round 8.
- **`py/aprv_wamr`** is the APRV-specific ctypes facade the brief asked
  for. It provides:
  - runtime init;
  - the two host imports as ctypes callbacks;
  - module load, instantiate and export lookup;
  - guest alloc and copy, `aprv_call`, result copy and free;
  - trap handling that discards the instance.

  Its `RuntimeInitArgs` layout is checked against `sizeof` in C.
  `driver.py -- inproc:aprv_wamr` runs the same tests and corpus through
  it, in process.
- **The wasmtime-py rows** are round 8's own facade, imported from its
  folder unchanged, and re-timed here by `py/wasmtime_first.py`.

## Start-up (`results/startup.txt`, generated in `results/summary.txt`)

Fresh process to first verified g5. "Runtime size" is the stripped host
binary for the Rust rows (engine included) and the stripped `libiwasm.so`
for the WAMR rows; the C host adds 31 KB. The Python rows add CPython.

| Row | Runtime size (stripped) | 4 CPUs | 1 CPU | 1 CPU: init / load / instantiate / first call | 1 CPU: 2nd call | RSS after first result |
|---|---:|---:|---:|---|---:|---:|
| wasmi1-eager | 1.61 MB | 108.3 ms | 106.7 ms | 0.0 / 44.6 / 1.5 / 57.2 ms | 33.0 ms | 14 MiB |
| wasmi1-lazytr | 1.61 MB | 89.9 ms | 91.9 ms | 0.0 / 21.7 / 1.3 / 65.3 ms | 35.0 ms | 12 MiB |
| wasmi1-lazy | 1.61 MB | 76.6 ms | 77.6 ms | 0.0 / 4.9 / 1.3 / 67.9 ms | 36.6 ms | 13 MiB |
| wasmi2-auto-eager | 1.67 MB | 96.8 ms | 100.7 ms | 0.0 / 63.5 / 1.5 / 32.4 ms | 15.1 ms | 19 MiB |
| wasmi2-auto-lazytr | 1.67 MB | 65.4 ms | 69.2 ms | 0.0 / 19.7 / 1.5 / 43.5 ms | 16.3 ms | 14 MiB |
| wasmi2-auto-lazy | 1.67 MB | 62.1 ms | 54.1 ms | 0.0 / 5.1 / 1.5 / 44.1 ms | 15.1 ms | 14 MiB |
| wasmi2-tail-eager | 1.67 MB | 98.9 ms | 100.9 ms | 0.0 / 64.4 / 1.5 / 31.5 ms | 16.3 ms | 19 MiB |
| wasmi2-tail-lazytr | 1.67 MB | 71.5 ms | 69.2 ms | 0.0 / 20.9 / 1.8 / 43.3 ms | 15.1 ms | 14 MiB |
| wasmi2-tail-lazy | 1.67 MB | 57.7 ms | 54.3 ms | 0.0 / 5.3 / 1.5 / 44.0 ms | 14.8 ms | 14 MiB |
| wasmi2-tail-ind-eager | 1.69 MB | 96.2 ms | 98.0 ms | 0.0 / 56.3 / 1.5 / 36.4 ms | 16.8 ms | 14 MiB |
| wasmi2-tail-ind-lazytr | 1.69 MB | 68.0 ms | 71.6 ms | 0.0 / 18.8 / 1.5 / 47.7 ms | 16.9 ms | 13 MiB |
| wasmi2-tail-ind-lazy | 1.69 MB | 60.3 ms | 57.8 ms | 0.0 / 5.4 / 1.5 / 47.2 ms | 17.2 ms | 13 MiB |
| wasmi2-loop-eager | 1.67 MB | 139.7 ms | 139.4 ms | 0.0 / 60.6 / 1.6 / 74.0 ms | 40.4 ms | 19 MiB |
| wasmi2-loop-lazytr | 1.67 MB | 122.9 ms | 112.8 ms | 0.0 / 19.8 / 1.5 / 88.0 ms | 43.7 ms | 14 MiB |
| wasmi2-loop-lazy | 1.67 MB | 96.3 ms | 100.2 ms | 0.0 / 5.4 / 1.5 / 89.9 ms | 42.0 ms | 14 MiB |
| wasmi2-loop-ind-eager | 1.60 MB | 107.6 ms | 108.5 ms | 0.0 / 56.1 / 1.5 / 47.1 ms | 26.7 ms | 14 MiB |
| wasmi2-loop-ind-lazytr | 1.60 MB | 85.5 ms | 87.6 ms | 0.0 / 21.6 / 1.7 / 60.5 ms | 26.7 ms | 13 MiB |
| wasmi2-loop-ind-lazy | 1.60 MB | 84.1 ms | 70.5 ms | 0.0 / 5.6 / 1.6 / 59.4 ms | 31.8 ms | 13 MiB |
| wasmi2-unstable-eager | 1.65 MB | 103.8 ms | 101.3 ms | 0.0 / 63.0 / 1.5 / 31.5 ms | 15.1 ms | 19 MiB |
| wasmi2-unstable-lazytr | 1.65 MB | 66.6 ms | 75.9 ms | 0.0 / 18.3 / 5.5 / 48.3 ms | 15.9 ms | 14 MiB |
| wasmi2-unstable-lazy | 1.65 MB | 57.5 ms | 67.5 ms | 0.0 / 8.8 / 2.3 / 51.8 ms | 14.9 ms | 14 MiB |
| wamr-classic | 0.30 MB | 357.1 ms | 367.5 ms | 4.5 / 24.6 / 1.4 / 333.6 ms | 114.5 ms | 17 MiB |
| wamr-fast | 0.32 MB | 135.5 ms | 133.9 ms | 4.7 / 80.0 / 1.6 / 44.0 ms | 23.2 ms | 23 MiB |
| wamr-fastjit-lazy | 0.69 MB | 195.2 ms | 449.1 ms | 6.9 / 29.5 / 375.9 / 32.9 ms | 3.7 ms | 31 MiB |
| wamr-fastjit-eager | 0.69 MB | 156.0 ms | 453.5 ms | 6.5 / 433.4 / 1.7 / 7.8 ms | 3.6 ms | 30 MiB |
| wamr-multitier-lazy | 49.87 MB | 356.1 ms | 698.1 ms | 9.6 / 133.6 / 524.0 / 20.6 ms | 8.5 ms | 146 MiB |
| wamr-llvmjit-lazy | 49.46 MB | 84,557.2 ms (1 run) | 110,703.9 ms (1 run) | 5.6 / 25,938.3 / 659.7 / 84,089.6 ms | 1.8 ms | 977 MiB |
| wamr-llvmjit-eager | 49.46 MB | 106,003.8 ms (1 run) | 152,991.3 ms (1 run) | 6.0 / 152,938.1 / 1.7 / 32.7 ms | 1.7 ms | 976 MiB |
| wamr-multitier-eager | 49.85 MB | 111,875.9 ms (1 run) | 160,340.7 ms (1 run) | 18.2 / 160,286.8 / 1.7 / 19.5 ms | 2.7 ms | 986 MiB |
| wasmtime-cranelift | 11.97 MB | 988.6 ms | 3,194.8 ms | 0.1 / 3,187.1 / 0.3 / 3.9 ms | 1.6 ms | 115 MiB |
| wasmtime-winch | 11.97 MB | 510.0 ms | 951.7 ms | 0.2 / 939.7 / 0.3 / 7.8 ms | 3.8 ms | 124 MiB |
| wasmtime-pulley | 11.97 MB | 1,112.7 ms | 3,329.8 ms | 0.1 / 3,222.4 / 0.4 / 102.8 ms | 58.9 ms | 104 MiB |
| py-wamr-fast | 0.32 MB | 162.4 ms | 164.8 ms | 5.0 / 84.9 / 1.6 / 44.5 ms | 23.2 ms | 33 MiB |
| py-wamr-fastjit-eager | 0.69 MB | 230.7 ms | 486.3 ms | 9.4 / 424.6 / 1.7 / 7.2 ms | 9.2 ms | 41 MiB |
| py-wasmtime-cranelift | wasmtime-py 49.0.0 | 1,096.7 ms | 3,259.8 ms | 0.0 / 3,193.1 / 0.8 / 4.4 ms | 2.0 ms | 136 MiB |
| py-wasmtime-winch | wasmtime-py 49.0.0 | 625.8 ms | 1,018.3 ms | 0.0 / 945.5 / 1.0 / 10.3 ms | 4.5 ms | 145 MiB |
| py-wasmtime-cranelift-cwasm (precompiled) | wasmtime-py 49.0.0 | 63.6 ms | 72.0 ms | 0.0 / 2.9 / 0.6 / 7.9 ms | 3.9 ms | 31 MiB |

## Warm-up and steady state (`results/procs.txt`)

The JWS columns come after 100+ g5 calls in the same instance, so JWS #1
is not a cold call. "4 CPUs" is the mean of four pinned processes running
at once. For `wamr-llvmjit-lazy` and `wamr-multitier-lazy`, the steady
window overlaps WAMR's background compilation. Those two rows understate
the speed they reach once it finishes; the eager rows show that speed.

| Row | g5 calls #1 / #2 / #5 / #10 / #100 (ms), 1 CPU | g5/s 1 CPU | g5/s per CPU, 4 CPUs | JWS #1 / #100 (ms), 1 CPU | JWS/s 1 CPU | JWS/s per CPU, 4 CPUs | Peak RSS | Parity (identical/rows) | ABI tests |
|---|---|---:|---:|---|---:|---:|---:|---|---|
| wasmi1-eager | 56.6 / 32.8 / 32.8 / 33.2 / 32.6 | 29.5 | 29.6 | 165.1 / 134.8 | 7.5 | 7.7 | 14 MiB | 6,179/6,179 | 37/37 + iso 2/2 |
| wasmi1-lazytr | 64.8 / 32.8 / 37.4 / 33.2 / 34.8 | 29.3 | 29.3 | 159.3 / 142.1 | 7.3 | 7.6 | 13 MiB | 6,179/6,179 | 37/37 + iso 2/2 |
| wasmi1-lazy | 67.0 / 34.6 / 35.2 / 36.6 / 32.6 | 29.5 | 29.7 | 144.1 / 127.4 | 7.6 | 7.5 | 13 MiB | 6,179/6,179 | 37/37 + iso 2/2 |
| wasmi2-auto-eager | 31.0 / 14.9 / 15.9 / 15.1 / 17.3 | 64.1 | 63.0 | 89.0 / 78.0 | 13.0 | 12.6 | 19 MiB | 6,179/6,179 | 37/37 + iso 2/2 |
| wasmi2-auto-lazytr | 42.9 / 15.4 / 15.9 / 15.2 / 15.1 | 62.5 | 63.0 | 86.1 / 79.6 | 12.8 | 12.4 | 14 MiB | 6,179/6,179 | 37/37 + iso 2/2 |
| wasmi2-auto-lazy | 44.8 / 17.6 / 15.1 / 15.0 / 15.2 | 64.0 | 63.6 | 88.1 / 80.1 | 12.5 | 12.4 | 14 MiB | 6,179/6,179 | 37/37 + iso 2/2 |
| wasmi2-tail-lazytr | 44.3 / 17.0 / 14.9 / 14.8 / 14.7 | 63.0 | 64.7 | 83.5 / 77.0 | 12.6 | 12.4 | 14 MiB | 6,179/6,179 | 37/37 + iso 2/2 |
| wasmi2-tail-ind-lazytr | 45.0 / 17.8 / 17.2 / 17.1 / 17.1 | 55.5 | 56.8 | 101.2 / 92.3 | 10.1 | 10.7 | 13 MiB | 6,179/6,179 | 37/37 + iso 2/2 |
| wasmi2-loop-lazytr | 92.3 / 46.0 / 41.4 / 44.4 / 41.4 | 24.1 | 23.4 | 179.5 / 169.8 | 5.8 | 5.8 | 14 MiB | 6,179/6,179 | 37/37 + iso 2/2 |
| wasmi2-loop-ind-lazytr | 69.3 / 27.9 / 26.8 / 26.2 / 25.9 | 36.7 | 37.6 | 134.3 / 117.1 | 8.1 | 8.0 | 13 MiB | 6,179/6,179 | 37/37 + iso 2/2 |
| wasmi2-unstable-lazytr | 43.4 / 15.6 / 15.8 / 15.6 / 15.2 | 63.2 | 62.7 | 85.1 / 76.5 | 12.3 | 12.6 | 14 MiB | 6,179/6,179 | 37/37 + iso 2/2 |
| wamr-classic | 312.3 / 110.6 / 114.0 / 111.8 / 113.5 | 8.5 | 8.4 | 400.3 / 373.0 | 2.6 | 2.5 | 18 MiB | 6,179/6,179 | 37/37 + iso 2/2 |
| wamr-fast | 54.1 / 33.8 / 26.6 / 25.2 / 22.9 | 41.2 | 41.6 | 153.8 / 109.3 | 9.4 | 8.9 | 25 MiB | 6,179/6,179 | 37/37 + iso 2/2 |
| wamr-fastjit-lazy | 31.7 / 3.7 / 3.4 / 3.5 / 3.8 | 276.8 | 276.1 | 14.6 / 13.6 | 67.9 | 66.4 | 31 MiB | 6,179/6,179 | 37/37 + iso 2/2 |
| wamr-fastjit-eager | 8.1 / 3.5 / 3.5 / 3.7 / 3.4 | 274.4 | 270.1 | 15.9 / 17.1 | 67.8 | 68.2 | 30 MiB | 6,179/6,179 | 37/37 + iso 2/2 |
| wamr-multitier-lazy | 56.9 / 15.8 / 10.4 / 10.7 / 10.4 | 127.6 | 124.0 | 33.2 / 33.7 | 32.5 | 32.4 | 476 MiB | 6,179/6,179 | 37/37 + iso 2/2 |
| wamr-llvmjit-lazy | 85,269.9 / 1.8 / 9.8 / 9.8 / 11.0 | 229.4 | 218.5 | 14,593.5 / 21.6 | 64.3 | 66.1 | 976 MiB | 6,179/6,179 | 37/37 + iso 2/2 |
| wamr-llvmjit-eager | 21.1 / 2.2 / 2.0 / 2.0 / 1.5 | 604.1 | 596.6 | 9.8 / 6.1 | 183.4 | 169.5 | 976 MiB | 6,179/6,179 | 37/37 + iso 2/2 |
| wamr-multitier-eager | 17.7 / 1.6 / 1.6 / 1.6 / 1.5 | 592.5 | 603.2 | 9.5 / 5.0 | 189.6 | 188.4 | 986 MiB | 6,179/6,179 | 37/37 + iso 2/2 |
| wasmtime-cranelift | 5.0 / 1.9 / 1.7 / 1.7 / 1.9 | 574.6 | 552.4 | 7.2 / 8.0 | 143.4 | 144.4 | 115 MiB | 6,179/6,179 | 37/37 + iso 2/2 |
| wasmtime-winch | 8.0 / 3.9 / 4.0 / 3.8 / 4.1 | 247.7 | 238.9 | 14.1 / 14.7 | 72.7 | 69.5 | 124 MiB | 6,179/6,179 | 37/37 + iso 2/2 |
| wasmtime-pulley | 88.3 / 44.9 / 46.1 / 45.3 / 44.2 | 22.1 | 21.7 | 227.4 / 229.3 | 4.6 | 4.6 | 104 MiB | 6,179/6,179 | 37/37 + iso 2/2 |
| py-wamr-fast | 43.3 / 23.4 / 23.0 / 23.6 / 23.8 | 41.4 | 40.4 | 110.0 / 107.4 | 9.4 | 9.2 | 34 MiB | 6,179/6,179 | 37/37 + iso 2/2 |
| py-wamr-fastjit-eager | 11.4 / 5.6 / 5.5 / 5.5 / 4.2 | 271.9 | 259.1 | 14.8 / 14.3 | 65.8 | 66.1 | 41 MiB | 6,179/6,179 | 37/37 + iso 2/2 |

The dispatch builds' eager and lazy rows, and the three wasmtime-py rows,
were timed for start-up only.

## Cold start against throughput

**Against the owner's usable band of 10 to 20 JWS/s per core** (JWS is the
slower operation):

| JWS/s per core | Rows |
|---|---|
| Well above 20 | WAMR Fast JIT (68), Wasmtime Winch (73), Cranelift (143), WAMR LLVM JIT once compiled (183) |
| 10 to 20 | Wasmi 2.0 with tail-call dispatch (12.3 to 13.0), Wasmi 2.0 with indirect dispatch (10.1 to 10.7) |
| Below 10 | WAMR fast interpreter (9.4), Wasmi 2.0 switch loop (8.1), Wasmi 1.1 (7.5), Wasmi 2.0 call loop (5.8), Pulley (4.6), WAMR classic (2.6) |

On g5 every row except WAMR classic (8.5/s) clears 20.

**The trade-off on one CPU, first result → JWS per second:**

- Wasmi 2.0 lazy: 54 ms → 12.5
- WAMR fast interpreter: 134 ms → 9.4
- WAMR Fast JIT: 450 ms → 68
- Winch: 952 ms → 73
- Cranelift: 3,195 ms → 143
- LLVM JIT (eager): 153 s → 183

On four CPUs the compilers use their threads: Cranelift drops to 989 ms,
Winch to 510 ms, the Fast JIT to 156 ms. Wasmi and the WAMR interpreters
barely change, since they do not compile in parallel.

**Break-even, from the per-call means above (EXPECTED; derived, not
measured end to end).** A cold process that then verifies N JWS spends
54 ms + N × 80 ms on Wasmi 2.0 lazy, against:

- 450 ms + N × 15 ms on the WAMR Fast JIT, which is faster after about 6
  JWS or 33 g5;
- 3,195 ms + N × 7 ms on Cranelift at start, which is faster after about
  43 JWS.

Below those counts the interpreter's head start wins.

## Is Wasmi's lazy mode Endive-like?

The question is whether it gives a very fast first result, translating
functions only as they are first used.

**Yes, for the first result (TESTED).** With `CompilationMode::Lazy`:

- `Module::new` takes 5 ms for the 2.9 MB module;
- instantiation takes 1.5 ms;
- the first g5 takes 44 ms, including translating every function it
  touches;
- the second g5 takes 15 ms, which is steady state already;
- the first JWS after 100 g5 calls takes 88 ms against a steady 80 ms.

The ES256 path needed little that g5 had not already translated.

**What validation costs.** `LazyTranslation` validates the whole module
first, which costs about 15 ms more (load 19.7 ms against 5.1 ms). It
avoids the case the docs warn about: with `Lazy`, an invalid function is
only reported when first called.

**How it compares with Endive.** The Endive round
(`2026-09-26-endive-build-time-jvm.md`, JDK 21, another machine) measured
335 to 380 ms for the first instance inside a running JVM, plus 160 to
360 ms for the first verification. Wasmi's whole process, from spawn,
takes 54 to 62 ms.

**The difference is peak speed.** Endive's code gets HotSpot's JIT, and
that note measured 153 g5/s on one JDK 21 thread. Wasmi stays an
interpreter at 64 g5/s. WAMR's Fast JIT is the nearest thing here to
Endive's "fast start, then compiled speed": 156 to 450 ms, then 274 g5/s.

## WAMR's "lazy" JIT is background compilation (TESTED)

WAMR's lazy JIT does not wait for a function to be called before
compiling it.

- **Lazy.** In lazy builds, `wasm_runtime_load` starts WAMR's compile
  threads (4 by default, `WASM_ORC_JIT_BACKEND_THREAD_NUM`), and they
  compile every function in the background. A call that reaches an
  uncompiled function compiles it on the spot.
- **Eager.** The same threads run, and load waits for them
  (`wasm_loader.c`: "Wait until all jit functions are compiled for eager
  mode").

Two consequences show in the tables:

- On one CPU the background threads compete with the first call. Fast JIT
  lazy spends 376 ms in instantiate (`_initialize` waits for its
  functions) and ends at 449 ms, the same as eager's 454 ms.
- The lazy LLVM JIT still needs 85 s before its first result on four
  CPUs and 111 s on one. On one CPU that is 26 s of load, then a first
  call that waits 84 s. Its first JWS after that waits another 14.6 s.

## Wasmi 2.0 dispatch (TESTED)

All at LazyTranslation, on one CPU.

**Same speed as the default (63.0 g5/s, 12.6 JWS/s):**

- Forced tail calls (`wasmi2-tail`): 63.0 g5/s, 12.6 JWS/s. The same
  code as the default on x86-64.
- Nightly `become` (`wasmi2-unstable`): 63.2 g5/s, 12.3 JWS/s. No gain.

**Slower:**

| Build | g5/s | JWS/s | Against the default |
|---|---:|---:|---|
| Indirect dispatch | 55.5 | 10.1 | 12% slower on g5, 20% on JWS |
| Switch loop | 36.7 | 8.1 | 1.7 times slower on g5, 1.6 on JWS |
| Call loop | 24.1 | 5.8 | 2.6 times slower on g5, 2.2 on JWS |

**Start-up.** The dispatch build changes start-up only through the first
call's speed. Load time depends on the compilation mode alone (5, 19 and
60 ms).

**Wasmi 2.0 against 1.1.** With the default dispatch, 2.0 is 2.2 times
1.1 on g5 and 1.7 times on JWS. Wasmi's changelog claims "geomean roughly
2.2x faster than Wasmi v1.0".

## Python: the ctypes facade against wasmtime-py (TESTED)

**Correctness.** Both facade rows pass the same 37 tests and 2 isolation
checks, and give 6,179 of 6,179 identical rows.

**What the facade costs.**

- Start-up adds about 30 ms over the native C host: CPython starts, and
  `ctypes` loads `libiwasm.so`. That is 162 against 135 ms for the fast
  interpreter.
- Steady speed does not change: 41.4 against 41.2 g5/s interpreted, 272
  against 274 g5/s on the Fast JIT.

**One CPU, from spawn to first verified g5:**

- wasmtime-py with a precompiled `.cwasm`: 72 ms. It needs round 8's
  per-platform artifact and its Wasmtime version pin.
- The facade over the WAMR fast interpreter: 165 ms.
- The facade over the WAMR Fast JIT: 486 ms.
- wasmtime-py with Winch at start: 1,018 ms.
- wasmtime-py with Cranelift at start: 3,260 ms.

**What it would take to ship.** WAMR has no Python package (round 8). The
facade therefore means building and shipping a `libiwasm.so` per
platform: 0.32 MB for the interpreter, 0.69 MB with the Fast JIT.

**Threading.** The facade calls from one thread only. WAMR requires
`wasm_runtime_init_thread_env` on any other thread, and the spike does
not do that.

## Correctness and isolation (TESTED)

- **Corpus.** All 24 corpus rows returned the same answers as Node for
  the whole 6,179-row corpus, including the 811 `hostile` rows. There were
  no traps.
- **ABI tests.** All 37 tests pass on every row, with one adaptation:
  - Round 7's version-mismatch test also checks that the trap's only
    backtrace frame is `aprv_call`.
  - Neither Wasmi's nor WAMR's API exposes that frame, and the host does
    not ask Wasmtime for it.
  - The driver instead checks that the trap came from the raw `aprv_call`
    invocation and that no host import ran. That held on every row.
- **Isolation checks**, on every row:
  - A trap in one instance leaves another instance of the same module
    verifying.
  - Out-of-range input traps the instance, not the process.
- **No hangs.** No run hit a timeout, and nothing had to be killed.

## Not tested

- **Other platforms.** Everything ran on x86-64 Linux only, not aarch64,
  macOS or Windows. On other targets Wasmi's `auto-dispatch` may fall back
  to the loop backend (per its `build.rs`).
- **Lambda itself.** A fractional vCPU was not simulated; Lambda was
  stood in for by `taskset -c 0`.
- **Other WAMR settings.** Not tried:
  - LLVM JIT opt or size levels below 3, and segue;
  - WAMR's hardware bound checks off;
  - a Fast JIT code cache larger than 10 MiB;
  - running other modes out of the multi-tier build.
- **Steady speed of the lazy WAMR JIT rows after their background compile
  finishes.** The eager rows stand in for it.
- **Threads.** More than one thread per process was not tried in the
  native hosts or the facade.
- **Other Python rows.**
  - A Python binding for Wasmi was not built; the brief asked only for
    WAMR.
  - wasmtime-py throughput was not re-run on this CPU. The native
    Wasmtime rows here stand in for it.
- **Endive itself** was not re-run. Its figures come from its own note,
  on another machine.
- **Import time in the facade rows.** The Python import time was not
  broken out from the first-result figure.
- **Deliberately out of scope (the brief):** AOT and precompiled guest
  artifacts, WASI, libc and multi-module.

## Disk and processes (`results/disk.txt`)

- **Disk.** 6,713 MB was free at the start. Removing round 8's scratch
  intermediates brought it to 7,304 MB. The builds and runs peaked at
  5,452 MB free, with 1,854 MB in this round's scratch. After cleanup,
  7,026 MB is free and the round's scratch holds 280 MB.
- **Deleted:** the Cargo target and home directories, the extracted LLVM
  and its `.deb`s, the driver outputs, and the downloaded crate sources.
- **Kept, so the timing rows can rerun without a rebuild:** `bin/` (the
  Rust hosts, 51 MB) and `wamr/` (the eight `libiwasm.so` builds and
  their hosts, 229 MB).
- **Never done:** LLVM was not built from source.
- **Processes.** No background process is left running.
