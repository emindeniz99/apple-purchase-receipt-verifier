# Final Python runtime round: pywasm, Wasmi 2.0 behind a thin binding, and a default

Date: 2026-09-27 (round 11). Code, scripts and raw results are in
`2026-09-27-python-runtime-final/`. Its `README.md` has the file table and
the commands to reproduce.

**Question.** Which Wasm runtime should the Python package use by default
to run the one canonical `aprv.wasm`? Rounds 7 to 9 measured wasmtime-py
(raw and with a precompiled `.cwasm`) and WAMR's interpreter and Fast JIT
behind a ctypes facade. This round adds the two candidates they left
open: pure-Python pywasm 2.2.3, and Wasmi 2.0.0 as a small shared library
behind a thin binding. It checks whether that library builds for the
wheel targets. It tests the resource bounds our embedding can enforce, and
ends with one comparison table and one recommendation. It feeds the Python
row of the one-Rust-core plan. It does not rewrite the plan.

Labels: TESTED (ran here), DOCUMENTED (read in a primary source), EXPECTED
(inferred, not run). Nothing under `python/`, `rust/`, `docs/rust-core` or
any other production path changed.

The security side of Wasmi 2.0.0 is the separate desk review
`2026-09-27-wasmi-security-review.md` (another agent's note). Its unsafe
inventory, C API review and audit history are not repeated here. This
note cites its verdict. This note's own security content is the
resource-exhaustion tests of section 4, which ran against the two bindings
built here.

**Environment** (`results/versions.txt`):

- Ubuntu 24.04 x86-64, 4 vCPUs (Intel Xeon 2.80 GHz), 16 GB RAM. This is
  **the same CPU as round 9**, so round 9's rows are directly comparable
  and were not re-timed. Round 8 ran on a 2.10 GHz Xeon. Its wasmtime-py
  throughput figures are marked where they appear.
- CPython 3.12.3, Rust 1.98.1 (`lto = "fat"`, `codegen-units = 1`), Wasmi
  2.0.0, `wasmi_c_api_impl` 2.0.0, pywasm 2.2.3.
- Module: `aprv-abi1.wasm`, 2,952,613 bytes, sha256 `b14e14b2…87b636b3`,
  unchanged since the ABI v1 round.

The measurement harness is round 9's, unchanged (start-up: parent
CLOCK_MONOTONIC to the child's stamp at its first verified g5, median of 7
cold processes; "1 CPU" = `taskset -c 0`; throughput: calls #1, #2, #5,
#10, #100, then a steady loop of at least 20 calls and 2 s, for g5 and
then the shared-sandbox JWS).

## Answer

**Default: Wasmi 2.0.0 behind a narrow APRV-specific Rust cdylib, loaded
with ctypes.** The cdylib is `wasmi-cdylib/`: 280 lines, 10 exported
functions, 13 `unsafe` blocks. Configure it with LazyTranslation, the
default (auto) dispatch, validation on, fuel metering at 5e9 per call, a
64 MiB linear-memory cap and one instance, memory and table per store.

- **Cold start: about 100 ms to the first verified g5 on one CPU
  (TESTED; 93 to 115 ms over every run).** Among the Python options only
  the precompiled wasmtime-py module is faster (72 ms), and it needs a
  per-platform guest artifact.
- **Throughput meets the floor: about 60 g5 and 12 JWS per second per
  core (TESTED).** Threads in one process scale linearly: 4 threads give
  240 g5/s and 48 JWS/s.
- **Size.** It adds a 1.6 MB library to each platform wheel, and installs
  4.5 MB with the module.
- **Every bound tested in section 4 held from Python (TESTED).** Fuel,
  the memory cap and the instance limits held, and every hostile case
  failed only its instance. Section 4 tested only the two Wasmi bindings,
  not wasmtime-py or WAMR.

The security review reaches the same binding choice independently.

The runner-up is **wasmtime-py with a precompiled Cranelift `.cwasm`**. It
is the more mature and more audited runtime, with 15 times the JWS
headroom. It costs a per-platform guest artifact pinned to the Wasmtime
major, and about 44 MB installed instead of 4.5 MB. Owner priority 7 says
to avoid that when a comparably clean alternative exists, and the Wasmi
route is one. If audited-runtime maturity is weighted above priority 7,
the `.cwasm` route is the answer instead. Nothing measured here rules it
out.

**Rejected:**

- **pywasm:** about 2,000 times under the JWS floor.
- **Wasmi through its generic C API:** the same speed, but none of the
  bounds are reachable (fuel, memory cap, instance limits).
- **WAMR's interpreter:** 9.4 JWS/s is under the floor, and its 165 ms
  cold start is slower than Wasmi's.
- **WAMR's Fast JIT:** a 486 ms cold start on one CPU, and a JIT in the
  sandbox boundary.
- **wasmtime-py raw:** 3.3 s to the first result on one CPU.

## Final comparison (owner's section 5)

Sources:

- This round: `results/startup.txt`, `results/startup-ab.txt`,
  `results/ab-summary.txt`, `results/procs.txt`, `results/pywasm.txt`,
  `results/build.txt`.
- Round 9 (same CPU): `2026-09-27-wasm-execution-modes.md`, its
  `results/startup.txt` and `results/procs.txt`.
- Round 8 (2.10 GHz CPU): `2026-09-27-python-runtime-options.md`.

Throughput is one process on one CPU. "Installed" is the runtime plus
facade plus `aprv.wasm` on x86-64 Linux.

| Option | Pure/Native | Platform-specific runtime? | Extra guest artifact? | 1-CPU first result | Receipt/s | JWS/s | RSS | Installed size | Custom code we own | Maturity/security notes |
|---|---|---|---|---:|---:|---:|---:|---:|---|---|
| pywasm 2.2.3 | pure Python | no | no | **91.8 s** | 0.017 | **0.006** | 175 MiB | 3.3 MB (0.31 MB pywasm `.py` + module) | 189-line facade | Memory-safe by construction (Python). No validation pass. Traps are `assert` statements, and under `python -O` the module does not even parse (fails closed). Unusable on speed |
| **Wasmi 2.0 + thin binding (Rust cdylib, recommended)** | native runtime | yes: one `.so`/`.dll`/`.dylib` per wheel | no | **97–106 ms** bounded (93–115 all runs) | 58–61 | 11.7–12.2 | 22 MiB | 4.5 MB (lib 1.57 MB) | 280-line Rust cdylib (13 `unsafe` blocks, 10 exports) + 182-line ctypes facade + a wheel build per platform | Review: sound as the boundary for this single trusted module, with conditions. The executor has been unaudited since v0.36, and one issue was reported privately upstream; not reachable for aprv.wasm. Tested here: fuel, a 64 MiB cap and instance limits hold from Python |
| Wasmi 2.0 via the official C API | native runtime | yes | no | 103 ms | 61 | 12.0 | 23 MiB | 4.7 MB (lib 1.69 MB) | 340-line ctypes facade over 32 C functions | Same engine. Fuel is unusable through `wasm.h` (every call traps), and there is no memory or instance limiter. Module errors carry no reason. 303 exports, 76 of which always abort (review) |
| WAMR Fast Interpreter | native runtime | yes | no | 164.8 ms (r9) | 41.4 (r9) | 9.4 (r9) | 34 MiB (r9) | ≈3.3 MB (lib 0.32 MB) | 324-line facade + a CMake build of `libiwasm` per platform | C runtime. The official Python binding is not on PyPI (round 8). Not covered by this round's review |
| WAMR Fast JIT (eager) | native runtime | yes | no | 486.3 ms (r9) | 271.9 (r9) | 65.8 (r9) | 41 MiB (r9) | ≈3.7 MB (lib 0.69 MB) | as above | As above, plus a JIT inside the boundary |
| wasmtime-py raw (Cranelift at start) | native runtime | yes (wasmtime-py's own wheels) | no | 3,259.8 ms (r9); Winch 1,018.3 ms | 573 (r8, 2.10 GHz) | 177 (r8) | 136 MiB (r9) | ≈35 MB (wasmtime 49.0.0 installs 32.2 MB) | none beyond the round 7 facade | Mature; the most scrutinised runtime of the set. Threads did not scale in round 7 |
| wasmtime-py + `.cwasm` | native runtime | yes | **yes, per platform** | 72.0 ms (r9) | 577 (r8) | 181 (r8) | 31 MiB (r9) | ≈44 MB (32.2 MB + a facade wheel installing about 11.5 MB) | a `.cwasm` build and release step per target, pinned to the Wasmtime major | Mature. A `.cwasm` is native code trusted like the `.so`, and it is refused by any other Wasmtime major (round 8) |

The Wasmi cells are ranges over this round's runs:

- **First result.** The bounded configuration measured 97.0 to 106.4 ms
  (three A/B rounds of 7 cold processes). The unbounded one measured 93.1
  to 115.4 ms (the row run and the A/B rounds), all on one CPU.
- **Throughput.** Medians of 5 interleaved A/B runs, fuel on and off.

## 1. pywasm 2.2.3 (TESTED unless marked; `results/pywasm.txt`)

**The release, the floor and the size.**

- 2.2.3 is the current PyPI release. PyPI declares no `requires_python`.
- The project README (github.com/libraries/pywasm) says Python >= 3.12.
- The code uses `typing.Self` 48 times, so it cannot import below 3.11
  (EXPECTED). `pywasm/__init__.py` still says `version = '2.2.1'`.
- The wheel is 44,605 bytes and pure Python: 7,088 lines in 8 files,
  306,686 bytes installed, no native code.
- The facade `py/aprv_pywasm` is 189 lines and needs nothing but pywasm.

**Stop rule, fixed before the run (`scripts/pywasm.sh`).** Time g5 #1 and
#2 and JWS #1 in one fresh process. If a steady JWS call takes longer
than 1 s (under 1 JWS/s, a tenth of the owner's ~10 floor), record and
stop: no corpus, no ABI suite.

| Step | Time | RSS after |
|---|---:|---:|
| `import aprv_pywasm` | 36 ms | 14.9 MiB |
| parse `aprv.wasm` | 4,217 ms | 168.2 MiB |
| instantiate + `_initialize` | 37 ms | 172.8 MiB |
| g5 call #1 (first result 91.8 s after process start) | 87,499 ms | 174.8 MiB |
| g5 call #2 | 60,307 ms (0.017/s) | 174.8 MiB |
| JWS call #1 | 170,275 ms (0.006/s) | 174.9 MiB |

Both g5 calls and the JWS verified. **The stop rule fired on JWS #1:
170 s against a 1 s limit.** Calls #5, #10 and #100, the 6,179-row
corpus and the ABI suite were not run. Call #100 of g5 alone would take
about 100 minutes.

**Traps are `assert`s (TESTED, `py/pywasm_asserts.py`).** `unreachable`,
an invalid handle and out-of-range input each raise `AssertionError`
under plain `python`. Under `python -O` asserts are stripped. The parser
reads bytes inside asserts, so the module does not parse: a
`UnicodeDecodeError` in the custom-section reader. That fails closed, but
the sandbox's correctness then depends on the interpreter flag.

**The upside, quantified.** No native library, no platform wheel matrix
(one `py3-none-any` wheel), no precompiled guest artifact, no native
binding: 189 lines of Python. In each of those respects it beats every
other row. The price is roughly 2,000 times the JWS latency of the Wasmi
row, and 8 times its RSS.

## 2. Wasmi 2.0.0 as a small shared library (TESTED unless marked)

### Two bindings, built side by side

**Official C API: `wasmi-capi/` + `py/aprv_wasmi_capi` (the owner's
preferred route).**

- The crate is `wasmi_c_api_impl` 2.0.0 (published 2026-09-01). Its lock
  resolves `wasmi` 2.0.0 (`results/build.txt`).
- Its default features are `std`, `memory64` and `auto-dispatch`, and it
  turns on `wasmi/validate`. Its `wasmi.h` still says
  `WASMI_VERSION "0.35.0"`, a stale string.
- The facade binds 32 functions: `wasm.h` plus
  `wasmi_config_compilation_mode_set` and `wasmi_config_consume_fuel_set`.
  The docstring lists them. None of them is in the unimplemented or
  always-abort set.
- The host imports are Python callbacks (`CFUNCTYPE`).

What the C API cannot do for us (TESTED, `results/exhaust.txt`):

- **Fuel is unusable.** Only `wasmi_store_t` can set fuel, and no
  `wasm_*` function accepts a `wasmi_store_t`. With metering on, every
  call through a `wasm_store_t` traps at once: `ResumableOutOfFuel`,
  `required_fuel: 14`. That includes `_initialize` and a plain g5 verify.
  So the C API route runs with no CPU bound at all.
- **No limiter.** There is no `StoreLimits` or resource limiter. A guest
  grew to 1 GiB (RSS 1.02 GiB), a 128 MiB initial memory instantiated, and
  a second table instantiated.
- `wasm_module_new` returns NULL with no reason for a malformed module.

**Narrow cdylib: `wasmi-cdylib/` + `py/aprv_wasmi_rs` (the review's
recommended shape).**

- It exposes 10 `extern "C"` functions: `aprv_rt_new/free`,
  `aprv_inst_new/free`, `aprv_inst_invoke`, `aprv_buf_free`,
  `aprv_inst_raw`, `aprv_inst_memory_size`, `aprv_inst_fuel_used` and
  `aprv_import_counts`.
- Everything inside uses Wasmi's safe Rust API.
- The host imports run in Rust, so Python never re-enters during a call.
- The 13 `unsafe` blocks only read and write the caller's pointers and
  box/unbox the two handles.
- `catch_unwind` wraps every entry point.
- It is 280 lines, above the brief's 100 to 200. The extra lines are the
  raw-export entry and the fuel and import-count queries, which the tests
  need.
- The facade is 182 lines.

**Library sizes (stripped, x86-64, `results/build.txt`):**

| Library | Stripped | gzip -9 | Exported functions |
|---|---:|---:|---:|
| `libaprv_wasmi.so` | 1,569,496 | 615,879 | 10 |
| `libwasmi.so` (C API) | 1,686,448 | 656,341 | 303 |

A wheel-like zip holding the library, the facade and `aprv.wasm` is
1.59 MB (cdylib) or 1.63 MB (C API). Installed, that is 4.53 MB or
4.65 MB.

### Correctness

Rows, each run in process with LazyTranslation:

- the C API route;
- the cdylib unbounded;
- the cdylib bounded (fuel 5e9 and the 64 MiB cap);
- the bounded cdylib built with `extra-checks`.

Each row passed:

- **37/37 ABI and facade tests** and **2/2 isolation checks**
  (`results/tests-*.txt`);
- **6,179 of 6,179 rows byte-identical to Node, 0 traps,** across the
  five corpora (`results/calls-*.txt`). That is 6,178 calls plus one
  mapping row with no call, counted as round 9 counted them.

### Start-up (`results/startup.txt`, `results/startup-ab.txt`)

| Row | 4 CPUs | 1 CPU | Breakdown, median run (init / load / instantiate / first call / second call) |
|---|---:|---:|---|
| cdylib, LazyTranslation | 93.1 ms | 93.1 ms | 0.4 / 18.7 / 1.5 / 42.5 / 15.3 ms |
| cdylib, Lazy | 85.3 ms | 81.0 ms | 0.5 / 5.7 / 1.4 / 44.9 / 15.5 ms |
| C API, LazyTranslation | 102.6 ms | 103.0 ms | 0.6 / 20.1 / 1.8 / 50.3 / 16.9 ms |
| C API, Lazy | 99.2 ms | 91.5 ms | 0.8 / 9.9 / 2.5 / 49.8 / 16.7 ms |
| native Wasmi 2.0, LazyTranslation (round 9) | 65.4 ms | 69.2 ms | |
| native Wasmi 2.0, Lazy (round 9) | | 54.1 ms | |

- **Limits cost nothing at start (TESTED).** An interleaved A/B ran 3
  rounds × 7 cold processes on one CPU (`scripts/startup-ab.sh`). The
  round medians were 101.5 / 99.8 / 115.4 ms with limits off, and
  97.0 / 97.5 / 106.4 ms with fuel and the cap on.
- **The Python start-up cost over native is about 20 to 30 ms.** Round 9's
  native host ran in the same A/B at 71.1 / 80.5 / 103.7 ms, so the
  median of the round medians is 80.5 ms native against 97.5 to 101.5 ms
  in Python. The cost is interpreter start and imports: the in-process
  phases add up to about 63 ms against 93 ms end to end. The 1-CPU and
  4-CPU figures agree because nothing runs on a second thread.
- **This machine's start-up noise is about ±15 ms** (see the spreads
  above). Differences smaller than that between rows here are not
  findings.
- **Lazy is about 10 ms faster to the first result than
  LazyTranslation,** as in round 9: load drops from 19 to 6 ms because
  nothing is validated up front. LazyTranslation stays the primary mode
  (the brief). It validates the whole module at load, so a malformed
  module fails before any call.

### Throughput and the Python overhead

**Interleaved A/B (`results/ab-summary.txt`).** Five rounds, each running
four variants back to back on CPU 0:

- round 9's native Wasmi 2.0 host (LazyTranslation);
- the cdylib with fuel off;
- the cdylib with fuel on;
- the C API.

| Variant | g5/s median (min–max) | JWS/s median (min–max) | Peak RSS |
|---|---:|---:|---:|
| native Wasmi 2.0 LazyTranslation | 60.0 (57.3–63.4) | 11.9 (10.6–12.8) | 14.3 MiB |
| cdylib, fuel off | 60.9 (55.7–62.0) | 12.2 (11.8–12.7) | 21.7 MiB |
| cdylib, fuel 10e9 | 58.4 (57.5–60.6) | 11.7 (11.0–12.1) | 21.6 MiB |
| C API | 61.4 (58.0–63.1) | 12.0 (11.6–12.4) | 22.7 MiB |

- **Python plus either binding adds no measurable per-call cost.** It is
  +1.5% and +2.3% on g5 against native, inside the min–max spread. It adds
  about 7 to 8 MiB of RSS: the interpreter.
- **Fuel metering costs about 4%** (−4.1% g5, −4.1% JWS). That is close to
  the noise, but consistent across all five rounds.
- **`extra-checks` costs nothing measurable here**
  (`results/ab-extra-checks-summary.txt`, 5 rounds, both builds bounded).
  It measured 58.9 against 58.9 g5/s and 11.7 against 11.9 JWS/s.
  Wasmi documents about 20%, which this module does not show. The
  `extra-checks` library is 20 KB larger.

**Warm-up (cdylib, 1 CPU, `results/procs.txt`):**

- g5 calls #1, #2, #5, #10, #100: 42.2, 15.8, 17.1, 16.1, 15.9 ms.
- JWS: 88.4, 82.0, 76.9, 103.8, 81.6 ms.

Steady state is reached at call #2, as in round 9.

**Processes (`results/procs.txt`).** Four processes, one per CPU, gave
58.2 g5/s and 11.6 JWS/s per core on the cdylib, and 61.0 / 12.1 on the
C API. That is the same as one process.

**Threads (`results/threads.txt`).** One process with one `Verifier` per
thread:

| Binding | g5/s at 1 / 2 / 4 threads | JWS/s at 1 / 2 / 4 threads |
|---|---|---|
| cdylib, fuel off | 58.0 / 115.7 / 239.6 | 12.6 / 24.8 / 47.9 |
| cdylib, fuel 10e9 | 59.8 / 115.5 / 237.0 | 11.9 / 24.5 / 47.7 |
| C API | 62.2 / 122.1 / 246.0 | 12.1 / 24.0 / 47.8 |

Scaling is linear. ctypes drops the GIL for each foreign call, and a
verification spends almost all its time inside one. The C API's Python
callbacks retake the GIL for each host import. That did not show, because
a call makes very few of them. wasmtime-py's threads did not scale past two
in round 7. Here a threaded server needs no process pool.

### Fuel budget (`results/fuel-envelope.txt`, `results/fuel-heaviest.txt`)

**Every corpus row, metered, with a budget no row can reach:**

| Corpus | Rows | Max fuel (row) | Mean fuel | Max linear memory |
|---|---:|---:|---:|---:|
| cases | 153 | 2,445,659,026 (`endpoint/verify-at-the-byte-floor`) | 101.5 M | 23,789,568 |
| hostile | 810 | 597,719,365 | 8.6 M | 6,160,384 |
| algorithms | 22 | 564,025,531 | 77.7 M | 2,162,688 |
| substrate | 193 | 328,090,621 | 36.3 M | 4,521,984 |
| fuzz | 5,000 | 328,476,549 | 11.9 M | 6,881,280 |

g5 takes 39.3 M fuel and the shared-sandbox JWS 173.5 M. The heaviest row,
the 1.38 MB byte-floor receipt through the endpoint operation, takes
2.44e9 fuel and 619 ms. That is about 3.9e9 fuel per second on this
workload. Fuel is about 0.1% nondeterministic between runs: 2,442 M here
against 2,446 M in the envelope run. The 4 MB DER at the size cap is
refused before it costs anything (0.9 M fuel).

**Budget: 5,000,000,000 per call, 2.05 times the heaviest row.**

- The heaviest row is a well-formed, correctly signed receipt at the
  contract's byte floor, the largest legitimate work in the corpus.
- 2x covers the fuel jitter and a receipt somewhat heavier than any
  fixture.
- A tight infinite loop spends the budget in 6.7 s. The loop costs about
  0.75e9 fuel per second, because a branch-only loop does less per unit of
  fuel than real code. At 10e9 the same loop runs 13.3 s
  (`results/exhaust.txt`).

**Memory cap: 64 MiB, 2.8 times the corpus peak of 23.8 MB (22.7 MiB).**
The bounded rows ran the whole corpus and the ABI suite at 5e9 and 64 MiB
with identical answers.

## 3. ARM64 and the wheel targets

**Native ARM64: pending, needs a native runner.** This container is
x86-64 only. The owner did not authorise creating workflows, branches or
pushes to reach an ARM runner. `scripts/arm64-native.sh` is ready to run
on Linux AArch64 or an Apple Silicon Mac. It builds round 9's native
Wasmi host and both libraries, and records the dispatch `cfg` Wasmi's
build script chose. It then runs, for the native row and both Python rows:

- start-up (all CPUs and pinned);
- 1-process and 4-process throughput;
- the 37 ABI tests;
- thread scaling;
- sizes.

Its inputs are the module (sha256-checked) and the cases calls file.
macOS has no `taskset`, so there the script runs a shim that ignores
`-c N`, and the summary says the "pinned" rows are unpinned.

**Which dispatch auto-dispatch selects (TESTED at build time,
`results/cross.txt`).** Wasmi's build script emits `wasmi_use_tail_calls`
for every x86-64 and aarch64 target built here, so auto-dispatch picks the
tail-call backend on ARM64 too. Its `build.rs` decides by architecture
alone (DOCUMENTED). What that dispatch costs or gains on real ARM64
hardware is the pending measurement.

**Cross-builds of the cdylib from this x86-64 container (TESTED,
`results/cross.txt`).** Tools: the rustup targets, and `ziglang` 0.16.0
plus `cargo-zigbuild` 0.23.4 from PyPI, which is the pair maturin uses.
The nine rustup targets took 1.3 GB and the zig venv 430 MB of scratch
space. Sizes are rustc-stripped.

| Wheel target | Result | Library | gzip -9 | Notes |
|---|---|---:|---:|---|
| Linux glibc x86_64 | OK | 1,591,784 | 627,095 | glibc 2.17 symbols at most: manylinux2014 |
| Linux glibc aarch64 | OK | 1,480,288 | 585,967 | glibc 2.17: manylinux2014 |
| Linux musl x86_64 | OK | 1,589,264 | 625,703 | needs `-C target-feature=-crt-static`: the musl targets default to static CRT, which cannot make a cdylib. NEEDED `libc.so` |
| Linux musl aarch64 | OK | 1,478,392 | 585,084 | as above |
| macOS x86_64 | **blocked here** | | | zig cannot link without Apple's SDK (`xcrun --sdk macosx` not found). Build on a macOS runner (EXPECTED to be routine), or with an SDK the owner is licensed to use |
| macOS arm64 | **blocked here** | | | as above |
| Windows x86_64 | OK (MinGW ABI) | 1,485,312 | 597,409 | imports only system DLLs and the UCRT API sets; no MinGW runtime DLL |
| Windows arm64 | OK (`aarch64-pc-windows-gnullvm`) | 1,246,208 | 517,130 | same import set |
| Windows x86_64 / arm64, MSVC ABI | **blocked here** | | | `link.exe` not found. Needs a Windows runner, or cargo-xwin, which downloads the MSVC CRT and Windows SDK under Microsoft's licence (not accepted here) |

- **A MinGW DLL is enough for this binding (EXPECTED).** ctypes loads any
  DLL. The library links no CPython and shares no CRT objects with it, so
  the MSVC ABI is not required. The MinGW DLLs were not loaded on Windows.
- **One unrun check on musl.** The musl libraries name `libc.so` as
  NEEDED. musl's loader is expected to resolve that to itself inside a
  musl Python (EXPECTED; no musl rootfs here). Round 10's Alpine work can
  confirm it.
- **Totals.** Six of the eight wheel targets build from one Linux host.
  macOS needs a macOS runner. MSVC-ABI Windows is optional.

**aarch64 correctness smoke under QEMU (TESTED; correctness only, not
performance; `results/qemu-smoke.txt`).**

- **What ran.** There is no aarch64 Python or libc in this container, so
  the Python facade cannot be loaded under emulation. Instead, round 9's
  native Wasmi host (unchanged source) ran with the same engine features:
  Wasmi 2.0.0, auto-dispatch, LazyTranslation. It was built as a static
  `aarch64-unknown-linux-musl` executable and run under `qemu-aarch64`
  8.2.2, user mode.
- **The build.** Its build script chose `wasmi_use_tail_calls` there too.
- **Results.** The first cold process verified g5. The 37 ABI tests and 2
  isolation checks passed over the line protocol. All five corpora gave
  6,179 of 6,179 rows byte-identical to Node, with 0 traps.
- **What this shows.** The tail-call dispatch computes the same answers on
  aarch64 as on x86-64.
- **What it does not show.** It says nothing about speed on ARM64, and it
  did not exercise the Python binding on aarch64.

## 4. Resource exhaustion (TESTED, `results/exhaust.txt`)

**Method.** Nineteen cases, each in its own child Python process. The
parent kills the child's process group if it has not answered in 20 s.
After each case the child checks that it is alive, and where the module
loaded it asks a fresh instance for the benign op (42). The hostile guests
are `wat/hostile.wat` (ops 0 to 10), `two-tables.wat` and
`big-memory.wat`. All have aprv.wasm's imports and lifecycle. The 37 ABI
tests already cover bad guest pointers and lengths through the ABI (null
input, input past memory, a u32-overflowing range, bad handles, double
free, use after free).

| Case | cdylib, bounded (fuel 5e9, 64 MiB, 1 instance/memory/table) | cdylib, no fuel, no memory cap (count limits still on) | C API | C API, fuel on |
|---|---|---|---|---|
| benign op | 42 | 42 | 42 | traps: out of fuel |
| infinite loop | trap: all fuel consumed, **6.7 s** (13.3 s at 10e9) | **hang, killed at 20 s** | **hang, killed at 20 s** | traps: out of fuel |
| unbounded recursion (thin / 33-local frames) | trap: call stack exhausted, 2 ms | same | trap: StackOverflow | out of fuel |
| grow 1 page at a time towards 256 MiB, touching each | stops at 1,024 pages (64 MiB); `memory.grow` returns −1 | reaches 256 MiB | reaches 256 MiB | out of fuel |
| one `memory.grow` of 1 GiB | −1 (refused) | **granted, RSS 1.02 GiB** | **granted, RSS 1.02 GiB** | out of fuel |
| `random_get`, negative pointer / straddling the end | trap (host import refuses) | same | same | out of fuel |
| store past memory, `call_indirect` to an empty slot, divide by zero, `unreachable` | trap | trap | trap | out of fuel |
| malformed module / truncated `aprv.wasm` / not Wasm | rejected with a reason | same | rejected, **no reason** | same |
| module with two tables | **refused** (too many tables) | refused | instantiates | out of fuel |
| module with 128 MiB initial memory | **refused** (limiter) | instantiates (142 MiB RSS) | instantiates | out of fuel |
| `aprv.wasm` g5 | verified | verified | verified | **out of fuel** |
| `aprv.wasm`: `aprv_alloc(96 MiB)`, then g5 in the same instance | alloc returns 0; g5 verifies | alloc succeeds (memory 98 MiB); g5 verifies | same as unbounded | out of fuel |

Observations:

- **In every case the Python process survived,** and where the module
  loaded, a fresh instance answered 42.
- **No case crashed or aborted the process.** The only failure that
  reached the process was the unbounded infinite loop. It is a hang, not a
  crash, and only fuel prevents it: Wasmi has no epoch or interrupt
  mechanism.
- **Wasmi grows memory eagerly.** A granted 1 GiB grow committed 1 GiB of
  RSS, so without the cap a single guest instruction can take up to 4 GiB.
- **With the cap, a refused grow returns −1 to the guest** (Wasmi's
  default `trap_on_grow_failure = false`). `aprv.wasm`'s own allocator
  handles that cleanly: `aprv_alloc(96 MiB)` returns 0 under the cap, and
  the same instance then verifies g5. In the facade, `aprv_alloc`
  returning 0 is a `WasmTrapError` and a fresh instance, as the ABI tests
  already require.
- **The stack bound is Wasmi's default** (1,000 frames of recursion depth)
  and caught both recursion shapes in 2 ms. The review asks for explicit
  caps sized to `aprv.wasm`. This spike did not set or size them.

## Conflicts and open items

- **Panic policy (a conflict between the review and this spike).** The
  review asks for two things together: `panic = "abort"` in the cdylib's
  profile, and `catch_unwind` around every call. With `panic = "abort"`,
  `catch_unwind` catches nothing, so a Wasmi panic ends the Python
  process: fail-stop. This spike kept `panic = "unwind"` and catches at
  every entry. A panic becomes status 3, and the facade discards that
  instance, as it does after a trap. Engine-wide state shared between
  instances is still suspect after a panic. No run here panicked, so
  neither policy was exercised. **The owner picks.** Fail-stop is the
  conservative choice for a security boundary. Unwind-and-discard keeps a
  server process alive.
- **Not applied in the spike's cdylib:** explicit stack-height and
  recursion caps, and the review's requirement 4. The cdylib sets fuel,
  the memory cap, the instance/memory/table counts and validation. A
  production cdylib should apply the review's whole requirement list.
- **The Python floor.** pywasm would need Python >= 3.12 (its README), but
  it is rejected anyway. The ctypes facades need nothing beyond the
  standard library: 3.12 ran them, and nothing in them is newer than 3.8
  (EXPECTED).
- **Pending:** the native ARM64 numbers (owner's script), a macOS build on
  a macOS runner, and the musl `libc.so` load check (round 10).

## Where these results stop holding

- One x86-64 CPU model. ARM64 performance is unmeasured.
- One module (`aprv-abi1.wasm`, sha256 above), whose fuel and memory
  envelope was measured on this corpus. The budget must be re-derived if
  the module or the ABI changes.
- Wasmi 2.0.0 and `wasmi_c_api_impl` 2.0.0 exactly. The C API's fuel gap
  is a property of this version's API surface.
- Throughput differences under about 5% are noise here. The A/B min–max
  spreads are 5 to 10%.
- The Windows DLLs were built, not loaded. macOS was not built.

## Disk and processes (`results/disk.txt`)

- About 4.9 GB free before cleanup and 5.8 GB after. The round's scratch
  peaked at about 0.5 GB, plus 1.3 GB of rustup cross targets.
- Removed: build and run outputs, the downloaded crate sources, the
  zigbuild cache, and the macOS, Windows and aarch64-glibc rustup targets.
- Kept for round 10's static musl builds: the two musl rustup targets and
  the `ziglang`/`cargo-zigbuild` venv. Round 9's `bin/` and `wamr/` are
  untouched.
- No background process is left.
