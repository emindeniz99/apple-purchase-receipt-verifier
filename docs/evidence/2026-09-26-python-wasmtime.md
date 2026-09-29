# aprv.wasm on Python with wasmtime-py

Date: 2026-09-26. Code, scripts and raw results are in
`2026-09-26-python-wasmtime/`. Its `README.md` has the file table and the
commands to reproduce.

**Question.** Can Python host the one canonical `aprv.wasm` (ABI v1, from
`2026-09-26-wasm-abi-v1`) through the official Bytecode Alliance
`wasmtime` package, behind a minimal facade, and what does that do to the
platforms the Python package reaches? The round covers:

- corpus parity;
- the ABI and trap tests;
- concurrency;
- speed;
- a clean consumer install;
- platform coverage against the 19 wheels R12 planned.

Labels: TESTED (ran here), DOCUMENTED (read in a primary source), EXPECTED
(inferred, not run).

Nothing under `rust/`, `python/`, `docs/rust-core` or any other production
path changed. The environment: Ubuntu 24.04 x86_64, 4 cores, CPython
3.12.3 (3.10.20 for the sdist consumer), wasmtime 49.0.0 from PyPI.

## Result

- **Parity: identical (TESTED).** All 6,179 rows run: the 1,179 corpus rows
  plus the 5,000 mutants.
  - 0 answers differ from round 4's native rows.
  - Every row is byte-identical to Node, with `request_date*` masked where
    it is the wall clock.
  - 0 traps (`results/calls.txt`).
- **ABI and trap tests: 37/37 (TESTED).** That is the 33 mandatory tests
  plus 4 tests of the facade's contract (`results/abi-tests.txt`).
  - A version mismatch traps inside `aprv_call` with no host import called;
    the trap's only frame is `aprv_call`.
  - After every trap, a fresh instance verifies g5.
- **Speed: far above the floor, but threads do not scale past two
  (TESTED).** One thread takes 1.78 ms for g5 (561 per second) and 5.20 ms
  for the JWS (192 per second).
  - Processes scale: four give 2,259 per second for g5 and 698 for the JWS,
    3.8× and 3.6×.
  - Threads do not: 583, 946 and 566 per second for g5 at 1, 2 and 4
    threads. Four threads are slower than two.
  - A Python deployment should use worker processes (the usual gunicorn or
    uvicorn model) with one Verifier per worker.
- **The clean consumer works (TESTED).** The facade builds as an sdist and
  a wheel (a `py3-none-any` wheel of 979 KB holding `aprv.wasm`). Each
  installs with plain `pip` into a new virtual environment that fetches
  `wasmtime==49.0.0` from PyPI:
  - the wheel on Python 3.12;
  - the sdist on Python 3.10.

  Both verify g5 from an empty directory (`results/build.txt`).
- **Platforms: 8 of R12's 19 wheels (DOCUMENTED).** Details are in their own
  section below.
- **A thread-safety bug in wasmtime-py 49.0.0 shapes the facade (TESTED).**
  Details are in their own section below.

## wasmtime-py (DOCUMENTED, `results/facts.txt`)

| | |
|---|---|
| Version | 49.0.0, uploaded 2026-09-21; `requires_python >=3.9`; Apache-2.0 WITH LLVM-exception |
| Cadence | a release a month for the last 12 months (38.0.0 on 2025-10-20 through 49.0.0), tracking Wasmtime's own monthly majors |
| Activity | 37 commits by 9 authors in the 12 months to 2026-09-26, in bytecodealliance/wasmtime-py |
| Files of 49.0.0 | manylinux1 x86_64, manylinux2014 aarch64, musllinux_1_2 x86_64 and aarch64, macOS 10.13 x86_64 and 11.0 arm64, Windows amd64 and arm64, Android 26 arm64 and x86_64, one `py3-none-any` wheel, and an sdist |
| Binding | ctypes over the Wasmtime C API. `CDLL` releases the GIL for every call into Wasm |

The coordinator's summary of the platform list is right, with three
corrections a consumer would hit:

1. **The `py3-none-any` wheel contains only the Windows x86_64 DLL.** pip
   picks it on every platform that has no wheel. That was checked with
   `pip download --platform` for ppc64le, s390x, i686, armv7l, armv6l,
   win32 and musl riscv64. `import wasmtime` then fails. The loader
   (`_ffi.py`) raises "unsupported architecture" for anything but x86_64 and
   aarch64, and "only works on 64-bit platforms" for 32-bit Pythons.
   The failure comes at import time, not at install time.
2. **The x86_64 glibc wheel is tagged `manylinux1` (glibc 2.5), but its
   library needs `GLIBC_2.28`.** pip installs it on CentOS 7 (2.17) or
   Amazon Linux 2 (2.26), and loading it fails there (EXPECTED from the
   symbol versions; not run on such a system). The aarch64 wheel needs
   2.18 against its manylinux2014 tag of 2.17.
3. **The sdist is not a source build.** Its build backend downloads a
   prebuilt Wasmtime C API from Wasmtime's GitHub releases. So it helps
   only where such a download exists and the loader accepts the
   architecture.

## Platform coverage against R12's 19 wheels

R12 planned 19 wheels, one per platform tag:

- manylinux: x86_64, aarch64, armv7l, i686, ppc64le, s390x, riscv64;
- `linux_armv6l`;
- musllinux: x86_64, aarch64, armv7l, i686, ppc64le, riscv64;
- Windows: amd64, win32, arm64;
- macOS: arm64, x86_64.

The facade is one pure-Python wheel, so its reach is exactly wasmtime-py's.

| R12 wheel | With wasmtime-py 49.0.0 |
|---|---|
| manylinux x86_64, aarch64 | yes (glibc 2.28 and 2.18 in practice) |
| musllinux x86_64, aarch64 | yes |
| macOS arm64, x86_64 | yes (11.0 and 10.13) |
| Windows amd64, arm64 | yes |
| manylinux armv7l, i686, ppc64le, s390x, riscv64 | no |
| `linux_armv6l` | no |
| musllinux armv7l, i686, ppc64le, riscv64 | no |
| Windows win32 | no |
| (not in R12) Android arm64, x86_64 | yes |

- **Kept: 8 of 19.** Lost: 11, and the 32-bit and big-endian machines are
  gone entirely.
- **Gained: Android.** It is not in R12.
- **Where the losses matter.** They are exactly R12's "niche" and "low" rows
  (IBM Power and Z, 32-bit Raspberry Pi, i686, riscv64, 32-bit Windows
  Python). On those, the current plan's sdist fallback (build with Rust)
  would be replaced by an import error.
- **Getting them back.** Either wasmtime-py would have to ship them, or the
  project would need a second, pure-Python or native path.
  - Wasmtime itself publishes C API builds for s390x, riscv64, i686 and
    armv7 Linux (v49.0.0 release assets, `results/facts.txt`). ppc64le is
    not among them.
  - wasmtime-py's loader accepts only x86_64 and aarch64, so those builds
    are unused.

## The handle-table race in wasmtime-py 49.0.0 (TESTED, `results/slab-race.txt`)

**The bug.** wasmtime-py stores Python callbacks in a `Slab`, a list with an
in-place free list. Handles are freed from finalizers, on whichever thread
runs them. Upstream fixed it on 2026-09-24, after 49.0.0 (wasmtime-py#344,
"Make `Slab` safe to use from multiple threads").

**The run.** `py/slab_race.py` uses `sys.setswitchinterval(1e-6)` so that
thread switches land between statements. Four threads ran for 10 s each.

| Pattern | Rounds | Exceptions | Callbacks returning another function's value |
|---|---:|---:|---:|
| host functions created per Store (`wasmtime.Func`) | 190 | 118,533 (`TypeError: list indices must be integers or slices, not tuple`, the upstream symptom) | 2 |
| the facade: host functions defined once on a process-wide `Linker` | 4,419 | 0 | 0 |

**What the facade does about it.** It defines `aprv.clock_now_ms` and
`aprv.random_get` once, on a `Linker` that lives for the whole process.
Their two slab handles are allocated at start-up and never freed.

**What else a production facade needs.** It should also pin the fixed
wasmtime-py release once it ships. A second process-wide global remains in
49.0.0: `LAST_EXCEPTION`, which carries a host callback's exception into
the trap. Only a callback that raises would touch it, and the facade's
callbacks raise only on an out-of-range `random_get`.

## Measurements

**Speed.** One instance, full bridge lifecycle plus `bytes` copy,
`results/bench.txt`.

| Row | Mean per call | Per second |
|---|---:|---:|
| g5 receipt (op 1), 1,000 after 200 warm-up | 1,783 µs | 561 |
| shared-sandbox JWS (op 258) | 5,198 µs | 192 |
| endpoint request `{}` (answers 21002; the bridge's own cost), 20,000 | 178 µs | |

Node (V8) on the same module took 1,343 and 4,819 µs, figures from the ABI
v1 note. Python is 33% and 8% slower. Most of the difference is the
bridge: a call that does almost nothing costs 178 µs, in seven ctypes calls
plus one clock callback. An earlier run of the same benchmark gave 1,678
and 5,252 µs; the run-to-run noise is about ±6%.

**Scaling.** One Verifier per worker, total per second.

| Row | Workers | 1 | 2 | 4 | 4 ÷ 1 |
|---|---|---:|---:|---:|---:|
| g5 | threads (`results/threads.txt`) | 583 | 946 | 566 | 1.0× |
| g5 | processes (`results/processes.txt`) | 595 | 1,123 | 2,259 | 3.8× |
| JWS | threads | 207 | 321 | 296 | 1.4× |
| JWS | processes | 191 | 376 | 698 | 3.6× |

- **Thread scaling is poor.** ctypes releases the GIL for each call into
  Wasm, and each thread has its own Store. Even so, threads reach at most
  1.6× at two and fall back at four.
- **Why.** Each verification is seven short ctypes calls (each drops and
  retakes the GIL) plus the clock callback, which retakes it from inside
  Wasm. Four threads contend for it. The cause was not investigated
  further.
- **An earlier run matched.** It ran while another agent's compiler was
  busy, and gave the same shape.
- **The floor holds anyway.** Even one thread per process is 19 to 56 times
  the floor.

**Start-up.** Fresh processes, `results/startup.txt`.

| Step | Time |
|---|---|
| `import aprv_wasm` | about 45 ms |
| The first `Verifier` | 0.81 to 0.94 s: Cranelift compiles the 3 MB module |
| Every later `Verifier` | 0.4 to 0.6 ms |
| The first call | about 4 ms |

The compile happens once per process.

- **The alternative for short-lived processes.** A module precompiled for
  one wasmtime version and CPU (`Module.serialize`, 8,552,264 bytes) loads
  with `Module.deserialize` in 11 ms.
- **What that would mean for the package.** The facade would ship or cache
  a precompiled blob per wasmtime version and CPU, and fall back to
  compiling.
- **An earlier run was slower.** It ran on a busy machine and took 1.57 to
  1.78 s for the first Verifier.

## Behaviour

- A trap raises `WasmTrapError`, and the Verifier discards its instance and
  starts a fresh one on the next call.
- A version mismatch raises `AbiMismatchError`.
- A verification failure is a value, never an exception.
- Results are copied into Python `bytes` before the handle is freed.
- Linear memory stays at 2,097,152 bytes over 2,000 further calls.
- `results/isolation.txt` has two checks. Four threads with one Verifier
  each, trapping on every 7th call: 180 good calls and exactly 30 traps per
  thread. Two instances in one thread: a trap in one leaves the other
  untouched.

## Limits

- Linux x86_64, CPython 3.12 (and 3.10 for the install) only.
- Free-threaded CPython did not run.
- The platform table comes from the wheel list, the loader and the library
  symbol versions. Only Linux x86_64 ran.
