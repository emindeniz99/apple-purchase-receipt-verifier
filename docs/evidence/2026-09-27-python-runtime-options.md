# Python start-up: avoiding the per-process Cranelift compile

Date: 2026-09-27. Code, scripts and raw results are in
`2026-09-27-python-runtime-options/`. Its `README.md` has the file table and
the commands to reproduce.

**Question.** Round 7 (`2026-09-26-python-wasmtime.md`) found that every
Python process spends about 0.9 s compiling `aprv.wasm` with Cranelift
before its first verification. Does it have to? The owner asked for
mature, upstream options only:

- wasmtime-py's own knobs: the Winch compiler, Cranelift opt levels,
  Wasmtime's disk cache, a module precompiled with `Module.serialize`;
- Pulley, if wasmtime-py exposes it;
- WAMR, if its Python route is mature;
- one-line verdicts, with no builds, for wasmer-python, pywasm3, pywasm,
  WasmEdge and Extism.

The answer feeds the Python packaging plan. The owner set two judgments:
servers, which pay start-up once per worker, and AWS Lambda-like cold
starts, where the disk cache does not count (a fresh ephemeral `/tmp`, a
read-only package directory).

Labels: TESTED (ran here), DOCUMENTED (read in a primary source), EXPECTED
(inferred, not run).

Nothing under `python/`, `rust/`, `docs/rust-core` or any other production
path changed. Environment (`results/versions.txt`): Ubuntu 24.04 x86_64,
4 cores (Intel Xeon, 2.10 GHz), CPython 3.12.3, wasmtime-py 49.0.0 from
PyPI, the Wasmtime 49.0.1 CLI for cross-compiling. The module is ABI v1,
`aprv-abi1.wasm`, sha256 `b14e14b2…87b636b3`, 2,952,613 bytes. "One core"
means the process ran under `taskset -c 0`, the stand-in for a one-vCPU
Lambda.

## Result

- **The compile is avoidable. Ship it precompiled (TESTED).** A process
  that loads a `.cwasm` made by `Module.serialize` reaches its first
  verified g5 in 65 ms on 4 cores and 62 ms on one. Compiling at start
  takes 934 ms and 2,923 ms. The load itself drops from 863 ms to 0.9 ms;
  Python's own start and `import wasmtime` (about 36 ms) are most of what
  remains.
- **It costs nothing at run time (TESTED).** A module precompiled for the
  baseline x86-64 target (no host CPU features) verifies at the same speed
  as a native compile: 577 against 573 receipts and 181 against 177 JWS
  per second on one thread. All 6,179 corpus rows stay byte-identical and
  37/37 ABI tests pass.
- **It needs no writable disk.** The `.cwasm` sits inside the platform
  wheel next to the `.so` that wasmtime-py already ships. That is the one
  fast option that holds for a Lambda cold start.
- **The price: about +2.7 MB per platform wheel and a pin on the Wasmtime
  major (TESTED).** A `.cwasm` from 49.x loads in any 49.x wasmtime-py and
  is refused by 48.0.0. A facade that keeps the `.wasm` and compiles it
  when the `.cwasm` is refused never breaks. It only goes slow.
- **Winch halves the compile and halves the speed (TESTED).** Compiled at
  start it reaches the first result in 468 ms (4 cores) and 834 ms (one
  core), then verifies at 288 receipts and 90 JWS per second, 9 times the
  floor. wasmtime-py 49.0.0 reaches it only through a private `_ffi` call.
- **Pulley runs through wasmtime-py and misses the floor (TESTED).** 6.2
  JWS per second on one thread, under 10. That matches the server spike's
  5.6 to 7.5.
- **Caches help servers only (TESTED).** Wasmtime's `Config.cache` gives
  95 ms warm; a per-machine file cache gives 110 ms on a hit. Both pay the
  full compile on the first run and need a writable directory.
- **WAMR's Python route is not mature (DOCUMENTED).** The binding is not on
  PyPI, it builds the library from source at install time, and nobody has
  committed to it in 12 months. It was not measured, per the owner's rule.
- **The other runtimes are out (DOCUMENTED).** One line each, at the end.

## Options measured

One row per way of getting compiled code into a process. Everything ran
through round 7's harness with this folder's `py/aprv_wasm` first on
`PYTHONPATH`. "Start-up" is the wall time a parent measures for
`python first_result.py`: interpreter start, `import`, load or compile,
instantiate, first verified g5. It is the median of 7 cold processes.

| Option | Start-up, 4 cores / 1 core | First call | g5/s, 1 thread | JWS/s, 1 thread | g5/s per core, 4 processes | JWS/s per core, 4 processes |
|---|---:|---:|---:|---:|---:|---:|
| Cranelift, compiled at start (round 7) | 934 / 2,923 ms | 4.1 ms | 573 | 177 | 512 | 173 |
| Cranelift opt level `none`, at start | 739 / 2,338 ms | 4.0 ms | 497 | 163 | 492 | 161 |
| Winch, at start | 468 / 834 ms | 7.3 ms | 288 | 90 | 274 | 87 |
| Pulley, at start | 1,002 / 3,105 ms | 64 ms | 28 | **6.2** | 28 | **6.1** |
| **Cranelift `.cwasm`, baseline x86-64** | **65 / 62 ms** | 4.3 ms | 577 | 181 | 504 | 154 |
| Winch `.cwasm`, baseline x86-64 | 66 / 72 ms | 7.0 ms | 297 | 96 | 263 | 85 |
| Pulley `.cwasm` (`pulley64`) | 164 / 167 ms | 66 ms | as Pulley | as Pulley | as Pulley | as Pulley |
| Cranelift + `Config.cache`, first run / warm | 966 / 2,892 ms, then 95 / 94 ms | 3.9 ms | as Cranelift | | | |
| Cranelift + file cache, miss / hit | 1,014 / 3,099 ms, then 110 / 121 ms | 4.3 ms | as Cranelift | | | |

Sources: `results/startup.txt`, `results/bench.txt` (1,000 calls after 200
warm-up), `results/processes.txt` (the 4-process total divided by 4). The
floor is 10 per second per core; only Pulley's JWS rows fall under it.

**Parity and ABI tests (TESTED).** Six options ran the full corpus:
Cranelift, Cranelift `none`, Winch, Pulley, and the Cranelift and Winch
`.cwasm`. Each gave 6,179 of 6,179 rows byte-identical to Node (the 1,179
corpus rows plus the 5,000 mutants), 0 DIFFERENT and 0 traps
(`results/calls-*.txt`). The same six passed 37/37 ABI and facade tests
(`results/abi-tests-*.txt`). The Pulley `.cwasm` ran start-up only. The
two cache rows run the Cranelift engine, and they ran start-up only.

**Noise.** Round 7 measured the same Cranelift path at 561 receipts and 192
JWS per second; the 4-process JWS rows here spread from 154 to 173 per
core. Treat differences under about 10% as noise. Winch's halving is well
outside it.

**What the start-up breakdown shows** (`median_run` in
`results/startup.txt`, 4 cores):

- interpreter start plus `import aprv_wasm`: about 55 to 60 ms, the same
  for every option;
- `Module.deserialize_file` of the `.cwasm`: 0.9 ms. It maps the file.
  Round 7's `Module.deserialize` from bytes took 11 ms;
- instantiate: 0.3 to 0.8 ms;
- first call: 4 ms for Cranelift, 7 ms for Winch, 64 ms for Pulley.

On one core the compile-at-start rows get three times slower, because
Wasmtime compiles functions in parallel by default. Winch suffers least
(1.8 times). With `Config.parallel_compilation` off, the 4-core start-up
takes 2,867 ms, the same as the one-core row (`run.sh startup-serial`).

## Servers and Lambda

**A server** pays start-up once per worker. Four workers starting together
on 4 cores each get about one core, so each waits about the one-core
figure of 2.9 s, and together they spend about 11 CPU-seconds compiling
the same module four times (EXPECTED from the one-core row; not measured
with 4 workers at once). A worker recycled by `max_requests` pays it
again. Every option in the table
serves a server. The precompiled module removes the cost with no
configuration and no writable directory.

**A Lambda cold start** pays start-up on the request that woke it, on a
fractional or single vCPU, with no cache that survives:

| Option | Cold start to first result, one core | Needs a writable disk |
|---|---:|---|
| Cranelift at start | 2,923 ms | no |
| Winch at start | 834 ms | no |
| Cranelift `.cwasm` in the wheel | **62 ms** | no |
| `Config.cache` or a file cache | 2,892 or 3,099 ms (always the first run) | yes |

A function with less than one vCPU would stretch the compile rows further
and leave the `.cwasm` row near its floor, since that row does almost no
work (EXPECTED; not run on Lambda).

## The precompiled module in each platform wheel

**Size (TESTED, `results/precompile.txt`, `results/cross.txt`).** Round 7's
facade is one `py3-none-any` wheel of 978,842 bytes that holds the `.wasm`.

| Artifact | Raw | Deflated, as a wheel stores it |
|---|---:|---:|
| Cranelift `.cwasm`, x86-64 Linux | 8,556,416 | 2,727,928 |
| Cranelift `.cwasm`, the other five targets (CLI) | 7,892,128 to 10,072,000 | 2,503,609 to 2,746,831 |
| Winch `.cwasm`, six targets (CLI) | 12,611,936 to 14,082,472 | 2,482,157 to 2,513,402 |
| Pulley `.cwasm` (`pulley64`) | 6,467,568 | 2,410,404 |

A platform wheel that keeps the `.wasm` for the fallback and adds its own
Cranelift `.cwasm` grows from 0.98 MB to about 3.7 MB, and installs about
11.5 MB. Each wheel carries only its own platform's module.

**What a `.cwasm` pins (TESTED, `results/pinning.txt`).**

- **The Wasmtime major.** wasmtime-py 48.0.0 refuses every 49 module with
  "Module was compiled with incompatible version '49'". A module made by
  the 49.0.1 CLI loads in wasmtime-py 49.0.0 and passes 37/37, so patch
  releases are compatible.
- **The compiler.** Cranelift and Winch modules refuse each other ("Module
  was compiled with/without Winch calling convention").
- **The architecture.** `pulley64` and x86-64 refuse each other.
- **Not the CPU features.** Native and baseline Cranelift modules load in
  each other's engines on this host, and the baseline target showed no
  speed cost. A module compiled with the host's features would be refused
  on an older CPU (EXPECTED; not run), so the wheel must carry the
  baseline build.

**The facade this implies (EXPECTED).** Depend on `wasmtime>=49,<50`, load
the wheel's `.cwasm` with `Module.deserialize_file`, and compile the
bundled `.wasm` if Wasmtime refuses it. A user who forces another
wasmtime-py then gets round 7's 0.9 s start, never an error. Each monthly
Wasmtime major means a facade release to move the pin. The pin can also
clash with an application that depends on another wasmtime-py major
itself.

**Trust.** Loading a `.cwasm` runs its machine code with no validation.
Wasmtime's Rust API marks `Module::deserialize` `unsafe` for that reason
(not re-read this round). A module inside the wheel carries the same trust
as the wheel's `.so`, and pip checks both against the wheel's `RECORD`
hashes. A writable cache directory is a place where anyone with write
access can plant native code, which is one more reason to keep caches out
of the default.

**Building the modules (TESTED, `results/cross.txt`).** wasmtime-py's
library contains only the host's backend:

- `Config.target = "aarch64-unknown-linux-gnu"` aborts the whole Python
  process with a Rust panic ("Support for this target is disabled"), not a
  Python exception;
- macOS and Windows targets raise "does not match the host".

The Wasmtime CLI of the same major compiles all six desktop targets
(Linux, macOS and Windows on x86-64 and aarch64) from one x86-64 Linux
machine in about 1 s each. Its default garbage collector differs from
wasmtime-py's, so it needs `-C collector=drc`; without that flag
wasmtime-py refuses the file ("compiled for the copying collector"). The
x86-64 Linux modules it made pass 37/37 in wasmtime-py 49.0.0. The five
foreign ones were not loaded anywhere.

## Platform coverage and install

Each wasmtime-py option keeps round 7's reach: wasmtime-py 49.0.0 ships
wheels for x86-64 and aarch64 on manylinux, musllinux, macOS and Windows,
plus Android (`results/facts.txt`). The precompiled route needs one
`.cwasm` per OS and architecture. Glibc and musl Linux should share one
module, and Android needs its own `*-linux-android` build (EXPECTED; not
run). A platform with no `.cwasm` gets the `py3-none-any` wheel and compiles
at start.

For a pip user the install stays `pip install` with nothing to build. The
package's release job gains one step: fetch the Wasmtime CLI of the pinned
major and compile six to eight modules.

## Winch through wasmtime-py

wasmtime-py 49.0.0's `Config.strategy` setter accepts only `"auto"` and
`"cranelift"` (`results/facts.txt`). The spike sets Winch through the C API
with `wasmtime._ffi.wasmtime_config_strategy_set(cfg.ptr(), 2)`, the value
of `WASMTIME_STRATEGY_WINCH` in Wasmtime's `config.h`. A released package
should not call a private module. A one-line upstream change adding
`"winch"` to the setter would remove that. Wasmtime 49's tier document
lists Winch as a Tier 1 compiler and calls its aarch64 support complete for
core Wasm (DOCUMENTED).

Winch is the better choice only for a compile at start, and only where
start-up matters more than speed. Precompiled, it starts no faster than
Cranelift (66 against 65 ms) and verifies at half the speed.

## Pulley

`Config.target = "pulley64"` works in wasmtime-py 49.0.0, so the owner's
condition for a re-measure held. The interpreter verifies 28 receipts and
6.2 JWS per second on one thread (24.5 on four processes), with a 64 ms
first call. The Rust server spike found 5.6 to 7.5 JWS per second
(`2026-09-26-aprv-server/results/pulley.txt`); Python adds nothing to the
interpreter's cost. It stays out: it misses the floor, and on every
platform where wasmtime-py runs, Cranelift runs too.

## WAMR (DOCUMENTED, `results/facts.txt`, `results/wamr-build.txt`)

WAMR itself is active: 291 commits by 51 authors in 12 months, latest
release WAMR-2.4.5. Its Python route is a different story:

- **Not packaged.** Neither `wamr` nor `wamr-python` exists on PyPI. The
  binding lives in `language-bindings/python` of the WAMR repository.
- **Stale.** Its last commit is from 2025-06-17: 0 commits in 12 months.
- **Built at install time.** Its `setup.py` runs `utils/create_lib.sh`,
  which builds `libiwasm` with CMake and a C compiler and generates the
  ctypes layer with `ctypesgen`. The build turns on
  `WAMR_BUILD_DEBUG_INTERP`, and WAMR's Linux CMake file then switches the
  fast interpreter off.
- **Not production code.** `wamr.py` prints "deleting Engine", "deleting
  Module" and others to stdout from its destructors, and hard-codes the
  heap sizes.
- **Few prebuilt tools.** Of the four release asset names probed for
  WAMR-2.4.5, only the x86-64 Ubuntu 22.04 builds of `wamrc` (the AOT
  compiler) and `iwasm` exist, with no published checksum.

Using WAMR from Python would mean this project owning a `libiwasm` build
per platform, its own ctypes binding and an AOT file per target. That is
the job wasmtime-py already does. `scripts/build-wamr.sh` built two
`libiwasm` variants (fast interpreter; classic interpreter with fast JIT)
before the owner narrowed the round. Nothing measured them.

## Other runtimes (DOCUMENTED, `results/facts.txt`; not built)

| Runtime | Verdict |
|---|---|
| wasmer-python | Abandoned: last commit 2023-05-01, last PyPI release 1.1.0 on 2022-01-07, wheels for CPython 3.7 to 3.10 only |
| pywasm3 | Out: PyPI has 0.5.0 from 2021-06-02, sdist only. The wasm3 README still announces "a minimal maintenance phase", although its maintainer has pushed commits again since September 2026. An interpreter, the same class as Pulley |
| pywasm | Out: "A WebAssembly interpreter written in pure Python" (its README), 2 authors in 12 months; far slower than Pulley (EXPECTED) |
| WasmEdge | Out: the WasmEdge repository's `bindings/` holds Java and Rust only, and the PyPI name `wasmedge` holds a single 0.0.1 sdist from 2021 |
| Extism | Out: a plugin framework on top of Wasmtime with its own calling convention, so `aprv.wasm` would need rebuilding for it (EXPECTED), and it cannot start faster than the Wasmtime underneath. The Python SDK had 3 commits in 12 months |

## Limits

- Linux x86-64 only, CPython 3.12. No macOS, Windows or aarch64 load of a
  `.cwasm` ran; the five foreign CLI modules were only compiled.
- Lambda was simulated with `taskset -c 0` on a local machine. No Lambda
  function ran, and fractional vCPUs were not simulated.
- A module built for the baseline target was not tried on an older CPU.
- The Pulley `.cwasm`, the file cache and `Config.cache` ran start-up
  only, not the corpus. They run the same compiled code as rows that did.
- The cost of a refused `.cwasm` before the fallback compile was not
  timed.
- Four workers starting at once were not measured.

## Recommendation

| Option | Verdict | Where |
|---|---|---|
| **Cranelift `.cwasm` for the baseline target in each platform wheel, `wasmtime>=49,<50`, the `.wasm` kept as a compile fallback** | **Adopt.** 62 to 65 ms to the first result, full speed, no writable disk, +2.7 MB per wheel, one facade release per Wasmtime major | Servers and Lambda |
| Cranelift compiled at start (round 7) | Keep as the fallback only. 0.9 s on 4 cores, 2.9 s on one | A wasmtime-py major the wheel does not pin, or a platform without a `.cwasm` |
| Winch compiled at start | Revisit when wasmtime-py's `Config.strategy` accepts `"winch"`. It would make the fallback 2 to 3.5 times faster at start and half as fast at run time | A future fallback |
| Winch `.cwasm` | Reject. No faster to start than Cranelift's, half the speed, larger files | |
| Cranelift opt level `none` | Reject. Saves 20% of the compile and 13% of receipt speed | |
| `Config.cache` | Optional knob for servers with a persistent, private cache directory. Never the default, never on Lambda | Servers only |
| A per-machine file cache in the facade | Reject. `Config.cache` does the same upstream | |
| Pulley | Reject. 6.2 JWS/s is under the floor, and Cranelift covers every platform wasmtime-py reaches | |
| WAMR | Reject for now. The Python binding is unpackaged, stale and debug-built. Reconsider only if wasmtime-py stops shipping | |
| wasmer-python, pywasm3, pywasm, WasmEdge, Extism | Reject, per the table above | |
