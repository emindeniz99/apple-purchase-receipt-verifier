# WebAssembly architecture bake-off: one Rust policy, one C substrate, four Wasm routes

Date: 2026-09-26. Code, scripts and raw results:
`2026-09-26-wasm-architecture-bakeoff/` (its `README.md` has the file table,
the artifact names and the commands). It builds on
`2026-09-26-security-substrate-bakeoff.md` ("the previous bake-off") and
reuses its adapter, policy, corpora, Java oracle rows and comparison scripts
unchanged. Every claim carries one label: TESTED (ran here), DOCUMENTED
(read in a source file, manifest or vendor document), EXPECTED (inferred,
not run), UNKNOWN, NOT APPLICABLE.

Nothing in `rust/`, `docs/rust-core/` or any other production path changed.
The core was copied to `$SCRATCH` and patched there. `DECISIONS.md` is not
touched; section 22 only drafts an R21 for the owner.

## The question

Can one Rust APRV policy over one mature C substrate (AWS-LC or OpenSSL,
LibreSSL where its own Emscripten path allows) run as the same security
implementation on native, Node, Bun, Deno, browsers, Cloudflare workerd,
wazero and Wasmtime, packaged through different Wasm routes: WASI preview 1
with a minimal host (A), Emscripten (B), a freestanding core module (C),
and the Component Model with WIT and jco (D)? The answer feeds R21 and the
long-term substrate choice in `docs/rust-core/`.

Short answer. Yes, for both AWS-LC and OpenSSL, and it was not close. The
previous bake-off's conclusion that "no rust-openssl substrate reaches the
npm target" was true only of `wasm32-unknown-unknown`. Built for
`wasm32-wasip1` and linked with a 74-line C file that defines the WASI
functions inside the module, the AWS-LC build imports exactly one host
function, `aprv.clock_now_ms`. OpenSSL imports that one plus
`aprv.random_get`. Those core modules gave the same answer as their own
native build on all 1,179 rows in Node, Bun, Deno, Chromium, Firefox,
WebKitGTK, workerd, wazero and Wasmtime. Emscripten (all three libraries)
and a WIT component transpiled by jco (AWS-LC and OpenSSL) did the same on
every host they could run on. So one security implementation is enough.
The 58 pure-Rust `wasm32-unknown-unknown` traps were only the missing clock
seam. With SURFACE.md 4.1's seam: 0 traps, 1,179 of 1,179 rows the same as
native. What still separates the options is the C code in the trusted base,
the 287 lines inside `unsafe` and the toolchain weight. Correctness and
portability no longer do.

## Do not confuse build targets with security implementations

This note counts **security implementations**, not build targets. They are
different things, and mixing them up is how "we need two cores" gets
concluded by mistake.

- **One substrate.** AWS-LC source compiled natively, for `wasm32-wasip1`,
  by Emscripten and inside a component is **one** security implementation
  built four ways. Same for OpenSSL.
- **One policy.** The same Rust policy (`core-patch/substrate.rs` over the
  core) behind the C ABI (`rust/ffi`), behind a core-module export list and
  behind a WIT interface is **one** policy implementation with three ABIs.
- **Two implementations** would be native on AWS-LC while the browser runs
  an unrelated custom Rust CMS/X.509 stack. Nothing measured here forces
  that.

The evidence for "one implementation" is not that the artifacts build. On
each backend, every artifact gave the same answer as that backend's native
build on all 1,179 rows (`results/parity-summary.txt`). The Java
three-way tallies of all 94 candidate runs equal the native build's
(`results/java-parity.txt`). The only lines that differ there are the
diagnostic runs (no clock seam, failing RNG) and the one failed workerd run
that produced no rows.

## 1. Executive table

"Same as native" = the row-by-row comparison with the native C ABI build of
the same backend (`$SPIKE/py/same.py`), 1,179 rows, four corpora.

| | Pure Rust | AWS-LC 1.73.0 | OpenSSL 4.0.2 | LibreSSL 4.3.2 |
|---|---|---|---|---|
| Native C ABI (reference) | TESTED | TESTED | TESTED | TESTED |
| A: `wasm32-wasip1`, minimal JS host, same as native | 1,179 (TESTED) | 1,179 (TESTED) | 1,179 (TESTED) | does not compile (previous bake-off, TESTED) |
| C: freestanding core module, imports | `aprv.clock_now_ms` | `aprv.clock_now_ms` | `aprv.clock_now_ms`, `aprv.random_get` | not built (depends on A) |
| C: hosts at 1,179 same | Node, Bun, Deno, Chromium, Firefox, WebKitGTK, workerd, wazero, Wasmtime | the same 9 | the same 9 | n/a |
| B: Emscripten 6.0.10, hosts at 1,179 same | not built (not needed) | Node, Bun, Deno, 3 browsers, workerd | the same 7 | the same 7 |
| B: source patches | n/a | 0 (one cmake wrapper line) | 0 (a Configure line) | 0 (`-sFILESYSTEM=1` at link) |
| D: WIT component, hosts at 1,179 same | not built | Wasmtime native CM; jco in Node, Bun, Deno, 3 browsers, workerd | the same 8 (via the WASI 0.2 adapter) | not built |
| npm tarball prototype | no | 3 (core, Emscripten, component): Node, Bun, Deno, 3 browsers, `wrangler dev` (TESTED) | not packed | not packed |
| Java tallies equal native tallies | yes | yes | yes | yes |
| Wasm features needed | wasm2 / lime1 | wasm2 / lime1 (+ legacy exceptions under Emscripten) | same | Emscripten only: + legacy exceptions |
| Randomness needed on the corpus | none | none | EC blinding in ECDSA verify (section 10) | none (Emscripten build) |

Sources: `results/parity-summary.txt`, `results/java-parity.txt`,
`results/imports.txt`, `results/features.txt`, `results/npm-smoke.jsonl`,
`results/builds.txt`.

## 2. Versions

All exact versions and download hashes are in `results/versions.txt` and
`scripts/fetch-tools.sh`. The main ones:

- rustc 1.94.1 (stable) for everything except P3. P3 used rustc
  1.100.0-nightly (2026-09-25), installed under `$SCRATCH` only.
- wasi-sdk 34.0; Emscripten 6.0.10 (official release binaries); host clang
  18.1.3.
- AWS-LC 1.73.0 (aws-lc-sys 0.41.0); OpenSSL 4.0.2; LibreSSL 4.3.2;
  rust-openssl `openssl` 0.10.81 / `openssl-sys` 0.9.117.
- wit-bindgen 0.62.0; wasm-tools 1.259.0; jco 1.35.0 and preview2-shim
  0.26.0; Wasmtime 49.0.1 CLI and wasmtime-py 49.0.0; the wasmtime v49.0.1
  `wasi_snapshot_preview1.reactor.wasm` adapter; binaryen 132; wabt 1.0.37.
- Node 22.22.2, Bun 1.3.11, Deno 2.9.7; wazero 1.12.0 (Go 1.25).
- workerd 1.20260926.1 and wrangler 4.141.0, both local only.
- Browsers: Chromium 141.0.7390.37 (Playwright 1.56.1), Firefox 156.0.1
  (Mozilla release tarball, headless), WebKitGTK 2.52.6 MiniBrowser (Ubuntu
  package, under Xvfb).
- The Java oracle is JDK 25.0.4.1 with Bouncy Castle 1.86. Its rows come
  from the previous bake-off and were not rerun.

## 3. Method

- **Corpora.** The previous bake-off's 1,179 rows: `cases` (153),
  `substrate` (193, including the 39 historical-time rows), `hostile` (811,
  131 of them not expressible through the C ABI) and `algorithms` (22).
  They come from `fixtures/` or from test keys. No production receipt was
  used.
- **Reference.** The native C ABI builds (`rust`, `awslc`, `ossl402`,
  `libressl432`), rebuilt with `scripts/native-baseline.sh`. Their Java
  tallies are identical to the previous bake-off's
  (`results/java-parity.txt`, last block).
- **What goes into every artifact.** The same scratch core, patched with the
  previous bake-off's `core.patch` plus `core-patch/clock-seam.patch` (40
  changed lines). The unchanged `rust/ffi` C ABI. A 37-line shim
  (`shim/`) for allocation and clock installation. For Route D, a
  wit-bindgen guest (`component/guest/`) that calls the same C ABI
  functions.
- **Comparison.** Every artifact × host run is compared row by row with the
  native build of the same backend (`scripts/run-parity.sh`,
  `workerd-parity.sh`, `browser-parity.sh`; all appended to
  `results/parity.txt`). The three-way Java tally is then recomputed with
  `$SPIKE/py/tri.py` (`scripts/java-parity.sh`).
- **Hosts.** Every JS host (Node, Bun, Deno, workerd, the three browsers)
  runs the same pure-ES driver (`js/driver.mjs`). Wasmtime runs through
  wasmtime-py (`py/run_wasmtime*.py`) and wazero through a Go runner
  (`wazero/`).
- **Import policies of the minimal host** (`js/hosts.mjs`):
  - `trap`: implements clock, random, empty args and environment, no
    preopens, and a stdout/stderr that only captures. Any other WASI call
    traps.
  - `strict`: every import except `aprv.clock_now_ms` traps.
- **What "PASS" means.** A run that traps or differs on any row is not
  counted as a pass. `results/parity.txt` is append-only. It keeps six
  failed runs, each followed by a `# NOTE`: four were harness bugs, fixed and
  rerun; two are findings (sections 7 and 8).

## 4. Clock: the 58 traps (TESTED)

The previous bake-off saw 58 of 1,179 rows trap on pure-Rust
`wasm32-unknown-unknown` and suspected the clock. That is now proven
(`results/clock-traps.txt`, `py/clock_traps.py`):

- Without the seam (`rust-uu-noseam`), 58 rows trap on Node, Bun and Deno.
- With the seam (`rust-uu`), exactly 58 rows read the host clock (60 reads).
  Zero rows trapped without reading the clock, and zero rows read the clock
  without trapping before.
- The reads come from four places:

  | Where the clock is read | Rows | Reads per row |
  |---|---|---|
  | Endpoint without a pinned clock | 28 | 1 |
  | Endpoint without a pinned clock | 2 | 2 |
  | Endpoint with a pinned clock (the response's `request_date`) | 2 | 1 |
  | JWS without `signedDate` | 3 | 1 |
  | Receipts without a receipt date | 23 | 1 |

- With the seam: 0 traps, and 1,179 of 1,179 rows the same as native on
  Node, Bun, Deno, workerd and all three browsers.

The code has three fallbacks to the system clock: `receipt.rs:134`,
`jws.rs:455` and `endpoint.rs:525`, plus `SystemClock::now` in `clock.rs`.
The patch routes all of them through one function, `clock::system_now()`.
On native targets it is `SystemTime::now()`, as before.

On `wasm32-unknown-unknown`, and on any wasm build compiled with
`--cfg aprv_host_clock`, `system_now()` reads a function installed once
through `platform::install_clock`:
- A second install call is refused.
- The hook does not exist on native targets.
- With no clock installed it panics, which is exactly today's trap.

Semantics are unchanged: where today's code reads the system clock, it
reads the host's wall clock. The shim installs `aprv.clock_now_ms`
(`Date.now()`). A host answer that is not a finite instant after 1970 maps
to 1970, where no Apple chain is valid, so the failure is closed.

**Does the seam let a module avoid WASI clock imports?** Yes (TESTED):
`rust-w1h`, `awslc-w1h` and all Route C and D AWS-LC builds read time only
through `aprv.clock_now_ms` / `clock-now-ms`. For OpenSSL the seam removes
the Rust-side clock read, but OpenSSL's DRBG still calls libc `time()`
(section 10). In Route C that call resolves to the same `aprv.clock_now_ms`,
so no WASI clock import remains.

## 5. Route A: WASI preview 1 with a minimal host

The previous bake-off already ran `wasm32-wasip1` modules. What is new:
exact imports, which of them are ever called, and whether a tiny JS object
can replace a WASI runtime.

**Imports** (`results/imports.txt`, wasm-tools 1.259.0):

| Module | Imports | Called on the 1,179 rows (parity.txt call counts) |
|---|---|---|
| `rust-w1` | 5: `environ_get`, `environ_sizes_get`, `clock_time_get`, `fd_write`, `proc_exit` | `clock_time_get` only (60, the Rust fallbacks) |
| `awslc-w1` | 10: the above plus `fd_close`, `fd_prestat_get`, `fd_prestat_dir_name`, `fd_seek`, `random_get` | `clock_time_get` only (58, the Rust fallbacks) |
| `awslc-w1h` (Rust clock through `aprv`) | 11: `aprv.clock_now_ms` plus the 10 | **no WASI call at all**: the `strict` host, where every WASI import traps, passes 1,179/1,179 |
| `ossl-w1` | 17: adds `fd_read`, `fd_readdir`, `fd_fdstat_*`, `fd_filestat_get`, `path_open`, `path_filestat_get` | `clock_time_get` (1,272) and `random_get` (1 per instance) |
| `ossl-w1h` | 18 | `random_get` 1 per instance; `clock_time_get` 1,214, all from the DRBG's `time()`; `aprv.clock_now_ms` 58 |

Classification of the WASI imports (TESTED through the `trap` and `strict`
hosts, and `results/callsites-*.txt`):

- **Imported but never called on this workload: every file, directory,
  environment, argument and exit function.** The `trap` host makes each of
  them trap; no run trapped. `path_open` and `fd_readdir` come from
  OpenSSL's config and cert-directory code, which the adapter never reaches
  (`OPENSSL_NO_LOAD_CONFIG` and no default paths; previous bake-off
  section 7).
- **Called during receipt and JWS verification: the clock only.** In Rust
  it is the fallback instant (section 4), for both receipts and JWS. In
  OpenSSL it is the DRBG's `time()`, which runs in JWS (ECDSA) verification
  and in the ECDSA-signed receipt algorithms, not in RSA receipts.
- **Called on the first use, then not again: OpenSSL's `random_get`.** It
  seeds the DRBG once per instance, lazily, on the first EC operation.
- **Unreachable in this configuration:** `proc_exit` and `fd_write`. They
  are reachable only through a Rust panic, and no row panicked.

**Minimal host (TESTED).** A plain `WebAssembly.instantiate(module,
imports)` with no `node:wasi` runs all three WASIp1 builds at 1,179/1,179 on:
- Node (`trap` host);
- workerd (the same object inside a Worker);
- wazero and Wasmtime (their own WASI, nothing preopened).

`node:wasi` in Node also passes (`nodewasi` rows). The WASI part of
`js/hosts.mjs` is about 40 code lines. It is a fixed answer set, not a WASI
implementation. It has no files, no directories and no environment.

**workerd's built-in WASI.** With the flags `nodejs_compat` and
`enable_nodejs_wasi_module`, `node:wasi` imports, but constructing it
answers "The WASI method is not implemented" (`results/parity.txt` line
135, TESTED). So on workerd the only working WASIp1 path is our own import
object. It works: `awslc-w1` and `ossl-w1` both 1,179/1,179 in workerd.

**npm.** A WASIp1 module packages exactly like Route C (section 6) plus the
40-line WASI answer set (EXPECTED; no separate WASIp1 tarball was packed).
Route C makes that answer set unnecessary, so no WASIp1-only package was
built.

## 6. Route C: freestanding core module (TESTED)

**How it works.** wasi-libc calls every WASI function through a symbol named
`__imported_wasi_snapshot_preview1_<name>`, which carries the import
attributes (DOCUMENTED in wasi-libc's `__wasilibc_real.c`).
`c/wasi-none.c` (104 lines, 74 of code) defines those symbols, so `wasm-ld`
resolves them inside the module. The finished `.wasm` imports no
`wasi_snapshot_preview1` at all. What the module can still reach:

- **Clock.** `clock_time_get` answers `aprv.clock_now_ms` (or traps in the
  component build, section 8).
- **Random.** `random_get` becomes the import `aprv.random_get` with
  `-DAPRV_HOST_RANDOM` (OpenSSL). Otherwise it traps (AWS-LC and pure Rust
  never call it).
- **Environment and arguments** are empty.
- **Every descriptor** answers EBADF, and `path_open` answers ENOSYS.
  `proc_exit` traps.

This is a link-time host, not a runtime. It patches nothing in AWS-LC,
OpenSSL, wasi-libc or rustc.

**Results** (`results/imports.txt`, `results/parity-summary.txt`):

| Module | Imports | Hosts at 1,179/1,179 same as native |
|---|---|---|
| `rust-c` | `aprv.clock_now_ms` | Node, Bun, Deno (strict), Chromium, Firefox, WebKitGTK, workerd, wazero, Wasmtime |
| `awslc-c` | `aprv.clock_now_ms` | the same 9, with the `strict` host |
| `ossl-c` | `aprv.clock_now_ms`, `aprv.random_get` | the same 9 |
| `awslc-c` / `ossl-c` after `wasm-opt -Oz` | unchanged | Node (TESTED); `-Oz` is parity-safe |

- In workerd, `awslc-c` called `aprv.clock_now_ms` 58 times over 1,179 rows
  and nothing else. `ossl-c` called `aprv.random_get` once and
  `aprv.clock_now_ms` 1,257 times.
- The target shape "`import wasm from './aprv.wasm'` plus a tiny host
  object" is exactly `npm/core/workerd.js` plus `npm/core/instantiate.js`
  (20 code lines). It passed under `wrangler dev` (section 14).
- `wasm32-unknown-unknown` through rust-openssl is still impossible (the
  `libc` crate has no C types there; previous bake-off, not retried).
  Route C does not need that target. `wasm32-wasip1` plus link-time WASI
  definitions produces a module every plain `WebAssembly` host accepts.

**What it costs.**
- 74 lines of C.
- The previous bake-off's WASIp1 link fixes: `crt1-reactor.o`, and the
  emulation libraries.
- The host must call `_initialize` before `aprv_init`.
- It depends on a wasi-libc internal symbol name. That name is not a
  documented stable interface. If a wasi-sdk release renames it, the link
  fails loudly with undefined imports rather than miscompiling (EXPECTED).
  `scripts/imports.sh` would show it.

## 7. Route B: Emscripten (TESTED)

Rust's `wasm32-unknown-emscripten` target (stable) builds the shim as a
static library. `emcc` links it into one `.wasm` plus an ES-module glue:
`-O3 -sMODULARIZE -sEXPORT_ES6 -sFILESYSTEM=0 -sALLOW_MEMORY_GROWTH
-sSTACK_SIZE=1048576`, with 23 `aprv_*` exports
(`scripts/build-emscripten.sh`). A `cdylib` does not work: rustc then
drives `emcc` as a program link and fails with "undefined symbol: main"
(`results/builds.txt`).

| | AWS-LC | OpenSSL | LibreSSL |
|---|---|---|---|
| Library build | aws-lc-sys through cmake-rs. Emscripten's toolchain file sets processor `x86`; AWS-LC then adds `-msse2` and emcc refuses it. Fix: a one-line `emcmake` wrapper adding `-DEMSCRIPTEN_SYSTEM_PROCESSOR=wasm32`. No source patch. | `Configure linux-generic32 no-asm no-threads no-sock ... --with-rand-seed=getrandom -DNO_SYSLOG`, 1m03s. No source patch (`rand_unix.c` already has a `__EMSCRIPTEN__` getentropy branch, DOCUMENTED). | Its documented `emcmake cmake` path; 496/496 steps, no option beyond the native build's. |
| Link | as above | as above | fails with `-sFILESYSTEM=0`: libcrypto's socket BIOs pull in `$SOCKFS`. Needs `-sFILESYSTEM=1`. |
| `.wasm` raw / gzip | 1,117,625 / 517,525 B | 2,161,403 / 880,207 B | 967,791 / 426,765 B |
| Generated JS glue | 12,808 B (web-only 11,783) | 12,857 B (web-only 12,857) | 78,886 B (web-only 76,340): MEMFS, SOCKFS, WebSocket code |
| JS functions imported | 10 | 22 | 27, including `socket`, `connect`, `sendto` |
| Called on the corpus | `environ_*` (libc init), clock, heap growth | the same plus `random_get` once and `emscripten_date_now` (DRBG `time()`) | the same as AWS-LC; the socket and file imports are never called |
| Filesystem emulation | no | no | yes (dormant) |
| Initial memory | 18.2 MB | 18.5 MB | 18.2 MB |
| Hosts at 1,179/1,179 | Node, Bun, Deno, Chromium, Firefox, WebKitGTK, workerd | the same 7 | the same 7 |

**Finding: workerd needs a second glue.** workerd presents
`process.versions.node` (22.19.0) with `import.meta.url` null. The default
`web,worker,node` glue takes its Node branch and fails at import
(`results/builds.txt`). The same `.wasm`, byte for byte, linked with
`-sENVIRONMENT=web,worker`, runs 1,179/1,179 in workerd and under
`wrangler dev`. So an Emscripten package carries two glue files and one
`.wasm`.

**Compared with Route C** (same AWS-LC, same policy, same rows):
- Emscripten needs the legacy exception-handling proposal: 152 to 160
  try/catch sites. That is outside wasm2/lime1 (section 12).
- It starts with about 18 MB of linear memory, against 1.4 MB.
- It ships 11 to 79 KB of generated JS that answers `getcwd`, `openat`,
  `fcntl`, `ioctl` and so on. The APRV workload never calls those, but
  they are part of the reviewed surface.

Emscripten solves browser and workerd for all three libraries. It is a
second, heavier way to do what Route C already does.

## 8. Route D: Component Model, WIT and jco

**Upstream state (DOCUMENTED, 2026-09-26).**
- `cargo-component` is no longer needed. Rust's `wasm32-wasip2` target and
  `wasm-component-ld` emit components directly.
- A `wasm32-wasip1` core becomes a component with `wasm-tools component new`
  (plus the WASI p1-to-p2 adapter if it imports WASI).
- wit-bindgen 0.62 generates the guest bindings.
- jco 1.35 transpiles a component to core wasm plus ES modules plus `.d.ts`.
- WASI 0.3 (P3) exists as `wasm32-wasip3` on nightly only, with async
  canonical ABI (`cm-async`).

**The interface** (`component/wit/aprv.wit`, 53 code lines). Built from
SURFACE.md's public API, not from internal types:
- **Resources:** `receipt-verifier` (`create`, `verify`, `verify-base64`),
  `jws-verifier` (`create`, `verify-transaction`,
  `verify-app-transaction`, `verify-raw`) and `endpoint` (`create`,
  `verify-receipt-json`).
- **Errors:** an `enum reason` of 13 values, and `record
  verification-error { reason, message: option<string> }` inside a
  `variant error { verification, configuration(string) }`.
- **Payloads** return as JSON strings.
- **Two worlds:** `aprv-minimal` imports only `clock-now-ms: func() -> f64`;
  `aprv-wasi` imports nothing of its own.

No pointer, length or free call reaches JS. The guest (`component/guest/`,
198 code lines, 63 of them inside `unsafe`) calls the same C ABI functions
as every other route, so the policy under test is the same one.

| Component | How it was built | Imports | Size | Hosts at 1,179/1,179 |
|---|---|---|---|---|
| `awslc-comp` (`aprv-minimal`) | wasip1 core + `wasi-none.c -DAPRV_CLOCK_TRAP` + `component new`, no adapter | `clock-now-ms` only | 1,431,359 B | Wasmtime 49 native Component Model; jco in Node, Bun, Deno, Chromium, Firefox, WebKitGTK, workerd |
| `ossl-comp` (`aprv-wasi`) | wasip1 core + `wasi-none.c -DAPRV_KEEP_WASI_RANDOM_CLOCK` + the wasmtime v49.0.1 reactor adapter | 6 WASI 0.2.12 interfaces: `io/error`, `io/streams`, `cli/stderr`, `clocks/monotonic-clock`, `clocks/wall-clock`, `random/random` | 2,974,268 B | Wasmtime native (its own WASI, nothing preopened); jco with our 41-line `js/wasi-p2-min.mjs` in Node, Bun, Deno, 3 browsers, workerd |
| `awslc-p2` (standard `wasm32-wasip2`, no stub) | rustc + aws-lc-sys with wasi-sdk's `wasi-sdk-p2.cmake` | 18 WASI 0.2.6 interfaces including `filesystem/types`, `filesystem/preopens` and `cli/*` | 1,467,212 B | Wasmtime native; jco + preview2-shim in Node; a trap-stub run shows only `wall-clock#now` is ever called |
| `awslc-p3` (`wasm32-wasip3`, nightly) | rustc 1.100 nightly + `wasi-sdk-p3.cmake` | 18 WASI 0.3.0 interfaces; needs `cm-async` | 1,504,456 B | none (see below) |

**jco output** (`results/sizes.txt`, `results/loc.txt`):
- `aprv.js` is 202,031 B for AWS-LC (4,553 code lines) and 236,337 B for
  OpenSSL; 34,016 and 40,249 B gzipped with the driver.
- The core wasm is split into 3 to 4 modules; the extra ones are 210 B to
  4.7 KB.
- It also emits `.d.ts` files.
- The glue contains `fetch` and `node:fs` only in its loader; no
  `process.env` and no WebSocket (`results/imports.txt`).
- workerd needs static wasm imports for every core module (a generated
  `modules.mjs`), because it refuses to compile wasm bytes at run time.

**Harness finding worth keeping.** JS `TextDecoder` strips a UTF-8 BOM by
default. The first jco run turned `hostile/endpoint/bom` from 21002 into 0
until the driver used `ignoreBOM: true` (`results/parity.txt` line 297). A
typed JS facade must decode with `ignoreBOM: true`, or it silently changes
what the core sees.

**P2 versus P3.**
- **What APRV needs:** synchronous calls, bytes and strings in, a result
  out. P2 components carry exactly that (TESTED, both substrates).
- **What P2 adds:** nothing APRV uses. The standard `wasm32-wasip2` build
  imports 18 interfaces (filesystem, stdin, terminal...) that a verifier
  never calls; only the wall clock is read. The hand-built `aprv-minimal`
  world avoids all of them.
- **P3 builds.** The nightly toolchain produces a valid component
  (TESTED, `results/p3.txt`).
- **P3 does not run on any host available here:**
  - jco 1.35.0 output fails to load in Node 22 (`SyntaxError` at `await
    task.enter()`), also with `--async-mode jspi`.
  - Wasmtime 49's CLI `--invoke` cannot address resource constructors.
  - wasmtime-py 49 offers no WASIp3 linker.
- **P3 costs:** a nightly compiler, the `cm-async` feature (outside
  wasm2/lime1), and no working JS path. It buys a synchronous verifier
  nothing. P3 was not run on the corpus, so its parity is UNKNOWN.

## 9. Hosts: workerd, wrangler, browsers, wazero, Wasmtime

- **workerd** 1.20260926.1, compatibility date 2026-09-26, local `serve`.
  - Runs at 1,179/1,179 (TESTED): core modules (`rust-uu`, `rust-c`,
    `awslc-c`, `ossl-c`, `awslc-w1`, `ossl-w1`), web-only Emscripten glue
    (3 libraries) and jco output (2 components).
  - None of these need a compatibility flag. The flags `nodejs_compat` and
    `enable_nodejs_wasi_module` were set only for the `node:wasi` probe
    (section 5). The harness ran `workerd serve --experimental` throughout.
    Whether the plain core-module runs need it is UNKNOWN, but `wrangler
    dev`, which does not pass it, ran all three packages.
- **`wrangler dev --local`** (4.141.0): the three AWS-LC npm packages
  installed from tarballs pass the smoke vectors (TESTED,
  `results/npm-smoke.jsonl`). Nothing was deployed. The OpenSSL and
  LibreSSL artifacts ran in workerd but not under wrangler (EXPECTED to
  behave the same).
- **Browsers.** Chromium 141, Firefox 156 and WebKitGTK 2.52.6 each ran
  every browser-capable artifact at 1,179/1,179: `rust-uu`, `rust-c`,
  `awslc-c`, `ossl-c`, the three Emscripten builds and the two jco
  components (`scripts/browser-parity.sh`, 36 corpus runs per browser).
  Safari itself was not run. WebKitGTK shares the WebKit engine and
  JavaScriptCore, but Apple's Safari builds and platform integration differ,
  so Safari is EXPECTED, not TESTED.
- **wazero** 1.12.0 and **Wasmtime** 49: every core module (Routes A and C)
  at 1,179/1,179. Wasmtime also ran the components on its native Component
  Model. wazero has no Component Model (DOCUMENTED). Emscripten output
  imports JS functions and was not run on either (NOT APPLICABLE; Emscripten
  `STANDALONE_WASM` not tried).

## 10. Randomness

**Where OpenSSL draws randomness** (`results/callsites-openssl-wasip1.txt`,
name-section stacks through `js/callsites.mjs`):
- **Every** `random_get` and DRBG `clock_time_get` comes from
  `BN_priv_rand_range_ex` / `RAND_priv_bytes_ex`, called by
  `ossl_ec_GFp_simple_field_inv` and `ossl_ec_point_blind_coordinates`.
- That is OpenSSL's side-channel blinding of EC field inversion and point
  coordinates, which it applies in ECDSA verification too.
- The first call instantiates the DRBG and seeds it through `getentropy` →
  `random_get` (once per instance). Each later generate call stamps
  `time()`: 1,214 reads over the corpus.

**Why AWS-LC draws none** (TESTED). On the `strict` host, where
`random_get` traps, AWS-LC ran all 1,179 rows with zero calls
(`awslc-w1h`, `awslc-c`). Its ECDSA verify path does not blind (EXPECTED
from the call-site evidence; AWS-LC source not audited for this). Pure Rust
(RustCrypto verify) imports no randomness at all.

**Is it security-relevant for verification?** Verification uses only
public values: the key, the signature and the message. Blinding protects
secrets, and a verify operation has none to protect (EXPECTED). The
mitigation was left on anyway, as the brief requires. Nothing was disabled
to shrink imports.

**Behavior under a broken RNG** (TESTED, all 1,179 rows, `ossl-w1h`,
`results/rng-openssl-wasip1.txt`):

| RNG mode | Same code as native | Accepted natively, rejected here | Rejected with another reason | New acceptances | Rows that called `random_get` |
|---|---|---|---|---|---|
| Failing (`random_get` answers EIO) | 1,103 | 46 | 30 | **0** | 95 |
| All zeros | 1,179 | 0 | 0 | 0 | 4 |

A failing RNG makes OpenSSL refuse ECDSA verification, so it fails closed.
A constant RNG changes no verdict, as expected for blinding. A host must
still supply real randomness, and every host here uses
`crypto.getRandomValues` in 65,536-byte chunks (`js/hosts.mjs`,
`npm/core/instantiate.js`, `js/wasi-p2-min.mjs`). `Math.random` is never
used.

**Emscripten.** `random_get` is called once per instance for OpenSSL and
not at all for AWS-LC or LibreSSL, although all three import it (TESTED,
`results/parity.txt` call counts). Emscripten's glue fills it from
`crypto.getRandomValues` (DOCUMENTED in the generated glue).

## 11. Trust isolation (TESTED)

The question: can a Wasm route reach a filesystem CA store, a host trust
store, environment-controlled roots, the network, or a config file?

- **Route C: no.** `awslc-c` and `rust-c` import one function, a clock.
  `ossl-c` imports a clock and random bytes. A module cannot reach anything
  it does not import, and workerd's call log confirms that nothing else was
  asked for.
- **Route A with the minimal host: no.** The host has no preopened
  directories and an empty environment. The previous bake-off's planted
  `SSL_CERT_FILE` / `OPENSSL_CONF` test (`$SPIKE/results/wasm-isolation.txt`)
  still describes these modules.
- **Emscripten: no by behavior; possible by shape.** The glue answers
  `openat`, `stat` and `getdents` from an empty in-memory view with
  `FILESYSTEM=0`. The LibreSSL glue carries SOCKFS/WebSocket code, which
  could open a WebSocket if libcrypto's socket BIO were ever reached. The
  policy never reaches it; not a single socket call was made. That is
  dormant capability, not use.
- **None of the glue reads environment variables:** there is no
  `process.env` in any Emscripten or jco glue (`results/imports.txt`).
- **Components.** `awslc-comp` imports only `clock-now-ms`. `ossl-comp`
  imports clocks, random and stderr; no filesystem, no sockets.
- **Standard P2 and P3 components** declare filesystem and preopens
  imports. Wasmtime ran them with nothing preopened. The imports are still
  capability requests a host must deny, so the hand-built `aprv-minimal`
  world is the capability-minimal one.

Trust therefore stays in the pinned Apple roots compiled into the core, on
every route.

## 12. Wasm features (TESTED, `results/features.txt`)

`py/features.py` validates each artifact with one proposal switched off at
a time (wasm-tools 1.259.0).

| Artifact | Needs | Validates as |
|---|---|---|
| Core modules (Routes A and C), all three backends | sign-extension, saturating float-to-int, bulk memory, reference types (the `call_indirect` overlong encoding only) | wasm2 and lime1 |
| Components and jco core modules | the same | wasm2 and lime1 |
| Emscripten builds (all three) | the same minus reference types, **plus legacy exceptions** (152, 160, 160 try/catch sites) | none of wasm1/wasm2/lime1 |
| P3 component | the same plus `cm-async` | none of wasm1/wasm2/lime1 |

No artifact needs SIMD, threads, multi-memory, memory64, GC, tail calls or
relaxed SIMD. Everything is wasm32; wasm64 is unnecessary. The legacy
exception opcodes are what Emscripten emits by default. Chromium, Firefox,
WebKitGTK, Node, Bun, Deno and workerd accepted them. The standardized
`exnref` form was not tried.

## 13. Size, memory, latency (informational only)

Performance was not a selection criterion. Numbers: `results/sizes.txt`
and `results/bench.jsonl`, 1,000 calls, one thread, a shared 4-vCPU VM.

| Artifact | `.wasm` raw | strip + gzip | JS the host loads | Node receipt µs | Node JWS µs | Init ms | Memory |
|---|---|---|---|---|---|---|---|
| `rust-uu` | 621,862 | 198,992 | 11,901 (driver, not shipped) | 3,183 | 3,310 | 3.0 | 1.2 MB |
| `awslc-c` | 1,406,386 | 555,409 (Oz 505,948) | package facade 5,762 | 1,116 | 2,574 | 5.3 | 1.4 MB |
| `ossl-c` | 2,933,868 | 971,415 (Oz 853,886) | same | 1,395 | 4,550 | 12.0 | 2.1 MB |
| `awslc-em` | 1,117,625 | 517,525 | glue 12,808 | 1,115 | 2,464 | 8.6 | 18.2 MB |
| `ossl-em` | 2,161,403 | 880,207 | glue 12,857 | 1,240 | 4,384 | 15.7 | 18.5 MB |
| `libressl-em` | 967,791 | 426,765 | glue 78,886 | 1,159 | 2,467 | 13.4 | 18.2 MB |
| `awslc-comp` (jco) | 1,422,760 core | 558,789 | `aprv.js` 202,031 | 1,238 | 2,772 | 10.5 | n/a |
| `ossl-comp` (jco) | 2,957,692 core | 975,874 | `aprv.js` 236,337 | 1,413 | 4,711 | 20.0 | n/a |
| native `.so` (reference) | rust 1,068,768; awslc 3,049,104; ossl402 8,428,112; libressl432 2,644,272 | | | | | | |

On these runs the C substrates were 2 to 3 times faster than pure Rust for
receipts (RSA), and AWS-LC was faster for JWS. Bun numbers are in the same
file. `wasm-opt -Oz` saved 20 to 27 % raw and kept parity. SHA-256 prefixes
of every artifact are in `results/sizes.txt`.

## 14. npm prototypes and the Lambda-like run (TESTED)

Three private tarballs (`npm/`, `scripts/npm-pack.sh`, `results/npm-pack.txt`),
all AWS-LC, all `"private": true`, never published:

| Package | Tarball | Layout |
|---|---|---|
| `aprv-spike-core` (Route C) | 567,366 B, 9 files | `aprv.wasm` + `instantiate.js` + `abi.js` + one entry per host (`node.js`, `browser.js`, `workerd.js`) through conditional exports + `index.d.ts` |
| `aprv-spike-emscripten` | 534,225 B, 10 files | one `aprv-em.wasm`, node+web glue and web-only glue, the same `abi.js` facade |
| `aprv-spike-component` | 603,169 B, 14 files | jco output (3 core modules, `aprv.js`, `.d.ts`), a 44-line typed facade |

Installed from the tarballs into a clean consumer, each passed the smoke
vectors on:
- Node, Bun and Deno;
- Chromium, Firefox and WebKitGTK, loading straight from `node_modules`
  without a bundler;
- `wrangler dev --local`.

That is 21 of 21 runs (`results/npm-smoke.jsonl`). The vectors are a
genuine g5 receipt against the pinned Apple roots, a JWS, and rejections.
No native addon anywhere.

**Lambda-like** (`npm/lambda/`, `results/lambda-like.jsonl`): a
handler-shaped module under `node --permission --allow-fs-read=<consumer
dir>`.

- Each package imports cold in 14 to 24 ms.
- 200 repeated and 64 concurrent invocations gave 0 mismatches, for each
  package.
- 4 parallel processes also passed.
- File writes, reads outside the package, and `child_process` were denied
  (`ERR_ACCESS_DENIED`).
- The `worker_threads` probe returned `ERR_WORKER_PATH`, which is
  inconclusive about permissions.

This shows the module needs nothing beyond reading its own `.wasm`. It is
not AWS Lambda. Real Lambda is NOT TESTED.

## 15. Code ownership (`results/loc.txt`)

Code lines (no comments or blanks), and lines inside `unsafe`:

| Piece | Code lines | Inside `unsafe` | Who needs it |
|---|---|---|---|
| Custom generic security code today: `asn1` 265, `cms` 148, `x509` 374, `chain` 82, `crypto` 200 | 1,069 | 0 | pure Rust |
| `rust/ffi` C ABI (production, unchanged) | 701 | 72 | every native and wasm artifact |
| Adapter `security-openssl` (previous bake-off) | 823 | 287 (62 sites) | every substrate build |
| Policy `substrate.rs` | 184 | 0 | every substrate build |
| Wasm shim | 37 | 7 | Routes A, B, C |
| `core-patch/clock-seam.patch` | 40 changed | 0 | every wasm build (and SURFACE.md 4.1 anyway) |
| `c/wasi-none.c` | 74 (C) | all of it is C | Route C and the components |
| Emscripten cmake wrapper | 1 | n/a | AWS-LC under Emscripten |
| WIT | 53 | n/a | Route D |
| Component guest | 198 | 63 | Route D |
| JS facade shipped: core / Emscripten / component | 100 / 91 / 44 | n/a | per package |
| Generated JS shipped: Emscripten glue / jco glue | 12.8-78.9 KB / 4,553-5,649 lines | n/a | Routes B / D |

After a switch to a substrate, `cms.rs`, `x509.rs`, `chain.rs` and
`crypto.rs` go. `asn1.rs` (265) stays for the receipt payload and the
prescan (previous bake-off section 15; EXPECTED, since the spike keeps all
modules compiled). So:
- APRV-owned generic security code drops from 1,069 to about 265 lines.
- Lines inside `unsafe` rise from 72 to 366: C ABI 72, adapter 287, shim 7.
  A component adds its guest's 63 if the guest calls the C ABI. A guest that
  calls the Rust API directly would need none (EXPECTED).
- Route C adds 74 lines of C that the repository owns.

Portability glue does not undo the saving. The Route C package adds 100
hand-written JS lines, 74 of C and 7 of `unsafe` Rust. Emscripten and jco
add generated code that nobody here writes but someone must review.

## 16. Licensing (DOCUMENTED; no legal conclusion)

| Component | License as declared | Where |
|---|---|---|
| AWS-LC via aws-lc-sys 0.41.0 | "ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND ..." | crate `Cargo.toml`, `LICENSE` |
| OpenSSL 4.0.2 | Apache-2.0 | `LICENSE.txt` |
| LibreSSL 4.3.2 | OpenSSL + SSLeay licenses (with advertising clauses) plus ISC | `COPYING` |
| Emscripten runtime and generated glue | MIT or University of Illinois/NCSA, at the user's choice | Emscripten `LICENSE` |
| jco, preview2-shim, jco-transpile | Apache-2.0 WITH LLVM-exception | their `package.json` |
| wasi-libc (linked into every wasip1 module), wasm-tools, wit-bindgen, the WASI adapter | Apache-2.0 WITH LLVM-exception, Apache-2.0 or MIT (wasi-libc also carries musl's MIT) | upstream repositories (EXPECTED from their license files; not re-read for this note) |

None of them is copyleft. The spike's packages carry a
`THIRD-PARTY-NOTICES.txt` with the AWS-LC license, plus the Emscripten
license for that package. It does not yet include Rust std's, wasi-libc's or
jco's license texts. A real package must add those, and must decide
whether jco's generated `aprv.js` carries jco's license (UNKNOWN; jco does
not state it for its output). The target library stays MIT.

## 17. Final comparison matrix

Labels: TESTED, DOCUMENTED, EXPECTED, UNKNOWN, NOT APPLICABLE (NA). "prev"
= TESTED in the previous bake-off, not rerun here. Numbers are from the
files named above.

### 17a. Semantics

The genuine Apple BER, PKCS#7/CMS, X.509/PKIX, historical-time,
pinned-trust and Apple-OID rows are all inside the 1,179-row corpora. So a
row that is the same as native carries each property that native was
TESTED for.

| Row | Builds | Full corpus | Native parity | Java parity (tallies = native) | Genuine Apple BER | PKCS#7/CMS | X.509/PKIX | Historical time | Pinned trust | Apple OIDs |
|---|---|---|---|---|---|---|---|---|---|---|
| Pure Rust (native; wasm `rust-uu`/`rust-c`) | TESTED | TESTED, 1,179 | TESTED (wasm = native) | TESTED | TESTED | TESTED (own code) | TESTED (own code) | TESTED | TESTED | TESTED |
| AWS-LC native | TESTED | TESTED | reference | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED (prev isolation) | TESTED |
| AWS-LC WASIp1 | TESTED | TESTED | TESTED 1,179 | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED |
| AWS-LC Emscripten | TESTED | TESTED | TESTED 1,179 | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED |
| AWS-LC freestanding | TESTED | TESTED | TESTED 1,179 | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED |
| AWS-LC component / jco | TESTED | TESTED | TESTED 1,179 | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED |
| OpenSSL native | TESTED | TESTED | reference | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED (prev) | TESTED |
| OpenSSL WASIp1 | TESTED | TESTED | TESTED 1,179 | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED |
| OpenSSL Emscripten | TESTED | TESTED | TESTED 1,179 | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED |
| OpenSSL freestanding | TESTED | TESTED | TESTED 1,179 | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED |
| OpenSSL component / jco | TESTED | TESTED | TESTED 1,179 | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED |
| LibreSSL native | TESTED | TESTED | reference | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED (prev) | TESTED |
| LibreSSL Emscripten | TESTED | TESTED | TESTED 1,179 | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED |

Java tallies per corpus (agree / cand=java / cand=rust / cand-own / abi;
`results/java-parity.txt`):

| Backend | cases | substrate | hostile | algorithms |
|---|---|---|---|---|
| Pure Rust | 153 0 0 0 0 | 170 0 23 0 0 | 657 0 23 0 131 | 8 0 14 0 0 |
| AWS-LC | 152 0 0 1 0 | 166 19 4 4 0 | 655 16 7 2 131 | 8 11 1 2 0 |
| OpenSSL | 153 0 0 0 0 | 167 20 3 3 0 | 655 10 12 3 131 | 8 12 1 1 0 |
| LibreSSL | 153 0 0 0 0 | 166 20 3 4 0 | 655 16 7 2 131 | 8 12 1 1 0 |

The mismatch rows themselves are the previous bake-off's, unchanged
(`$SPIKE`'s section 5). Wasm packaging added none and removed none.

### 17b. Capabilities

| Row | Host imports | Filesystem dependency | Network dependency | Secure RNG required | Clock required |
|---|---|---|---|---|---|
| Pure Rust wasm | `aprv.clock_now_ms` (TESTED) | none (TESTED) | none (TESTED) | no (TESTED) | yes, for undated inputs (TESTED) |
| AWS-LC native | libc (NA) | none: no config, no default paths (prev TESTED) | none (prev TESTED) | no on this workload (EXPECTED from wasm evidence) | yes (as Rust) |
| AWS-LC WASIp1 | 10 or 11 WASI imports, 0 called with host clock (TESTED) | imported, never called (TESTED) | none (TESTED) | no (TESTED) | yes (TESTED) |
| AWS-LC Emscripten | 10 JS functions (TESTED) | glue stubs, never called (TESTED) | none (TESTED) | no (TESTED) | yes (TESTED) |
| AWS-LC freestanding | `aprv.clock_now_ms` only (TESTED) | none (TESTED) | none (TESTED) | no (TESTED) | yes (TESTED) |
| AWS-LC component | `clock-now-ms` only (TESTED) | none (TESTED) | none (TESTED) | no (TESTED) | yes (TESTED) |
| OpenSSL native | libc (NA) | none (prev TESTED) | none (prev TESTED) | yes, EC blinding (EXPECTED from wasm evidence) | yes |
| OpenSSL WASIp1 | 17 or 18 WASI imports, 2 called (TESTED) | imported, never called (TESTED) | none (TESTED) | yes: fails closed without it (TESTED) | yes (TESTED) |
| OpenSSL Emscripten | 22 JS functions (TESTED) | glue stubs, never called (TESTED) | none (TESTED) | yes (TESTED) | yes (TESTED) |
| OpenSSL freestanding | `aprv.clock_now_ms`, `aprv.random_get` (TESTED) | none (TESTED) | none (TESTED) | yes (TESTED) | yes (TESTED) |
| OpenSSL component | 6 WASI 0.2 interfaces (TESTED) | none (TESTED) | none (TESTED) | yes (TESTED) | yes (TESTED) |
| LibreSSL native | libc (NA) | none (prev TESTED) | none (prev TESTED) | no on this workload (EXPECTED from wasm evidence) | yes |
| LibreSSL Emscripten | 27 JS functions incl. socket (TESTED) | MEMFS linked, never called (TESTED) | SOCKFS/WebSocket linked, never called (TESTED) | no: imported, never called (TESTED) | yes (TESTED) |

### 17c. Hosts

Chrome = Chromium 141 (Playwright). WebKit = WebKitGTK 2.52.6; Safari
itself is EXPECTED on every wasm row. CF local = `wrangler dev --local`.

| Row | Node | Bun | Deno | Chrome | Firefox | WebKit | workerd | CF local | wazero | Wasmtime |
|---|---|---|---|---|---|---|---|---|---|---|
| Pure Rust wasm | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | EXPECTED | TESTED | TESTED |
| AWS-LC native | NA | NA | NA | NA | NA | NA | NA | NA | NA | NA |
| AWS-LC WASIp1 | TESTED | prev | prev | EXPECTED | EXPECTED | EXPECTED | TESTED | EXPECTED | TESTED | TESTED |
| AWS-LC Emscripten | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED (web glue) | TESTED | NA | NA |
| AWS-LC freestanding | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED |
| AWS-LC component / jco | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | NA | TESTED (native CM) |
| OpenSSL native | NA | NA | NA | NA | NA | NA | NA | NA | NA | NA |
| OpenSSL WASIp1 | TESTED | prev | prev | EXPECTED | EXPECTED | EXPECTED | TESTED | EXPECTED | TESTED | TESTED |
| OpenSSL Emscripten | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED (web glue) | EXPECTED | NA | NA |
| OpenSSL freestanding | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | EXPECTED | TESTED | TESTED |
| OpenSSL component / jco | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | EXPECTED | NA | TESTED (native CM) |
| LibreSSL native | NA | NA | NA | NA | NA | NA | NA | NA | NA | NA |
| LibreSSL Emscripten | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED | TESTED (web glue) | EXPECTED | NA | NA |

### 17d. Cost

Unsafe = APRV-owned Rust lines inside `unsafe` (C ABI 72 + adapter 287 +
shim 7 + guest 63, as they apply). Custom security = generic ASN.1/CMS/
X.509/PKIX/crypto code APRV owns after a switch (EXPECTED for substrate
rows, section 15). Wasm and JS sizes are strip+gzip and raw glue bytes.

| Row | Unsafe | Custom security | Wasm | JS | npm packaging | License | Patch burden | Maintenance burden |
|---|---|---|---|---|---|---|---|---|
| Pure Rust | 72 native, 79 wasm | 1,069 | 199 KB | driver only | one `.wasm` today (TESTED in production) | MIT/Apache crates | none | own parser, path, crypto glue; RustSec |
| AWS-LC native | 359 | 265 | NA | NA | NA | ISC/Apache/MIT/BSD mix | none | library advisories + rebuild per target |
| AWS-LC WASIp1 | 366 | 265 | 556 KB | ~40-line WASI set | EXPECTED like core | same | 5 build flags, 2 link fixes (prev) | + wasi-sdk |
| AWS-LC Emscripten | 366 | 265 | 518 KB | 12.8 KB + 11.8 KB glue | TESTED | + Emscripten MIT/NCSA | 1-line cmake wrapper | + emsdk, two glues, legacy EH |
| AWS-LC freestanding | 366 + 74 C | 265 | 555 KB | 100 lines facade | TESTED | same | Route A + `wasi-none.c` | + wasi-libc internal symbol |
| AWS-LC component / jco | 422 + 74 C | 265 | 559 KB core | 202 KB jco glue | TESTED | + jco Apache-2.0-LLVM | Route C + WIT + guest | + jco, wit-bindgen, wasm-tools |
| OpenSSL native | 359 | 265 | NA | NA | NA | Apache-2.0 | none | as AWS-LC |
| OpenSSL WASIp1 | 366 | 265 | 973 KB | ~40-line WASI set | EXPECTED | Apache-2.0 | own wasi-sdk build, 2 link fixes (prev) | + wasi-sdk |
| OpenSSL Emscripten | 366 | 265 | 880 KB | 12.9 KB glue | EXPECTED | + Emscripten | a Configure line | + emsdk |
| OpenSSL freestanding | 366 + 74 C | 265 | 971 KB | 100 lines facade | EXPECTED (same package, other `.wasm`) | Apache-2.0 | Route A + `wasi-none.c` | + random import |
| OpenSSL component / jco | 422 + 74 C | 265 | 976 KB core | 236 KB jco glue + 41-line WASI shim | EXPECTED | + jco | + WASI adapter | + adapter version |
| LibreSSL native | 359 | 265 | NA | NA | NA | OpenSSL/SSLeay/ISC | none | CMake per target, no s390x (prev) |
| LibreSSL Emscripten | 366 | 265 | 427 KB | 78.9 KB glue (MEMFS, SOCKFS) | EXPECTED | same + Emscripten | `-sFILESYSTEM=1` | dormant socket/FS code to review |

## 18. Second-tier candidates (research only; none built)

Crate versions from crates.io on 2026-09-26. "WASIp1" and
"Emscripten/browser" are EXPECTED unless marked; the library-capability
columns are the previous bake-off's section 15 plus upstream documentation.

| Candidate | CMS/PKCS#7 verify | X.509/PKIX | BER indefinite | Rust integration | Native static | WASIp1 | Emscripten / browser | Component | License | Activity | Test further? |
|---|---|---|---|---|---|---|---|---|---|---|---|
| BoringSSL (`boring` 5.2.0) | no PKCS#7 signature verification (EXPECTED; rust-openssl gates `pkcs7` out) | yes | UNKNOWN | `boring` crate | yes | UNKNOWN | UNKNOWN | UNKNOWN | crate metadata Apache-2.0; upstream a mix of ISC, OpenSSL and Apache-2.0 (EXPECTED) | active | no: AWS-LC is its maintained superset for this need |
| wolfSSL (`wolfssl` 7.4.0) | yes (DOCUMENTED) | yes | UNKNOWN | thin crate | yes | UNKNOWN | UNKNOWN | UNKNOWN | crate metadata GPL-2.0-or-later; upstream GPL-3.0 or commercial (prev) | active | no: copyleft for a MIT library |
| Botan (`botan` 0.14.0) | no CMS SignedData verify (EXPECTED) | yes, path validation | UNKNOWN | FFI crate | yes | UNKNOWN | EXPECTED (Botan's build system has an Emscripten target; not checked) | UNKNOWN | BSD-2 (Rust crate MIT) | active | no: would need custom CMS code again |
| Mbed TLS (`mbedtls` 0.13.6) | limited, DER-only `pkcs7` (EXPECTED) | yes | no (would fail the Xcode receipt, EXPECTED) | crate | yes | EXPECTED (portable C) | EXPECTED | UNKNOWN | Apache-2.0 OR GPL-2.0-or-later | active | no: BER gap |
| NSS (`nss` 0.7.1, 2016) | full CMS (DOCUMENTED) | yes | yes (EXPECTED) | no maintained crate | heavy (NSPR) | UNKNOWN | UNKNOWN | UNKNOWN | MPL-2.0 | active upstream, stale crate | no: build weight, no binding |
| GnuTLS (`gnutls` 0.1.3, 2016) | `gnutls_pkcs7_verify` (DOCUMENTED) | yes | UNKNOWN | stale crate | yes (+ nettle, gmp) | UNKNOWN | UNKNOWN | UNKNOWN | LGPL-2.1+ | active upstream, stale crate | no: LGPL static-link terms |
| Bouncy Castle Rust | not published on crates.io (TESTED lookup) | UNKNOWN | UNKNOWN | none | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | MIT (BC's usual) | UNKNOWN | no: nothing to test yet |

None of them solves a problem that AWS-LC or OpenSSL leaves open here.
Browser and workerd reach, the one reason a second-tier library might have
been needed, is solved by both primary candidates.

## 19. Architectures A to E

| | A. Pure Rust (today) | B. AWS-LC everywhere | C. OpenSSL everywhere | D. Mature native + pure-Rust browser | E. Hybrid Rust (BER guard + mature pieces) |
|---|---|---|---|---|---|
| Verification implementations | 1 | 1 (TESTED on every host) | 1 (TESTED on every host) | 2 | 1 |
| Generic security code APRV owns | 1,069 lines | ~265 (prescan and payload) | ~265 | 1,069 + ~265 | 413 to 869, by hybrid (prev section 15) |
| Lines inside `unsafe` | 72 | 366 (+63 for a C-ABI component guest) | 366 | 366 + 79 | ~110 to 270 (EXPECTED) |
| C in the trusted base | none | AWS-LC | OpenSSL | AWS-LC natively only | the chosen library |
| Java-equal rows (substrate 193 / algorithms 22) | 170 / 8 | 185 / 19 | 187 / 20 | differs per platform | between A and B/C (EXPECTED) |
| Portability measured | every host (TESTED) | every host (TESTED) | every host (TESTED) | every host | EXPECTED like B/C |
| Toolchains per release | rustc | rustc, clang, cmake, libclang, wasi-sdk | rustc, perl, clang, wasi-sdk | union of A and B | as B/C |
| Security review burden | own BER/CMS/X.509/path code, fuzzed here | a mature library + 287-line adapter + 74 C lines | same, plus a host RNG import | both; every disagreement between the two is a bug to hunt | own parser + adapter |
| Release complexity | lowest | a library rebuild per target (R12) | same; openssl-src pins 3.6 natively | highest | as B/C |
| Long-term maintenance | own code forever | follow AWS-LC advisories; rust-openssl compatibility | follow OpenSSL advisories | two stacks drifting | two layers |

D is the option the owner wants to avoid, and nothing here requires it.
The previous bake-off recommended A because B and C seemed to fail on the
npm path. That reason is now gone.

## 20. Recommendations

The owner's stated priorities are ready-made security code over
hand-written, with speed not mattering. The evidence above leads to these,
each on measured grounds:

1. **Best security architecture:** one Rust policy over AWS-LC, keeping
   `asn1.rs` as the bounded prescan in front of it. It replaces 804 lines
   of hand-written CMS/X.509/path/crypto code with a maintained library. It
   agrees with Java more often than today's core. It needs no randomness
   for verification, and it imports only a clock on the web. The price is
   366 lines inside `unsafe` and a C library in the trusted base. OpenSSL
   is an equal-semantics alternative through the same adapter.
2. **Best native:** AWS-LC through the shared adapter. This is unchanged
   from the previous bake-off; OpenSSL 4.0.2 is a close second.
3. **Best browser and workerd:** the Route C core module. It imports one
   function and runs on wasm2/lime1 features. It needs no compatibility
   flag in workerd, a 100-line JS facade and 1.4 MB of memory, and passed
   on all 9 hosts. Emscripten and jco also pass but ship more generated code
   (12-79 KB and 202 KB), and Emscripten needs legacy exceptions and two
   glues.
4. **Best single security core:** AWS-LC. OpenSSL works equally well on
   every host but needs a host CSPRNG import and is twice the size. Both
   meet "one implementation"; AWS-LC meets it with the smaller capability
   set.
5. **Lowest custom security-code ownership:** B or C, about 265 generic
   lines against 1,069. The portability glue (74 C lines and a 100-line JS
   facade) is not security-protocol code.
6. **Lowest build and packaging burden:** still pure Rust (A): one
   toolchain, one `.wasm`, no C. Among substrate options, Route C with
   AWS-LC. If this is the deciding criterion, A wins, and the note should
   say so plainly.
7. **Best long-term direction:** B with Route C for every JS and Go host,
   the C ABI for native, and OpenSSL kept buildable through the same
   adapter as a tested fallback substrate. Keep the pure-Rust core in the
   repository until a production migration has passed the same corpus on
   every package; it is the known-good reference.
8. **Most future-proof Component Model direction:** keep the WIT file as
   the typed interface definition, with P2-shaped synchronous calls and the
   `aprv-minimal` world (only a clock import). Build a component from the
   same core for Wasmtime and other native-Component-Model hosts. Do not
   ship npm through jco yet, because Route C does the same job with 100
   lines (5.8 KB) of hand-written JS instead of 202 KB of generated glue. Do not target P3.

**Does the winner depend on browser support being mandatory?** Not any
more. The same AWS-LC module runs in browsers, so browser support does not
decide between A and B. What decides is whether the owner prefers C
code plus 366 `unsafe` lines (B) or 1,069 lines of own parsing and path
code with 72 `unsafe` lines (A). The owner's brief states the first
preference.

## 21. The 14 decision questions

1. **Can AWS-LC back the same APRV implementation on native, Node, Bun,
   Deno, wazero, browser and workerd?** Yes, TESTED. 1,179/1,179 rows the
   same as native AWS-LC on every one of those hosts (Route C; also
   Emscripten and jco).
2. **Can OpenSSL?** Yes, TESTED on the same hosts. It needs one extra
   import, random bytes, for EC blinding.
3. **Is WASIp1 alone sufficient with a tiny JS host instead of a full WASI
   runtime?** Yes, TESTED. A ~40-line answer set replaces `node:wasi`, and
   workerd's own `node:wasi` is a stub ("not implemented"). With AWS-LC and
   the host clock, not a single WASI call is made. Route C removes even the
   answer set.
4. **Does Emscripten solve browser and workerd cleanly for AWS-LC?** It
   solves them (TESTED, 7 hosts, no source patch, one cmake wrapper line).
   It is not the cleanest route: it needs legacy exceptions, ~18 MB of
   memory, generated POSIX-shaped glue, and a separate web-only glue for
   workerd.
5. **For OpenSSL?** Yes, TESTED on 7 hosts, with 0 source patches (a
   Configure line). It has the same caveats as AWS-LC and 22 imported JS
   functions.
6. **Does LibreSSL's official Emscripten support make it meaningfully
   better than WASIp1 showed?** It makes LibreSSL work: it builds cleanly
   and passes 1,179/1,179 on 7 hosts, where WASIp1 did not compile. It is
   not better than AWS-LC or OpenSSL. The link needs `-sFILESYSTEM=1`,
   which ships 79 KB of glue with MEMFS and SOCKFS/WebSocket code that is
   never called but must be reviewed. It also has no WASIp1 or freestanding
   form.
7. **Can AWS-LC or OpenSSL compile to freestanding core Wasm with only a
   tiny explicit import set?** Yes, TESTED. AWS-LC imports
   `aprv.clock_now_ms` only; OpenSSL imports that plus `aprv.random_get`.
   It takes a 74-line link-time C file and no library patch.
8. **Does WIT and the Component Model materially improve the ABI and
   package design?** The contract, yes: typed errors and resources, no
   pointers in JS, a declared capability list, and a native path on
   Wasmtime. The npm package, no: jco adds 202 KB of glue and a
   multi-module layout to do what a 100-line facade over the core module
   does.
9. **Can jco make a component practical in browsers and workerd today?**
   Yes, TESTED: 1,179/1,179 in Chromium, Firefox, WebKitGTK and workerd,
   and the packaged component under `wrangler dev`. Two conditions: workerd
   needs static imports for each core module, and the facade must decode
   strings with `ignoreBOM: true`.
10. **Does WASI 0.2 or 0.3 buy APRV anything over P1 or core Wasm?** No.
    APRV needs a clock and, for OpenSSL, random bytes. The standard P2
    build adds 18 interface imports that are never called except the wall
    clock (TESTED). P3 adds async machinery that a synchronous verifier
    does not use.
11. **Is P3 useful, or just newer with less runtime compatibility?** Just
    newer. It builds only on nightly, needs `cm-async`, and had no working
    runtime path here (jco 1.35.0 output fails to load; the Wasmtime CLI
    and wasmtime-py could not drive it). Its parity is UNKNOWN.
12. **Can we avoid maintaining two security implementations?** Yes, TESTED:
    one AWS-LC (or OpenSSL) implementation passed on every host in scope.
13. **If not, exactly why not?** Not applicable: it can be avoided. The
    remaining risks are outside the measured set: real Safari and iOS
    WebKit, real Lambda and Cloudflare production, and hosts without
    WebAssembly at all.
14. **If mature C-backed security could not reach browsers and workerd,
    what would be the smallest pure-Rust fallback?** It is not needed. If
    it were forced, the BER-capable envelope reader (`asn1.rs` + `cms.rs`,
    413 lines) could not be dropped, because RustCrypto `cms` rejects BER
    indefinite length (previous bake-off, TESTED). Nor could the pinned-root
    path check (`chain.rs`, 82). `x509.rs` (374) might be replaced by
    `x509-cert` for DER certificates (EXPECTED), and `crypto.rs` (200) is
    already a thin RustCrypto wrapper. So the fallback would be about 495
    to 869 lines, not the whole 1,069.

## 22. Proposed R21 (draft for the owner; `DECISIONS.md` not modified)

> **R21. One security implementation on every target.** The Rust policy
> runs over one mature C substrate, AWS-LC, through the rust-openssl
> adapter. It is packaged as (1) the C ABI for native bindings and (2) a
> `wasm32-wasip1` core module that imports only `aprv.clock_now_ms`,
> linked with a link-time WASI definition file, for Node, Bun, Deno,
> browsers, Cloudflare Workers and wazero. A WIT world with only a clock
> import is the typed interface definition, and a component from the same
> core serves native Component Model hosts. OpenSSL stays buildable through
> the same adapter as the fallback substrate. Emscripten, jco-for-npm and
> WASI 0.3 are not used. The pure-Rust core stays until the substrate
> build has passed the shared fixtures on every package. Revisit if: a
> required host cannot run wasm2/lime1 core modules; wasi-libc changes its
> import symbol scheme; AWS-LC starts drawing randomness in verification;
> or the `unsafe` surface of the adapter cannot be kept under review.

This draft rests on the minimum results the brief required:
- AWS-LC native, WASIp1, Emscripten, workerd and browsers;
- OpenSSL native, WASIp1, Emscripten, workerd and browsers;
- a real APRV component with WIT, run through jco in browsers;
- LibreSSL through Emscripten.

All of these are TESTED above. Adopting it is the owner's call.

## 23. Not tested, and where these results stop holding

- **Safari and iOS WebKit** were not run. WebKitGTK 2.52.6 on Linux stands
  in for the engine, so they are EXPECTED.
- **AWS Lambda and Cloudflare production** were not tested. Only
  `node --permission` and local `workerd` / `wrangler dev` ran; nothing was
  deployed.
- **P3 parity is UNKNOWN**, because no runtime could run the component.
- **wrangler dev ran only the AWS-LC packages.** OpenSSL and LibreSSL
  artifacts ran in plain workerd.
- **WASIp1 modules were not run in browsers or on Bun/Deno again.** Bun and
  Deno are covered by the previous bake-off's build without the seam.
  WASIp1 has the same imports as Route C plus WASI, so browsers are
  EXPECTED.
- **LibreSSL** was not retried for WASIp1 or freestanding, which would need
  a LibreSSL patch set (previous bake-off).
- **No fuzz campaign ran on wasm.** The 5,000-mutant fuzz corpus was run
  natively in the previous bake-off only. Wasm parity rests on the 1,179
  rows.
- **Only Linux x86_64 build hosts.** Every browser ran headless or under
  Xvfb on Linux. Timings come from a shared 4-vCPU VM; treat differences
  under 10 % as noise.
- **A few conclusions come from source reading, not code audits:** AWS-LC's
  lack of blinding in ECDSA verify is inferred from call sites, and the
  wasi-libc symbol scheme is read from source, not a documented interface.
- **Exact versions.** Results hold for the versions in
  `results/versions.txt`. A new wasi-sdk, Emscripten, jco or workerd
  release can change imports or glue. `scripts/imports.sh` and the parity
  runs are the regression check.
- **Harness side effects outside `$SCRATCH`:** crates in the Cargo
  registry and the Ubuntu package `webkit2gtk-driver`. The rustup targets
  `wasm32-unknown-emscripten` and `wasm32-wasip2` were added for the run
  and removed afterwards; reproducing needs them again (folder README).
- **The Java oracle is JDK 25 with BC 1.86 only**, and its rows are reused
  from the previous bake-off.
- **Data.** Every corpus is from `fixtures/` or generated from test keys.
  No production receipt was used.
