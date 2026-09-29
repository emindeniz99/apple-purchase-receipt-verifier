# WebAssembly architecture bake-off (2026-09-26)

Sources for `../2026-09-26-wasm-architecture-bakeoff.md`. The question: can
ONE Rust APRV policy over ONE mature C substrate (AWS-LC or OpenSSL; LibreSSL
where its own Emscripten path allows) run unchanged on native, Node, Bun,
Deno, browsers, Cloudflare workerd, wazero and Wasmtime, through different
Wasm build routes? Nothing here changes production code: the core is copied
to `$SCRATCH`, patched there and built there.

It reuses the previous bake-off (`../2026-09-26-security-substrate-bakeoff/`)
unchanged: its rust-openssl adapter (`security-openssl/`), its policy
(`core-patch/substrate.rs`, `core.patch`), its request corpora and Java
oracle rows, `py/tri.py`, `py/same.py`, and its native and WASI build
scripts.

Placeholders: `$REPO` is the repository root, `$SCRATCH` a scratch directory
outside it, `$EV` this folder, `$SPIKE` the previous bake-off's folder,
`$CORPORA` the previous bake-off's corpora (`cases`, `hostile`, `algorithms`,
`substrate` and the `jvm25-*` Java rows).

## Artifact names

| Name | Route | What it is |
|---|---|---|
| `rust`, `ossl402`, `libressl432`, `awslc` | native | The previous bake-off's C ABI `.so` variants, rebuilt (tallies identical) |
| `rust-uu-noseam`, `rust-uu` | core wasm | pure Rust, `wasm32-unknown-unknown`, without and with the clock seam |
| `rust-w1`, `ossl-w1`, `awslc-w1` | A | `wasm32-wasip1` with the clock seam, Rust "now" through WASI |
| `*-w1h` | A | same, Rust "now" through the `aprv.clock_now_ms` import |
| `rust-c`, `awslc-c`, `ossl-c` | C | `*-w1h` plus `c/wasi-none.c` at link time: no WASI import left |
| `awslc-em`, `ossl-em`, `libressl-em` (`*-web`) | B | Emscripten 6.0.10; `-web` = the same `.wasm` with web-only glue |
| `awslc-comp` (`awslc-min`) | D | WIT component, world `aprv-minimal`: imports only `clock-now-ms` |
| `ossl-comp` (`ossl-wasi`) | D | WIT component through the WASI 0.2 reactor adapter |
| `awslc-p2`, `awslc-p3` | D | the standard `wasm32-wasip2` / `wasm32-wasip3` builds of the same guest |

## Files

| File | Question it answered |
|---|---|
| `core-patch/clock-seam.patch` | SURFACE.md 4.1's clock seam in a scratch core: are the 58 `wasm32-unknown-unknown` traps only the missing seam? Can a module avoid WASI clock imports? |
| `shim/` | The previous shim (unchanged C ABI + `aprv_alloc`/`aprv_dealloc`) plus `aprv_init`, which installs the host clock. Built as cdylib or, for Emscripten, staticlib. |
| `c/wasi-none.c` | Route C: defines every WASI p1 function wasi-libc imports, so the module imports none; clock and (OpenSSL) random become `aprv.*` imports. |
| `cmake/emcmake-wasm32.sh` | Route B: the one build shim AWS-LC needed under Emscripten (`-DEMSCRIPTEN_SYSTEM_PROCESSOR=wasm32`). |
| `component/wit/aprv.wit` | Route D: a small real APRV API in WIT (resources, typed errors), worlds `aprv-minimal` and `aprv-wasi`. |
| `component/guest/` | Route D: wit-bindgen 0.62 guest; each method calls one C ABI function. |
| `scripts/fetch-tools.sh` | Downloads and checks every toolchain (sha256), writes `$SCRATCH/env.sh`. |
| `scripts/native-baseline.sh` | Rebuilds the native variants and runs the four corpora (reference rows for every wasm run). |
| `scripts/build-core.sh` | Builds the shim or guest for one target over a patched scratch core; options `CLOCK_SEAM`, `HOST_CLOCK`, `STUB_WASI`, `SHIM`, `CRATE_FEATURES`. |
| `scripts/build-wasip1.sh`, `build-emscripten.sh`, `build-wasip2.sh`, `build-wasip3.sh` | Per-route builds, with the exact flags. |
| `scripts/run-parity.sh` | One artifact, one runtime (Node, Bun, Deno, wazero, Wasmtime), 1,179 rows, compared row by row with the native build of the same backend (`$SPIKE/py/same.py`). Appends to `results/parity.txt`. |
| `scripts/workerd-parity.sh`, `workerd/` | The same in workerd (local), for core modules, Emscripten and jco output; probes workerd's built-in `node:wasi`. |
| `scripts/browser-parity.sh`, `browser/` | The same in Chromium (Playwright), Firefox (stock release, headless) and WebKitGTK MiniBrowser (Xvfb). |
| `js/driver.mjs`, `js/hosts.mjs`, `js/run.mjs` | The runner: pure-ES C ABI driver shared by every JS host; the minimal import object (policies `enosys`, `trap`, `strict`); CLI. |
| `js/emscripten-host.mjs`, `js/jco-driver.mjs`, `js/run-jco.mjs`, `js/wasi-p2-min.mjs` | Emscripten instantiation with import counting; typed WIT runner; a 41-line WASI 0.2 host for the OpenSSL component. |
| `js/callsites.mjs` | Which wasm functions call a given import (name-section stacks). |
| `wazero/` | The previous wazero runner, extended with the `aprv` host module and WASI only on demand. |
| `py/run_wasmtime.py`, `py/run_wasmtime_component.py` | Wasmtime 49 runners: core modules, and components on Wasmtime's native Component Model. |
| `py/clock_traps.py` | Trap rows versus clock-reading rows. |
| `py/rng_summary.py` | OpenSSL with a failing and an all-zero RNG. |
| `py/features.py` | Which Wasm proposals each artifact needs (leave-one-out validation). |
| `py/parity_matrix.py` | `results/parity.txt` condensed per artifact and host. |
| `py/loc_other.py`, `scripts/loc.sh` | Line, `unsafe` and glue counts (Rust through `$SPIKE/py/loc.py`). |
| `scripts/imports.sh`, `scripts/sizes.sh`, `scripts/bench.sh` | Import lists, sizes and hashes, informational latency. |
| `scripts/java-parity.sh` | Three-way Java tallies (`$SPIKE/py/tri.py`) for every wasm run, checked against the native build of the same backend. |
| `npm/` | Three package prototypes (core module, Emscripten, component), their smoke tests (Node/Bun/Deno, browsers, `wrangler dev`) and a Lambda-like run under Node's permission model. `scripts/npm-pack.sh` packs them; all are `"private": true`. |
| `scripts/all.sh` | The whole run in order. |
| `results/` | `parity.txt` (every run), `parity-summary.txt`, `clock-traps.txt`, `imports.txt`, `callsites-*.txt`, `rng-openssl-wasip1.txt`, `features.txt`, `sizes.txt`, `bench.jsonl`, `loc.txt`, `java-parity.txt`, `builds.txt`, `p3.txt`, `npm-pack.txt`, `npm-smoke.jsonl`, `lambda-like.jsonl`, `versions.txt`. |

`results/parity.txt` is append-only. It keeps six failed runs, each followed
by a `# NOTE` line: four were harness bugs (fixed, then rerun), two are
findings (Emscripten's node+web glue in workerd; the P3 component under
jco).
`py/parity_matrix.py` counts the last run per corpus.

## Reproduce

Linux x86_64, 4 vCPUs, the previous bake-off's prerequisites (rustc 1.94.1,
clang, cmake, ninja, perl, Python 3, Node 22, Bun, Deno, Go), plus
`rustup target add wasm32-unknown-emscripten wasm32-wasip2`, Playwright's
Chromium, `apt-get install webkit2gtk-driver` and `xvfb-run`.

```sh
export REPO=... SCRATCH=... CORPORA=<previous bake-off's $SCRATCH/corpora>
export PLAYWRIGHT_MODULE=<path to playwright/index.mjs>
EV=$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff
$EV/scripts/fetch-tools.sh && . $SCRATCH/env.sh
$EV/scripts/all.sh
python3 $EV/py/parity_matrix.py $EV/results/parity.txt > $EV/results/parity-summary.txt
python3 $EV/py/features.py <artifacts> > $EV/results/features.txt
```

The `wrangler dev` consumer (`$SCRATCH/consumers/worker`) is a directory
with `npm install $SCRATCH/npm-dist/*.tgz`, `wrangler.toml`
(`compatibility_date = "2026-09-26"`), and `src/<core|emscripten|component>.js`
of the form `import * as pkg from 'aprv-spike-<name>'; ... smoke(pkg, vectors)`
(`npm/smoke.mjs`, `vectors.mjs` from `npm/make-vectors.mjs`).

Pinned downloads and their hashes are in `scripts/fetch-tools.sh` and
`results/versions.txt`. No binaries, archives, toolchains, library sources,
`node_modules` or target directories are kept here; sizes and hashes of the
built artifacts are in `results/sizes.txt` and `results/npm-pack.txt`.
