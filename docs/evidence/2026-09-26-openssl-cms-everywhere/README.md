# OpenSSL CMS everywhere (2026-09-26)

Sources for `../2026-09-26-openssl-cms-everywhere.md`. The question: does
the OpenSSL 4.0.2 CMS path hold on every route and host before R21 is
written? That path is the follow-up's `adapter-cms`, with the substrate
bake-off's `asn1.rs` prescan as the guard. The round also covers:

- the vendored build;
- the wasm32-unknown-unknown blocker;
- a fuzz campaign on the CMS path;
- the 18 rows where it still differs from Java.

This round writes nothing to production code. It reuses three earlier
folders unchanged (`$SPIKE`, `$PREV` and `$FUP`, defined below). Everything
is built with rustc 1.98.1 from `$SCRATCH`, except the fuzz binaries, which
need nightly (see `scripts/fuzz.sh`). The only OpenSSL is 4.0.2.

Placeholders:

| Name | Meaning |
|---|---|
| `$REPO` | the repository root |
| `$SCRATCH` | the scratch directory of the wasm bake-off; this round writes under `$SCRATCH/cms` |
| `$CORPORA` | the substrate bake-off's corpora |
| `$SPIKE` | `../2026-09-26-security-substrate-bakeoff` |
| `$PREV` | `../2026-09-26-wasm-architecture-bakeoff` |
| `$FUP` | `../2026-09-26-substrate-followup` |

## Files

| File | Question it answered |
|---|---|
| `scripts/env.sh` | Shared settings: rustc 1.98.1 from `$SCRATCH/rustup`, and the three earlier folders |
| `scripts/vendored.sh` | Task 1: `openssl-src` 400.0.1+4.0.2 through a copy of openssl-sys 0.9.117 with one manifest line changed, and the corpus against the `OPENSSL_DIR` build |
| `scripts/build.sh` | Task 2: builds the CMS path for every route (native, Route C, WASIp1, Emscripten, component and jco) from the earlier rounds' inputs |
| `scripts/parity.sh` | Task 2: one artifact on one host, 1,179 rows, compared with native CMS. Covers Node, Bun, Deno, wazero, Wasmtime (core and component), workerd and the three browsers, through the wasm bake-off's runners |
| `scripts/matrix.sh` | Task 2: every artifact on every host it supports (33 runs) |
| `scripts/java.sh` | Task 2: three-way Java tallies for every run, compared with native CMS |
| `scripts/npm.sh`, `npm/wasip1/instantiate.js` | Task 2: npm tarballs for the Route C and WASIp1 CMS modules, and the smoke matrix, including `wrangler dev --local` and the Lambda-like run. `instantiate.js` is the WASIp1 package's fixed WASI answer set |
| `scripts/inspect.sh` | Task 2: the imports, Wasm features and sizes of each final module |
| `scripts/unknown.sh` | Task 3: the CMS shim for `wasm32-unknown-unknown`, with its compile errors kept |
| `scripts/fuzz.sh` | Task 4: the repository's `verify-receipt` and `verify-transaction` fuzz targets over the CMS build, with OpenSSL instrumented (ASan and libFuzzer) |
| `py/matrix.py` | Task 2: `results/parity.txt` condensed to artifact x host (`results/matrix.txt`) |
| `py/fuzz_campaign.py` | Task 4: summary of the libFuzzer logs |
| `py/prescan_model.py` | Task 5: a model of three read-only pre-checks and which non-Java rows they would align |
| `results/parity.txt` | Every comparison run of the round |
| `results/matrix.txt` | Task 2: the artifact x host table (the workerd Emscripten label reads `/trap`, but that host policy does not apply to Emscripten) |
| `results/vendored.txt` | Task 1: the exact change, the Configure line and the result |
| `results/java-tallies.txt` | Task 2: the tallies for native, vendored and all 33 wasm runs |
| `results/npm-pack.txt`, `results/npm-smoke.jsonl` | Task 2: the tarballs and the 16 smoke runs |
| `results/imports.txt`, `results/sizes.txt` | Task 2: imports, features, sizes and hashes (no artifact is committed) |
| `results/unknown-unknown.txt` | Task 3: every error and its cause |
| `results/fuzz-campaign.txt` | Task 4: executions, coverage and findings |
| `results/prescan-model.txt` | Task 5: the model's result over the four corpora and the 5,000 mutants |
| `results/versions.txt` | Exact versions |

## Reproduce

These commands assume Linux x86_64, the wasm bake-off's toolchains
(`$SCRATCH/env.sh`), and the follow-up's `$SCRATCH/rustup` with rustc
1.98.1 plus these targets: wasm32-wasip1, wasm32-unknown-emscripten and
wasm32-unknown-unknown.

```sh
export REPO=... SCRATCH=... CORPORA=... PLAYWRIGHT_MODULE=... FIREFOX=... WRANGLER=... WORKERD=...
. $SCRATCH/env.sh
CE=$REPO/docs/evidence/2026-09-26-openssl-cms-everywhere
RUSTUP_HOME=$SCRATCH/rustup CARGO_HOME=$SCRATCH/cargo198 \
  rustup target add --toolchain 1.98.1 wasm32-unknown-emscripten wasm32-unknown-unknown
# native reference, then task 1
$CE/scripts/build.sh native
REF=$SCRATCH/fu/run/ossl402cmspre $CE/scripts/parity.sh native cms-native $SCRATCH/cms/art/native
$CE/scripts/vendored.sh > $SCRATCH/cms/build-vendored.log   # summary written by hand: results/vendored.txt
# task 2
for r in routec wasip1 emscripten component; do $CE/scripts/build.sh $r; done
$CE/scripts/matrix.sh
python3 $CE/py/matrix.py $CE/results/parity.txt > $CE/results/matrix.txt
$CE/scripts/java.sh > $CE/results/java-tallies.txt
$CE/scripts/npm.sh pack > $CE/results/npm-pack.txt
$CE/scripts/npm.sh smoke > $CE/results/npm-smoke.jsonl
$CE/scripts/inspect.sh imports > $CE/results/imports.txt
$CE/scripts/inspect.sh sizes > $CE/results/sizes.txt
# task 3
$CE/scripts/unknown.sh
# task 4 (needs the follow-up's $SCRATCH/inst/openssl-4.0.2-fuzz and fuzz corpus)
$CE/scripts/fuzz.sh build
$CE/scripts/fuzz.sh run verify-receipt 2700 & $CE/scripts/fuzz.sh run verify-transaction 2700 & wait
python3 $CE/py/fuzz_campaign.py $SCRATCH/cms/fuzz > $CE/results/fuzz-campaign.txt
# task 5
python3 $REPO/docs/evidence/2026-09-25-java-native-image-spike/py/run_rust.py $REPO $SCRATCH/cms/art/native \
  $CORPORA/fuzz.jsonl > $SCRATCH/cms/run/cms-native-fuzz.jsonl
python3 $CE/py/prescan_model.py $CORPORA $SCRATCH/cms/run/cms-native $SCRATCH/cms/run/cms-native
```

## What is not here

Binaries, archives, library sources, `node_modules`, fuzz corpora and
target directories all stay in `$SCRATCH/cms`. The fuzz reproducers would
have been test inputs built from test keys, but the campaigns found
nothing, so there are none.
