# Substrate follow-up (2026-09-26)

Sources for `../2026-09-26-substrate-followup.md`. The note answers five
follow-up questions to the two bake-offs of the same day:

1. Do the OpenSSL (and LibreSSL) npm packages and the WASIp1 modules in
   browsers pass, as the AWS-LC ones did?
2. Does anything change with today's newest toolchain and libraries?
3. Which of the Java gaps does OpenSSL's CMS API close?
4. Did any input ever crash the native process, and does a real fuzz
   campaign find anything?
5. The answers, one line each.

Nothing here changes production code. The core is copied to `$SCRATCH` and
patched there.

This folder reuses two earlier folders unchanged, and edits neither:
- `../2026-09-26-security-substrate-bakeoff/` (`$SPIKE`): its adapter, the
  policy, the corpora and Java oracle rows, `py/tri.py`, `py/same.py`, and
  `build-variant.sh`;
- `../2026-09-26-wasm-architecture-bakeoff/` (`$PREV`): its wasm artifacts,
  npm facades, JS runners, browser page and build scripts.

Placeholders:
- `$REPO`: the repository root.
- `$SCRATCH`: the same scratch directory as the wasm bake-off; this round
  writes under `$SCRATCH/fu`.
- `$CORPORA`: the substrate bake-off's corpora.

## Files

| File | Question it answered |
|---|---|
| `scripts/npm-pack.sh` | 1a: packs `aprv-spike-core-openssl`, `-emscripten-openssl`, `-emscripten-libressl` and `-component-openssl` from the wasm bake-off's facades and artifacts (all `"private": true`) |
| `scripts/npm-smoke.sh` | 1a: installs those tarballs into clean consumers and runs the wasm bake-off's smoke matrix: Node, Bun, Deno, Chromium, Firefox, WebKitGTK, the Lambda-like run and `wrangler dev --local` |
| `npm/component-wasi/facade.js`, `workerd.js` | 1a: the component facade for a component that imports WASI 0.2 (OpenSSL); it passes `wasi-p2-min.mjs` as imports. workerd needs four static core-module imports |
| `scripts/parity.sh`, `scripts/browser-parity.sh` | 1b and 2: one artifact on one runtime or browser, 1,179 rows, against a reference row set. These run the wasm bake-off's runners unchanged and write only to this folder |
| `scripts/rust198.sh` | 2: native and Route C rebuilds for OpenSSL and AWS-LC with rustc 1.98.1 (installed under `$SCRATCH`), compared with the rustc 1.94.1 builds |
| `scripts/build-libs.sh` | 2 and 4: OpenSSL 4.1.0-beta1 (pinned hash), and OpenSSL 4.0.2 with ASan plus libFuzzer coverage |
| `scripts/newest.sh` | 2: OpenSSL 4.1.0-beta1 under the unchanged adapter; aws-lc-sys 0.45.0 (AWS-LC 5.7.0) through a copy of openssl-sys 0.9.117 whose only change is its `aws-lc-sys` requirement |
| `adapter-cms/adapter-cms.patch`, `adapter-cms/cms_path.rs` | 3: the adapter's `cms` feature: `SignedData` on OpenSSL's CMS API (`CMS_SignerInfo_verify`, `CMS_SignerInfo_verify_content`, `CMS_SignerInfo_cert_cmp`), same API, same policy |
| `scripts/build-cms.sh` | 3: builds the C ABI with the `cms` feature (`PRESCAN=1` adds `substrate-prescan`) |
| `scripts/cms-tri.sh` | 3: four corpora, three-way against Java and Rust, and row by row against the PKCS7-path build |
| `c/cms-probe.c` | 3: why a library's `CMS_SignerInfo_verify` refuses a SignerInfo (LibreSSL's ECDSA refusals) |
| `py/fuzz_summary.py` | 3: summary of `tri-*-fuzz.txt`: totals, and the rows accepted where Java and Rust both reject |
| `scripts/fuzz.sh` | 4: seeds from the corpora, instrumented builds of the repository's own `rust/fuzz` targets `verify-receipt` and `verify-transaction` over the substrate core (OpenSSL 4.0.2 and AWS-LC 1.73.0), and one campaign per target |
| `results/parity.txt` | 1b and 2: every comparison run, append-only |
| `results/npm-pack.txt`, `results/npm-smoke.jsonl` | 1a: tarball contents and hashes; 32 smoke runs |
| `results/sizes.txt` | sizes and sha256 of every built artifact this round compared (none committed) |
| `results/java-tallies.txt` | 3 and 2: three-way tallies for PKCS7 and CMS paths and the newest libraries |
| `results/tri-<variant>-<corpus>.txt` | 3: the row lists behind the tallies (`--list`) |
| `results/cms-vs-pkcs7-<variant>.txt` | 3: rows whose verdict changed between the PKCS7 and CMS paths |
| `results/fuzz-cms.txt`, `results/tri-*-fuzz.txt` | 3: the 5,000-mutant smoke corpus through PKCS7, CMS and CMS+prescan |
| `results/cms-probe.txt` | 3: `CMS_SignerInfo_verify` on each `algorithms` receipt, OpenSSL and LibreSSL |
| `results/fuzz-campaign.txt` | 4: the four campaigns' final statistics and findings |
| `results/versions.txt` | exact versions and hashes |

## Reproduce

Linux x86_64 with the wasm bake-off's prerequisites (its README). This
round adds:
- clang 18's compiler-rt (`apt-get install libclang-rt-18-dev`), for the
  AWS-LC fuzz build;
- rustc 1.98.1 and the wasm bake-off's nightly, both under
  `$SCRATCH/rustup`;
- cargo-fuzz 0.13.2 under `$SCRATCH/cargo198`.

```sh
export REPO=... SCRATCH=... CORPORA=... PLAYWRIGHT_MODULE=... FIREFOX=... WRANGLER=...
FU=$REPO/docs/evidence/2026-09-26-substrate-followup
PREV=$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff
SPIKE=$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff
. $SCRATCH/env.sh                                   # the wasm bake-off's toolchains
# 1a  npm prototypes (OpenSSL, LibreSSL); ossl-em's node+web glue first
RUSTLIB=$SCRATCH/art/ossl-em.a $PREV/scripts/build-emscripten.sh link ossl-em
$FU/scripts/npm-pack.sh > $FU/results/npm-pack.txt
$FU/scripts/npm-smoke.sh > $FU/results/npm-smoke.jsonl
$FU/scripts/parity.sh ossl-em-nodeglue ossl402 node emscripten $SCRATCH/em/ossl-em/aprv-em.mjs
# 1b  WASIp1 modules in browsers
for br in chromium firefox webkit; do
  $FU/scripts/browser-parity.sh awslc-w1 $br awslc $SCRATCH/art 'kind=core&mod=awslc-w1.wasm&policy=trap'
  $FU/scripts/browser-parity.sh ossl-w1 $br ossl402 $SCRATCH/art 'kind=core&mod=ossl-w1.wasm&policy=trap'
done
# 2   newest toolchain and libraries
RUSTUP_HOME=$SCRATCH/rustup CARGO_HOME=$SCRATCH/cargo198 rustup toolchain install 1.98.1 --profile minimal --target wasm32-wasip1
$FU/scripts/rust198.sh build && $FU/scripts/rust198.sh run
$FU/scripts/build-libs.sh openssl-4.1.0-beta1 && $FU/scripts/newest.sh ossl410b1
$FU/scripts/newest.sh awslc045
# 3   CMS API
OPENSSL_DIR=$SCRATCH/inst/openssl-4.0.2 OPENSSL_STATIC=1 $FU/scripts/build-cms.sh ossl402cms
$FU/scripts/cms-tri.sh ossl402cms ossl402
PRESCAN=1 OPENSSL_DIR=$SCRATCH/inst/openssl-4.0.2 OPENSSL_STATIC=1 $FU/scripts/build-cms.sh ossl402cmspre
$FU/scripts/cms-tri.sh ossl402cmspre ossl402cms
OPENSSL_DIR=$SCRATCH/inst/libressl-4.3.2 OPENSSL_STATIC=1 $FU/scripts/build-cms.sh libressl432cms
$FU/scripts/cms-tri.sh libressl432cms libressl432
# 4   fuzzing (cargo install cargo-fuzz --locked into $SCRATCH/cargo198 first)
$FU/scripts/build-libs.sh openssl-fuzz
$FU/scripts/fuzz.sh seeds
$FU/scripts/fuzz.sh build ossl openssl && $FU/scripts/fuzz.sh build awslc awslc
for n in ossl awslc; do for t in verify-receipt verify-transaction; do
  $FU/scripts/fuzz.sh run $n $t 2700 &
done; done; wait
```

The fuzz-corpus comparison (`results/fuzz-cms.txt`) runs
`$REPO/docs/evidence/2026-09-25-java-native-image-spike/py/run_rust.py`
over `$CORPORA/fuzz.jsonl` for `rust`, `ossl402`, `ossl402cms` and
`ossl402cmspre`, then `$SPIKE/py/tri.py --list` and `py/fuzz_summary.py`.

No binaries, archives, library sources, `node_modules`, fuzz corpora or
target directories are kept here. Fuzz corpora and crash artifacts stay in
`$SCRATCH/fu/fuzz`. A reproducer, if one existed, would be quoted in the
note as a test input built from test keys, never a production receipt.
