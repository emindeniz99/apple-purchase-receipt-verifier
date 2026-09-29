# Wasm ABI v1 spike (2026-09-26)

Sources for `../2026-09-26-wasm-abi-v1.md`. They build a spike `aprv.wasm`
with one generic, versioned call over four operations that apply no policy.
That module then runs the repository's corpus, the mandatory ABI tests and
the round-6 benchmark on Node and on Endive.

Nothing here touches production code. `scripts/build.sh` is round 4's
template-tree recipe (OpenSSL 4.0.2, CMS path, `wasm32-wasip1`,
`wasi-none.c`), linked with this folder's `shim/` instead of `rust/ffi`.

Placeholders:

| Name | Meaning |
|---|---|
| `$REPO` | the repository root |
| `$SCRATCH` | the wasm bake-off's scratch directory; this round writes under `$SCRATCH/abi` |
| `$CORPORA` | the substrate bake-off's request corpora (1,179 rows, plus 5,000 mutants in `fuzz.jsonl`) |
| `$WASI_SDK` | wasi-sdk 34.0 |
| `$JDK17`, `$JDK21` | JDK homes (17 runs the Endive plugin; 21 runs everything) |

## Files

| File | What it is for |
|---|---|
| `shim/Cargo.toml.in`, `shim/src/lib.rs` | The ABI v1 module: `aprv_abi_version`, `aprv_alloc`/`aprv_dealloc`, `aprv_call(abi_version, operation, ptr, len) -> handle`, `aprv_result_ptr/len/free`; operations 1 to 4 and the spike-only test variants 257 to 260 |
| `scripts/env.sh` | Shared settings: the module path, round 4's native rows (the reference), rustc 1.98.1 |
| `scripts/build.sh` | Builds `$SCRATCH/abi/art/aprv-abi1.wasm` and prints its size, hash, imports and exports |
| `py/abi_calls.py` | Maps each corpus row onto an ABI v1 call and names the mapping (`direct`, `der-encoded`, `guid-dropped`, `no-call:*`) |
| `py/abi_compare.py` | Puts every ABI v1 answer into a category against the C ABI's answer for the same row, and checks that other hosts give byte-identical answers |
| `js/abi.mjs` | The JS bridge: exactly the two imports, and the full call lifecycle |
| `js/run-calls.mjs` | Runs a calls file on Node |
| `js/abi-tests.mjs` | The 33 mandatory ABI tests on Node |
| `js/base64-rule.mjs` | The `base64` group of `fixtures/cases.json` (receipt-data decoder), run through VERIFY_RECEIPT |
| `js/bench.mjs` | Node timing: 200 warm-up calls, 1,000 timed |
| `endive/pom.xml` | Endive 1.1.0 compiles the module to JVM bytecode at build time |
| `endive/src/main/java/spike/aprv/abi/AprvAbi.java` | The Java bridge (ByteArrayMemory, the same lifecycle) |
| `endive/.../AbiTests.java`, `RunCalls.java`, `Scale.java`, `Json.java` | The ABI tests, the corpus runner, thread scaling, and round 5's minimal JSON (package renamed) |
| `scripts/node.sh` | Node: calls, parity, ABI tests, base64 rule |
| `scripts/endive.sh` | `build`, `tests`, `calls` (byte identity with Node), `scale` |
| `scripts/bench.sh` | Node timing (3 runs) and Endive scaling |
| `results/node.txt` | Parity categories per corpus, the mapping counts, the ABI tests and the base64 rule, on Node |
| `results/endive-abi-tests.txt`, `results/endive-calls.txt` | The same on Endive, with the Endive rows compared with the Node rows |
| `results/bench.txt` | Timing and scaling |
| `results/aprv-call-head.txt` | The first instructions of `aprv_call` in the built module: the version test comes first |
| `results/versions.txt` | Exact versions, the module's size and hash |

## Reproduce

These commands assume round 4's inputs in `$SCRATCH`: `inst-wasm/openssl-4.0.2`
and the native rows `asn1/run/new-*.jsonl`. They also assume round 5's local
Maven repository in `$SCRATCH/endive/m2-build`, which holds the Endive
plugin; the build runs offline.

```sh
export REPO=... SCRATCH=... CORPORA=... WASI_SDK=... JDK17=... JDK21=...
AB=$REPO/docs/evidence/2026-09-26-wasm-abi-v1
sh $AB/scripts/build.sh
sh $AB/scripts/node.sh > $AB/results/node.txt
sh $AB/scripts/endive.sh build
sh $AB/scripts/endive.sh tests > $AB/results/endive-abi-tests.txt
sh $AB/scripts/endive.sh calls > $AB/results/endive-calls.txt
sh $AB/scripts/bench.sh > $AB/results/bench.txt
```

The hand-off for the server agent is `$SCRATCH/abi/READY`, which holds the
module's path, size and sha256.
