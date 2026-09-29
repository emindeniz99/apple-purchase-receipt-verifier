# Canonical ABI spike (2026-09-29, round 12)

Sources for `../2026-09-29-canonical-abi-spike.md`. The spike gives
`aprv.wasm` the canonical ABI (the Component Model's) as its export ABI. It
is the same `wasm32-wasip1` core module as ABI v1, built from the same core
tree. The result is then called two ways:

- by hand, on hosts with no component support (wazero, Endive);
- through a component runtime (jco, wasmtime-py).

Nothing here touches production code. The core is ABI v1's scratch tree
(core 0.6.0) and is only read. The operation bodies are ABI v1's
(`../2026-09-26-wasm-abi-v1/shim/src/lib.rs`), copied.

Placeholders:

| Name | Meaning |
|---|---|
| `$REPO` | the repository root |
| `$SCRATCH` | the wasm bake-off's scratch directory. It holds ABI v1's inputs (`abi/tree`, `abi/art/aprv-abi1.wasm`, `abi/calls`, `abi/run`), wasi-sdk 34.0, OpenSSL 4.0.2 for wasm, the tools in `tools/bin` and a Python venv in `pyvenv`. This round writes under `$SCRATCH/r12` (`$S` in the scripts) |
| `$CORPORA` | the substrate bake-off's request corpora (1,179 rows, plus 5,000 mutants in `fuzz.jsonl`) |

## Files

| File | What it is for |
|---|---|
| `guest/wit/aprv.wit` | The interface: `aprv:verifier@1.0.0`, `verify` (the enum and four functions) and `host` (`random-get`), world `aprv` |
| `guest/Cargo.toml.in`, `guest/Cargo.lock`, `guest/src/lib.rs` | The guest: wit-bindgen 0.62.0 `generate!`, `init` state, the two C symbols `wasi-none.c` calls (`aprv_clock_now_ms` returns the call's now-ms, `aprv_random_get` calls the WIT import), and ABI v1's four operation bodies |
| `scripts/env.sh` | Shared paths and the toolchain (rustc 1.98.1) |
| `scripts/build.sh` | `v1` rebuilds ABI v1 from its tree and checks it against b14e14b2. `cabi` and `checked` build the core module (`checked` turns on debug-assertions for the guest crate only) and run `wasm-tools component new` with no adapter. It prints sizes, hashes, imports, exports and custom sections |
| `scripts/sizes.sh` | Raw, stripped and gzip sizes; code and data sections |
| `py/calls_cabi.py` | Maps ABI v1's calls files onto the new interface: function, env, init config, pinned now-ms, text (non-UTF-8 input is replaced with U+FFFD and marked `lossy`) |
| `scripts/corpus.sh` | Runs the five corpora through one host and compares with ABI v1's Node rows using ABI v1's `abi_compare.py` |
| `py/classify.py` | Puts every row that is not byte-identical into a category: `not-a-string`, `init-refusal`, `clock-moves-chain` or `DIFFERENT` |
| `py/cross_host.py` | Compares every host's rows with wazero's, row by row |
| `hosts/wazero/` | Go host, canonical ABI by hand (`main.go`, between the markers). `tests.go` has the adapted ABI tests and the misuse cases. `bench.go` times start-up and throughput against ABI v1 |
| `hosts/endive/` | Java host, canonical ABI by hand (`AprvCabi.java`, between the markers), compiled at build time by Endive 1.1.0. `RunCalls.java` is the corpus runner |
| `scripts/endive.sh` | Builds the Endive jar (offline Maven, from the round-5 cache) and prints the java command |
| `hosts/jco/run-calls.mjs` | Node host on jco's generated bindings: the corpus, and binding-level checks |
| `hosts/jco/import-key.mjs` | Checks which import key jco's glue accepts |
| `scripts/jco.sh` | Installs jco 1.35.0, transpiles, runs the checks |
| `hosts/wasmtime-py/run_calls.py` | Python host on `wasmtime.component` (wasmtime-py 49.0.0): the corpus, and the checks a component host can still make |
| `scripts/count.sh` | Hand-written host line counts |
| `scripts/versions.sh` | Tool versions |
| `results/build-v1.txt`, `results/build.txt` | The ABI v1 rebuild (identical), and the build facts for both variants |
| `results/sizes.txt` | Size table |
| `results/corpus-*.txt` | Per host: `abi_compare.py`'s summary per corpus |
| `results/classify.txt` | Categories per host and corpus, with examples. Every host is compared row by row with wazero |
| `results/tests-wazero.txt` | The adapted ABI tests and misuse cases, for both variants |
| `results/tests-jco.txt`, `results/tests-wasmtime-py.txt` | Binding-level checks |
| `results/jco-transpile.txt` | jco's generated files and sizes, the `.d.ts`, and the import-key probe |
| `results/bindgen-wasmtime-py.txt` | `python -m wasmtime.bindgen`: absent in 49.0.0, and panics in 38.0.0 |
| `results/bench-wazero.txt` | wazero start-up and throughput: ABI v1 against each variant |
| `results/count.txt`, `results/versions.txt`, `results/disk.txt` | Line counts, versions, disk before and after cleanup |

## Reproduce

Everything writes to `$SCRATCH/r12`. Run the heavy steps one at a time.

```sh
export REPO=... SCRATCH=... CORPORA=...
FE=$REPO/docs/evidence/2026-09-29-canonical-abi-spike
S=$SCRATCH/r12

# 1. Modules (the v1 step takes about 50 s; each variant takes seconds once the core is cached)
sh $FE/scripts/build.sh v1 > $FE/results/build-v1.txt
sh $FE/scripts/build.sh cabi checked > $FE/results/build.txt
sh $FE/scripts/sizes.sh > $FE/results/sizes.txt

# 2. Calls files: made on first use by corpus.sh (py/calls_cabi.py -> $S/calls)

# 3. wazero (Go >= 1.25; GOTOOLCHAIN=auto fetches it)
cp -r $FE/hosts/wazero $S/wazero && go -C $S/wazero build -o $S/aprv-wazero .
sh $FE/scripts/corpus.sh wazero -- $S/aprv-wazero calls $S/art/aprv-cabi-checked.core.wasm > $FE/results/corpus-wazero.txt
sh $FE/scripts/corpus.sh wazero-unchecked -- $S/aprv-wazero calls $S/art/aprv-cabi.core.wasm > $FE/results/corpus-wazero-unchecked.txt
{ for m in aprv-cabi.core.wasm aprv-cabi-checked.core.wasm; do
    echo "## aprv-wazero tests $m"; $S/aprv-wazero tests $S/art/$m $S/calls/cases.jsonl; echo; done; } > $FE/results/tests-wazero.txt
taskset -c 0 $S/aprv-wazero bench $SCRATCH/abi/art/aprv-abi1.wasm,$S/art/aprv-cabi-checked.core.wasm $S/calls/cases.jsonl

# 4. Endive (JDK 21)
sh $FE/scripts/endive.sh build $S/art/aprv-cabi-checked.core.wasm
sh $FE/scripts/corpus.sh endive -- $(sh $FE/scripts/endive.sh java) spike.aprv.cabi.RunCalls > $FE/results/corpus-endive.txt

# 5. jco
sh $FE/scripts/jco.sh setup
sh $FE/scripts/jco.sh transpile > $FE/results/jco-transpile.txt
node $FE/hosts/jco/import-key.mjs $S/jco/out >> $FE/results/jco-transpile.txt
sh $FE/scripts/jco.sh tests > $FE/results/tests-jco.txt
sh $FE/scripts/corpus.sh jco -- node $FE/hosts/jco/run-calls.mjs $S/jco/out calls > $FE/results/corpus-jco.txt

# 6. wasmtime-py ($SCRATCH/pyvenv: pip install wasmtime==49.0.0)
P="$SCRATCH/pyvenv/bin/python $FE/hosts/wasmtime-py/run_calls.py"
$P tests $S/art/aprv-cabi-checked.component.wasm $S/calls/cases.jsonl > $FE/results/tests-wasmtime-py.txt 2>&1
sh $FE/scripts/corpus.sh wasmtime-py -- $P calls $S/art/aprv-cabi-checked.component.wasm > $FE/results/corpus-wasmtime-py.txt

# 7. Categories, counts, versions
{ python3 $FE/py/classify.py wazero $S/calls $SCRATCH/abi/run $S/run/wazero
  for h in wazero-unchecked endive jco wasmtime-py; do
    python3 $FE/py/classify.py $h $S/calls $SCRATCH/abi/run $S/run/$h | grep -v '^  '; done
  echo; python3 $FE/py/cross_host.py $S/calls $S/run; } > $FE/results/classify.txt
sh $FE/scripts/count.sh > $FE/results/count.txt
sh $FE/scripts/versions.sh > $FE/results/versions.txt
```

In the result files, `$SCRATCH` stands for the scratch path.
