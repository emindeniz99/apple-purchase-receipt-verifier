# Canonical ABI, final check (2026-09-29, round 13)

Sources for `../2026-09-29-canonical-abi-final.md`. This is round 12's
spike (`../2026-09-29-canonical-abi-spike/`, commit 10fc088) with the
owner's interface changes:

- the four inputs are `list<u8>`;
- `env` is a `u32`;
- the two internal exports stay.

The module is run through six runtimes:

- three hand-rolled hosts: wazero, Endive and WasmKit;
- jco on Node, Deno and Bun;
- wasmtime-py's typed component API;
- Rust Wasmtime 49 with `bindgen!`, including the runtime-only precompiled-component path that aprv-server would use.

Nothing here touches production code. The core is ABI v1's scratch tree
(core 0.6.0). It is only read; round 12 rebuilt it byte for byte.

Placeholders:

| Name | Meaning |
|---|---|
| `$REPO` | the repository root |
| `$SCRATCH` | the wasm bake-off's scratch directory. It holds ABI v1's inputs (`abi/tree`, `abi/art/aprv-abi1.wasm`, `abi/calls`, `abi/run`), wasi-sdk 34.0, OpenSSL 4.0.2 for wasm, the tools in `tools/bin`, a Python venv in `pyvenv` (wasmtime 49.0.0), round 7's Swift toolchain in `sw7/tc` and round 10's cargo home in `r10/cargo-home`. This round writes under `$SCRATCH/r13` (`$S` in the scripts) |
| `$CORPORA` | the substrate bake-off's request corpora (1,179 rows, plus 5,000 mutants in `fuzz.jsonl`) |
| `$DENO`, `$BUN`, `$SWIFT_TC` | a Deno binary, a Bun binary, and a Swift 6.3.x toolchain directory |

## Files

| File | What it is for |
|---|---|
| `guest/wit/aprv.wit` | The interface: inputs `list<u8>`, `env: u32`, outputs `string`; `host.random-get` |
| `guest/Cargo.toml.in`, `guest/Cargo.lock`, `guest/src/lib.rs` | Round 12's guest. The four bodies take bytes (ABI v1's bodies, unchanged), and `env` other than 0 or 1 traps |
| `scripts/env.sh`, `scripts/build.sh`, `scripts/sizes.sh` | Paths; builds the core module and the component, with no adapter; sizes against ABI v1 |
| `py/calls_bytes.py` | Maps ABI v1's calls onto the interface. Inputs pass as base64 bytes, unchanged |
| `scripts/corpus.sh`, `py/classify.py`, `py/cross_host.py` | Corpus through one host, compared with ABI v1's Node rows. `classify.py` checks the expectation (6,176 identical, 2 `clock-moves-chain`, 1 `init-refusal`). `cross_host.py` compares every host with wazero, row by row |
| `hosts/wazero/` | Go, by hand: `main.go`, whose marked region holds the signature table, `lower` and `Call`. `tests.go` has the ABI tests and misuse cases. `bench.go` has start-up and throughput against ABI v1 |
| `hosts/endive/` | Java, by hand (Endive 1.1.0, build-time compiled): `AprvCabi.java`, `Tests.java`, `RunCalls.java`. `StartBench.java` compiles ABI v1 into the same jar as `V1Module`, for start-up |
| `hosts/wasmkit/` | Swift, by hand (WasmKit 0.4.0): `Cabi.swift` (the marked region), `Tests.swift`, `Startup.swift` (with ABI v1's lifecycle) and `main.swift` |
| `hosts/jco/run-calls.mjs`, `hosts/jco/startup.mjs` | jco's generated glue, which runs unchanged on Node, Deno and Bun. `startup.mjs` runs ABI v1 through ABI v1's own `js/abi.mjs` |
| `hosts/wasmtime-py/run_calls.py`, `bytes_cost.py` | wasmtime-py's run-time-typed component API, and the per-byte cost of its `list<u8>` lowering |
| `hosts/wasmtime-rs/` | Rust, Wasmtime 49.0.1, `bindgen!` from `wit/aprv.wit` (a copy of the guest's). There are three builds (see its `Cargo.toml`), `precompile`, and start-up with embedded precompiled files |
| `scripts/endive.sh`, `scripts/wasmkit.sh`, `scripts/jco.sh`, `scripts/wasmtime-rs.sh` | Build, tests and start-up per host |
| `scripts/count.sh`, `scripts/versions.sh`, `py/startup_median.py` | Line counts, tool versions, start-up medians |
| `results/build.txt`, `results/sizes.txt`, `results/calls.txt` | Module facts, sizes, and the calls mapping |
| `results/corpus-*.txt`, `results/classify.txt` | Parity per host and corpus, and all hosts against each other |
| `results/tests-*.txt` | ABI tests and misuse cases per host |
| `results/bench-wazero.txt`, `results/startup-*.txt`, `results/startup-summary.txt` | Timing, and medians with deltas against ABI v1 |
| `results/count.txt` | Hand-written and generated line counts |
| `results/jco-transpile.txt` | jco's generated files, typings and import key |
| `results/wasmtime-py-bytes.txt` | wasmtime-py's cost per input byte |
| `results/wasmtime-rs-*.txt` | Rust host: builds, precompiled files, the feature-set matrix, binary sizes, the `bindgen!` output size |
| `results/endive-build.txt`, `results/wasmkit-build.txt`, `results/versions.txt`, `results/disk.txt` | Builds, versions, disk |

## Reproduce

Everything writes to `$SCRATCH/r13`. Run the heavy builds one at a time; the Rust full build takes about 6.5 minutes.

```sh
export REPO=... SCRATCH=... CORPORA=... DENO=... BUN=... SWIFT_TC=$SCRATCH/sw7/tc
FE=$REPO/docs/evidence/2026-09-29-canonical-abi-final
S=$SCRATCH/r13

# 1. Module and sizes
sh $FE/scripts/build.sh > $FE/results/build.txt
sh $FE/scripts/sizes.sh > $FE/results/sizes.txt

# 2. wazero (Go >= 1.25; GOTOOLCHAIN=auto fetches it)
cp -r $FE/hosts/wazero $S/wazero && go -C $S/wazero build -o $S/aprv-wazero .
sh $FE/scripts/corpus.sh wazero -- $S/aprv-wazero calls $S/art/aprv-cabi.core.wasm > $FE/results/corpus-wazero.txt
$S/aprv-wazero tests $S/art/aprv-cabi.core.wasm $S/calls/cases.jsonl > $FE/results/tests-wazero.txt
taskset -c 0 $S/aprv-wazero bench $SCRATCH/abi/art/aprv-abi1.wasm,$S/art/aprv-cabi.core.wasm $S/calls/cases.jsonl > $FE/results/bench-wazero.txt

# 3. Endive (JDK 21)
sh $FE/scripts/endive.sh build > $FE/results/endive-build.txt
sh $FE/scripts/endive.sh tests > $FE/results/tests-endive.txt
sh $FE/scripts/corpus.sh endive -- $(sh $FE/scripts/endive.sh java) spike.aprv.cabi.RunCalls > $FE/results/corpus-endive.txt
sh $FE/scripts/endive.sh startup 7 > $FE/results/startup-endive.txt

# 4. WasmKit
sh $FE/scripts/wasmkit.sh build > $FE/results/wasmkit-build.txt
sh $FE/scripts/wasmkit.sh tests > $FE/results/tests-wasmkit.txt
sh $FE/scripts/corpus.sh wasmkit -- $(sh $FE/scripts/wasmkit.sh cmd) > $FE/results/corpus-wasmkit.txt
sh $FE/scripts/wasmkit.sh startup 7 > $FE/results/startup-wasmkit.txt

# 5. jco on Node, Deno, Bun
sh $FE/scripts/jco.sh setup && sh $FE/scripts/jco.sh transpile > $FE/results/jco-transpile.txt
for r in node deno bun; do
  sh $FE/scripts/jco.sh tests $r
  sh $FE/scripts/corpus.sh jco-$r -- $(sh $FE/scripts/jco.sh cmd $r) > $FE/results/corpus-jco-$r.txt
  sh $FE/scripts/jco.sh startup $r 7 > $FE/results/startup-jco-$r.txt
done > $FE/results/tests-jco.txt

# 6. wasmtime-py
P="$SCRATCH/pyvenv/bin/python $FE/hosts/wasmtime-py/run_calls.py"
$P tests $S/art/aprv-cabi.component.wasm $S/calls/cases.jsonl > $FE/results/tests-wasmtime-py.txt 2>&1
sh $FE/scripts/corpus.sh wasmtime-py -- $P calls $S/art/aprv-cabi.component.wasm > $FE/results/corpus-wasmtime-py.txt
taskset -c 0 $SCRATCH/pyvenv/bin/python $FE/hosts/wasmtime-py/bytes_cost.py $S/art/aprv-cabi.component.wasm > $FE/results/wasmtime-py-bytes.txt

# 7. Rust Wasmtime 49
sh $FE/scripts/wasmtime-rs.sh full > $FE/results/wasmtime-rs-build.txt
$S/wt/aprv-wt-full tests $S/art/aprv-cabi.component.wasm $S/calls/cases.jsonl > $FE/results/tests-wasmtime-rs.txt
sh $FE/scripts/corpus.sh wasmtime-rs -- $S/wt/aprv-wt-full calls $S/art/aprv-cabi.component.wasm > $FE/results/corpus-wasmtime-rs.txt
sh $FE/scripts/wasmtime-rs.sh precompile > $FE/results/wasmtime-rs-precompile.txt
sh $FE/scripts/wasmtime-rs.sh runtime >> $FE/results/wasmtime-rs-build.txt
sh $FE/scripts/wasmtime-rs.sh engines >> $FE/results/wasmtime-rs-build.txt
sh $FE/scripts/wasmtime-rs.sh bindgen > $FE/results/wasmtime-rs-bindgen.txt
sh $FE/scripts/wasmtime-rs.sh sizes > $FE/results/wasmtime-rs-sizes.txt
sh $FE/scripts/wasmtime-rs.sh startup 7 > $FE/results/startup-wasmtime-rs.txt
# results/wasmtime-rs-features.txt: the `startup` commands it lists, one run each

# 8. Categories, medians, counts, versions
{ python3 $FE/py/classify.py wazero $S/calls $SCRATCH/abi/run $S/run/wazero
  for h in endive wasmkit jco-node jco-deno jco-bun wasmtime-py wasmtime-rs; do
    python3 $FE/py/classify.py $h $S/calls $SCRATCH/abi/run $S/run/$h | grep -v '^  '; done
  python3 $FE/py/cross_host.py $S/calls $S/run wazero endive wasmkit jco-node jco-deno jco-bun wasmtime-py wasmtime-rs
} > $FE/results/classify.txt
python3 $FE/py/startup_median.py $FE/results/startup-*.txt > $FE/results/startup-summary.txt
sh $FE/scripts/count.sh > $FE/results/count.txt
sh $FE/scripts/versions.sh > $FE/results/versions.txt
```

In the result files, `$SCRATCH` stands for the scratch path.
