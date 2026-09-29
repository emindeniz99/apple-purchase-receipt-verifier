# The .NET host for aprv.wasm (2026-09-29)

Sources and results for `../2026-09-29-dotnet-host.md`. The code under test is
the product, `dotnet/`: the library over the `Wasmtime` package, and
`dotnet/tools/CorpusRun`, which drives its host layer over the shared corpora.
This folder holds the scripts that run them and the results.

The module was the round-13 stand-in (`../2026-09-29-canonical-abi-final/`,
core 0.6), not the release build.

Placeholders:

| Name | Meaning |
|---|---|
| `$REPO` | the repository root |
| `$SCRATCH` | the wasm bake-off's scratch directory. It holds ABI v1's calls files (`wasm/abi/calls`) and Node rows (`wasm/abi/run`), and the .NET SDK. This round writes under `$S`, which defaults to `$SCRATCH/dotnet-host` |
| `$CORPORA` | the substrate bake-off's request corpora (1,179 rows, plus 5,000 mutants in `fuzz.jsonl`) |

## Files

| File | What it answers |
|---|---|
| `scripts/env.sh` | Paths and package folders for the other scripts |
| `scripts/corpus.sh` | Do the five corpora (6,179 rows) through the host layer give the ABI v1 Node rows? Uses round 13's `py/calls_bytes.py` and `py/classify.py` |
| `scripts/speed.sh` | Compile, first and later instance, and calls per second at 1 and 4 threads |
| `scripts/consumer.sh`, `Consumer/` | Does `dotnet pack` give a package a clean project restores from a local feed and verifies a receipt with? |
| `results/corpus-classify.txt`, `results/corpus-rows.txt` | The corpus run: 6,176 identical, 2 `clock-moves-chain`, 1 `init-refusal`, 0 traps |
| `results/tests-summary.txt`, `results/standin-fail-ids.txt` | Test counts on .NET 8, 9 and 10, and the 221 conformance cases that fail on the stand-in, by id and group |
| `results/speed-run1.txt`, `results/speed-run2.txt` | Start-up and throughput in two runs, with the machine's load before and after each |
| `results/consumer.txt` | The nupkg's size and files, and the clean consumer's run |
| `results/format.txt` | `dotnet format --verify-no-changes --severity info` |

## Reproduce

```sh
export REPO=... SCRATCH=... CORPORA=... S=$SCRATCH/dotnet-host
DH=$REPO/docs/evidence/2026-09-29-dotnet-host
sh $DH/scripts/corpus.sh > $DH/results/corpus.txt
sh $DH/scripts/speed.sh > $DH/results/speed.txt          # on an idle machine
sh $DH/scripts/consumer.sh > $DH/results/consumer.txt
(cd $REPO/dotnet && dotnet test)                          # the suite; 221 conformance cases fail on the stand-in
```

The conformance cases that fail are the stand-in's, not the wrapper's: the
0.6 core answers reasons and payloads the 0.7 wire does not have, which the
wrapper reports as `INTERNAL_ERROR` instead of guessing. The list changes when
the release module replaces the stand-in; every case must then pass.
