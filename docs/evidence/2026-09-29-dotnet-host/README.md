# The .NET host for aprv.wasm (2026-09-29)

Sources and results for `../2026-09-29-dotnet-host.md`. The code under test is
the product, `dotnet/`: the library over the `Wasmtime` package, and
`dotnet/tools/CorpusRun`, which drives its host layer over the shared corpora.
This folder holds the scripts that run them and the results.

The module is the release build of the 0.7 core (G1, lane/core 05b4ad9; G1b, c4410c7). It is
not committed: `scripts/g1.sh` copies it to the ignored path in the package.
The first round of this evidence ran the round-13 stand-in (the 0.6 core); its
numbers are in the git history.

Placeholders:

| Name | Meaning |
|---|---|
| `$REPO` | the repository root |
| `$SCRATCH` | a scratch directory. It holds the .NET SDK (put `dotnet` on `PATH`); this round writes under `$S`, which defaults to `$SCRATCH/dotnet-host` |
| `$G1` | a folder with `aprv.wasm`, `calls/<corpus>.pinned.jsonl` (the five corpora as call files, every unpinned clock pinned), `rows/module-<corpus>.jsonl` (the module's own answers, the reference rows) and `same.py` (byte-for-byte comparison of two row files) |

## Files

| File | What it answers |
|---|---|
| `scripts/g1.sh` | The whole re-check for a module, as one command: put the module in place and refresh its pin, run the suite on .NET 10 and 8, the Floor project, the corpora, the speed run |
| `scripts/env.sh` | Paths and package folders for the other scripts |
| `scripts/corpus.sh` | Do the five corpora (6,179 rows) through the host layer give the reference rows, byte for byte? |
| `scripts/speed.sh` | Compile, first and later instance, and calls per second at 1 and 4 threads |
| `scripts/consumer.sh`, `Consumer/` | Does `dotnet pack` give a package a clean project restores from a local feed and verifies a receipt with? |
| `results/corpus.txt` | The corpus run: 6,179 of 6,179 identical, 0 traps |
| `results/tests-summary.txt` | Test counts: 551 of 551 on .NET 8 and 10 (G1b) |
| `results/speed-run1.txt`, `speed-run2.txt`, `speed-run3.txt` | Start-up and throughput in three runs, with the machine's load before and after each |
| `results/consumer.txt` | The nupkg's size and files, and the clean consumer's run |
| `results/other-checks.txt` | Trimmed publish, fuzz, memory, package size |
| `results/format.txt` | `dotnet format --verify-no-changes --severity info` |

## Reproduce

```sh
export REPO=... SCRATCH=... G1=... S=$SCRATCH/dotnet-host
sh $REPO/docs/evidence/2026-09-29-dotnet-host/scripts/g1.sh
sh $REPO/docs/evidence/2026-09-29-dotnet-host/scripts/consumer.sh
```

`g1.sh` refreshes `dotnet/src/ApplePurchaseReceiptVerifier/wasm/aprv.wasm.sha256`;
commit that pin when the module changes. The timings are meaningful only on an
idle machine.
