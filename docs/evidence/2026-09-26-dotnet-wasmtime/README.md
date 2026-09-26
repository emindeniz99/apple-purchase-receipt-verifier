# aprv.wasm on .NET with wasmtime-dotnet (2026-09-26)

Sources for `../2026-09-26-dotnet-wasmtime.md`. The ABI v1 module from
`../2026-09-26-wasm-abi-v1/` runs here on the official Bytecode Alliance
`Wasmtime` NuGet package (48.0.2), through a minimal facade library. The
library is packed to a local feed and restored by a clean consumer project.

Placeholders:

| Name | Meaning |
|---|---|
| `$REPO` | the repository root |
| `$SCRATCH` | the wasm bake-off's scratch directory; this round writes under `$SCRATCH/dn7` (NuGet's package folders included) and reads the ABI v1 module and calls files from `$SCRATCH/abi` |
| `$CORPORA` | the substrate bake-off's request corpora |
| `$DOTNET_ROOT` | a .NET 10 SDK (plus the .NET 8 runtime for the net8.0 run) installed into scratch with `dotnet-install.sh --channel 10.0` and `--runtime dotnet --channel 8.0` |

## Files

| File | What it is for |
|---|---|
| `AprvWasm/AprvWasm.csproj`, `AprvWasm/AprvWasm.cs` | The facade library `Aprv.Wasm.Spike` (netstandard2.0 and net8.0): `AprvRuntime`, `AprvInstance`, `Verifier`; `aprv.wasm` embedded |
| `Tool/Program.cs`, `Tool/AbiTests.cs` | The harness (net10.0 and net8.0): `tests` (33 ABI tests plus 4 facade tests), `calls`, `startup`, `bench`, `threads`, `isolation` |
| `Consumer/` | A clean consumer: `Aprv.Wasm.Spike` from a local feed and `Wasmtime` from nuget.org, starting from an empty `NUGET_PACKAGES` |
| `scripts/env.sh`, `scripts/build.sh` (`tool`, `consumer`), `scripts/run.sh`, `scripts/facts.sh` | Settings, builds, runs (`RUNTIME=8` for net8.0), primary sources |
| `results/*.txt` | One file per mode; `*-net8.txt` are the net8.0 runs |

## Reproduce

Run the ABI v1 round's `scripts/build.sh` and `scripts/node.sh` first.

```sh
export REPO=... SCRATCH=... CORPORA=... DOTNET_ROOT=...
DW=$REPO/docs/evidence/2026-09-26-dotnet-wasmtime
sh $DW/scripts/build.sh tool > $DW/results/build.txt
sh $DW/scripts/facts.sh > $DW/results/facts.txt
sh $DW/scripts/run.sh tests > $DW/results/abi-tests.txt
for m in calls startup bench threads isolation; do sh $DW/scripts/run.sh $m > $DW/results/$m.txt; done
RUNTIME=8 sh $DW/scripts/run.sh tests > $DW/results/abi-tests-net8.txt
RUNTIME=8 sh $DW/scripts/run.sh calls > $DW/results/calls-net8.txt
sh $DW/scripts/build.sh consumer > $DW/results/build-consumer.txt
```

Run the timing modes on an otherwise idle machine, one at a time.
