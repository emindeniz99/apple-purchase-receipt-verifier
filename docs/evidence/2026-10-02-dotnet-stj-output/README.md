# .NET on System.Text.Json: the sources

The note is [../2026-10-02-dotnet-stj-output.md](../2026-10-02-dotnet-stj-output.md).

| Path | Question it answered |
|---|---|
| `dump/` | What does `ReceiptPayload.ToJson()` write before and after the switch, for the `verifyReceipt` cases of `fixtures/cases.json` and for hand-built payloads with awkward strings? Does every `verifyReceipt` and `verifySignedData` case keep its verdict? |
| `compare.py` | Of two dumps, which lines differ, which escapes only one side holds, and does each differing pair parse to the same JSON value? |
| `probe/` | What do `System.Text.Json`'s own encoders (`Default`, `UnsafeRelaxedJsonEscaping`) do to the same strings, on .NET 8 and 10? |

`dump/` is a console app over the library's public API. It is named
`ApplePurchaseReceiptVerifier.CorpusRun` because the library grants that
assembly `InternalsVisibleTo`, and the dump loads a case's roots with
`Internal.Certificates.TryLoad`, the same call the conformance runner
makes. It writes one line per item: the case id, `ok` and the result's
text as UTF-16 code units in hex (so a lone surrogate survives the file),
or the failure's reason. Endpoint answers carry the wall clock, so they
differ between any two runs and are left out of the comparison. The
`decodeBase64` cases are skipped: nothing they call writes JSON.

## Reproduce

Needs the .NET 10 SDK (and the .NET 8 runtime for `probe/` on net8.0),
Python 3 for `compare.py`, and a module built from the same tree
(`rust/bindings/abi/build.sh`).

```sh
export APRV_WASM=$SCRATCH/out/aprv.wasm   # built by rust/bindings/abi/build.sh
E=$REPO/docs/evidence/2026-10-02-dotnet-stj-output
cp -r $E/dump $E/probe $SCRATCH/          # builds land in $SCRATCH, not in git
git -C $REPO worktree add $SCRATCH/old 74b328b
for tree in old new; do
  lib=$SCRATCH/old; [ $tree = new ] && lib=$REPO
  for tfm in net8.0 netstandard2.0; do
    rm -rf $SCRATCH/dump/bin $SCRATCH/dump/obj
    dotnet run -c Release --project $SCRATCH/dump/Dump.csproj \
      -p:AprvLib=$lib/dotnet/src/ApplePurchaseReceiptVerifier/ApplePurchaseReceiptVerifier.csproj \
      -p:LibTfm=$tfm -- $REPO/fixtures $SCRATCH/$tree-$tfm.tsv
    grep -v '^endpoint/' $SCRATCH/$tree-$tfm.tsv > $SCRATCH/$tree-$tfm.noep
  done
done
python3 $E/compare.py $SCRATCH/old-net8.0.noep $SCRATCH/new-net8.0.noep
python3 $E/compare.py $SCRATCH/old-netstandard2.0.noep $SCRATCH/new-netstandard2.0.noep

dotnet run --project $SCRATCH/probe/Probe.csproj -f net8.0
dotnet run --project $SCRATCH/probe/Probe.csproj -f net10.0
```
