# .NET growth test on osx-arm64: sources

| File | Question |
|---|---|
| `pull-failures.sh` | Which `dotnet (<os>)` jobs of the ci workflow ran since the steady-state change, which failed, and what did the growth test print in each failing macOS job? |
| `macos-jobs.txt` | Every `dotnet (macos-latest)` job since 2026-09-29T17:00Z, every attempt: job id, attempt, conclusion, run id, created, head, event (the `pull-failures.sh` listing, macOS rows only). |
| `messages/job-<id>.txt` | The growth test's lines from each failing macOS job: the failed test, its message (every window, the controls, the breakdown) and which of the three test hosts passed or failed. `109518939472` and `109538858153` ran before the steady-state change (one window); the other nine ran after it. `114715074952` (main, 2026-10-12T08:01Z) came after the listing and was taken from its saved log with the same extraction. |
| `observe-windows.patch` | On Linux, what does each of six windows read, and what does the breakdown read, when nothing fails? Result: `linux/windows.txt`, `linux/breakdown.txt`. |
| `allocation-per-piece.patch` | How many bytes do the whole path and taking and returning an instance allocate per call? Result: `linux/allocation.txt` (16,032 B and 32 B). |
| `inject-leak-old-test.patch` | Does the test as it was on main (256 B budget, one reading) fail when every measured call keeps a 256 B array? No. Result: `linux/leak-256-unchanged-test.txt` (the patch plus one line printing each window). |
| `inject-leak.patch` | Does the changed test (128 B budget, two readings) fail on a 256 B array per call, and on 136 B and 128 B? The array size in the patch was edited for each. Result: `linux/leak-new-test.txt`. |
| `linux/ten-runs.txt` | Does the clean test pass 10 runs of 10 per runtime, before and after the change, and does the whole test project pass after it? |
| `probe-instruments.patch` | Does a compacting full collection, or the marked bytes of that collection (`GCMemoryInfo.PromotedBytes`), read differently from `GC.GetTotalMemory` on Linux, with and without a leak, and what does each leak size read? Results: `linux/instruments.txt`, `linux/leak-sizes.txt`. Environment variables pick the reading (`Q119_MODE`), the leak (`Q119_LEAK`, bytes per call) and the output file (`Q119_OBS`); they exist in this patch only. |

Reproduce. The CI part needs an authenticated `gh` and reaches only
logs younger than 90 days. Here the API answered 502 often enough that
the listing stopped once and was resumed from the run it stopped at,
with the same queries; four runs needed a second pass:

```sh
bash "$REPO/docs/evidence/2026-10-12-dotnet-growth-test-macos/pull-failures.sh" 2026-09-29T17:00:00Z "$SCRATCH/q119"
```

The Linux part, with .NET SDK 10 and the 8 and 9 runtimes, from a clean
checkout of main at 4f2b8cbc (every patch but `inject-leak.patch`,
which applies to the changed test), one patch at a time:

```sh
git -C "$REPO" apply docs/evidence/2026-10-12-dotnet-growth-test-macos/probe-instruments.patch
APRV_WASM="$REPO/go/internal/wasm/aprv.wasm" \
  dotnet build "$REPO/dotnet/tests/ApplePurchaseReceiptVerifier.Tests/ApplePurchaseReceiptVerifier.Tests.csproj" -c Release
B="$REPO/dotnet/tests/ApplePurchaseReceiptVerifier.Tests/bin/Release"
for leak in 0 128 256 264 280 512; do
  for f in net8.0 net9.0 net10.0; do
    Q119_MODE=total Q119_LEAK=$leak Q119_OBS="$SCRATCH/obs.txt" \
      "$B/$f/ApplePurchaseReceiptVerifier.Tests" --filter-method '*RepeatedVerificationDoesNotGrowUnboundedly'
  done
done
git -C "$REPO" checkout -- dotnet/tests/ApplePurchaseReceiptVerifier.Tests/PlatformTests.cs
```

`go/internal/wasm/aprv.wasm` has the SHA-256 the .NET pin names
(`d882964f…bec5`), so `APRV_WASM` embeds the release module without a
copy into `dotnet/`. The growth test itself runs the stub module.
