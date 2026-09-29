# CI notes for the .NET package over aprv.wasm

For the integrator. This lane does not edit `.github/`; these are the
changes `dotnet/` needs there and in the root documents. Results quoted
here were measured on Linux x86-64 with the release module (the 0.7 core,
rust-core b0a7f3d, 2,764,700 bytes), and are in
`docs/evidence/2026-09-29-dotnet-host.md`. `docs/evidence/2026-09-29-dotnet-host/scripts/g1.sh`
runs the whole re-check for a new module as one command.

## What the build needs

- **A new package, `Wasmtime` 48.0.2 from nuget.org**, is the library's only
  dependency (`Directory.Packages.props`). It is 200 MB unpacked, all
  platforms' native libraries included, so the first restore on a runner is
  the slow step. `System.Security.Cryptography.Pkcs` and
  `System.Formats.Asn1` are no longer restored. Every `packages.lock.json`
  under `dotnet/` was regenerated, so locked-mode restore still holds.
- **The module is not committed** (owner rule on large files). The build
  embeds `dotnet/src/ApplePurchaseReceiptVerifier/wasm/aprv.wasm`, which is
  in `dotnet/.gitignore`, or the file `APRV_WASM` names instead; a missing
  file is a build error that says so. `wasm/aprv.wasm.sha256` (`sha256sum`
  format, the 0.7 core module, 2,764,700 bytes) is committed and names
  the file that belongs there. Two ways to put the release's build in place:
  - copy it to that path and refresh the hash with
    `sha256sum aprv.wasm > aprv.wasm.sha256`; or
  - set `APRV_WASM=<path to aprv.wasm>` for the build. The project then
    embeds that file and writes its hash beside it, so nothing in the tree
    changes. `publish-nuget` already exports `APRV_WASM` after checking the
    file against build-wasm's SHA-256, so its existing Pack step needs no
    change, and `dotnet pack` takes the file lane D's release job provides.
    The override was checked here by building with a different module (the
    stand-in plus one custom section): the assembly embedded that file and
    its hash check passed.
  The `dotnet` test job has to put the module in place (or set `APRV_WASM`)
  before `dotnet test`. The assembly checks the hash again the first time a
  verifier is created.
- **`wasm-copies`** need not look at `dotnet/`: no copy of the module is
  committed here.
- **Licence texts.** `dotnet/licenses/` (OpenSSL, wasi-libc with its
  Apache-LLVM, Apache and MIT texts, Rust std, musl) is packed into the
  nupkg under `licenses/`. They are copies of `node/licenses/`; OpenSSL 4.0.2
  ships no NOTICE file. Refresh them with the toolchain's pins.

## Jobs in `ci.yml`

| Job | Change |
|---|---|
| `dotnet` (ubuntu, windows, macos; net8.0, net9.0, net10.0) | Command unchanged: `dotnet test -c Release` in `dotnet/`. With the release module all 384 conformance cases pass and so do the other 215 tests (599 in all), on .NET 8 and 10 (.NET 9 was last run at 524 of 524 with the 311 cases of G1). Run here on Linux with .NET 8.0.31 and 10.0.12, and on .NET 9.0.20 as a self-contained publish of the test project; Windows and macOS were not run: the `win-x64` and `osx-arm64` Wasmtime libraries are untested here |
| `dotnet-mono` | Unchanged and still meaningful only as far as it goes: `monop` reflects the netstandard2.0 assembly, which proves it loads and not that it runs. Running the wrapper on Mono needs Mono to find `libwasmtime` (it does not read NuGet's `runtimes/` folders), which was not tried; a job for it should copy `runtimes/linux-x64/native/libwasmtime.so` beside the test binary and set `LD_LIBRARY_PATH`. No Mono here |
| `dotnet-roots` | Deleted in Phase 7 (below) |
| `dotnet-trim` | Unchanged command. The sample was rewritten to read verdicts from the endpoint's `status` and passes here: `dotnet publish samples/TrimAotSmoke -c Release -warnaserror` (net9.0, self-contained, trimmed, `linux-x64`) then running it prints `trimmed smoke ok`. Wasmtime is trim-clean under `-warnaserror` in that configuration |
| `dotnet-fuzz` | Unchanged: `./run.sh all 60`. It builds and runs against the new library; 15 s per target here gave 0 crashes and 0 invariant failures (json 173,909 runs, receipt 44,333, receipt-base64 51,220, jws 32,611, endpoint-json 75,738). SharpFuzz instruments .NET IL only, so the module is a black box to it; the README says so. `dotnet/bench` builds (its `decodeBase64` row has no successor: the package has no public decoder) |
| `dotnet-format` | Unchanged: `dotnet format --verify-no-changes --severity info` is clean |
| `one-implementation` | `--enforce dotnet` fails today with 14 hits, all of one kind: `X509Certificate2` in `Config.cs`, `AppleRootCertificates.cs` and `Internal/Certificates.cs`. That type is the public 0.7 API (`Config.Roots`, `Config.Builder.Roots`, `AppleRootCertificates.Bundled`), which the lane brief keeps, and here it only carries DER in and out. Either the checker's `.NET X.509/CMS/ASN.1` pattern drops `X509Certificate2?` (the rest of it, `Pkcs`, `Formats.Asn1`, `AsnReader`, `SignedCms` and the signature APIs, has 0 hits), or the API changes in a breaking release; an owner call. Everything else the gate looks for is gone from `dotnet/src` |
| new, optional `dotnet-corpus` | `dotnet build -c Release dotnet/tools/CorpusRun`, then `CorpusRun calls <calls.jsonl>` per corpus and the reference rows' `same.py`, wherever the corpora live (they are not in the repository). The result here was 6,179 of 6,179 rows byte for byte identical to the module's own rows, 0 traps (`scripts/corpus.sh`) |

The post-publish smoke for NuGet should restore from nuget.org into an
empty package folder on `ubuntu-latest` and run a receipt through
`Config.Defaults()`; `docs/evidence/2026-09-29-dotnet-host/Consumer`
is a ready consumer, and it printed `endpoint: "status":0` for the genuine
G5 receipt from a local feed on .NET 10.

## Platforms and the musl note

- Wasmtime 48.0.2 ships native libraries for `linux-x64` (glibc 2.28),
  `linux-arm64` (glibc 2.18), `osx-x64`, `osx-arm64`, `win-x64` and
  `win-arm64`. There is no `linux-musl-*` build, no 32-bit build, no
  ppc64le, s390x or riscv64.
- On Alpine, .NET falls back from `linux-musl-x64` to `linux-x64`, whose
  library needs `libc.so.6` and `ld-linux-x86-64.so.2`; without `gcompat`
  the load is expected to fail. That is documented in the README, with
  `aprv-server` as the answer for Alpine users. It was not run here (no
  Alpine, no Docker daemon), so if a leg is added it should assert the
  documented failure message rather than a pass.
- `netstandard2.0` compiles and its assembly loads on .NET 8, 9 and 10 (the
  Floor project). .NET Framework, Mono and Unity did not run.

## Rows for the root documents

- `SUPPORT-MATRIX.md`, .NET row: floor "netstandard2.0, tested on net8 and
  later (net8.0, 9.0 and 10.0 on Linux x86-64)"; platforms as above; the
  Alpine limitation.
- `BENCHMARKS.md`: the .NET column loses `decodeBase64`.
- The CHANGELOG entry comes from the lane's `feat(dotnet)!:` commit and its
  `BREAKING CHANGE:` footer.

## Phase 7

`Internal/AppleRootData.cs`, `tools/GenerateRootData` (and its solution
entry) and the public `AppleRootCertificates` class with its `Bundled()`
are gone: Apple's three roots live only in the module. `Bundled()` was
removed rather than made to return an empty list, because an empty
"Apple's roots" list would turn "Apple's roots plus mine" into "mine
only" without a compile error; the README's "Upgrading from 0.7" table
says what replaces it. `Config.Defaults().Roots` stays empty.

| Where | Change |
|---|---|
| `ci.yml` `dotnet-roots` | delete the job: no generator and no generated file are left. |
| `one-implementation` | the .NET allowlist keeps `Config.cs` (`Config.Roots` and `Config.Builder.Roots` are `X509Certificate2`, the 0.7 API; only `RawData` reaches the module) and `Internal/Certificates.cs` (rebuilds an `X509Certificate2` from the DER `Config.Roots` hands back; no chain, key or signature). The `AppleRootCertificates.cs` entry is stale and must go. |
| `.github/smoke/nuget-smoke/Program.cs` | changed on this lane: the `AppleRootCertificates.Bundled().Count != 3` check is gone; the empty-`Roots` assertion and the genuine receipt stay. |
| `release.yml` `publish-nuget` | nothing: the package never listed the roots as a packed file. |

Verified here with G1c (`a35b9fce...40a1`): `dotnet test` project on
net10.0 and net8.0, 592 of 592 each (377 conformance cases plus 2
registry checks among them; two roots tests went with `Bundled()`), the
floor project 9 of 9 on net10.0 and net8.0, the corpora 6,179 of 6,179
identical through `tools/CorpusRun`. The net9.0 floor leg was built but
not run: no .NET 9 runtime here.

G1d (the final module, `4e9d2d85...c9dd`, 384 cases): `dotnet test` project 599 of 599 on net10.0 and net8.0 (384 conformance cases and 215 others), the floor project 9 of 9 on both, `dotnet format` clean, the corpora 6,179 of 6,179 identical (`docs/evidence/2026-09-29-dotnet-host/results/corpus.txt`), no wrapper change.


## The first Windows and macOS runs (run 36581848218)

- **`dotnet (windows-latest)`: the net9.0 and net10.0 test hosts exited with
  -1073740791 (`0xC0000409`).** Diagnosis from the logs and the upstream
  report (bytecodealliance/wasmtime-dotnet#374): since .NET 9 the SDK marks the
  generated apphost `/CETCOMPAT`, which turns on the hardware shadow stack, and
  Wasmtime's Windows trap recovery restores a thread context the shadow stack
  does not know, so Windows fail-fasts the process on the first guest trap.
  The log fits: net8.0 (apphost without the flag) passes the same tests with
  the same traps, the Floor tests (no trap anywhere) pass on all three
  runtimes, the crashed hosts ran 2.9 s and 8.4 s against 14.5 s for the passing
  net8.0 host, and the summary counts only 635 passed tests (594 of net8.0 and 27
  of the Floor runs, so 14 from the two crashed hosts). Several tests make the
  module trap on purpose (`AbiTests`, `FacadeTests`). Fix: `<CETCompat>false</CETCompat>` in
  `ApplePurchaseReceiptVerifier.Tests.csproj`; the flag lands in the apphost, so
  a build that reuses an old apphost needs `--no-incremental` to see it. Not
  established: no Windows machine here, so the fix is untested and the fail-fast
  sub-code was not seen. If the next run still crashes, run the net10.0 host
  under WER/ProcDump for the faulting address; the README documents the
  limitation for consumers.
- **`dotnet (macos-latest)`, osx-arm64:
  `PlatformTests.RepeatedVerificationDoesNotGrowUnboundedly`.** Diagnosed: a
  warm-up tail, not retention. The runs failed different runtimes (net10.0,
  then net8.0, then net8.0, and on PR #187 head 45815dc net9.0 and net8.0 while
  net10.0 passed), never Linux, where every figure reads 0.0 B per call. The
  figures of that last run, from the failure message:
  - net9.0 (9.0.20): 1,533.2 B per call (27 us each) in the measured window;
    the whole path measured again 0.0 B; clock -5.5, UTF-8 encoding 0.0, taking
    and returning an instance 0.0, lowering alone 5.5, export with a
    pre-lowered input 0.0, that plus the post-return 0.0, the whole native call
    0.0, reading the answer 0.0 B; 0 of 200 dropped results alive; the same
    pooled instance; store caches 10/1/0.
  - net8.0 (8.0.31): 3,504.6 B per call (105 us each); the whole path again
    -0.7 B; the pieces -5.9 to 16.5 B (one piece, -3,413.1 B, is a window that
    shrank); the same other facts.
  The growth exists only in the first window after the warm-up and is gone
  when the identical path is measured again, and no piece keeps anything, so
  it is the runtime's tiering and caches settling later on osx-arm64 than the
  400 ms warm-up allows. A per-call leak would be in the second window too.
  Earlier ideas that the figures ruled out: the linear memory of 262,144 B is
  the stub module's four pages on every platform, nothing in Wasmtime .NET
  48.0.2 or the wrapper's managed path keeps anything per call, and the
  time-control (an idle stretch as long as the calls) never grew.
  The test now judges the steady state: up to three consecutive windows of the
  whole path, passing on the first within the budget (256 B per call, net of
  the allocation control) and failing only when every window exceeds it, with
  every window's figure and the piece breakdown in the message. The budget is
  unchanged and there is no skip. A real leak grows in every window and still
  fails: injected leaks of 256 and 1,500 B per call fail on Linux in all three.
