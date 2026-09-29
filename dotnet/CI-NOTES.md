# CI notes for the .NET package over aprv.wasm

For the integrator. This lane does not edit `.github/`; these are the
changes `dotnet/` needs there and in the root documents. Results quoted
here were measured on Linux x86-64 with the round-13 stand-in module (the
0.6 core), and are in `docs/evidence/2026-09-29-dotnet-host.md`.

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
  format, the round-13 core module, 2,967,116 bytes) is committed and names
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
| `dotnet` (ubuntu, windows, macos; net8.0, net9.0, net10.0) | Command unchanged: `dotnet test -c Release` in `dotnet/`. Until the core's module replaces the stand-in, 221 of the 311 cases fail on every runtime (ids in `docs/evidence/2026-09-29-dotnet-host/results/standin-fail-ids.txt`), so this job is red by design; with the real module it must be 311 of 311 and every other test green (213 tests here). Run here on Linux with .NET 8.0.31 and 10.0.12, and on .NET 9.0.20 as a self-contained publish of the test project; identical failing set on all three. Windows and macOS were not run: the `win-x64` and `osx-arm64` Wasmtime libraries are untested here |
| `dotnet-mono` | Unchanged and still meaningful only as far as it goes: `monop` reflects the netstandard2.0 assembly, which proves it loads and not that it runs. Running the wrapper on Mono needs Mono to find `libwasmtime` (it does not read NuGet's `runtimes/` folders), which was not tried; a job for it should copy `runtimes/linux-x64/native/libwasmtime.so` beside the test binary and set `LD_LIBRARY_PATH`. No Mono here |
| `dotnet-roots` | Unchanged until Phase 7: `AppleRootData.cs` and `tools/GenerateRootData` stay for `AppleRootCertificates.Bundled()` and are untouched |
| `dotnet-trim` | Unchanged command. The sample was rewritten to read verdicts from the endpoint's `status` and passes here: `dotnet publish samples/TrimAotSmoke -c Release -warnaserror` (net9.0, self-contained, trimmed, `linux-x64`) then running it prints `trimmed smoke ok`. Wasmtime is trim-clean under `-warnaserror` in that configuration |
| `dotnet-fuzz` | Unchanged: `./run.sh all 60`. It builds and runs against the new library; 15 s per target here gave 0 crashes and 0 invariant failures (json 266,371 runs, receipt 2,494, receipt-base64 4,421, jws 4,585, endpoint-json 50,281). SharpFuzz instruments .NET IL only, so the module is a black box to it; the README says so. `dotnet/bench` builds (its `decodeBase64` row has no successor: the package has no public decoder) |
| `dotnet-format` | Unchanged: `dotnet format --verify-no-changes --severity info` is clean |
| `one-implementation` | `--enforce dotnet` fails today with 14 hits, all of one kind: `X509Certificate2` in `Config.cs`, `AppleRootCertificates.cs` and `Internal/Certificates.cs`. That type is the public 0.7 API (`Config.Roots`, `Config.Builder.Roots`, `AppleRootCertificates.Bundled`), which the lane brief keeps, and here it only carries DER in and out. Either the checker's `.NET X.509/CMS/ASN.1` pattern drops `X509Certificate2?` (the rest of it, `Pkcs`, `Formats.Asn1`, `AsnReader`, `SignedCms` and the signature APIs, has 0 hits), or the API changes in a breaking release; an owner call. Everything else the gate looks for is gone from `dotnet/src` |
| new, optional `dotnet-corpus` | `dotnet build -c Release dotnet/tools/CorpusRun`, then `CorpusRun calls <calls.jsonl>` per corpus and round 13's `classify.py`, wherever the corpora live (they are not in the repository). The result here was 6,176 identical, 2 `clock-moves-chain`, 1 `init-refusal` |

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
