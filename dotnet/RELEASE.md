# Releasing the .NET port

The `dotnet/Directory.Build.props` entry in `release-please-config.json` and
the `publish-nuget` job in `release.yml` are both implemented. Owner
bootstrap steps (the `ApplePurchaseReceiptVerifier` package id, the manual
first publish, configuring NuGet trusted publishing) live in
[`BOOTSTRAP.md`](../BOOTSTRAP.md) under "NuGet" — that section is current
and this file no longer repeats it. Until they are done, `publish-nuget`
skips itself rather than failing the tag run.

## `dotnet/README.md` is the packed readme

It is referenced by the csproj as `../../README.md` relative to
`src/ApplePurchaseReceiptVerifier/`, so moving either file breaks
`dotnet pack` with `NU5040`.

## `post-publish-smoke.yml` — added, one asset covered

The `nuget` job copies `.github/smoke/nuget-smoke/` outside the checkout and
restores `ApplePurchaseReceiptVerifier` from nuget.org at the exact version —
`Version="[$(SmokeVersion)]"`, an exact-version range, passed as
`-p:SmokeVersion=$VERSION` — then runs it. `Program.cs` asserts three bundled
roots, verifies `fixtures/public-receipts/receipt-sandbox-g5.b64` and checks
that a verifier configured for another bundle id rejects it with
`VerificationReason.WrongBundleId`.

Registries do not publish atomically, so the restore is retried; each attempt
passes `--no-cache`, because NuGet caches an HTTP response — a 404 for a
not-yet-indexed version included — for 30 minutes, the same cached-miss trap
the maven leg documents.

**Only `lib/net8.0` is covered.** The scratch project targets `net8.0`, which
is the floor of the two shipped assets. `lib/netstandard2.0` is selected by a
`net472` consumer and needs a Windows runner:

```
dotnet new console -f net472     # picks lib/netstandard2.0   (Windows runner)
```

That leg is not written; it is in `ROADMAP.md`.

The job is gated on the `registries` input, so it skips rather than fails while
NuGet is unbootstrapped (`BOOTSTRAP.md`).
