# Releasing the .NET port

The `dotnet/Directory.Build.props` entry in `release-please-config.json` and
the `publish-nuget` job in `release.yml` are both implemented. Owner
bootstrap steps (the `ApplePurchaseReceiptVerifier` package id, the manual
first publish, configuring NuGet trusted publishing) live in
[`BOOTSTRAP.md`](../BOOTSTRAP.md) under "NuGet" — that section is current
and this file no longer repeats it.

## `dotnet/README.md` is the packed readme

It is referenced by the csproj as `../../README.md` relative to
`src/ApplePurchaseReceiptVerifier/`, so moving either file breaks
`dotnet pack` with `NU5040`.

## `post-publish-smoke.yml` — not yet added

Mirror the other languages: install `ApplePurchaseReceiptVerifier` by name
from nuget.org into a scratch project **outside** the checkout, and verify a
genuine Apple receipt with it. The gap that job closes is the same one
everywhere — CI tests the working tree, and consumers receive the tarball.

Worth testing both assets from the registry package, since they are built
differently and only one of them is exercised by a `net8.0`-or-later
consumer:

```
dotnet new console -f net8.0     # picks lib/net8.0
dotnet new console -f net472     # picks lib/netstandard2.0   (Windows runner)
```

Registries do not publish atomically, so poll for the version to appear, the
way the existing `post-publish-smoke.yml` jobs do.
