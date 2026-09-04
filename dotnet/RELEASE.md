# Releasing the .NET port

## What `release-please-config.json` needs

The repository keeps one version across every manifest. Add
`dotnet/Directory.Build.props` to the `extra-files` list of the `.` package:

```json
{
  "type": "xml",
  "path": "dotnet/Directory.Build.props",
  "xpath": "//project/propertyGroup/version"
}
```

That takes the count in `CLAUDE.md`'s "one version, N files" sentence up by
one. `dotnet/Directory.Build.props` currently declares `0.3.0`, matching
`version.txt` and `.release-please-manifest.json`, so the first automated bump
lands on it like every other manifest.

Nothing else in `release-please-config.json` changes: the release type stays
`simple`, and the changelog sections are shared.

## What `release.yml` needs

One job, alongside the PyPI, npm and Maven jobs. It follows the same shape:
gated on `ci-passed`, skips loudly when the registry already has the version,
pins every action to a SHA, and sets **no dependency cache** — a poisoned cache
restore in a publish job becomes the published artifact.

```yaml
  publish-nuget:
    name: publish dotnet to NuGet
    runs-on: ubuntu-latest
    needs: ci-passed
    timeout-minutes: 25
    permissions:
      contents: read
      id-token: write          # NuGet trusted publishing (OIDC)
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - uses: actions/setup-dotnet@a98b56852c35b8e3190ac28c8c2271da59106c68 # v6.0.0
        with:
          dotnet-version: '9.0.x'

      - name: Skip if this version is already on nuget.org
        id: gate
        run: |
          set -euo pipefail
          VERSION=$(cat version.txt)
          if curl -fsSL "https://api.nuget.org/v3-flatcontainer/applepurchasereceiptverifier/$VERSION/applepurchasereceiptverifier.$VERSION.nupkg" -o /dev/null; then
            echo "nuget.org already has $VERSION — skipping publish."
            echo "publish=false" >> "$GITHUB_OUTPUT"
          else
            echo "publish=true" >> "$GITHUB_OUTPUT"
          fi

      - name: Pack
        if: steps.gate.outputs.publish == 'true'
        working-directory: dotnet
        run: dotnet pack src/ApplePurchaseReceiptVerifier -c Release -o "$RUNNER_TEMP/nupkg"

      # The tarball is what consumers receive: prove both target-framework
      # assets are in it before it reaches the registry. The npm job exists in
      # this shape because two releases shipped with no JavaScript at all.
      - name: Prove the package carries both assets
        if: steps.gate.outputs.publish == 'true'
        run: |
          set -euo pipefail
          PKG=$(ls "$RUNNER_TEMP"/nupkg/ApplePurchaseReceiptVerifier.*.nupkg)
          for entry in lib/netstandard2.0/ApplePurchaseReceiptVerifier.dll \
                       lib/net8.0/ApplePurchaseReceiptVerifier.dll \
                       README.md; do
            unzip -l "$PKG" | grep -q "$entry" \
              || { echo "::error::the package is missing $entry"; exit 1; }
          done

      - uses: NuGet/login@8d196754b4036150537f80ac539e15c2f1028841 # v1.2.0
        if: steps.gate.outputs.publish == 'true'
        id: nuget-login
        with:
          user: emindeniz99

      - name: Push
        if: steps.gate.outputs.publish == 'true'
        run: |
          set -euo pipefail
          dotnet nuget push "$RUNNER_TEMP"/nupkg/*.nupkg \
            --source https://api.nuget.org/v3/index.json \
            --api-key "${{ steps.nuget-login.outputs.NUGET_API_KEY }}" \
            --skip-duplicate
```

**Never rename `release.yml`.** It is already the match key npm's trusted
publisher uses, and NuGet's trusted publishing policy matches on the same
filename.

## Owner-only bootstrap steps

These need the account owner and cannot be done from CI or by an agent.

1. **The package id is `ApplePurchaseReceiptVerifier`,** not
   `apple-purchase-receipt-verifier`. This is a recorded amendment to D14, and
   it should be written into `PLAN.md` D14 in the same pull request as the
   first C# commit. A hyphenated id is legal on NuGet and unheard-of there;
   NuGet's search splits camel case, so "apple receipt" still finds it; and the
   id can never be changed after the first publish.
2. **The first publish must be manual.** NuGet's trusted publishing cannot
   create a package that does not exist. Publish the current version (0.3.0) by
   hand with an API key, then delete the key and let the automated path cut the
   next one — which also proves the whole chain end to end with no version
   collision.
3. **Then configure trusted publishing** on nuget.org: package
   `ApplePurchaseReceiptVerifier`, repository
   `emindeniz99/apple-purchase-receipt-verifier`, workflow file `release.yml`.
   After that, no NuGet API key exists anywhere in the repository.
4. **`dotnet/README.md` is the packed readme.** It is referenced by the csproj
   as `../../README.md` relative to `src/ApplePurchaseReceiptVerifier/`, so
   moving either file breaks `dotnet pack` with `NU5040`.

## What the post-publish smoke job should do

Mirror the other languages: install `ApplePurchaseReceiptVerifier` by name from
nuget.org into a scratch project **outside** the checkout, and verify a genuine
Apple receipt with it. The gap that job closes is the same one everywhere — CI
tests the working tree, and consumers receive the tarball.

Worth testing both assets from the registry package, since they are built
differently and only one of them is exercised by a `net8.0`-or-later consumer:

```
dotnet new console -f net8.0     # picks lib/net8.0
dotnet new console -f net472     # picks lib/netstandard2.0   (Windows runner)
```

Registries do not publish atomically, so poll for the version to appear, the
way the existing jobs do.
