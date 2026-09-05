# CI jobs to add for the .NET port

The orchestrator owns `.github/workflows/ci.yml`; this file is the exact YAML
to paste into it. Conventions copied from the existing jobs: every action
pinned to a full commit SHA with the tag in a comment, `persist-credentials:
false` on every checkout, `timeout-minutes` on every job, and no
`working-directory` on a `uses:` step (that makes GitHub reject the whole file
before any job starts).

Action SHAs, resolved from the upstream repositories:

| Action | Pin |
|---|---|
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1` (already in `ci.yml`) |
| `actions/setup-dotnet` | `a98b56852c35b8e3190ac28c8c2271da59106c68 # v6.0.0` |

Add `dotnet/` to `.github/dependabot.yml` with the `nuget` ecosystem and the
repository's usual 7-day cooldown, so `System.Security.Cryptography.Pkcs`,
`System.Formats.Asn1`, `Microsoft.CodeAnalysis.BannedApiAnalyzers` and
`xunit.v3` are bumped like every other dependency.

## Jobs

```yaml
  # The matrix that matters here is OS, not SDK: X.509 parsing, CNG versus
  # OpenSSL versus SecureTransport, and the time-zone database all differ per
  # platform, and this port touches all three. One job installs the SDKs and
  # runs the suite on each; the netstandard2.0 floor gets its own job below.
  dotnet:
    runs-on: ${{ matrix.os }}
    timeout-minutes: 25
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-dotnet@a98b56852c35b8e3190ac28c8c2271da59106c68 # v6.0.0
        with:
          dotnet-version: |
            8.0.x
            9.0.x
            10.0.x
      - run: dotnet test -c Release
        working-directory: dotnet

  # The netstandard2.0 asset is what a .NET Framework, Mono or Unity consumer
  # loads. dotnet test above already runs the floor project on CoreCLR against
  # that asset; this job runs the same project on Mono, which is the closest a
  # hosted runner gets to Unity's scripting backend.
  dotnet-mono:
    runs-on: ubuntu-latest
    timeout-minutes: 25
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-dotnet@a98b56852c35b8e3190ac28c8c2271da59106c68 # v6.0.0
        with:
          dotnet-version: '9.0.x'
      - run: sudo apt-get update && sudo apt-get install -y --no-install-recommends mono-complete
      - name: Load the netstandard2.0 asset under Mono
        working-directory: dotnet
        run: |
          set -euo pipefail
          dotnet build -c Release src/ApplePurchaseReceiptVerifier
          # A Mono host that cannot even load the assembly is the failure this
          # job exists to catch; the full suite stays on CoreCLR.
          monop -r:src/ApplePurchaseReceiptVerifier/bin/Release/netstandard2.0/ApplePurchaseReceiptVerifier.dll \
            ApplePurchaseReceiptVerifier.Receipt.ReceiptVerifier

  # certs/ is the reviewable source of truth for the pinned Apple roots;
  # Internal/AppleRootData.cs is generated from it and compiled in. A certs
  # change that forgets to regenerate would ship stale trust anchors, so the
  # generator runs and the diff must be empty — the same rule node's
  # roots-data.ts already follows.
  dotnet-roots:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-dotnet@a98b56852c35b8e3190ac28c8c2271da59106c68 # v6.0.0
        with:
          dotnet-version: '9.0.x'
      - run: dotnet run --project dotnet/tools/GenerateRootData -- "$GITHUB_WORKSPACE"
      - run: git diff --exit-code dotnet/src/ApplePurchaseReceiptVerifier/Internal/AppleRootData.cs

  # Trimming is the closest CI-runnable proxy for Unity IL2CPP's stripping: a
  # reflection-based serializer, an embedded resource or a dynamic code path
  # would surface here as an IL2xxx warning or as a runtime failure. The sample
  # verifies a receipt and asserts a foreign chain is still rejected, so a
  # trimmer that silently removed a check would fail the job rather than pass it.
  dotnet-trim:
    runs-on: ubuntu-latest
    timeout-minutes: 25
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-dotnet@a98b56852c35b8e3190ac28c8c2271da59106c68 # v6.0.0
        with:
          dotnet-version: '9.0.x'
      - name: Publish fully trimmed and verify a receipt with it
        working-directory: dotnet
        run: |
          set -euo pipefail
          dotnet publish samples/TrimAotSmoke -c Release -r linux-x64 -o "$RUNNER_TEMP/trim" \
            -warnaserror
          "$RUNNER_TEMP/trim/TrimAotSmoke" "$GITHUB_WORKSPACE/fixtures"

  # A drift gate on dotnet/.editorconfig, not a restyle: `dotnet format`
  # (apply mode) was trialled against a first-draft .editorconfig and
  # rewrote 28 files with analyzer-driven modernizations (switch
  # expressions, collection expressions, a primary constructor,
  # [GeneratedRegex] source generators, Substring-to-range) that are not
  # the codebase's current style — one file even came back with a literal
  # unresolved merge-conflict marker where two fixers collided on the same
  # block. dotnet/.editorconfig pins the Style/Performance/Usage analyzer
  # categories plus two individual rules (CA1513, xUnit2025 — the latter's
  # own fixer can't "Fix All in Solution") to :silent so this job checks
  # only real formatting/using-order drift; verified clean (exit 0, no
  # file changes) against the sources as they stand today.
  dotnet-format:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-dotnet@a98b56852c35b8e3190ac28c8c2271da59106c68 # v6.0.0
        with:
          dotnet-version: |
            8.0.x
            9.0.x
            10.0.x
      - run: dotnet format --verify-no-changes --severity info
        working-directory: dotnet
```

## Notes for whoever wires this up

- **`dotnet test` runs three projects**: the conformance plus native suite, the
  netstandard2.0 floor suite, and nothing else. `tools/GenerateRootData` and
  `samples/TrimAotSmoke` are in the solution but are not test projects.
- **No `dotnet restore --locked-mode` yet.** Central Package Management pins
  exact versions in `Directory.Packages.props`; a `packages.lock.json` would be
  strictly better and is a cheap follow-up.
- **The Unity claim is not made and this CI cannot make it.** The Mono job is
  evidence that the netstandard2.0 asset loads outside CoreCLR, not that it
  runs in an IL2CPP player. `ROADMAP.md` should carry the Unity smoke test as a
  task rather than the README carrying it as a claim.
- **Two security gates are already inside the test suite** rather than being
  separate jobs, so they cannot be skipped by editing a workflow:
  `ChainSecurityTests.ShippedAssemblyNeverReferencesX509Chain` scans the built
  IL, and `ClockTests.TheSystemClockIsReadAtExactlyTheDocumentedSites` scans
  the sources. `Microsoft.CodeAnalysis.BannedApiAnalyzers` plus
  `dotnet/BannedSymbols.txt` makes `new X509Chain()`, `X509Store`,
  `HttpClient`, `WebRequest` and `DateTime.UtcNow` compile errors in `src/`.
- **zizmor** already runs over `.github/workflows/`; the jobs above are written
  to keep it at zero findings (no `pull_request_target`, no interpolation of
  event fields into `run:`, least-privilege permissions inherited from the
  workflow-level `contents: read`).
