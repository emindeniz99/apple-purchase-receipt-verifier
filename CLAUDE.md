# Claude Rules — apple-purchase-receipt-verifier

Rules for AI assistants working in this repo. `CONTRIBUTING.md` is the
human-facing version; where they overlap, they agree.

## Commits and merges

- Conventional Commits, scope **mandatory**, area scopes: `java`, `node`,
  `python`, `swift`, `go`, `ruby`, `rust`, `php`, `dotnet`, `jvm-interop`,
  `fixtures`, `certs`, `ci`, `release`, `docs`, `repo`.
- Imperative subject, lowercase, ≤72 chars for the whole header. Body explains
  *why*, wrapped at 72.
- Commit as the identity that owns the signing key, so the commit shows
  Verified, and name the other party in a `Co-Authored-By:` trailer. In a
  cloud session (Claude Code on the web) the key belongs to the `claude`
  GitHub account: commit as `Claude <noreply@anthropic.com>`, never as the
  owner, and check `git config user.email` first because a fresh clone can
  arrive with the owner's email set. In a local session the key is the
  owner's: keep the owner's identity and credit the assistant and model in
  the trailer.
- Merge PRs with a **real merge commit** (`merge_method: "merge"`, locally
  `git merge --no-ff`). Never squash, never rebase-merge — squash/rebase are
  disabled in repo settings; do not re-enable them.
- Give the merge commit a body of the form `Merges #57: <PR title without
  its type(scope) prefix>`, never GitHub's default (the bare PR title,
  which is a Conventional Commit line). release-please reads merge commit
  bodies too, so a conventional body there is counted as a second change
  alongside the branch commit that already carries it, duplicating the
  entry in the generated changelog (observed in 0.4.0: `deps: Bump
  actions/setup-go from 6.5.0 to 7.0.0` listed twice, once from the
  dependabot branch commit and once from its merge commit). Dropping only
  the prefix keeps `git log` readable; the type, scope and any breaking
  marker still live on the branch commit, which release-please does read.

## The invariants that are easy to break

- **Never rename `.github/workflows/release.yml`.** npm, PyPI, RubyGems,
  crates.io and NuGet trusted publishing (OIDC) all match the workflow
  *filename*. Renaming it silently kills publishing on five registries.
- **Publish jobs never cache** (a poisoned cache restore becomes the shipped
  artifact). Test jobs do cache. Keep that split.
- **Floors are tested claims.** `@types/node` pins to the Node 20 engines
  floor, JUnit stays 5.x (JUnit 6 needs Java >8), the `java-runtime-8` CI job
  runs the suite on a real Temurin 8 JVM. Dependabot ignore rules encode
  this — don't "fix" them by upgrading.
- **The Node package inlines the roots.** `node/src/roots-data.ts` is
  generated from `certs/` by `node/scripts/gen-roots.mjs`; CI regenerates it
  and fails on a diff. Change `certs/`, re-run the script in the same commit.
  Reading the files at call time would break every bundled runtime.
- **Seven ports keep a COPY of `certs/`,** because their packaging cannot
  reach outside the package directory: `go/roots/certs`, `node/certs`,
  `php/certs`, `python/apple_purchase_receipt_verifier/certs`, `ruby/certs`,
  `rust/certs` and `swift/Sources/ApplePurchaseReceiptVerifier/certs`.
  `tools/check-cert-copies.mjs` diffs each copy against `certs/`, and CI
  regenerates the inlined forms (`ruby/lib/.../roots_data.rb`,
  `php/src/Internal/RootsData.php`, `dotnet/.../Internal/AppleRootData.cs`,
  `go generate`). Java inlines the roots as base64 constants in
  `AppleRootCerts`, with no copy and no generator: edit the constants by
  hand, and `AppleRootCertsTest` pins them to Apple's fingerprints and to
  `certs/`. A `certs/` change touches all of them in the same commit.
- **`certs/` pins all three published Apple roots deliberately** (PLAN.md
  D15, which superseded D12's two-root choice). Apple's guidance is to trust
  every root on its PKI page; don't prune them back to the two today's chains
  happen to end at.
- **One version, many files**: release-please bumps `version.txt`, the
  CHANGELOG and every `extra-files` entry in `release-please-config.json`
  together: the manifests (`node/package.json`, `python/pyproject.toml`,
  `java/pom.xml`, `rust/Cargo.toml`, `dotnet/Directory.Build.props`, the
  `jvm-interop` and `java-bench` poms, the version in `java/README.md`) and
  each port's version constant (Java `Version.java`, Python `version.py`,
  Ruby `version.rb`, Swift `Version.swift`, .NET `LibraryVersion.cs`, Go
  `version.go`), the generic ones found by their `x-release-please-version`
  marker. A new version constant joins that list in the commit that adds
  it. PHP carries no version string at all; the git tag is its version.
  Never hand-edit a version number.
- **Never delete or move a `go/v*` tag.** The Go module is published by that
  tag alone, and its hash is recorded in `sum.golang.org` forever; re-pointing
  one makes every consumer's build fail with a checksum mismatch that looks
  exactly like a supply-chain attack. A bad Go release is fixed forward with a
  `retract` directive in a new patch version.
- Tags created by release-please's `GITHUB_TOKEN` cannot trigger workflows —
  that's why `release-please.yml` explicitly dispatches `release.yml`. Don't
  remove that step as "redundant".

## Release budget

- Registries that still need a one-time owner action before their publish job
  can succeed are listed per registry in `BOOTSTRAP.md`. PHP is not publishable
  from this repository at all until the manifest-layout question there is
  settled.
- Maven Central's Usage Center caps `io.github.emindeniz99` at **7 releases
  per calendar month** (also 80 MB/release, 1,000 files). Every
  release-please PR merge spends one — `release.yml` publishes to Central on
  every tag, no dry-run.
- Merge a release PR only for a consumer-visible change: a fix, a feature, a
  docs correction that registries display, or a security bump of a shipped
  dependency. A `Package.resolved`/lockfile or CI-only bump is not one of
  these — let release-please keep accumulating those commits into the next
  real release instead of cutting a release for them.
- Before merging a release PR, check the month's count on
  https://central.sonatype.com (Usage Center) or count this month's tags
  (`git tag --sort=-creatordate | head`). Keep at least 2 releases in
  reserve for an emergency fix.
- SwiftPM consumers never see `Package.resolved` — they resolve from
  `Package.swift`'s `from:` floors — so a `Package.resolved` bump alone
  changes nothing for them and isn't release-worthy on its own.

## Behavior changes

The nine implementations are one product. A verification behavior change
touches all nine languages and `fixtures/` in the same PR, with the shared
fixture suite proving they still agree. If only one language changes behavior,
that's a bug, not a feature.

## CI hygiene

- Every action SHA-pinned with the tag in a comment; the swift container is
  digest-pinned. zizmor runs in CI and stays at 0 findings.
- All checkouts set `persist-credentials: false`; workflow `permissions:`
  blocks stay least-privilege (repo default token is read-only).

## Fixtures and privacy

`fixtures/` sandbox receipts are developers' own test data (documented in
their LICENSE-upstream files). Never add a production receipt — a real
receipt carries a real user's purchase history. This rule has bitten before.
