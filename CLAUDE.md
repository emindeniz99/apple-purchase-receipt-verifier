# Claude Rules — apple-purchase-receipt-verifier

Rules for AI assistants working in this repo. `CONTRIBUTING.md` is the
human-facing version; where they overlap, they agree.

## Commits and merges

- Conventional Commits, scope **mandatory**, area scopes: `java`, `node`,
  `python`, `swift`, `fixtures`, `certs`, `ci`, `release`, `docs`, `repo`.
- Imperative subject, lowercase, ≤72 chars for the whole header. Body explains
  *why*, wrapped at 72.
- Add a `Co-Authored-By:` trailer naming the assistant and model.
- Merge PRs with a **real merge commit** (`merge_method: "merge"`, locally
  `git merge --no-ff`). Never squash, never rebase-merge — squash/rebase are
  disabled in repo settings; do not re-enable them.

## The invariants that are easy to break

- **Never rename `.github/workflows/release.yml`.** npm and PyPI trusted
  publishing (OIDC) match the workflow *filename*. Renaming it silently kills
  publishing.
- **Publish jobs never cache** (a poisoned cache restore becomes the shipped
  artifact). Test jobs do cache. Keep that split.
- **Floors are tested claims.** `@types/node` pins to the Node 20 engines
  floor, JUnit stays 5.x (JUnit 6 needs Java >8), the `java-runtime-8` CI job
  runs the suite on a real Temurin 8 JVM. Dependabot ignore rules encode
  this — don't "fix" them by upgrading.
- **`certs/` pins exactly two Apple roots deliberately** (minimal trust
  anchors, PLAN.md D12). Don't add more because "the site lists many".
- **One version, five files**: release-please's extra-files bump
  `version.txt`, `node/package.json`, `python/pyproject.toml`, `java/pom.xml`
  and the CHANGELOG together. Never hand-edit a version number.
- Tags created by release-please's `GITHUB_TOKEN` cannot trigger workflows —
  that's why `release-please.yml` explicitly dispatches `release.yml`. Don't
  remove that step as "redundant".

## Release budget

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

The four implementations are one product. A verification behavior change
touches all four languages and `fixtures/` in the same PR, with the shared
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
