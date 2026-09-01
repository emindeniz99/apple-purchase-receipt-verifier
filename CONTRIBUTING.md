# Contributing

Four implementations of the same verifier — Java, Node, Python, Swift — kept
in lockstep by one shared fixture suite. A behavior change lands in all four
languages plus `fixtures/`, or it doesn't land.

## Running the tests

Each language runs the same fixtures:

```bash
cd java   && mvn test
cd node   && npm ci && npm test
cd python && pip install cryptography asn1crypto && python -m unittest discover -s tests
swift test   # manifest is at the repo root
```

CI runs these on every supported runtime line (Java 8–25, Node 20–26,
Python 3.9–3.14, Swift 6). The floors are claims we test, not decoration:
`@types/node` stays on 20 and JUnit stays on 5.x on purpose — see the
rationale comments in `.github/dependabot.yml` before "upgrading" them.

## Commits

Conventional Commits with a **mandatory scope**:

```
<type>(<scope>): <imperative subject, lowercase, ≤72 chars total>
```

- Types: `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `chore`, `build`, `ci`, `revert`.
- Scopes are areas: `java`, `node`, `python`, `swift`, `fixtures`, `certs`,
  `ci`, `release`, `docs`, `repo`.
- Body explains *why* (constraint, incident, trade-off), not what the diff
  already shows. Wrap at 72 chars.
- `feat`/`fix` drive release-please's version bump — use them only for
  user-visible changes.

## Merging

Pull requests merge with a **real merge commit** — never squash, never
rebase-merge. Per-commit history is the record of how the work was built;
squashing erases it irreversibly. (Squash and rebase merges are disabled in
the repo settings.)

## Releases

Fully automated — do not publish from a laptop:

1. Conventional Commits on `main` → release-please opens/updates a release PR
   (one version for all four languages; extra-files bump every manifest).
2. Merging that PR creates the tag + GitHub Release, and the workflow
   dispatches `release.yml` at the tag.
3. `release.yml` publishes to npm (OIDC), PyPI (OIDC), and Maven Central
   (token + GPG). SwiftPM consumes the tag directly.

Every publish job is version-gated: it skips loudly if the registry already
has that version, so re-runs are safe. **Never rename `release.yml`** — npm
and PyPI trusted publishing match the workflow filename.

Maven Central's Usage Center caps `io.github.emindeniz99` at 7 releases per
calendar month, and every release-please PR merge spends one, since
`release.yml` publishes to Central on every tag. Merge a release PR only for
a consumer-visible change — a fix, a feature, a docs correction that
registries display, or a security bump of a shipped dependency — not for a
`Package.resolved`/lockfile or CI-only bump; let release-please accumulate
those into the next real release instead. Before merging, check the month's
count on https://central.sonatype.com (Usage Center) or `git tag
--sort=-creatordate | head`, and keep at least 2 releases in reserve for an
emergency fix. Note that SwiftPM consumers never see `Package.resolved` —
they resolve from `Package.swift`'s `from:` floors — so a `Package.resolved`
bump alone changes nothing for them.
