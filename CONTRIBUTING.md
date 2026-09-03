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

node tools/lint-cases.mjs   # the shared conformance vectors, see below
```

CI runs these on every supported runtime line (Java 8–25, Node 20–26,
Python 3.9–3.14, Swift 6). The floors are claims we test, not decoration:
`@types/node` stays on 20 and JUnit stays on 5.x on purpose — see the
rationale comments in `.github/dependabot.yml` before "upgrading" them.

## Conformance vectors

`fixtures/cases.json` is the normative contract between the four
implementations: one language-neutral case per semantic fact, each naming a
registered fixture, the verifier config to build from it, and either the
payload fields the call must return or the canonical reason it must raise.
Each language reads the file through a thin adapter that knows nothing about
any individual case — `java/src/test/.../ConformanceCasesTest.java`,
`node/test/conformance.test.js`, `python/tests/test_conformance.py`,
`swift/Tests/.../ConformanceCasesTests.swift`.

**A behavior change means editing `cases.json` in the same commit.** The file
records what was decided, not what an implementation happened to do, so a
vector that disagrees with an implementation is a bug report against that
implementation until a human rules otherwise. Changing a returned field or a
raised reason without updating the vector leaves all four suites disagreeing
with the contract.

### Adding a case

1. Register the fixture in the `fixtures` map if it is not there yet: `path`
   relative to `fixtures/`, `role` (`input`, `trust-anchor` or `support`),
   `codec` (`raw`, `base64` or `utf8`), and the file's `contentSha256`.
2. Append the case: a unique `id` shaped `<area>/<what-it-pins>`, a
   `description` of the fact it pins, the `operation` (`verifyTransaction`,
   `verifyAppTransaction`, `verifyRaw`, `verifyReceipt` or
   `verifyReceiptEndpoint`), `input.fixture`, the `config`, and `expected`.
   A positive case carries `status: "ok"` plus the `fields` it pins; a field
   it does not list is not pinned. A negative case carries `status: "error"`
   plus a `reason` from the canonical vocabulary, and a `fault` naming its
   single intentional defect.
3. Run `node tools/lint-cases.mjs`. It validates the file against
   `fixtures/cases.schema.json`, re-hashes every registered fixture, and
   fails on a fixture file no case registers or an `input` fixture no case
   uses. CI runs the same command in the `conformance` job.
4. Run all four suites. The case must pass in every language; a disagreement
   is the finding, not something to paper over in an adapter.

Field paths in `expected.fields` are language-neutral: the shared camelCase
API names for the four library operations, the literal Apple wire keys for
`verifyReceiptEndpoint`, `x.length` for a collection size,
`list[key=value].field` to select one element, and `null` for "absent or
unset". The `comment` at the top of `cases.json` carries the full grammar and
the sources every expectation was derived from.

One case (`transaction/reject-stale-payload`) carries a `clock`. No library
takes an injectable clock today, so Java, Python and Swift skip it and print
why, while Node fakes time in its runner. A real clock seam would be a
library change in all four languages.

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
