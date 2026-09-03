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

One decision the vectors cannot hold: `verifyReceiptCore` (`verify_receipt_core`
in Python, `verifyCore` in Swift) is public in all four ports, so the endpoint
calls it directly instead of building a `ReceiptVerifier` with a wildcard
bundle id. Both spellings answer identically, so no case can tell them apart —
the four native suites pin that one, and Swift's `PublicApiTests` imports the
module without `@testable` so the visibility is checked at compile time.

### Adding a case

1. Register the fixture in the `fixtures` map if it is not there yet: `path`
   relative to `fixtures/`, `role` (`input`, `trust-anchor` or `support`),
   `codec` (`raw`, `base64` or `utf8`), and the file's `contentSha256` — the
   SHA-256 of the DECODED bytes, the ones the library is handed, not of the
   file as stored. That digest is enforced, not recorded: `lint-cases.mjs`
   re-hashes every registered fixture, and so does every adapter, over the
   whole registry before any case runs and again for each fixture a case
   loads. Regenerating or re-encoding a fixture without updating the digest
   fails all four suites.
2. Append the case: a unique `id` shaped `<area>/<what-it-pins>`, a
   `description` of the fact it pins, the `operation` (`verifyTransaction`,
   `verifyAppTransaction`, `verifyRaw`, `verifyReceipt` or
   `verifyReceiptEndpoint`), `input.fixture`, the `config`, and `expected`.
   A positive case carries `status: "ok"` plus the `fields` it pins; a field
   it does not list is not pinned. A negative case carries `status: "error"`
   plus a `reason` from the canonical vocabulary, and a `fault` naming its
   single intentional defect. Add a `clock` if — and only if — the answer
   depends on the current time; see below.
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

### Generating a fixture

Fixtures under `fixtures/generated/` are signed by a fake Apple PKI built in
`java/src/test/.../TestPki.java`, so no real Apple key material is needed.
Two generators write them, both at fixed epoch instants so nothing depends on
generation time:

- `FixtureGeneratorTest` — the original set. Gated behind
  `mvn test -Dtest=FixtureGeneratorTest -Dfixtures.generate=true`.
- `PortDivergenceFixtures` — the receipt whose attribute type is above
  2^31-1, and the receipts and payloads carrying no date of their own. It is
  a `main`, not a test, so it costs the suite no permanently skipped test;
  the class javadoc carries the exact command.

Every run mints fresh keys, so regenerating changes every byte and every
`contentSha256` that records it. The signing keys are deliberately not kept:
a fixture cannot be re-signed under a root that is already published, which
is why each generator emits its own roots beside its inputs.

### The clock

A case may carry a `clock`: one ISO-8601 UTC instant, the `now` the call is
answered at. All four libraries take an optional clock — `java.time.Clock`, a
`() => Date` supplier, a callable returning epoch seconds, a
`@Sendable () -> Date` — and each adapter hands the case's instant to the
verifier it builds. No runner fakes time and no runner skips a case for want
of a seam. A case without a `clock` gets no clock argument, so the library
reads the system clock exactly as a caller who never sets one does.

Pin a clock where the answer genuinely moves with time: the max-signed-age
(`STALE_PAYLOAD`) rule, and the `request_date` triple of
`verifyReceiptEndpoint`. Certificate validity is not such a place — it is
judged at the payload's `signedDate` or the receipt's creation date, and
where the input states neither, at the system clock (PLAN.md 2.1 step 4, 2.2
step 2). The expired-chain cases are deterministic and no injected clock may
move their verdict.

Pin a clock, too, to prove an answer does *not* move with it. Four cases run
an input carrying no date of its own — `receipt-no-creation-date`,
`receipt-expired-no-creation-date`, `transaction-no-signed-date`,
`transaction-expired-chain-no-signed-date` — under a clock planted inside an
expired certificate's window, or far past a live one's, and must reach the
verdict real time gives. That is where the "else current time" fallback is
held to the system clock: a caller who injects a clock to test staleness, or
to work around skew, must not thereby accept a chain that has expired.

`verifyReceipt` cases cannot pin one — the case shape in
`cases.schema.json` has no `clock`, so the linter rejects it. No port gives
`ReceiptVerifier` a clock parameter: no verdict on that path moves with the
current time, and its one "now" is a certificate-validity instant an injected
clock must not be able to shift. The clock option lives on the JWS verifier
(max signed age) and on the endpoint (`request_date`), and nowhere else.

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
