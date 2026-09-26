# Contributing

Nine implementations of the same verifier — Java, Node, Python, Swift, Go,
Ruby, Rust, PHP and .NET — kept in lockstep by one shared fixture suite. A
behavior change lands in all nine languages plus `fixtures/`, or it doesn't
land.

The same holds for features that do not change behavior, such as a new
entry point, a fast path or a benchmark: a feature lands in every port, or
[PORTS.md](./PORTS.md) says why a port does not have it. Update that table
in the PR that adds the feature.

## Running the tests

Each language runs the same fixtures:

```bash
cd java   && mvn test
cd node   && npm ci && npm test
cd python && uv sync && uv run python -m unittest discover -s tests
swift test   # manifest is at the repo root
cd go     && go test ./...
cd ruby   && rake test
cd rust   && cargo test
cd php    && composer install && vendor/bin/phpunit
cd dotnet && dotnet test -c Release

node tools/lint-cases.mjs   # the shared conformance vectors, see below
```

CI runs these on every supported runtime line (Java 8–25, Node 20–26,
Python 3.10–3.14, Swift 6, Go 1.22–1.27, Ruby 3.1–4.0, Rust 1.85 through beta,
PHP 8.1–8.5, .NET on Linux, Windows and macOS). The floors are claims we test,
not decoration: `@types/node` stays on 20 and JUnit stays on 5.x on purpose —
see the rationale comments in `.github/dependabot.yml` before "upgrading"
them.

## Adding or bumping a dependency by hand

`.github/dependabot.yml` holds every automated bump for seven days after the
release, the window in which a hijacked version usually gets pulled. A manual
`npm install`, `composer require` or gem bump skips that window. Check the
publish date before you commit the lockfile change:

```bash
npm view <package>@<version> time.modified
```

Under seven days old: wait, or say in the commit body why it cannot. CI
installs npm packages with `--ignore-scripts`; a dependency that needs its
install script to work is a reason to look for another dependency.

Every ecosystem that has a lockfile commits it, and CI installs from it
strictly, so a bump reaches CI only as a committed change to a lockfile
(SECURITY.md, "Dependency policy"). Regenerate the file the port names when
you change a manifest:

| Port | Lockfile | Regenerate with |
|---|---|---|
| node | `node/package-lock.json`, `node/fuzz/package-lock.json` | `npm install` |
| rust | `rust/Cargo.lock`, `rust/ffi/Cargo.lock` | `CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback cargo +stable generate-lockfile` in each; a plain `cargo update` ignores `rust-version` and can lock crates the declared floor cannot build |
| rust | `rust/fuzz/Cargo.lock` | `cargo generate-lockfile` in `rust/fuzz` |
| python | `python/uv.lock` | `uv lock` |
| php | `php/composer.lock` | `composer update` (resolves at the 8.1 floor, see below) |
| ruby | `ruby/Gemfile.lock`, `ruby/gemfiles/*.lock` | `bundle lock` with the matching `BUNDLE_GEMFILE` |
| dotnet | `dotnet/**/packages.lock.json` | `dotnet restore --force-evaluate` under the newest SDK line `ci.yml` installs (10.0.x); an older band asks for a different implicit ILLink version and fails locked mode |
| swift | `Package.resolved`, `swift/fuzz/Package.resolved` | `swift package update` |
| go | `go/tools/go.sum` | `go get` then `go mod tidy` in `go/tools` |

`php/composer.json` sets `config.platform.php` to 8.1.0, so a `composer
update` on any machine resolves the graph the PHP 8.1 leg has to install.
The Java port pins exact versions in `java/pom.xml` and Maven has no lockfile
format; the go library module has no dependencies at all.

## Conformance vectors

`fixtures/cases.json` is the normative contract between the nine
implementations: one language-neutral case per semantic fact, each naming a
registered fixture, the verifier config to build from it, and either the
payload fields the call must return or the canonical reason it must raise.
Each language reads the file through a thin adapter that knows nothing about
any individual case — `java/src/test/.../ConformanceCasesTest.java`,
`node/test/conformance.test.js`, `python/tests/test_conformance.py`,
`swift/Tests/.../ConformanceCasesTests.swift`, `go/conformance_test.go`,
`ruby/test/conformance_test.rb`, `rust/tests/conformance.rs`,
`php/tests/ConformanceCasesTest.php` and
`dotnet/tests/ApplePurchaseReceiptVerifier.Tests/Conformance.cs`.

**A behavior change means editing `cases.json` in the same commit.** The file
records what was decided, not what an implementation happened to do, so a
vector that disagrees with an implementation is a bug report against that
implementation until a human rules otherwise. Changing a returned field or a
raised reason without updating the vector leaves every suite disagreeing
with the contract.

One decision the vectors cannot hold: `verifyReceiptCore`
(`verify_receipt_core` in Python, Ruby and Rust, `verifyCore` in Swift and
.NET) is public in every port, so the endpoint calls it directly instead of
building a `ReceiptVerifier` with a wildcard bundle id. Both spellings answer
identically, so no case can tell them apart — the native suites pin that one,
and Swift's `PublicApiTests` imports the module without `@testable` so the
visibility is checked at compile time.

### Adding a case

1. Register the fixture in the `fixtures` map if it is not there yet: `path`
   relative to `fixtures/`, `role` (`input`, `trust-anchor` or `support`),
   `codec` (`raw`, `base64` or `utf8`), and the file's `contentSha256` — the
   SHA-256 of the DECODED bytes, the ones the library is handed, not of the
   file as stored. That digest is enforced, not recorded: `lint-cases.mjs`
   re-hashes every registered fixture, and so does every adapter, over the
   whole registry before any case runs and again for each fixture a case
   loads. Regenerating or re-encoding a fixture without updating the digest
   fails every suite.
2. Append the case: a unique `id` shaped `<area>/<what-it-pins>`, a
   `description` of the fact it pins, the `operation` (`verifyTransaction`,
   `verifyAppTransaction`, `verifyRaw`, `verifyReceipt`,
   `verifyReceiptBase64` or `verifyReceiptEndpoint`), `input.fixture`, the
   `config`, and `expected`. A base64 spelling is a `decodeBase64` group
   instead; see "Adding a base64 spelling" below.
   A positive case carries `status: "ok"` plus the `fields` it pins; a field
   it does not list is not pinned. A negative case carries `status: "error"`
   plus a `reason` from the canonical vocabulary, and a `fault` naming its
   single intentional defect. Add a `clock` if — and only if — the answer
   depends on the current time; see below.
3. Run `node tools/lint-cases.mjs`. It validates the file against
   `fixtures/cases.schema.json`, re-hashes every registered fixture, and
   fails on a fixture file no case registers or an `input` fixture no case
   uses. CI runs the same command in the `conformance` job.
4. Run all nine suites. The case must pass in every language; a disagreement
   is the finding, not something to paper over in an adapter. Every runner
   also checks that each case id in the file ran, so a case an adapter
   silently skips fails the suite. Only an explicit test filter turns that
   check off.

### Adding a base64 spelling

The `receipt-data` and `x5c` base64 spellings live in `cases.json` as
`decodeBase64` groups, one list for all nine ports. Do not add a spelling
list to a port's own tests. Put the string in the group for its category
(`base64/reject-whitespace-inside`, `base64/decodes-to-41`, ...) or start a
new group:

- `input.texts` holds the exact strings; the empty string and control
  characters are allowed. A string appears in one group only.
- An accepting group has `expected: {"status": "ok", "bytesHex": "<hex>"}`,
  the bytes every text decodes to. A refusing group has
  `expected: {"status": "error", "reason": "INVALID_RECEIPT_FORMAT"}`.
- `decoders` names the decoders the group runs through, normally
  `["receipt-data", "x5c"]`. Each runner calls the port's decoders
  directly. A refusal is `INVALID_RECEIPT_FORMAT` from the receipt-data
  decoder and `INVALID_CERTIFICATE` from the x5c decoder; the runner maps
  the reason, so a case never repeats it.
- The `description` says why, citing the Apple measurement in
  `docs/evidence/2026-09-23-verifyreceipt-base64.md` where there is one.

`lint-cases.mjs` checks each spelling against the rule on its own and
refuses a string listed twice. When a text fails, the runner names the case
id, the index and the escaped text.

Field paths in `expected.fields` are language-neutral: the shared camelCase
API names for the library operations, the literal Apple wire keys for
`verifyReceiptEndpoint`, `x.length` for a collection size,
`list[key=value].field` to select one element, and `null` for "absent or
unset". The `comment` at the top of `cases.json` carries the full grammar and
the sources every expectation was derived from.

### Generating a fixture

Fixtures under `fixtures/generated/` are signed by a fake Apple PKI built in
`java/src/test/.../TestPki.java`, so no real Apple key material is needed.
Twelve generators write them, all at fixed epoch instants so nothing depends
on generation time:

- `FixtureGeneratorTest` — the original set. Gated behind
  `mvn test -Dtest=FixtureGeneratorTest -Dfixtures.generate=true`.
- `PortDivergenceFixtures` — the receipt whose attribute type is above
  2^31-1, and the receipts and payloads carrying no date of their own.
- `HostileReceiptFixtures` — the four defective-signer receipts, the
  receipt-path twins of the `x5c` certificate mutations
  `HostileJwsFixtures` builds.
- `HostileJwsFixtures` — the eight hostile-JWS fixtures Python's
  coverage-guided fuzzing found escaping the library as bare exceptions,
  plus the `x5c[2]` vector that closed the last parser differential.
- `JwsSegmentFixtures` — the six empty-or-non-object compact-JWS segment
  fixtures (RFC 7515 §7.1 requires the first two segments to decode to JSON
  objects).
- `LargeReceiptFixture` — the two receipts pinning the contract's
  normative resource floor: 1,048,576 bytes of DER and 20,000 ASN.1 nodes
  in a single parse.
- `AbsentSignerFixture` — the receipt that separates "the signer is not in
  the bag" from "something in the bag is not a certificate".
- `ReceiptIdsFixture` — the receipt carrying the four attributes that used
  to sit in `unknownAttributes`: app-level 1, 15 and 16, and in-app 1713.
- `ReceiptCmsDefectFixtures` — the four receipts whose single defect sits in
  the CMS structure rather than in a certificate or in the payload: a
  receipt-signing end entity standing where the intermediate belongs, the
  intermediate absent from the certificate bag, a SignerInfo signature of
  zero bytes, and a CMS signed over zero bytes of encapsulated content.
- `X5cBase64Fixtures` — the five transactions whose `x5c[0]` is the
  genuine leaf spelled as something other than canonical standard base64
  (RFC 7515 §4.1.6): a junk character inside it, the base64url alphabet,
  PEM-style line breaks, the `=` padding omitted, and one `=` too many.
- `VerificationOrderFixtures` — the seven receipts that pin the legacy
  verification order: a creation date that is unreadable or stated twice,
  and a top-level entry or in-app purchase that cannot be read, each under
  a trusted, a foreign or an expired chain as the vector needs, with their
  own trusted and expired roots.
- `ReceiptBase64CapFixture` — the receipt string at the base64 receipt cap,
  `fixtures/limits/receipt-b64-at-cap.txt`: the canonical base64 of a
  genuinely signed receipt of 2,359,296 bytes, which is exactly 3,145,728
  characters. It takes `fixtures` rather than `fixtures/generated` as its
  argument, and `node tools/generate-limit-fixtures.mjs` must run after it,
  because the over-cap twin is built from its output.

The last eleven run as a `main`, not a `@Test`, so none of them costs the
suite a permanently skipped test. All eleven regenerate the same way, only
the class name changes:

```bash
mvn -B -q -f java/pom.xml test-compile
mvn -B -q -f java/pom.xml dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt
java -cp "java/target/test-classes:java/target/classes:$(cat /tmp/cp.txt)" \
     io.github.emindeniz99.applepurchasereceiptverifier.<ClassName> \
     fixtures/generated
node tools/lint-cases.mjs   # re-hash: every contentSha256 must be updated
```

Every run mints fresh keys, so regenerating changes every byte and every
`contentSha256` that records it. The signing keys are deliberately not kept:
a fixture cannot be re-signed under a root that is already published, which
is why each generator emits its own roots beside its inputs.

### The clock

A `verifyReceiptEndpoint` case may carry a `clock`: one ISO-8601 UTC
instant, the `now` the call is answered at. Every library's
`VerifyReceiptEndpoint` takes an optional clock (`java.time.Clock`, a
`() => Date` supplier, a callable returning epoch seconds, a
`@Sendable () -> Date`, a `Clock` trait, a PSR-20 `ClockInterface`, an
`IClock`), and each adapter hands the case's instant to the endpoint it
builds. No runner fakes time and no runner skips a case for want of a seam.
A case without a `clock` gets no clock argument, so the library reads the
system clock exactly as a caller who never sets one does.

Pin a clock where the answer genuinely moves with time: the `request_date`
triple of `verifyReceiptEndpoint`. Certificate validity is not such a place:
it is judged at the payload's `signedDate` or the receipt's creation date,
and where the input states neither, at the system clock (PLAN.md 2.1 step 4,
2.2 step 2). The expired-chain cases are deterministic and no injected clock
may move their verdict.

Pin a clock, too, to prove an answer does *not* move with it. Two endpoint
cases run a receipt carrying no creation date (`receipt-no-creation-date`,
`receipt-expired-no-creation-date`) under a clock planted inside an expired
certificate's window, or far past a live one's, and must reach the verdict
real time gives. That is where the "else current time" fallback is held to
the system clock: a caller who injects a clock to pin `request_date`, or to
work around skew, must not thereby accept a chain that has expired.

No other operation can pin one: the case shapes in `cases.schema.json` for
`verifyTransaction`, `verifyAppTransaction`, `verifyRaw`, `verifyReceipt`
and `verifyReceiptBase64` have no `clock`, so the linter rejects it. No port
gives `JwsVerifier` or `ReceiptVerifier` a clock parameter: no verdict on
those paths moves with the current time, and their one "now" is a
certificate-validity instant an injected clock must not be able to shift.
How old a signed payload may be is the caller's decision, so no case pins
one.

## Spikes and evidence

Every experiment's code goes into the repo, even code that answered "no":
a note at `docs/evidence/<date>-<name>.md` and its sources in
`docs/evidence/<date>-<name>/`, committed together. See
[docs/evidence/README.md](docs/evidence/README.md) for the layout.

## Commits

Conventional Commits with a **mandatory scope**:

```
<type>(<scope>): <imperative subject, lowercase, ≤72 chars total>
```

- Types: `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `chore`, `build`, `ci`, `revert`.
- Scopes are areas: `java`, `node`, `python`, `swift`, `go`, `ruby`, `rust`,
  `php`, `dotnet`, `jvm-interop`, `fixtures`, `certs`, `ci`, `release`,
  `docs`, `repo`.
- Body explains *why* (constraint, incident, trade-off), not what the diff
  already shows. Wrap at 72 chars.
- `feat`/`fix` drive release-please's version bump — use them only for
  user-visible changes.

## Merging

Pull requests merge with a **real merge commit** — never squash, never
rebase-merge. Per-commit history is the record of how the work was built;
squashing erases it irreversibly. (Squash and rebase merges are disabled in
the repo settings.)

Give the merge commit a body of the form `Merges #57: <PR title without its
type(scope) prefix>`, not GitHub's default, the bare PR title, which is a
Conventional Commit line. release-please reads merge commit bodies as commits
too, so a conventional body there duplicates the entry the branch commit
already produces (0.4.0's changelog lists `deps: Bump actions/setup-go from
6.5.0 to 7.0.0` twice for exactly this reason). Dropping only the prefix
keeps `git log` readable; the type, scope and any breaking marker still live
on the branch commit, which release-please does read.

## Releases

Fully automated — do not publish from a laptop:

1. Conventional Commits on `main` → release-please opens/updates a release PR
   (one version for every language; extra-files bump every manifest that
   carries a version string, and a step in the same workflow regenerates
   the three lockfiles that carry it too).
2. Merging that PR creates the tag + GitHub Release, and the workflow
   dispatches `release.yml` at the tag.
3. `release.yml` publishes to npm (OIDC), PyPI (OIDC), RubyGems (OIDC),
   crates.io (OIDC), NuGet (OIDC) and Maven Central (token + GPG), and creates
   the `go/vX.Y.Z` tag that publishes the Go module through
   `proxy.golang.org`. SwiftPM consumes the plain tag directly. PHP is not
   published from this repository — see `BOOTSTRAP.md`.

Every publish job is version-gated: it skips loudly if the registry already
has that version, so re-runs are safe, and each one proves the built artifact
carries the library before pushing it. **Never rename `release.yml`** — npm,
PyPI, RubyGems, crates.io and NuGet trusted publishing all match the workflow
filename.

Four of the nine registries are not live yet: each needs a one-time owner
action, listed per registry in [BOOTSTRAP.md](./BOOTSTRAP.md).

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
