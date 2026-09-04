# Roadmap — apple-purchase-receipt-verifier

Milestone status lives here (see [PLAN.md](./PLAN.md) §4 for the full plan).
Delete an item in the same commit that ships it.

## Next

- **The three remaining parser differentials.** The compact-JWS segment
  differential is closed (see the strict-decoding commit); three more are
  recorded in the port READMEs and still have no shared vector:
  1. **`x5c[2]`**: java decodes and parses the third certificate, so an
     unparseable one is `INVALID_CERTIFICATE` there and reaches the
     signature check in node, python, swift, rust and the rest. It is
     untrusted by design everywhere, so no verdict about a well-formed JWS
     moves -- but the ports disagree about a malformed one and nothing
     pins it.
     Since the receipt-base64 change, go additionally rejects junk inside
     an x5c entry (its receipt decoder is shared with x5c), where the other
     ports skip it -- the same open question, one port wider.
  2. **Resource bounds differ by an order of magnitude and are absent in
     five ports.** Measured: node budget 200,000 (ruby), 100,000 (rust,
     go), 20,000 (php), and no constant at all in node, python, java,
     dotnet, swift. Receipt size cap 8 MiB (rust), 2 MiB (php), 1 MiB
     (go), unfound elsewhere. Only php caps the JWS input. Genuine
     receipts are under 80 KB and 3,000 nodes so nothing breaks today,
     but the contract should state a normative floor -- every port MUST
     accept a well-formed receipt up to N bytes and M nodes -- and a
     vector should pin it, or a large legitimate receipt becomes another
     port-dependent verdict.
  3. **Chain path length**: java lets the JDK PKIX builder cap it at 5
     while every hand-rolled walk uses 6.
- **Fuzzing runs opposite to parser size.** go has three fuzz targets and
  seed corpora on every build; rust now has seven under `rust/fuzz/`
  (the ASN.1, X.509 and CMS readers on their own, the three verifiers,
  and the endpoint body), run for a fixed budget by the `rust-fuzz` CI
  job. dotnet (3,896 lines) and php (3,271) still have none. The
  deterministic mutation corpora node, rust and php do have are
  regression tests, not fuzzing.
- **No test proves the OS trust store is unreachable in swift, python,
  node or java.** go (`systemtrust_test.go`), rust (`trust_pinning.rs`),
  php (`PinnedAnchorsTest.php`) and ruby each install or point at a CA the
  platform would accept and require the library to reject it anyway.
  Swift is the port most likely to reach Security.framework by accident
  and is one of the four without such a test.
- **`THREAT-MODEL.md` does not exist.** PLAN.md 2.3 is fifteen lines and
  the rest is spread across nine port READMEs, each restating pinned
  anchors, no network and the marker OIDs. One page -- assets, attacker
  capabilities, what is in scope, what is explicitly out, and the test
  that proves each line -- is the first thing a security reviewer asks
  for.
- **java/ and swift/ have no README.** They are the first two ports
  published, and Maven Central shows only the pom description. The five
  ports written later each carry a reason-code table, a trust-model
  section and a clock-seam explanation that java and swift consumers do
  not get.
- **1,817 lines of `ci-job.md` and `RELEASE.md` now contradict the real
  files.** They were the right artefact for handing a port's CI and
  release wiring over, and the wrong one to keep once it is wired:
  `rust/RELEASE.md` still carries a literal `<pin to a full commit SHA>`
  placeholder, `ruby/RELEASE.md` opens with "Nothing here has been
  applied" while its publish job exists, and `php/ci-job.md` says a SHA is
  unresolved that ci.yml resolved. Delete them, or reduce each to a
  pointer at the file that superseded it.
- **Stale counts and language lists in the docs.** INTENT.md names a
  single root for each path where D15 pins all three; PLAN.md 4's
  milestone list stops at four languages and leaves "CI workflow per
  language" unchecked against 40 jobs; dotnet/README.md says 56 cases;
  several files still say "all four languages".
- **An unbootstrapped registry fails the release rather than skipping
  it.** Every publish job skips loudly when the registry already has the
  version, but rubygems, crates and nuget each fail at their OIDC step
  when the registry has never been set up -- and the `smoke` job needs all
  seven, so one unbootstrapped registry blocks post-publish verification
  of the four that are live. README.md reads as though those ports were
  merely waiting.

- **No branch protection in practice.** main reports protected, yet an
  admin push lands directly, so either the pull-request requirement or
  admin enforcement is off. There is no CODEOWNERS, no commit signing,
  and 82 of 83 commits are authored by the assistant rather than
  co-authored by it.
- **`asn1crypto` is the one attacker-facing parser the project neither
  wrote nor fuzzes**, and its last release was 1.5.1 in 2022. Every other
  port parses hostile bytes with its own bounded reader or a first-party
  library. Decide before 1.0 whether python keeps it.
- **`jackson-databind` is the heaviest dependency in the project** and
  carries the CVE history a consumer's scanner will surface. The dotnet
  port faced the same choice and wrote a bounded JSON reader instead; the
  payloads here are small and flat.
- **The `cryptography>=40` floor is never installed.** Every python CI leg
  resolves the latest, so the floor is a claim.
- **Internal RBS signatures for the Ruby port**: `sig/` covers the public
  API and `rbs validate` proves it well-formed, which is what a consumer
  type-checks against. `steep check` also wants a signature for every
  private method and internal constant and reports 411 diagnostics
  without them, so the CI job does not run it. Writing those signatures
  makes the step viable; until then the gap is stated in `ci.yml` rather
  than hidden behind a job nobody runs.
- **Real receipt fixtures** (PLAN D6): owner to supply real production +
  sandbox receipts (and ideally a StoreKit-Test/Xcode receipt) as checked-in
  fixtures; add byte-level regression tests over them in every suite.
  Also use the corpus to confirm undocumented attribute ids
  (`is_trial_period`, `adam_id`, `version_external_identifier`) so
  COMPARISON.md's "not produced" list can shrink.
- **Mac App Store receipt fixture**: the harvest (fixtures/public-receipts/,
  done ✅ — genuine sandbox + legacy receipts verify in every
  language) covered iOS; a genuine macOS receipt is still missing.
- **Node 20 floor**: Node 20 reached end of life on 2026-04-30; raising the
  engines floor to 22 is a semver-major decision, nothing in the code needs
  it yet. Revisit when @types/node's pin (see .github/dependabot.yml) starts
  blocking a needed update.
- **Akamai EdgeWorkers**: the only runtime the README's WebCrypto list
  rests on an argument rather than a run, because there is no local
  runtime to run it in. Vercel Edge, Fastly Compute and flagless
  Cloudflare Workers are all tested on every push.
- **Post-publish smoke jobs for the five newer ports**:
  `post-publish-smoke.yml` still covers npm, PyPI, Maven Central and SwiftPM
  only. The Go, RubyGems, crates.io and NuGet legs are written out in each
  port's `RELEASE.md` and need their smoke programs under `.github/smoke/`
  before they can be wired. The Go one is the one that would catch the
  embedded `roots/certs` copy being absent from the module zip, which is the
  Go-shaped version of the incident that motivated that workflow. Add each leg
  with that registry's first release (see BOOTSTRAP.md).
- **Unity smoke test for the .NET port**: the `dotnet-mono` CI job is evidence
  that the netstandard2.0 asset loads outside CoreCLR, not that it runs in an
  IL2CPP player. Until something exercises a real player build, the README
  must not claim Unity support.
- **`ruby/gemfiles/tools.gemfile.lock`**: not committed, so `ruby-tools`
  resolves the lint and type toolchain on every run and cannot use
  `bundler-cache: true`. Dependabot cannot see that file either — its bundler
  ecosystem only discovers a manifest named `Gemfile` or `gems.rb`, which is
  why `.github/dependabot.yml` points at `/ruby` instead. Generating the lock
  and renaming the gemfile fixes both at once.
- **Dependency bumps inside the seven-day cooldown** land via dependabot on
  their own; swift-certificates 1.20.0 and swift-asn1 1.7.2 (released
  2026-09-01) will arrive that way.

## Upstream

Proposed our verified legacy-receipt validation as a PR in all four
languages (java#268, swift#133, python#208, node#427, filed against
issues #267/#132/#207/#426). Apple closed all four on 2026-08-27 as
"deprecated format, not adding this level of verification"
(https://github.com/apple/app-store-server-library-java/issues/267#issuecomment-5433242622).
The fork branches `app-receipt-verification` are kept current with
upstream main (merged 2026-09-02) so the PRs can be reopened if Apple
reconsiders.

Still worth filing as issues:

- **Foot-gun report**: `SignedDataVerifier` silently skips ALL signature
  verification when the configured environment is XCODE / LOCAL_TESTING.
  A production service misconfigured to a test environment would accept
  forged payloads with no error. An explicit opt-in flag (e.g.
  `allowUnverifiedTestPayloads`) would make the danger visible.
- **Java 8 support question**: upstream requires Java 11; large enterprise
  fleets still run 8 (why our Java build targets it). Worth asking if a
  lowered floor or a maintained 8-compatible artifact would be accepted.

## Later / hardening

- Decide whether to support the ancient `transactionReceipt`
  (purchase-info) format at all (double-wrapped payloads are handled ✅).
- **Dev-mode environments**: Apple's `SignedDataVerifier` deliberately
  skips signature verification for XCODE / LOCAL_TESTING payloads (they
  aren't Apple-signed). Our verifiers hard-fail them on chain validation.
  If local-testing support is ever needed, add an explicit, loudly-gated
  insecure dev mode — never reachable from production config.
- Optional OCSP revocation checking (opt-in "online mode", like the official
  library) for consumers who accept Apple calls.
- Notification-envelope convenience (typed `verifyNotification` that also
  verifies nested `signedTransactionInfo` / `signedRenewalInfo`) — today
  `verifyRaw` covers notifications with caller-side claim checks.
- Example integration snippet: "client sends `jwsRepresentation` → backend
  verifies → backend records transactionId (replay guard) → unlock product".
