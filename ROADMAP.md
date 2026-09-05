# Roadmap — apple-purchase-receipt-verifier

Milestone status lives here (see [PLAN.md](./PLAN.md) §4 for the full plan).
Delete an item in the same commit that ships it.

## Before 1.0 — the ordered list (2026-09-05)

Everything below is either in this file already or was found by the
2026-09-04 architecture review; this is the order it is being worked in.
Delete a line in the commit that ships it.

1. **Normative resource bounds in the contract** plus one vector. (Java's
   chain length is aligned: it now states MAX_PATH_LENGTH = 6 and counts
   self-issued intermediates, which the JDK default exempted.)
2. **Docs cleanup** — done except: java and swift READMEs (neither port
   has one), and the GitHub repository description, a repo setting that
   still names four languages (owner-only).
3. **Pin the five hostile-JWS inputs python fuzzing found as contract
   vectors**, so all nine ports answer them identically: a non-string
   `x5c` entry, `signedDate` 1e300/NaN/Infinity, one corrupt extension in
   an `x5c` certificate, an unimplemented EC curve in the issuer check,
   and a certificate with version 11. Python now fails each closed with
   node's reason; the other seven have not been asked.
4. **Release**: approve the held release-please run (first-time
   contributor gate; owner-only), register the signing key on GitHub,
   enforce branch protection for admins, bootstrap RubyGems, crates.io,
   NuGet and the Go proxy, and decide the PHP Packagist layout.

## Next

- **The two remaining parser differentials.** The compact-JWS segment
  differential is closed (see the strict-decoding commit); two more are
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
  admin enforcement is off. There is no CODEOWNERS. Commits are
  SSH-signed by the assistant environment's key (verified with git
  cat-file); GitHub shows them Verified once that key is registered as a
  signing key on the owner's account. Most commits are authored by the
  assistant rather than co-authored by it.
- **`asn1crypto` is kept by owner decision (PLAN.md D16)**: last release
  1.5.1 in 2022, about 155M downloads a month. Pin the tested range; the
  python fuzz target runs through it.
- **`jackson-databind` is kept by owner decision (PLAN.md D16)**: the
  heaviest dependency in the project and the one consumer scanners will
  flag, but maintained and widely deployed, and the payloads here are
  small and flat.
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
- **The RustCrypto 0.11/0.14 wave is deliberately not taken** (2026-09-05):
  `digest` 0.11, `sha1`/`sha2` 0.11 and `p256`/`p384` 0.14 all set
  `rust-version = 1.85` against this crate's 1.74.0 floor, and `rsa` is
  still 0.9 on `digest` 0.10 (0.10 is an rc), so the trait versions would
  not line up. Dependabot was told to ignore those majors (PRs #22–#24,
  #26, #27). Take the whole wave in one commit once `rsa` 0.10 is stable,
  and raise the MSRV to 1.85 in the same change (a D2-class decision).

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
