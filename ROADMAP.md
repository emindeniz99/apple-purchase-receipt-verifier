# Roadmap — apple-purchase-receipt-verifier

Milestone status lives here (see [PLAN.md](./PLAN.md) §4 for the full plan).
Delete an item in the same commit that ships it.

## Next

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
- **WebCrypto-only runtimes** (Vercel Edge, Fastly Compute): unsupported
  and documented as such. Supporting them means parsing X.509 with our own
  DER parser and verifying through `crypto.subtle`, which is async, so
  `verify()` would change shape. Wait for a request.
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
