# Roadmap — apple-purchase-receipt-verifier

Milestone status lives here (see [PLAN.md](./PLAN.md) §4 for the full plan).
Delete an item in the same commit that ships it.

## Before 1.0 — the ordered list (2026-09-05)

Everything below is either in this file already or was found by the
2026-09-04 architecture review; this is the order it is being worked in.
Delete a line in the commit that ships it.

1. **Docs cleanup** — done except: the GitHub repository description, a
   repo setting that still names four languages (owner-only).
2. **Release**: approve the held release-please run (first-time
   contributor gate; owner-only), register the signing key on GitHub,
   enforce branch protection for admins, bootstrap RubyGems, crates.io,
   NuGet and the Go proxy, and submit the repository to Packagist
   (the root manifest is landed; see BOOTSTRAP.md).

## Next

- **Matrix additions due** (one line each in `ci.yml`; policy and snapshot
  in `SUPPORT-MATRIX.md`): Java 27 on 2026-09-15, replacing 26 as the
  feature-release leg; Python 3.15 in October 2026; .NET 11 and PHP 8.6 in
  November 2026 (.NET 11 also joins the test projects' `TargetFrameworks`);
  Ruby 4.1 in December 2026; Go 1.28 in February 2027. Floors stay when a
  vendor line ends, so Java 17 (Oracle, 2026-09-30), Python 3.10
  (2026-10-31), .NET 8 and 9 (2026-11-10) and PHP 8.2 (2026-12-31) change
  nothing.
- **README.md's registry table still says the five newer ports are not
  installable.** The Go module is on `proxy.golang.org` as of `go/v0.4.0`,
  so its row and the sentence naming "a public repository for the Go module
  proxy" as a pending owner action are both stale. The RubyGems, crates.io
  and NuGet halves are still true. (The release itself no longer breaks on
  an unbootstrapped registry: `release.yml` asks each of those three whether
  the package exists and skips the publish with a `::notice::` when it does
  not — before OIDC for crates.io and NuGet, and after a failed OIDC for
  RubyGems, whose pending publisher is meant to create the gem — and the
  `smoke` job runs on the registries that did publish.)

- **No branch protection in practice.** main reports protected, yet an
  admin push lands directly, so either the pull-request requirement or
  admin enforcement is off. There is no CODEOWNERS. Commits are
  SSH-signed by the assistant environment's key, which belongs to the
  `claude` GitHub account, so they show Verified when authored as that
  account; CLAUDE.md records the rule (2026-09-06).
- **`asn1crypto` is kept by owner decision (PLAN.md D16)**: last release
  1.5.1 in 2022, about 155M downloads a month. Pin the tested range; the
  python fuzz target runs through it.
- **`jackson-databind` is kept by owner decision (PLAN.md D16)**: the
  heaviest dependency in the project and the one consumer scanners will
  flag, but maintained and widely deployed, and the payloads here are
  small and flat. The 2026-09-06 Java review measured the price: 14.4 MB
  of runtime jars behind a 46 KB library, of which `bcprov` is 10.1 MB
  and `jackson-databind` 1.7 MB. `JwsVerifier` needs BouncyCastle for
  exactly one thing, the P1363-to-DER signature re-encoding (a
  `DERSequence` of two integers, about twenty lines by hand), and binds
  two flat POJOs plus one `Map`, which `jackson-core` alone could do. A
  JWS-only consumer could then drop 12 MB. Revisit if a consumer asks.
- **The `cryptography>=40` floor is never installed.** Every python CI leg
  resolves the latest, so the floor is a claim.
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
- **Post-publish smoke gaps that remain.** The Go, RubyGems, crates.io and
  NuGet legs are wired; only the Go one has ever run against a real registry,
  because the other three are unbootstrapped and their legs skip until they
  are not. Two holes are left. **PHP has no leg**: Packagist has no publish
  job — the tag is the release — so there is no step of ours to verify, and
  `tools/php-consumer-smoke.mjs` already installs the real `git archive` in
  the `php-static` CI job; a Packagist leg would only be testing Composer.
  **The .NET leg tests one of the two shipped assets**: `net8.0` selects
  `lib/net8.0`, and `lib/netstandard2.0` needs a `net472` consumer on a
  Windows runner (`dotnet/RELEASE.md`).
- **Unity smoke test for the .NET port**: the `dotnet-mono` CI job is evidence
  that the netstandard2.0 asset loads outside CoreCLR, not that it runs in an
  IL2CPP player. Until something exercises a real player build, the README
  must not claim Unity support.
- **`ruby/gemfiles/*.gemfile` are invisible to dependabot**: the lint and
  type toolchain (`tools.gemfile`) and the fuzzer (`fuzz.gemfile`) now have
  committed locks and CI installs them frozen, but dependabot's bundler
  ecosystem only discovers a manifest named `Gemfile` or `gems.rb`, which is
  why `.github/dependabot.yml` points at `/ruby`. Until those two files are
  renamed, rubocop, rbs, steep and ruzzy are bumped by hand.
- **Dependency bumps inside the seven-day cooldown** land via dependabot on
  their own; swift-certificates 1.20.0 and swift-asn1 1.7.2 (released
  2026-09-01) will arrive that way.
- **The RustCrypto 0.11/0.14 wave is deliberately not taken** (2026-09-05):
  `digest` 0.11, `sha1`/`sha2` 0.11 and `p256`/`p384` 0.14 all set
  `rust-version = 1.85` against this crate's 1.74.0 floor, and `rsa` is
  still 0.9 on `digest` 0.10 (0.10 is an rc), so the trait versions would
  not line up. The five bumps (PRs #22–#24, #26, #27) are closed and the
  versions are ignored in `.github/dependabot.yml`'s cargo entry; the
  `@dependabot ignore` comments on the PRs never reached the bot. Take the
  whole wave in one commit once `rsa` 0.10 is stable, and raise the MSRV
  to 1.85 in the same change (a D2-class decision).
- **Three Dependabot alerts on `node/package-lock.json` stay open**
  (2026-09-05): `decompress` 4.2.1 (critical, Zip Slip) and two moderates
  in the chain `@fastly/js-compute` → `@bytecodealliance/weval` →
  `decompress`. All dev-only: the Fastly package exists for the
  `node-runtimes-fastly` job and is not in `dependencies`, so nothing
  published carries it. No fix to take: 3.45.0 is the newest Fastly
  release, `weval` 0.4.1 still depends on `decompress ^4.2.1`, and
  `decompress` has no release after 4.2.1. `weval` uses it to unpack its
  own binary from a GitHub release at install time, not to read input the
  tests supply. Dismiss the alerts as "vulnerable code is not actually
  used" (an owner action in the Security tab) and re-check when a Fastly
  release drops `weval` or `weval` drops `decompress`.

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
