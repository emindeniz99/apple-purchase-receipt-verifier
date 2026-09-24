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

- **Endpoint result API, base64 fast path and input caps: done ✅**
  (2026-09-22, #114 to #133). Every port's endpoint returns a
  `VerifyReceiptResult` with a verified flag and re-renders for the other
  environment without verifying again; every port decodes canonical base64
  on a fast path held to the tolerant decoder by a differential test; every
  port caps the receipt and the request body at Apple's 3,145,728 UTF-8
  bytes (measured 2026-09-23, COMPARISON.md), JSON depth at 64 and the JWS
  at 256 KiB, and `fixtures/cases.json` holds every cap as a MUST from both
  sides. Swift's release-build crash on Linux x86_64 with
  Swift 6.3.3 is fixed (#126), and CI now runs the Swift tests in release
  mode. PORTS.md has the per-port detail. The tolerant decoder and its
  fast path were replaced on 2026-09-23 by the rule Apple's verifyReceipt
  was measured to apply, canonical standard base64 only (THREAT-MODEL.md
  §3.8).
- **0.6.0 release notes must warn Swift users of 0.4.0 to 0.5.1**: release
  builds of those versions crash on a genuine receipt on Linux x86_64
  under Swift 6.3.3 (a miscompiled throw path, #126). Debug builds and
  tests pass, so a consumer's CI does not show it. Tell them to upgrade.
- **JWS cap, to be discussed**: it stays at 262,144 bytes. The request and
  receipt caps now match Apple's measured limit; nobody has checked whether
  Apple states a size limit for a JWS anywhere we could match.
- **SwiftPM checkouts carry the fixtures (owner decision)**: SwiftPM
  consumers check out the whole repository, and `fixtures/limits/` adds
  about 21.5 MB on disk to every checkout. The git transfer stays small
  because git compresses the padding. Package.swift declares only `certs`
  as resources, so nothing ships in a built product.
- **Cross-port benchmarks** (in progress): only `java-bench/` is committed.
  `go/bench_test.go` has five benchmarks with no recorded baseline.
- **A date round-trip conformance vector**: a date string parsed to an
  instant and rendered back as Apple's JSON must come out byte-identical in
  every port.
- **Name the unnamed receipt attributes by experiment** (RECEIPT-FIELDS.md
  "The unnamed types"). Receipts worth capturing: one after a receipt
  refresh, a Mac App Store receipt, a purchase made with an offer or an
  `appAccountToken`, and one holding a non-consumable and a non-renewing
  subscription.
- **Matrix additions due** (one line each in `ci.yml`; policy and snapshot
  in `SUPPORT-MATRIX.md`): Java 27 on 2026-09-15, replacing 26 as the
  feature-release leg; Python 3.15 in October 2026; .NET 11 and PHP 8.6 in
  November 2026 (.NET 11 also joins the test projects' `TargetFrameworks`);
  Ruby 4.1 in December 2026; Go 1.28 in February 2027. Floors stay when a
  vendor line ends, so Java 17 (Oracle, 2026-09-30), Python 3.10
  (2026-10-31), .NET 8 and 9 (2026-11-10) and PHP 8.2 (2026-12-31) change
  nothing.
- **Floor policy (owner decision, 2026-09-21)**: a floor moves when it
  blocks a dependency refresh or a security fix, never because a newer
  line exists. Applied the same day: Python 3.9 to 3.10 (#89, the uv
  Dependabot job could not move cryptography or mypy across the dead
  split) and Rust 1.74 to 1.85 (#91, a plain `cargo update` locked
  edition-2024 crates the floor could not parse). Held on purpose: Java 8
  (enterprise consumers, PLAN D2; JUnit 6 is test-only and stays ignored),
  Swift 6.1 (swift-crypto 5.0 needs 6.2, the 4.x line still ships), Node 20
  (next candidate, see below).
- **Model the receipt attributes Apple's verifyReceipt echoes and we held
  as raw bytes** — done ✅ (2026-09-21, measured against Apple's own answer
  for a genuine production receipt, which stays out of the repository):
  type 1 is `adam_id`/`app_item_id`, 15 is `download_id`, 16 is
  `version_external_identifier`, 1713 is `is_trial_period`, across all nine
  ports. `web_order_line_item_id` stays in the output when 1711 is zero on
  a non-subscription: Apple's live answer omitted it for a consumable, but
  Apple's response reference lists the field without a product-type
  condition, and the owner chose the reference over the observed answer
  (2026-09-21). With those, the emulation matches Apple on 30 of 31 fields;
  the last, `in_app_ownership_type`, is family sharing state that no
  receipt carries. Synthetic fixtures from the generator, four conformance
  vectors. Type 11 stays unmodelled: only TPInAppReceipt names it
  (`developer id`), no other parser or Apple document corroborates it, and
  it maps to no `verifyReceipt` or App Store Server API field
  (RECEIPT-FIELDS.md "The unnamed types").
- **Apple's step 4, the app-version match (type 3), is a caller
  responsibility** in every port: the server cannot know which binary is
  running. RECEIPT-FIELDS.md states it; the accessor exists.
- **The distroless `java17-debian12` image is deprecated** (last rebuilt
  2026-02-20, Debian OpenJDK, not Temurin); distroless now builds only
  debian13 from Temurin debs. `java-distroless` runs the whole suite inside
  java17-debian12 and java17/21/25-debian13 (`:nonroot`, digest-pinned), on
  their own JVM and java.security and again under a SHA-1-free
  `jdk.certpath.disabledAlgorithms`. Move deployments to `java17-debian13`
  or `java21-debian13`.
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
- **Legacy receipts fail on RHEL 9 in five ports (known issue, owner
  decision 2026-09-24: fix after 0.6.0).** RHEL 9's DEFAULT crypto policy
  makes the system OpenSSL refuse SHA-1 signatures. Apple's legacy chain
  (leaf and WWDR intermediate) and the legacy CMS signature are SHA-1, so a
  genuine legacy receipt is `INVALID_CHAIN`, the same verdict as a forgery.
  Modern (g5) receipts and every JWS are unaffected. Observed in an
  AlmaLinux 9.8 container (OpenSSL 3.5.5, `update-crypto-policies` DEFAULT),
  after checking that the container really refused SHA-1:

  | Port | On RHEL 9 DEFAULT |
  |---|---|
  | Ruby, PHP | always fails: both use the system OpenSSL |
  | .NET | always fails on Linux: `System.Security.Cryptography` loads the system libssl |
  | Python | fails only with the distro `cryptography` package; the PyPI wheel bundles its own OpenSSL and passes |
  | Node | fails only with RHEL's `nodejs` package (`node_shared_openssl`); nodejs.org, nvm and Docker builds bundle OpenSSL and pass |
  | Rust, Go, Swift, Java | pass: pure-language crypto, their own BoringSSL copy, or Java's private BouncyCastle (#152) |

  PHP ran only the legacy and g5 receipts, not its full suite; Swift was not
  run on RHEL (inferred from its code and binary); FIPS mode is untested.
  Workaround until the fix: `update-crypto-policies --set DEFAULT:SHA1`.

  The fix (owner decision: a library where one fits). RHEL blocks "verify a
  SHA-1 signature" but not the raw RSA public-key operation, and plain SHA-1
  hashing still works. So for `sha1WithRSAEncryption` only, on Apple's
  pinned chain and the receipt's CMS signature, recover the signed block
  with the RSA public key and compare it in constant time with the exact
  expected bytes `3021300906052b0e03021a05000414 || SHA1(data)`. Build the
  expected bytes and compare; never parse what was recovered, which is how
  the lax-parsing signature forgeries (Bleichenbacher 2006) happen.
  SHA-256 and stronger stay on the normal verify path. Per port:
  .NET moves to BouncyCastle (as Java did, #152); PHP uses phpseclib;
  Python uses `cryptography`'s `recover_data_from_signature`; Ruby uses
  OpenSSL's `verify_recover`; Node uses `crypto.publicDecrypt` (the web
  build has no raw RSA in WebCrypto, so it needs a `BigInt` modPow or a
  documented limitation). This deliberately goes around a policy the host
  administrator set, for Apple's pinned legacy chain only, which is the
  same trade Java made.

  Add one CI job that runs every port's conformance suite, all nine, in an
  `almalinux:9` container (pulled from quay.io; Docker Hub rate-limits) with
  the DEFAULT policy. It is the only check that catches this coming back,
  and it gives Swift its first real run on RHEL.
- **The other eight ports have not had the Java review's error-mapping
  pass.** Java (#153) now maps an unexpected error before the signature is
  verified to the format reason (21002 for a receipt, `INVALID_JWS_FORMAT`
  for a JWS), never to `INTERNAL_ERROR`: before the signature passes,
  everything is attacker input, and 21009 means "not the client's fault".
  Check each port for the same rule on both paths. The certificate-verdict
  rule (unreadable signer `INVALID_CERTIFICATE`, any other unreadable
  certificate `INVALID_RECEIPT_FORMAT`) is already held by the shared suite.
- **Map Apple's own tests to ours, one by one.** Apple's Java library has
  30 verification tests; `fixtures/apple-official` already imports its test
  data. A name-level match on 2026-09-24 found the missing ones all belong
  to features we do not have: notification and renewal checks (5), OCSP and
  its cache (6), and Xcode payloads accepted without verification (3; we
  reject them on purpose). Map every test, add any we miss for a feature we
  have, and file the rest under the matching item below. Then add a monthly
  workflow that opens an issue when Apple's libraries release with test
  names we have not mapped yet.
- **Vendor-readability review of the other eight ports**, as done for Java,
  and a last read of the Java port as a whole now that #152 to #154 changed
  it.

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
  and `jackson-databind` 1.7 MB (re-measured 2026-09-21 at BouncyCastle
  1.86: 11.2 MiB total, `bcprov` 7.2 MB; java/README.md has the table). `JwsVerifier` needs BouncyCastle for
  exactly one thing, the ES256 check over the raw `r || s` signature
  (`SHA256withPLAIN-ECDSA`; the JDK's own `SHA256withECDSAinP1363Format`
  is Java 9+, so on Java 8 dropping BouncyCastle means DER-encoding the
  signature by hand, about twenty lines), and binds
  two flat POJOs plus one `Map`, which `jackson-core` alone could do. A
  JWS-only consumer could then drop 12 MB. Revisit if a consumer asks.
- **The `cryptography>=40` floor is never installed.** Every python CI leg
  resolves the latest, so the floor is a claim.
- **Real receipt fixtures** (PLAN D6): owner to supply real production +
  sandbox receipts (and ideally a StoreKit-Test/Xcode receipt) as checked-in
  fixtures; add byte-level regression tests over them in every suite.
  The corpus has now been decoded end to end (RECEIPT-FIELDS.md):
  `is_trial_period` is type 1713 on every genuine in-app entry, and is now
  modelled alongside types 1, 15 and 16 (see the attribute-modelling entry
  above). A genuine production receipt checked locally on 2026-09-21 (not
  committed) resolved the ambiguity the sandbox corpus left: type 1 is
  `adam_id`/`app_item_id`, 15 is `download_id`, 16 is
  `version_external_identifier`, each equal to the value Apple's
  verifyReceipt returned for the same receipt. A committed production
  fixture is still wanted; until then the synthetic fixture
  `receipt-ids.der` (generator `ReceiptIdsFixture`) carries these types,
  with a download id of 2^63 - 1 (a nineteen-digit, eight-byte integer) to
  force exact-digit handling.
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
- **The RustCrypto 0.11/0.14 wave is deliberately not taken** (2026-09-21):
  the MSRV move to 1.85.0 that the wave needed is done — `rust-version` in
  `rust/Cargo.toml` and `rust/ffi/Cargo.toml` now reads 1.85.0, matching
  `digest` 0.11, `sha1`/`sha2` 0.11 and `p256`/`p384` 0.14. What still blocks
  the wave is `rsa`: it is still 0.9 on `digest` 0.10, and `rsa` 0.10 is
  still a release candidate (0.10.0-rc.18 as of 2026-04-27; stable is
  0.9.10), so the trait versions would not line up. The five bumps
  (PRs #22–#24, #26, #27) are closed and the versions are ignored in
  `.github/dependabot.yml`'s cargo entry; the `@dependabot ignore` comments
  on the PRs never reached the bot. Take the whole wave in one commit once
  `rsa` 0.10 is stable. It is also the next Rust speed step: measured
  2026-09-23, one RSA-2048 verify takes about 92 µs on 0.10.0-rc.18
  against 221 µs on 0.9.10, and a receipt does three, which would take the
  g5 receipt from about 740 µs to about 350 µs.
- **Faster Rust RSA beyond `rsa` 0.10 is not taken** (2026-09-23). `ring`
  (27 µs per verify) or `aws-lc-rs` (24 µs) would make the g5 receipt about
  5 times faster, but both bring C and assembly into a crate whose C ABI is
  cross-compiled, plus a licence review. Caching verified certificate
  signatures would skip two of the three verifies with the current crate,
  but it puts shared mutable state in the security core and an attacker's
  own chain could fill the cache, so it needs a THREAT-MODEL decision
  first.
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

## Java 0.7 (from the 2026-09-24 reviews)

Found by the pre-0.6.0 vendor, readability and production reviews of the
Java port and deferred by the owner. None lets a forged receipt or JWS
through.

- **The other eight ports: check the unauthenticated-key cost.** Java
  decoded every embedded key before the chain was checked, and
  BouncyCastle's primality test on a 16384-bit RSA modulus made one small
  receipt cost about 14 seconds of CPU. Java now decodes a key only after a
  pinned root vouches for its certificate. Measure each port with the same
  input and port the fix where it applies.
- **Hide the `internal` package.** It is public because Java 8 has no
  modules, so any code on the classpath can reach the shared BouncyCastle
  provider. A multi-release jar with a `module-info` would close it.
- **Typed `verifyNotification` and `verifyRenewalInfo`.** Today they go
  through `verifyRaw`, and the caller must check `bundleId`, `environment`
  and `appAppleId` by hand.
- **A concurrency stress test for the shared `JcaSignerInfoVerifierBuilder`**,
  whose thread safety rests on BouncyCastle internals checked at 1.86.
- **Shorter Javadoc.** Several comments are essays, for example the 22
  lines on `MAX_PATH_LENGTH`.
- **Test code a vendor can read:** remove the references to other ports
  and to `tools/lint-cases.mjs`, replace the hand-written tokenizer in
  `TrustStoreIsolationTest` with ArchUnit rules and split the file, turn
  `ConformanceCasesTest` into a `@ParameterizedTest` without reflection,
  and put tests in the package of the class they test.
- **Smaller items:** ES256 accepts high-s signatures (malleable, not a
  forgery); `deviceGuid` length is not validated; two strict base64
  decoders; the three-argument `JwsVerifier` rejects every PRODUCTION
  payload, which its Javadoc should say louder.

## After 0.6.0 (open items from the 2026-09-24 session)

Agreed with the owner during the 0.6.0 run-up and not yet written down
elsewhere in this file.

- **Java API redesign in 0.7.** Breaking changes are fine before 1.0;
  collect the API complaints above into one release.
- **Shared-suite security cases for legacy receipts**, to match what the
  JWS side already pins: a twin of an Apple certificate, a genuine receipt
  with one content byte changed, a receipt with no signer, a signature by
  a stranger's key, chain length and certificate count caps, BER-encoded
  content, deep nesting, detached content, several SignerInfos, and an
  intermediate without Apple's marker OID.
- **Refuse a receipt with more than one SignerInfo.** Java checks only
  the first one today, and a test pins that behaviour until this lands.
- **Align the other eight ports with Java on the receipt signer
  algorithm.** Java accepts any algorithm under the pinned chain since
  0.6.0; the others still allow only RSA with SHA-1 or SHA-256.
- **`failureCause` for `INTERNAL_ERROR` (21009)** should carry the inner
  parser exception, so an operator can see why Apple-signed content did
  not parse.
- **Trailing JSON tokens** after the request object are accepted. Measure
  what Apple's endpoint does with them, then match it.
- **README wording in node, swift and php** still suggests retrying on
  `INTERNAL_ERROR`, which is deterministic; say "alert and escalate"
  instead, as the Java README does.
- **From the final blind Java reviews (2026-09-24), for the 0.7 API work:**
  - `ReceiptVerifier` accepts sandbox and TestFlight receipts, and the
    caller must check `receiptType()`. Both reviewers' top money risk:
    take an accepted-environments set, as `JwsVerifier` does.
  - `VerifyReceiptResult.isVerified()` is true for 21007 and 21008, so a
    caller granting on it would grant a sandbox receipt in production.
    Add an `isAccepted()` meaning `status() == 0`.
  - An optional expected bundle id on `VerifyReceiptEndpoint`.
  - `TransactionPayload` lacks newer claims (`revocationType`,
    `revocationPercentage`, `appTransactionId`, `offerDiscountType`,
    `offerPeriod`, `storefrontId`, `isUpgraded`), and `StrictClaims` has no
    strict boolean reader.
  - The top-down chain walk exists twice, in `ReceiptVerifier` and
    `JwsVerifier`; share one implementation, and catch the same exception
    types in both.
  - Build the CMS signer verifier per call instead of sharing it, if the
    benchmark allows.
  - Pin deep ASN.1 nesting with a test. Checked by hand on 2026-09-24:
    500,000 levels of indefinite-length and 20,000 of definite-length
    nesting both return `INVALID_RECEIPT_FORMAT` with no stack overflow.
  - Comment reflow damage and dated facts ("measured on", "checked in
    BouncyCastle 1.86") that will go stale.
  - JWS `crit` header handling (RFC 7515), and an explanation of why x5c
    entries skip the canonical re-encode check the other segments get.

## Working notes for agents (2026-09-21)

Things that cost a round trip once and should not cost another.

- Dependabot commands posted through the GitHub integration are neutralised
  (`@dependabot rebase` never reaches the bot). Use the update-branch API
  instead; a branch update also re-runs CI, which is how a Maven Central
  HTTP 429 was cleared without a re-run permission.
- The uv Dependabot job pins one version per package across every Python
  in the lock, so it fails as soon as a package drops the oldest split.
  Fixed for good by dropping 3.9; if it recurs, the floor is the fix.
- Dependabot's bundler ecosystem only discovers `Gemfile`/`gems.rb`;
  `ruby/gemfiles/*.gemfile` are refreshed by hand (`bundle update` with
  `BUNDLE_GEMFILE`, then rubocop, rbs and steep).
- Dependabot's swift ecosystem checks the repository out as `repo`, so a
  path dependency needs `name:` or the product lookup fails (#85).
- A plain `cargo update` ignores `rust-version`; use
  `CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback` (CONTRIBUTING.md).
  clippy's `borrow_as_ptr` is gated on the MSRV, so raising the floor can
  surface new lint errors in untouched code.
- .NET lock files regenerate under the newest SDK line CI installs (10.0.x);
  `dotnet/fuzz` sits outside the solution and needs its own
  `restore --force-evaluate`.
- The distroless Java images' `java.security` can be read without Docker by
  pulling the layer blobs over HTTPS and untarring `conf/security/`.

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
  If local-testing support is ever needed, prefer verifying over skipping:
  Xcode can export the public certificate of the key that signs StoreKit
  testing payloads (Editor, Save Public Certificate), so an opt-in Xcode
  mode could pin that certificate and check the signature for real, with
  the Apple marker-OID check relaxed in that mode only. Never reachable
  from production config. Low priority: sandbox testing already works.
- **C ABI phase 2: prebuilt binaries, an owner decision.** Phase 1 shipped:
  `rust/ffi/` is a `cdylib`/`staticlib` with a generated header, three test
  layers and a three-OS CI leg, and it is buildable from source only. Phase 2
  would attach a built `.so`/`.dylib`/`.dll` plus the header to each GitHub
  release, per OS and architecture, so a C or Elixir consumer does not need a
  Rust toolchain. It is not queued, because it is a decision rather than a
  task: it means cross-compilation legs in `release.yml`, an
  architecture/libc support promise (glibc versus musl, x86-64 versus
  aarch64) that binaries make and source does not, signing and attestation
  for every artifact, and a second thing to get right at every release.
  Source-only is honest until someone asks.
- **Java speed beyond removing waste is not taken** (2026-09-23). Our own
  readers for DER attribute sets, short strings and integers, and receipt
  dates took legacy `core` from about 3,560 to 1,500 µs, and were reverted
  (8d7c870): the owner prefers BouncyCastle and java.time to a second
  parser we would maintain. Three more options each give up a guarantee
  java/README.md makes, so none is queued:
  - Checking the chain with a direct signature check instead of PKIX. PKIX
    costs about 90 µs per receipt, and keeping it means chain building,
    validity windows and CA constraints come from BouncyCastle's maintained
    PKIX code rather than ours; `TrustStoreIsolationTest` depends on it.
  - Hashing the CMS content with the JDK's provider instead of the pinned
    BouncyCastle one: about 90 µs saved on the legacy receipt (SHA-1 over
    75 KB), but the digest would come from whichever JCA provider the JVM
    lists first, which widens the trust boundary.
  - A cache of parsed embedded certificates keyed by their DER: maybe 25%
    on a small receipt, but it is process-wide mutable state, which the
    thread-safety design and `ConcurrencyTest` avoid on purpose.
- **PHP worst-case JSON body memory**: a 3 MiB request body of arrays
  nested 60 deep peaks at about 331 MB inside `json_decode` on PHP 8.4 and
  about 561 MB on PHP 8.1, so php/README.md tells you to give a worker at
  least 384M of `memory_limit` (640M on 8.1). A pre-scan of the raw body could reject that shape before
  `json_decode` runs. Not queued.
- **.NET fixed cost per receipt, a trust-model decision**: what remains
  after the caps work is OpenSSL 3.0 decoding each certificate (about 150
  to 190 us) and importing its RSA key (about 125 us), and both get slower
  per call as threads are added. Three options: check the signer info
  ourselves instead of through `SignedCms`, cache the anchors' keys, or
  cache embedded certificates' keys by their exact DER. Each changes what
  the port trusts between calls, so the owner decides first.
- **Revocation, still offline.** Apple's library can ask Apple's OCSP
  responder about the leaf and intermediate (`enableOnlineChecks`), caching
  the answer for 15 minutes and returning `RETRYABLE_VERIFICATION_FAILURE`
  when the network fails. We never check revocation, so a leaked Apple
  signing key would be accepted until a release blocks it. The offline
  shape worth building: a helper that downloads Apple's CRL, checks its
  signature against the pinned root, and hands it to the verifier, which
  stays offline; the caller refreshes it on a schedule. Optional OCSP (an
  opt-in "online mode") stays a later choice for consumers who accept Apple
  calls.
- **Updating the pinned roots at run time: open for discussion.** Today the
  root fingerprints live in the code and change only through a reviewed
  release. Downloading roots over TLS from apple.com proves the bytes came
  from a server holding an apple.com certificate, so trust would then also
  rest on every certificate authority that can issue one, and on any
  TLS-inspecting proxy with its own CA. A middle path: a release ships the
  fingerprints of roots Apple has announced, and the helper accepts a
  downloaded root only if it matches one of them. The owner leans towards
  allowing downloads; decide before building the CRL helper above.
- **Typed renewal-info and notification APIs** (StoreKit 2 JWS only; legacy
  receipts have neither). Apple's library has `verifyAndDecodeRenewalInfo`
  and `verifyAndDecodeNotification`, which check bundle id, app Apple id
  and environment for the caller; ours offer only `verifyRaw`, which leaves
  those checks to the caller and is easy to get wrong. Add typed methods in
  all nine ports, the notification one also verifying the nested
  `signedTransactionInfo` and `signedRenewalInfo`, with conformance cases.
- **A verified-chain cache, measured first.** Apple's library caches a
  verified chain for 15 minutes, but only with online checks on, because
  only then is the validation date always "now". Offline, the date is each
  payload's own, so a safe cache keys on the exact DER of the leaf and
  intermediate, keeps the verified public key, and on a hit still checks
  every certificate's validity window against that payload's date
  (signatures, OIDs and the anchor do not depend on the date). Bounded,
  for example 32 entries. Java would save about 90 µs a receipt; the Rust
  and .NET entries above name the same trade. A bug here accepts a
  forgery, so it needs a THREAT-MODEL decision and a measured need first.
