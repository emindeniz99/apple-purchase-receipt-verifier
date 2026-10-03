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
   enforce branch protection for admins, bootstrap RubyGems, NuGet and
   Docker Hub, submit the repository to Packagist, and settle the Maven
   Central release count and the Java 8 CI distribution (BOOTSTRAP.md has
   each). crates.io stays at 0.7 until `openssl-sys` accepts OpenSSL 4.

## Decisions of 2026-09-29 and 30 (owner)

Taken after #187 merged the Rust core into `main` (b96f14e). The records
are in docs/rust-core/DECISIONS.md where they are architectural.

1. **crates.io.** The core crate stays at 0.7 on crates.io until an
   `openssl-sys` release can vendor OpenSSL 4. The owner opened
   [rust-openssl#2692](https://github.com/rust-openssl/rust-openssl/pull/2692),
   an opt-in `vendored-4` feature; its CI results are in
   docs/evidence/2026-09-30-rust-openssl-vendored-4-upstream.md (R19).
2. **Parity corpus.** A release asset of this repository, tag
   `corpus-2026-09-29`, pinned in git by `fixtures/corpus.json`, which
   #200 introduced (merged 2026-09-30); the repository variables are no
   longer read (R35).
3. **Floors.** A floor moves only when a dependency, a security fix or CI
   forces it. Go moves to 1.25 for wazero 1.12; the other floors stay
   (R30, SUPPORT-MATRIX.md).
4. **Dependencies.** One sweep pull request to the newest versions the
   floors allow, then Dependabot weekly. The sweep is #204.
5. **API.** The 0.7 shape stays in all nine packages; Java keeps
   `runtimeProbe`; roots keep the native certificate type in Java, .NET
   and Go and are bytes elsewhere; Java's `Environment.value()` becomes
   public; the WIT package version moved to `aprv:verifier@0.1.0` in one
   pull request across every binding on 2026-10-01 (R36).
   - Decided 2026-10-01 (DECISIONS.md R41): internals that leaked are
     hidden (Rust's top-level `decode_receipt_data`; Go's `String()`
     methods that repeated `ToJSON()`/`JSON()`; Swift's
     `Environment.appleValue`; Node's `VerificationError`; PHP's
     `idJson`, `attributesJson` and `jsonValue`; Ruby's `Guest`,
     `InstancePool`, `Runtime`, `Wire`, `PayloadJson` and
     `RootsRejected`), and each language builds a `Config` one way, in
     its own idiom (Python's `Config.create` and `Config.defaults`,
     Ruby's `Config.builder`, PHP's `ConfigBuilder` and Rust's
     `Config::defaults()` removed; Go's and Swift's size-cap constants
     removed). Kept: the result and payload types' constructors, and
     .NET's `JsonPayload.Create`, its payload's one public constructor.
   - Decided 2026-10-02 (DECISIONS.md R41, amended): Ruby's
     `Config.defaults` and PHP's `Config::defaults()` are removed, since
     each only called the no-argument constructor (Java's
     `Config.defaults()` stays); Python's `MAX_RECEIPT_BYTES`,
     `MAX_REQUEST_BYTES` and `MAX_JWS_BYTES` are removed, with the
     `endpoint` and `jws` modules that held only them, as Go's and Swift's
     were; and .NET reads and writes JSON with `System.Text.Json` (a
     package on netstandard2.0) instead of its hand-written reader and
     writer. `ToJson` escapes with the library's relaxed encoder (the
     owner's Q20), so its text can differ from 0.7's in escaping, and in
     value only for a lone surrogate (now U+FFFD; the module never writes
     one); checked on the `verifyReceipt` and `verifySignedData` cases and
     hand-built payloads.
   - Decided 2026-10-01 (DECISIONS.md R39, amended the same day): the
     core reads a root as DER or PEM, told apart by the bytes, through
     OpenSSL's PEM reader; wrappers pass bytes and read neither format.
   - **Open for the owner:** Node's `createConfig()` and
     `createVerifier()` names.

   Later, not in 0.8.0: an optional `expect {bundleId, environment}`
   argument on the verify calls, checked in the core and answered as a
   verdict. Every README leaves that check to the caller today.
6. **Divergences.** A core-versus-Java difference is fixed only when it
   changes an Apple-signed input's verdict or accepts something unsigned.
   Otherwise its case becomes `oneOf` and nobody writes code to imitate
   the other implementation (R20). The 2026-09-30 audit classified four
   Java rules from lane J-align as imitation: the six-level cap on
   constructed strings, the ten-CRL cap, the five-octet length kept raw,
   and the `ConstructedStrings` rewriter. OpenSSL refuses those BER
   encodings, and Apple never sends them. Their removal and the eight
   cases that become port-defined land in their own pull request.
   Examined and kept: `keyless_target_path` in `rust/src/path.rs` (it
   reports path problems at the depths `X509_verify_cert` would), and
   `signature_names_digest` in `rust/openssl/src/cms.rs` (continuity
   with the 0.7 core's `INVALID_SIGNATURE`, not a security boundary; its
   case is already `oneOf`).
7. **Fuzz findings and supply chain.** Apply to OSS-Fuzz with the six
   existing targets; every fuzz job encrypts any finding to the owner's
   public key and sends a notice through a Telegram bot, with only the
   target name and a hash in the log; add OpenSSF Scorecard (R37). Wired
   2026-10-01 (Scorecard, the sealed nightly findings with the Telegram
   notice, the same for the eight per-push fuzz jobs in ci.yml, the
   OSS-Fuzz draft in `docs/oss-fuzz/`); waiting on the owner's
   age key, the two Telegram secrets and the OSS-Fuzz submission
   (BOOTSTRAP.md). The draft leaves `abi-call` out until its harness can
   run under OSS-Fuzz.
8. **Attestation.** Unchanged: provenance and CycloneDX SBOM attestations
   (R34).
9. **Unsupported runtimes.** SUPPORT-MATRIX.md lists LLRT, CloudFront
   Functions, Hermes, GraalJS and Nashorn beside Fastly Compute and Akamai
   EdgeWorkers, each with its reason (R5).
10. **PHP's refusal of an empty root list** stays (OD-16).
11. **Java artifact naming. Decided 2026-10-01 (DECISIONS.md R41):** the
    `-wasm` artifactId stays, at the same version numbers as the
    BouncyCastle artifact, with no qualifier. Its POM description and
    README call it the newer engine, offered as a preview whose API may
    still change before 1.0. A `-wasm` version suffix would have doubled
    the Maven Central deployments per release, and Dependabot and
    Renovate would have proposed "upgrading" Wasm consumers to the
    BouncyCastle build.
12. **This record**, in one docs pull request.
13. **CLAUDE.md** drops its section on security reviews of runtimes. The
    2026-09-27 evidence note stays as it is.

## 0.8.0: one core, merged; open items (2026-09-30)

The eight non-Java packages run one Rust core as `aprv.wasm`, `aprv-server`
runs it for Java 8, PHP and any other language, and the Java
implementation stays beside it (PLAN.md D17 to D30,
[docs/rust-core/](./docs/rust-core/README.md)). #187 merged it into `main`
on 2026-09-29 (b96f14e). #200, the CI fix the release pull request #182
waited for, merged on 2026-09-30 (86ff162) and refreshed #182. From the
decisions above, the removal of Java's imitation rules merged on
2026-10-01 (#203, 4bb529e) and the dependency sweep is #204, which also
moves Go's floor (R30); the WIT version rename (R36) is decided and not
yet made. What is still open
from the migration:

- **The nightly `java-differential` job failed on `main`** at b96f14e
  (run 36698598330): `tools/differential/recorded.json` was stale, with
  one row missing and four out of date. Fixed by #202 on 2026-10-01
  (107b7f6); the next nightly run confirms it. The same run also failed
  `java-wasm-s390x` (surefire: "Given path does not end with java
  executor"), which stays open under "CI still missing" below.

- **Re-measure on an idle runner.** Every 0.8 timing in BENCHMARKS.md was
  taken on a heavily loaded shared machine. Swift's JWS came out at about
  the guideline's 10 per second per core with no margin; the owner decides
  if a platform falls below it (docs/rust-core/DECISIONS.md R4). The Java
  main artifact and the native core were not re-measured at all, and ARM64
  speed is unmeasured (the ARM64 spike branch of
  docs/rust-core/MIGRATION.md).
- **`aprv-server`'s default lifecycle.** The `init` measurement met R23's
  rule for making `--lifecycle pool` the default
  (docs/evidence/2026-09-29-init-cost.md); the server still starts a fresh
  instance per request unless told otherwise. Flip the default, or record
  why fresh stays.
- **A third review round** for the second round's fixes and the last ABI
  work, which have had no reader but their authors
  (docs/rust-core/REVIEW-LOG.md §10.9).
- **The test inventory's open rows.** docs/rust-core/TEST-INVENTORY.md
  lists 78 port-only tests whose behaviour has no shared case yet; each
  becomes a case in `fixtures/cases.json`, or a Rust test when its input is
  too large for one.
- **CI still missing:** `java-wasm-s390x` (the Endive corpus under QEMU
  before each release, the big-endian check); CodeQL over `java-wasm/`;
  the licence texts of the code compiled into the module inside the
  `-wasm` jar.
- **PHP on macOS and Windows** installs no binary until the release
  publishes those builds' exact files and pins their hashes in
  `php/SHA256SUMS`; until then those platforms use a server URL.
- **A guest time limit in the in-process hosts.** Only `aprv-server`
  enforces one (epoch interruption); Wasmtime's hosts could too.
- **Python's compile time.** Winch halves the compile at half the speed;
  wasmtime-py reaches it only through a private call today.
- **Exotic CPUs** without a Cranelift backend (ppc64le, loongarch64,
  32-bit) have no `aprv-server` build; nothing is decided (R31).
- **workerd's production 128 MB limit** was not measured; the local
  workerd peaked at 104 MiB on the hostile receipt.

## 0.7: the API redesign — done (owner, 2026-09-27)

Shipped on `feat/0.7-verifier-api` for all nine ports, as designed in
[docs/design/0.7-api.md](./docs/design/0.7-api.md): one `Verifier` with
`verifyReceipt`, `verifySignedData` and `verifyReceiptEndpoint`, a `Config`
of roots and clock, no policy parameters, results that never throw, the
eight reasons, and the 311 shared cases in `fixtures/cases.json`. Ruby's
floor moved to 3.3 and PHP's to 8.2 (SUPPORT-MATRIX.md). The items it
settled have been removed from the sections below. Two follow-ups stay
open: a multi-release jar with `module-info` for Java 9+ ("Java, after
0.7" below), and RHEL 9 and Codecov, which the owner scheduled after 0.7
(below and in "Later / hardening").

## Next

- **Endpoint result API, base64 fast path and input caps: done ✅**
  (2026-09-22, #114 to #133; the 0.6 endpoint result object this added is
  gone in 0.7, which returns the response JSON). Every port decodes canonical base64
  on a fast path held to the tolerant decoder by a differential test; every
  port caps the receipt and the request body at Apple's 3,145,728 UTF-8
  bytes (measured 2026-09-23, COMPARISON.md), JSON depth at 64 and the JWS
  at 256 KiB, and `fixtures/cases.json` holds every cap as a MUST from both
  sides. Swift's release-build crash on Linux x86_64 with
  Swift 6.3.3 is fixed (#126), and CI now runs the Swift tests in release
  mode. The tolerant decoder and its
  fast path were replaced on 2026-09-23 by the rule Apple's verifyReceipt
  was measured to apply, canonical standard base64 only (THREAT-MODEL.md
  §3.8).
- **JWS cap, to be discussed**: it stays at 262,144 bytes. The request and
  receipt caps now match Apple's measured limit; nobody has checked whether
  Apple states a size limit for a JWS anywhere we could match.
- **SwiftPM checkouts carry the fixtures (owner decision)**: SwiftPM
  consumers check out the whole repository, and `fixtures/limits/` adds
  about 21.5 MB on disk to every checkout. The git transfer stays small
  because git compresses the padding. Package.swift declares only the
  module, its hash and the licence texts as resources, so no fixture ships
  in a built product.
- **A date round-trip conformance vector**: a date string parsed to an
  instant and rendered back as Apple's JSON must come out byte-identical in
  every port.
- **Name the unnamed receipt attributes by experiment** (RECEIPT-FIELDS.md
  "The unnamed types"). Receipts worth capturing: one after a receipt
  refresh, a Mac App Store receipt, a purchase made with an offer or an
  `appAccountToken`, and one holding a non-consumable and a non-renewing
  subscription.
- **Matrix additions due** (one line each in `ci.yml`; policy and snapshot
  in `SUPPORT-MATRIX.md`): Python 3.15 in October 2026; .NET 11 and PHP 8.6
  in November 2026 (.NET 11 also joins the test projects' `TargetFrameworks`);
  Ruby 4.1 in December 2026; Go 1.28 in February 2027; Java 28 in March 2027,
  replacing 27 as the feature-release leg. Java 27 replaced 26 in the `java`
  job on 2026-09-28 (done ✅; 26 reached EOL on 2026-09-18). Floors stay when a
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
  Node 20 (next candidate, see below). Moved in 0.8.0 because a runtime
  required it: Swift 6.1 to 6.3 with macOS 15 and iOS 18, WasmKit's floors
  (PLAN.md D25); Go 1.22 to 1.25 for wazero 1.12 (owner decision,
  2026-09-30; the `go` matrix drops its 1.22 to 1.24 legs). **Restated
  2026-09-30:** a floor moves only when a dependency, a security fix or CI
  forces it. Node 20, Python 3.10, PHP 8.2, Ruby 3.3, .NET 8, Swift 6.3 and
  Java 8 stay (docs/rust-core/DECISIONS.md R30).
- **Model the receipt attributes Apple's verifyReceipt echoes and we held
  as raw bytes** — done ✅ (2026-09-21, measured against Apple's own answer
  for a genuine production receipt, which stays out of the repository):
  type 1 is `adam_id`/`app_item_id`, 15 is `download_id`, 16 is
  `version_external_identifier`, 1713 is `is_trial_period`, across all nine
  ports. `web_order_line_item_id` stayed in 0.6's output when 1711 is zero
  on a non-subscription: Apple's live answer omitted it for a consumable,
  but Apple's response reference lists the field without a product-type
  condition, and the owner chose the reference over the observed answer
  (2026-09-21). 0.7 omits it, as Apple's endpoint does
  (docs/design/0.7-api.md). With those, the emulation matches Apple on 30
  of 31 fields;
  the last, `in_app_ownership_type`, is family sharing state that no
  receipt carries. Synthetic fixtures from the generator, four conformance
  vectors. Type 11 stays unmodelled: only TPInAppReceipt names it
  (`developer id`), no other parser or Apple document corroborates it, and
  it maps to no `verifyReceipt` or App Store Server API field
  (RECEIPT-FIELDS.md "The unnamed types").
- **Apple's step 4, the app-version match (type 3), is a caller
  responsibility** in every package: the server cannot know which binary is
  running. RECEIPT-FIELDS.md states it; the accessor exists.
- **The distroless `java17-debian12` image is deprecated** (last rebuilt
  2026-02-20, Debian OpenJDK, not Temurin); distroless now builds only
  debian13 from Temurin debs. `java-distroless` runs the whole suite inside
  java17-debian12 and java17/21/25-debian13 (`:nonroot`, digest-pinned), on
  their own JVM and java.security and again under a SHA-1-free
  `jdk.certpath.disabledAlgorithms`. Move deployments to `java17-debian13`
  or `java21-debian13`.
- **RubyGems and NuGet are still unbootstrapped, and crates.io is held at
  0.7** (BOOTSTRAP.md has the owner actions). The release itself no longer breaks on them:
  `release.yml` asks each of the three whether the package exists and skips
  the publish with a `::notice::` when it does not — before OIDC for
  crates.io and NuGet, and after a failed OIDC for RubyGems, whose pending
  publisher is meant to create the gem — and the `smoke` job runs on the
  registries that did publish. The Go module has been on `proxy.golang.org`
  since `go/v0.4.0`; README.md and BOOTSTRAP.md say so as of 2026-09-28.
- **Legacy receipts on RHEL 9: fixed by design in 0.8.0, not yet run
  there.** RHEL 9's DEFAULT crypto policy makes the system OpenSSL refuse
  SHA-1 signatures, and Apple's legacy chain and CMS signature are SHA-1.
  In 0.7 that failed genuine legacy receipts in Ruby, PHP and .NET, and in
  Python and Node with the distribution's own packages (observed in an
  AlmaLinux 9.8 container, OpenSSL 3.5.5). In 0.8.0 no package uses the
  system's crypto: the Wasm packages verify with the OpenSSL compiled into
  the module, and the Java implementation with its own BouncyCastle
  (#152). Add one CI job that runs every package's conformance suite in an
  `almalinux:9` container (pulled from quay.io; Docker Hub rate-limits)
  with the DEFAULT policy, which proves it and keeps it from coming back.
- **Map Apple's own tests to ours, one by one.** Apple's Java library has
  30 verification tests; `fixtures/apple-official` already imports its test
  data. A name-level match on 2026-09-24 found the missing ones all belong
  to features we do not have: notification and renewal checks (5), OCSP and
  its cache (6), and Xcode payloads accepted without verification (3; we
  reject them on purpose). Map every test, add any we miss for a feature we
  have, and file the rest under the matching item below. Then add a monthly
  workflow that opens an issue when Apple's libraries release with test
  names we have not mapped yet.
- **Vendor-readability review of the wrappers and of `aprv-server`**, as
  done for Java, and a last read of the Java implementation as a whole now
  that #152 to #154 and the 0.8 alignment changed it.

- **No branch protection in practice.** main reports protected, yet an
  admin push lands directly, so either the pull-request requirement or
  admin enforcement is off. There is no CODEOWNERS. Commits are
  SSH-signed by the assistant environment's key, which belongs to the
  `claude` GitHub account, so they show Verified when authored as that
  account; CLAUDE.md records the rule (2026-09-06).
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
  blocking a needed update. The owner confirmed on 2026-09-30 that it
  stays.
- **Post-publish smoke gaps that remain.** The Go, RubyGems, crates.io and
  NuGet legs are wired; only the Go one has ever run against a real registry,
  because the other three are unbootstrapped and their legs skip until they
  are not. The `packagist` leg installs the published PHP package and runs
  `aprv-install`. One hole is left: **the .NET leg tests one of the two
  shipped assets**: `net8.0` selects
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
## Java, after 0.7 (from the 2026-09-24 reviews)

Found by the pre-0.6.0 vendor, readability and production reviews of the
Java port and deferred by the owner. None lets a forged receipt or JWS
through.

- **A multi-release jar with a `module-info`** for Java 9 and later. 0.7
  already made the implementation package-private in one package; a
  `module-info` would only add hiding for modular consumers, at the cost of
  a second compile pass.
- **Test code a vendor can read:** remove the references to other ports
  and to `tools/lint-cases.mjs`, replace the hand-written tokenizer in
  `TrustStoreIsolationTest` with ArchUnit rules and split the file, turn
  `ConformanceCasesTest` into a `@ParameterizedTest` without reflection,
  and put tests in the package of the class they test.
- **Smaller items:** ES256 accepts high-s signatures (malleable, not a
  forgery); two strict base64 decoders.
- **From the last-look security and quality reviews (2026-09-28)**, both
  SHIP; nits left for after the tag:
  - Split `ReceiptCore.verifySignature` (68 lines), and consider an
    `AuthenticatedCertificates` wrapper type so the compiler holds the
    trust boundary.
  - The 15-argument positional `ReceiptPayload` constructor.
  - `equals`/`hashCode` render JSON; owner decision: keep.
  - JWS x5c entries tolerate trailing bytes and PEM wrapping through
    BouncyCastle's `CertificateFactory`, while the receipt path refuses
    trailing bytes; check against the core before changing.
  - `Endpoint`'s `default:` branch maps any future `Reason` to 21009.
  - `pom.xml` has no plugin pins for resources, install, deploy and
    clean, and sets `doclint none`.
  - Error-message consistency: the empty endpoint body wording, and the
    chain-length bound message omits its number.
  - CI: PR wall time is dominated by 62 queued jobs and fixed-budget fuzz
    jobs, not installs; consider fuzzing on `main` and nightly with a
    1-minute PR smoke budget.

## After 0.6.0 (open items from the 2026-09-24 session)

Agreed with the owner during the 0.6.0 run-up and not yet written down
elsewhere in this file.

- **Shared-suite security cases for legacy receipts** still missing after
  the 0.7 cases: BER-encoded content and detached content.
- **Trailing JSON tokens** after the request object are accepted. Measure
  what Apple's endpoint does with them, then match it.
- **A result accessor that cannot be misread**: a `payloadOrThrow()`-style
  method, or a Verified/Failed pair of result types. Today callers write
  `verified()` and then read a nullable `payload()`. Decision deferred by
  the owner; if it comes, it lands in every package at once so the
  packages stay in parity.
- **JWS `crit` and `typ` headers**: the core and Java ignore header members
  they do not know, while RFC 7515 §4.1.11 says a `crit` naming a parameter
  the recipient does not understand must be rejected. Apple's signed data
  carries only `alg` and `x5c`. If added, it is a behaviour change: the
  core, Java and a shared case in `fixtures/cases.json` together.
- **From the final blind Java reviews (2026-09-24):**
  - Build the CMS signer verifier per call instead of sharing it, if the
    benchmark allows.
  - Comment reflow damage and dated facts ("measured on", "checked in
    BouncyCastle 1.86") that will go stale.
  - An explanation of why x5c entries skip the canonical re-encode check
    the other segments get. (`crit` handling is the cross-port item above.)

## Decided for 0.7, still open (owner, 2026-09-24)

Everything else decided for 0.7 in this session shipped with it.

- **Smarter CI.** Per-area job selection landed with 0.8.0: the
  `changes` job runs a package's jobs only when its files change, and a
  change to the core, the bindings or the toolchain selects every package.
  Still open: skip tests for Markdown-only changes, except under
  `fixtures/`, whose README digest is pinned in `cases.json`; move fuzzing
  to `main` and a nightly run; scan CodeQL per changed language; and gate
  branch protection on one aggregate "CI OK" job so skipped jobs do not
  block a PR.

Measured the same day, for capacity planning (0.6.0, genuine receipts,
a 4-core container): about 1,270 verifications per second on one core,
about 4,840 on four, no wrong answer in 1,000,000 calls at 4 and at 8
threads.

## Second integration feedback and the Java slowdown (2026-09-25)

A second team integrating 0.6.0 on the legacy path sent nine requests; 0.7
answered them. What stays open:

- **Test signer fields:** the `TestPki` test-jar must be able to set
  bundle id, product id, transaction id, purchase date, cancellation date
  and expiration date. This is enough to replace committed real receipts
  in grant and freshness tests.
- **Interruption: not added (owner).** The JDK's `Signature`,
  BouncyCastle, Nimbus and Apple's own library do not check the interrupt
  flag inside CPU-bound work, and since #161 no call runs longer than
  milliseconds. Advise a worker pool instead of a single thread.
- **Java speed: deferred (owner, 2026-09-27).** 0.6.0 is 2.2 times
  slower on typical receipts (345 to 755 µs; BENCHMARKS.md has the
  bisect). The two candidate fixes, a signature cache and a single
  signature check per certificate, are in "Later / hardening" with the
  reasons.

## Integration feedback on 0.7.0, to evaluate (2026-09-28)

A team running 0.7.0 on a legacy purchase path sent a backlog. Nothing in
it is urgent: no item changes a verdict or a security property, and each
has a working workaround in their code. Each claim below was checked
against the source. Nothing is decided yet.

Their call pattern today: build `{"receipt-data": ...}` around the
base64, call `verifyReceiptEndpoint(PRODUCTION, ...)`, call it again with
`SANDBOX` on 21007 to get the receipt body, and call `verifyReceipt` on
any non-zero status to get the `Failure`. A TestFlight receipt costs two
full verifications and a failing one costs two; they measured p50 0.43 ms
for a production receipt and 0.78 to 0.87 ms for a sandbox one.

| # | Ask | Checked | Size | Suggested |
|---|---|---|---|---|
| 1 | One verification that yields the status, Apple's JSON for the receipt's own environment, and the `Failure` with its cause | True. On an internal error `Endpoint.respond` answers 21009 and drops the exception, so a caller's log has no stack trace | See below; the core, Java and every package | Do, as a renderer, not a fourth verify method |
| 2 | Take the raw base64, not a request body the library parses back | True | Covered by 1 | Folded into 1 |
| 3 | Declare the real dependency floors: jackson-core 2.16 (the pom says 2.22.2, which a BOM managing 2.21 turns into a `RequireUpperBoundDeps` failure) and the real BouncyCastle floor | True for Jackson. The BouncyCastle floor is untested; the decoder uses classes from 1.70 on | Small for Jackson, plus a CI leg on the floor and a Dependabot rule so bumps do not undo it | Jackson: do. BouncyCastle: measure in CI before declaring anything below 1.86 |
| 4 | A public `TestPki` builder: set the receipt type (the public `receiptPayload` always writes `ProductionSandbox`), omit `web_order_line_item_id` (always 42 today), set cancellation date (1712) and receipt expiration (21), no forced unknown attribute 9999; named setters instead of `inAppPurchase(long, String, String, String, String, String)`, where the two date strings cannot be told apart | True | About 150 lines, test-jar only, plus a sources jar for it | Do. Closes "Test signer fields" above |
| 5 | `AppleStatus.isAppleRetryable(status, isRetryable)`: 21005, Apple's 21009 and 21100 to 21199, unless `is_retryable` is false | The class doc already says this in prose | About 20 lines | Do; decide whether other ports get it |
| 6 | Say that `ReceiptPayload.toJson()` is not a verifyReceipt body | True. The class doc's "one vocabulary" line misled them into a wrong diff | One sentence | Do |
| 7 | Make `Environment.value()` public, to log `Production` or `Sandbox` | True, package-private today | One keyword | Do |
| 8 | Check the interrupt flag between decode, chain and signature | Repeat of the 0.6 ask | Small | Keep "not added" (above). Their own worst case is 3.7 ms |

They asked to leave `Endpoint.MAX_REQUEST_BYTES` and the `Reason` to
status map package-private.

**Item 1, the shape to prefer.** Their proposal is a fourth method,
`verifyReceiptEndpointResult(base64)`, returning a new record of status,
receipt environment, JSON and failure. A smaller shape gives the same
result without a fourth verify method or a new type: `verifyReceipt`
already returns the `Failure` with its cause, so what is missing is only
the rendering. One helper on `Verifier`,
`endpointJson(Environment, VerificationResult<ReceiptPayload>)`, renders
Apple's body from a result the caller already has: the status-0 body for
the receipt's own environment, `{"status":21007}` or `21008` when asked
for the other one, and `{"status":N}` for a failure. `verifyReceiptEndpoint`
then becomes "parse the body, verify, render", so the two paths cannot
drift. Java is about 15 lines because the renderer and both status maps
exist already; the core has the same internals, and reaching the
wrappers needs a new export and so a new ABI version, a design question of
its own. The endpoint JSON on failure stays `{"status":N}` and never gains
a reason field, so it stays comparable with Apple's own answer.

**Packaging, if accepted.** Items 3 (Jackson), 4, 5, 6 and 7 are small
Java pull requests with no library risk. Item 1 needs a short design note
first, then the core and Java, then every package. All
of them are `feat`, so the pending 0.7.1 becomes 0.8.0.

Already fixed in 0.7.0, from their earlier list: `web_order_line_item_id`
omitted when 0, `Environment.fromReceiptType`, the runtime probe in
`Verifier.create`, jackson-databind test-only, `Version.CURRENT`, the
`TestPki` test-jar and the `AppleStatus` constants.

## Smaller Java review findings, not yet scheduled (2026-09-24)

From the six pre- and post-0.6.0 Java reviews; none lets a forged receipt
or JWS through. Kept here so they are not lost with the review reports.

- **THREAT-MODEL.md correction:** "the host cannot
  change a verdict" is overstated, because BouncyCastle still reads JVM-wide
  `org.bouncycastle.*` properties (`rsa.max_size`, `rsa.max_mr_tests`,
  `x509.max_cert_path_build_nodes`).
- **Performance leftovers:** the receipt payload is parsed twice; each chain
  signature is verified twice (top-down walk, then PKIX); JCA factories are
  looked up per call.
- **Small code hygiene:** `catch (Exception e)` where the types are known;
  a `@Nullable ASN1Set` dereferenced without a guard (safe today because the
  count is checked first); a redundant `unmodifiableMap` wrap in the models.
- **Owner decision (2026-09-24): all nine ports reach Java's quality.** No
  port is frozen or reduced to security fixes only. Since 0.8.0 that means
  the core, the Java implementation and every wrapper.
- **README additions:**
  - For a 21009 on a consumable, reconcile with the App Store Server API's
    Get Transaction Info by transaction id: Get Transaction History does
    not return consumables the app has finished.
  - The App Store Server API is rate-limited per hour, unlike
    verifyReceipt; this library has no limit because it makes no call.
  - Why this library exists: Apple's App Store Server Library extracts
    transaction ids from a receipt but does not validate it, so servers
    that still accept receipts from iOS versions before StoreKit 2 need a
    local validator.
- **Size caps stay fixed at Apple's 3 MiB** (owner decision, 2026-09-24):
  a configurable lower cap was proposed and declined.

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

- **Coverage reports with Codecov (owner, 2026-09-27).** Upload each
  package's coverage from CI so a pull request shows which lines its tests
  miss, across the core, Java and every wrapper in one place. The free Developer plan
  allows unlimited uploads for a public repository
  (<https://about.codecov.io/pricing/>, checked 2026-09-27). Needs a
  coverage report per package in a format Codecov reads, an upload step
  pinned by commit SHA with `contents: read` only, and a decision on
  whether a coverage drop fails the check or only comments.
- **Java signature checks, deferred (owner, 2026-09-27).** Java verifies
  each chain signature twice: once in the top-down walk that fixed the
  unauthenticated-key DoS (#161), once inside BouncyCastle's PKIX
  builder, about 170 µs extra per call. Dropping the walk brings the DoS
  back, and replacing PKIX means hand-written certificate checks, so
  neither is acceptable. A cache of successful signature checks (about
  345 µs per call instead of 755) waits too. 0.7 ms per call covers
  current loads; revisit when a user reports CPU pressure.
- **Online revocation checks (OCSP or CRL).** Offline verification is the
  point of the library, so this would be an opt-in at most. Not queued.
  Apple publishes revocations only through the CRL (`crl.apple.com`) and
  OCSP (`ocsp.apple.com`) addresses in its certificates. Apple's own
  library runs OCSP behind `enableOnlineChecks` and then judges validity
  at the current time instead of `signedDate`. The shape that keeps this
  library offline: the host downloads the CRL on its own schedule (every
  15 minutes, say) with its own HTTP client and hands the bytes to a
  helper, which verifies the CRL's signature under the pinned root and
  keeps the revoked serials in memory. `Config.builder().revocations(...)`
  wires it in, and each call does an in-memory lookup. A revoked chain
  fails as `INVALID_CERTIFICATE`. Open policy question for the host: accept
  or reject when the CRL is stale because a download failed. The 0.7
  design keeps room for this (docs/design/0.7-api.md).
- **A per-certificate distrust list in `Config`**, for a leaked historical
  Apple leaf key (THREAT-MODEL.md §4). Not built until that day comes.
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
- **A verified-chain cache, measured first.** Apple's library caches a
  verified chain for 15 minutes, but only with online checks on, because
  only then is the validation date always "now". Offline, the date is each
  payload's own, so a safe cache keys on the exact DER of the leaf and
  intermediate, keeps the verified public key, and on a hit still checks
  every certificate's validity window against that payload's date
  (signatures, OIDs and the anchor do not depend on the date). Bounded,
  for example 32 entries. Java would save about 90 µs a receipt. A bug
  here accepts a
  forgery, so it needs a THREAT-MODEL decision and a measured need first.
