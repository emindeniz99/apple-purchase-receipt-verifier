# Agent Rules — apple-purchase-receipt-verifier

Rules for AI coding agents working in this repo (Claude Code, Codex and
others). This is the one source of truth: Codex reads it natively, and
`CLAUDE.md` imports it. `CONTRIBUTING.md` is the human-facing version;
where they overlap, they agree.

## Commits and merges

- Conventional Commits, scope **mandatory**, area scopes: `java`, `node`,
  `python`, `swift`, `go`, `ruby`, `rust`, `php`, `dotnet`, `jvm-interop`,
  `fixtures`, `certs`, `ci`, `release`, `docs`, `repo`.
- Imperative subject, lowercase, ≤72 chars for the whole header. Body explains
  *why*, wrapped at 72.
- Commit as the identity that owns the signing key, so the commit shows
  Verified, and name the model in a `Co-Authored-By:` trailer. In a cloud
  session (Claude Code on the web) the key belongs to the `claude` GitHub
  account: commit as `Claude <noreply@anthropic.com>`, never as the owner,
  and check `git config user.email` first because a fresh clone can arrive
  with the owner's email set. The trailers name the model and the session
  (`Co-Authored-By: Claude <model> <noreply@anthropic.com>` and
  `Claude-Session: <url>`), not the owner, who decides in the chat and
  writes no line of the commit (owner, 2026-10-03). In a local session the
  key is the owner's: keep the owner's identity and credit the assistant
  and model in the trailer.
- Merge PRs with a **real merge commit** (`merge_method: "merge"`, locally
  `git merge --no-ff`). Never squash, never rebase-merge — squash/rebase are
  disabled in repo settings; do not re-enable them.
- Give the merge commit a body of the form `Merges #57: <PR title without
  its type(scope) prefix>`, never GitHub's default (the bare PR title,
  which is a Conventional Commit line). release-please reads merge commit
  bodies too, so a conventional body there is counted as a second change
  alongside the branch commit that already carries it, duplicating the
  entry in the generated changelog (observed in 0.4.0: `deps: Bump
  actions/setup-go from 6.5.0 to 7.0.0` listed twice, once from the
  dependabot branch commit and once from its merge commit). Dropping only
  the prefix keeps `git log` readable; the type, scope and any breaking
  marker still live on the branch commit, which release-please does read.

## The shape of the product

- **One Rust core, two implementations.** `rust/` is the core (Apple's
  policy over OpenSSL 4). It is compiled once per release to `aprv.wasm`,
  and eight packages run that one file: Node (jco), Go (wazero), Python
  (wasmtime-py), Ruby (the `wasmtime` gem), Swift (WasmKit), .NET
  (Wasmtime), the Java `-wasm` artifact (Endive on Java 11+, `aprv-server`
  on Java 8), and PHP (through `aprv-server`). `rust/server` is
  `aprv-server`; `rust/ffi` is the C ABI. `java/` is the second,
  independent implementation over BouncyCastle, and it stays
  (docs/rust-core/DECISIONS.md R25, R33).
- **Wrappers contain no verification logic.** A wrapper reads the clock,
  moves bytes into the module, reads its JSON back, pools instances and
  maps the outcome. It never parses a receipt, checks a signature, reads a
  certificate or decides trust (docs/rust-core/ARCHITECTURE.md §9,
  SURFACE.md §10). The `one-implementation` CI job
  (`tools/check-one-implementation.mjs --enforce all`) fails on a crypto,
  X.509, ASN.1, CMS or JWS API in any non-Java wrapper outside its tests.
  It is the one list of those APIs: a package's own tests do not repeat
  it, so a new banned API goes into the tool. It allows a CSPRNG for
  `random-get` and a SHA-256 over a module or server binary against its
  pin; a per-file allowlist names every other exception with its reason
  (the 0.7 public types .NET and Go keep for a caller's roots, which only
  carry DER to the module). Do not grow the allowlist to make a wrapper
  "help" the core.
- **`aprv.wasm` imports exactly `random-get`, and its WIT is the
  contract.** `rust/bindings/abi/wit/aprv.wit` (`aprv:verifier@0.1.0`) is
  what every host binds. `rust/bindings/abi/build.sh` and
  `tools/check-wasm.sh` fail on any other import or export, and CI diffs
  the interface read back from the component against the committed file.
  Changing the WIT is changing the ABI version: the export names carry it,
  so every wrapper must move with it in the same PR.
- **Every copy of the module is pinned, and only the release tooling
  refreshes it.** Each package checks its `aprv.wasm` (Node: the
  component) against the SHA-256 in the `.sha256` file beside it. Go and
  the Swift package commit the module itself (`go/internal/wasm/`,
  `swift/Sources/ApplePurchaseReceiptVerifier/Resources/`; DECISIONS.md
  R14); every other package packs the file the release's `build-wasm` job
  built. On the release branch `release-please.yml` rewrites every copy
  and every pin together (`tools/refresh-wasm-pins.sh`). Never copy a new
  module into `go/` or `swift/` by hand and never edit a `.sha256` by
  hand; a pin that lags the core between releases is expected.
- **No binary over 100 KB enters git** except those two committed module
  copies and the generator-built size-limit fixtures under `fixtures/`,
  which pin a cap or a floor: `fixtures/limits/`, written by
  `tools/generate-limit-fixtures.mjs` (deterministic) and
  `ReceiptBase64CapFixture`, and the receipts at a cap or floor in
  `fixtures/generated-0.7/`, written by `LargeReceiptFixture`,
  `VerifierApiFixtures` and `ReceiptBase64CapFixture` (the Java generators
  sign with fresh keys). Every such blob stays in history forever.

## The invariants that are easy to break

- **Never rename `.github/workflows/release.yml`.** npm, PyPI, RubyGems,
  crates.io and NuGet trusted publishing (OIDC) all match the workflow
  *filename*. Renaming it silently kills publishing on five registries.
- **Publish jobs never cache** (a poisoned cache restore becomes the shipped
  artifact). Test jobs do cache. Keep that split. Publish jobs also never
  rebuild the module or the server: they take the files `build-wasm` and
  `build-server` produced and check their hashes.
- **Floors are tested claims.** `@types/node` pins to the Node 20 engines
  floor, JUnit stays 5.x (JUnit 6 needs Java >8), `golang.org/x/sys` stays
  below 0.48 (0.48 and later need a Go newer than the 1.25 floor), and the
  `java-runtime-8` and `java-wasm-runtime-8` CI jobs run the main artifact
  and the `-wasm` server engine on a real Java 8 JVM. Dependabot ignore
  rules encode this — don't "fix" them by upgrading.
- **Java 8 runs no native code inside the JVM.** The `-wasm` artifact on
  Java 8 reaches the module through `aprv-server` in a child process, never
  through JNI, JNA or FFM. No library in this repository defines a system
  property or an environment variable of its own for engine or source
  selection: the Java engine is chosen with `Engine`/`ServerSource` in
  code, and a library that let the environment swap the module would let
  anything that sets a variable change a verdict. `APRV_WASM` and
  `APRV_COMPONENT` are read by build and test tooling only; `APRV_LISTEN`
  and `APRV_TOKEN` belong to the `aprv` binary; Python's
  `APRV_WASM_CACHE_DIR` moves its compile cache and nothing else.
- **The module embeds the roots.** `rust/certs/` is the one copy of
  `certs/`, compiled into the core with `include_bytes!` and pinned to
  Apple's fingerprints in `rust/src/roots.rs`. Java keeps its own base64
  constants in `AppleRootCerts` (in `java/` and in `java-wasm/`), with no
  copy and no generator: edit them by hand, and `AppleRootCertsTest` pins
  them to Apple's fingerprints and to `certs/`. `aprv-server` serves the
  built-in roots' fingerprints from `rust/server/src/roots.rs`.
  `tools/check-cert-copies.mjs` diffs every copy against `certs/`. A
  `certs/` change touches, in one commit: `certs/`, `rust/certs/` and the
  fingerprints in `rust/src/roots.rs`, the server's fingerprints, both
  Java `AppleRootCerts`, and then a rebuilt module; the genuine-receipt
  cases in `fixtures/cases.json` that verify under the default roots
  prove the result.
- **`certs/` pins all three published Apple roots deliberately** (PLAN.md
  D15, which superseded D12's two-root choice). Apple's guidance is to trust
  every root on its PKI page; don't prune them back to the two today's chains
  happen to end at.
- **One version, many files**: release-please bumps `version.txt`, the
  CHANGELOG and every `extra-files` entry in `release-please-config.json`
  together: the manifests (`node/package.json`, `python/pyproject.toml`,
  `java/pom.xml`, `java-wasm/pom.xml`, `rust/Cargo.toml` with its
  `aprv-openssl` dependency line, `rust/openssl/Cargo.toml`,
  `dotnet/Directory.Build.props`, the `jvm-interop` and `java-bench` poms,
  the version in `java/README.md` and `java-wasm/README.md`) and each
  package's version constant (Java `Version.java` in `java/` and in
  `java-wasm/`, Python `version.py`, Ruby `version.rb`, Swift
  `Version.swift`, .NET `LibraryVersion.cs`, Go `version.go`), the generic
  ones found by their `x-release-please-version` marker. The crates that
  are never published (`aprv-surface`, `aprv-wire`, `aprv-abi`,
  `aprv-server`, the C ABI, the fuzz crate) stay at `0.0.0`; the C ABI
  reports the core's version. A new version constant joins that list in
  the commit that adds it. PHP carries no version string at all; the git
  tag is its version. Never hand-edit a version number.
- **Never delete or move a `go/v*` tag.** The Go module is published by that
  tag alone, and its hash is recorded in `sum.golang.org` forever; re-pointing
  one makes every consumer's build fail with a checksum mismatch that looks
  exactly like a supply-chain attack. A bad Go release is fixed forward with a
  `retract` directive in a new patch version. `tag-go-module` refuses to tag
  a tree without the committed module and its pin.
- Tags created by release-please's `GITHUB_TOKEN` cannot trigger workflows —
  that's why `release-please.yml` explicitly dispatches `release.yml`. Don't
  remove that step as "redundant".

## Release budget

- Registries that still need a one-time owner action before their publish job
  can succeed are listed per registry in `BOOTSTRAP.md`. PHP publishes from
  the root `composer.json` (layout A) once the owner submits the repository to
  Packagist and installs its GitHub App; see the Packagist section there.
  crates.io stays at 0.7 until `openssl-sys` accepts OpenSSL 4
  (`vars.APRV_PUBLISH_CRATES`, BOOTSTRAP.md).
- Maven Central's Usage Center caps `io.github.emindeniz99` at **7 releases
  per calendar month**, about 80 MB and about 1,000 files per calendar month
  (https://central.sonatype.org/publish/maven-central-publishing-limits/).
  The working budget is **5 releases a month**, with 2 of them kept in
  reserve for an emergency fix: once `vars.APRV_PUBLISH_JAVA_WASM` is
  `true` (the `-wasm` artifact is held until the owner flips it;
  BOOTSTRAP.md) a release deploys two artifactIds and the two
  `aprv-server` classifier jars, about 10.5 MB, and the owner confirms
  the count with Sonatype (BOOTSTRAP.md). Every release-please PR
  merge spends one — `release.yml` publishes to Central on every tag, no
  dry-run.
- Merge a release PR only for a consumer-visible change: a fix, a feature, a
  docs correction that registries display, or a security bump of a shipped
  dependency. An OpenSSL advisory that reaches the core is such a bump: it
  rebuilds `aprv.wasm` and the server binaries. A `Package.resolved`/lockfile
  or CI-only bump is not one of these — let release-please keep accumulating
  those commits into the next real release instead of cutting a release for
  them.
- Before merging a release PR, check the month's count on
  https://central.sonatype.com (Usage Center) or count this month's tags
  (`git tag --sort=-creatordate | head`).
- SwiftPM consumers never see `Package.resolved` — they resolve from
  `Package.swift`'s `from:` floors — so a `Package.resolved` bump alone
  changes nothing for them and isn't release-worthy on its own.

## Behavior changes

The Rust core and the Java implementation are the two implementations of
one product, and `fixtures/cases.json` is the contract between
them. A verification behavior change touches the Rust core, the Java
implementation and `fixtures/` in the same PR, with the shared cases
proving the two still agree. Every package runs all the cases, one test
each, so the wrappers need no change for a behavior change; a wrapper that
would need one is holding logic it must not hold. A divergence between the
core and Java is recorded in docs/rust-core/DECISIONS.md R20; one that
changes an Apple-signed input's verdict, or accepts something unsigned, is
a bug. Never edit a case to make an implementation pass.

## CI hygiene

- Every action SHA-pinned with the tag in a comment; the swift container is
  digest-pinned. zizmor runs in CI and stays at 0 findings.
- All checkouts set `persist-credentials: false`; workflow `permissions:`
  blocks stay least-privilege (repo default token is read-only).

## Fixtures and privacy

`fixtures/` sandbox receipts are developers' own test data (documented in
their LICENSE-upstream files). Never add a production receipt — a real
receipt carries a real user's purchase history. This rule has bitten before.

The owner sometimes hands an agent production receipts to check that the
verifier still reads what Apple sends. Keep them in a scratch folder outside
the repository. They never go into the repo, its history, CI, an issue or a
PR, and neither does anything else that identifies a user or a purchase.

What identifies someone is never recorded, in any file, commit message,
issue, PR, note or log: the receipt itself (whole or in part), transaction
ids, original transaction ids, web order line item ids, download ids,
device or bundle identifiers of the owner's apps, and exact purchase or
creation timestamps.

What identifies no one may be quoted as evidence: attribute type numbers,
an enum or reason code (for example `cancellation_reason` `"1"`), a
field's format or type, and verdicts with their reasons. When in doubt
whether a value could single out a user, an app or a purchase, leave it
out.

`tools/private-receipt-check.mjs` prints only verdicts and unknown
attribute type numbers. A new attribute type becomes a test built from a
generated receipt of the same shape.

## Spikes and evidence

Every experiment's code goes into the repo, even code that answered "no".
A spike that measures something ends with a note at
`docs/evidence/<date>-<name>.md` and its sources in
`docs/evidence/<date>-<name>/`, committed together. Code left on a scratch
disk is lost when the session ends, and a result nobody can rerun is a
claim, not evidence. Layout and what stays out (binaries, local paths,
secrets, production receipts) are in `docs/evidence/README.md`.
