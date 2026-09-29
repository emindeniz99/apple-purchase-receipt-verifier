# Migration status

Live state of the `rust-core` integration branch. The orchestrator
updates this file as lanes start, hand back and merge; the owner reads
it, and the final pull request to `main`, once at the end.

Started 2026-09-29. Owner's rules: everything accumulates on `rust-core`;
lanes are `lane/*` branches merged back with real merge commits; no
owner review until the final pull request; agents review each other's
work.

## Lanes

| Lane | Branch | Scope | State |
|---|---|---|---|
| A1 core | `lane/core` | steps 1.1, 1.2: the core on OpenSSL 4, native build | handed back 2026-09-29 (head d5c2838): 548 tests, conformance 313/313, vendored and `OPENSSL_DIR` builds identical on 6,179 rows, no verdict change against the 0.7 core except 5 JWS rows the Java implementation already verifies, `rust/ffi` 22 tests plus C++ and ctypes 278/278, isolation test under strace; evidence note `2026-09-29-openssl-core-parity` |
| A2 core | `lane/core` | steps 1.3, 1.4, 1.5 (build script), 1.14: workspace, surface, wire, canonical ABI, schemas | handed back 2026-09-29 (head 05b4ad9): the real `aprv.wasm` (3,005,922 B) and component (3,008,364 B), reproducible from a fresh clone; 311 of 311 cases through the trap host with 0 traps, ABI tests 18 checks on Node and 11 on Wasmtime, module identical to its native twin on 6,179 of 6,179 corpus rows and to A1's 0.7 rows on the 5,897 the text API could take; every answer validates against the four JSON Schemas; workspace 589 tests, clippy clean, `check-layering` and `check-wasm.sh` pass; `wasi:random` measured and not adopted; evidence note `2026-09-29-aprv-wasm-parity` |
| A-fix core | `lane/core` | step 1.10 close-out: the three reviews' blocking and fix-before-merge findings, then a rebuilt module | started 2026-09-29 (brief `core-fix.md`) |
| A3 core | `lane/core` | steps 1.7, 1.8, 1.12, 1.13 | waits on A-fix |
| B server | `lane/server` | Phase 2 against the stand-in component | handed back 2026-09-29 (head 38042f0); parked until the real component: 24 tests green, clippy clean in both feature sets, static musl binary runs in an empty chroot, corpus over HTTP (fresh and pool) and the CLI 6,149 identical + 27 over-cap + 3 intended, 311 cases 119 pass / 159 stand-in / 33 not expressible, managed smoke 10/10, hostile component 6/6, Schemathesis 394 passed, Spectral 0 beside stand-in schemas; Docker not built (no daemon) |
| C node | `lane/host-node` | steps 4.1 to 4.5 | **G1 green** 2026-09-29 (head 9e1f8a0): on the real component 676 tests pass on Node 20, 22, 24 and 26 with 311 of 311 cases on both entry points, corpus 6,179 of 6,179 identical with 0 traps, smokes on Bun, Deno, workerd, edge-runtime and Chromium, tarball 1,044,973 B, one-command re-run `node/scripts/g1.mjs`; the only fix was the runner's own base64 judgement; timings on a loaded machine: g5 about 5 ms, first `createVerifier` 135 to 153 ms; the hostile 3 MiB receipt grows linear memory to 73.9 MiB (stand-in 53.2 MiB) and costs 0.8 s before `MALFORMED`, which the review fix for the payload pre-read should shrink; the production workerd 128 MB limit stays unmeasured |
| C go | `lane/host-go` | steps 4.6, 4.7 | **G1 green** 2026-09-29 (head 3ce225a): on the real module 311 of 311 cases, full suite and `-race` green, host-layer corpus 6,179 of 6,179 identical to the module's rows with 0 traps, no wrapper change needed for the 0.7 wire, pin updated, one-command re-run `go/internal/corpusrun/g1.sh`; timings on a loaded machine: g5 5.4 ms, JWS 22 ms, instance plus `init` 13 to 27 ms (2 ms on the stand-in), first compile 2.3 s; earlier: staticcheck 0, static binary runs in an empty chroot |
| C java (Endive, API shell) | `lane/host-java` | steps 3.1, 3.2, 3.5 to 3.8 | handed back 2026-09-29 (head b4cfcb1); parked until the real module: 366 tests green on JDK 21, the 311 cases on 11, 17 and 21 with 90 passing and 221 listed stand-in differences, Java 8 leg 32 tests green, `java/` unchanged (516 tests), corpus 6,176/2/1 at 1 and 4 threads, class majors 52/55 proven, 0 native references across 475 classes, classpath guard proven with Maven and Gradle |
| C python | `lane/host-python` | steps 5.1 to 5.3 | handed back 2026-09-29 (head d4613dc after the blob rewrite and the env-override fix); parked until the real module: 94 of 311 cases on the stand-in, host-layer corpus 6,176/2/1 in 13 s, CPython 3.10 to 3.14 green (218 expected failures each), ruff and mypy clean, 8 platform-tagged wheels built and the install-failure path proven with a faked platform |
| C ruby | `lane/host-ruby` | step 5.5 | handed back 2026-09-29 (head d223f7b after the blob rewrite and the env-override fix); parked until the real module: 90 of 311 cases on the stand-in (221 differ), corpus 6,176/2/1, rubocop, steep and rbs clean, gem 1,025,024 B, clean install picks the prebuilt native gem; thread scaling and the first-create time to be re-measured on a quiet machine (5.6 s here against the spike's 1.3 s) |
| C swift | `lane/host-swift` | step 5.4 | handed back 2026-09-29 (head 0ef6614 after the blob rewrite); parked until the real module: 57 tests with 46 passing, the 9 failures all stand-in; 311 cases 90 pass / 221 stand-in; corpus 6,176/2/1 in 116 s; `swift format lint --strict` clean; release builds on Linux; iOS and macOS are CI's |
| C dotnet | `lane/host-dotnet` | step 5.6 | handed back 2026-09-29 (head 3966e00 after the blob rewrite); parked until the real module: 524 tests with 303 passing and the same 221 stand-in failures on net8 and net10 (net9 self-contained too), Floor project 9/9 on 8, 9, 10, corpus 6,176/2/1, `dotnet format` clean, nupkg 2,108,091 B with a clean consumer; evidence note `2026-09-29-dotnet-host` |
| D supply chain | `lane/supply-chain` | steps 1.5, 1.13 to 1.15, 2.8 to 2.10 jobs, CI matrix, release.yml | **merged** 2026-09-29 (head cff064d); actionlint and zizmor at 0; jobs gated on the other lanes' files, see `.github/CI-NOTES.md` |
| E java server engine | `lane/host-java` (after C java) | step 3.3, 3.4, 3.9 | handed back 2026-09-29 (head 87b0ab4 after the blob rewrite); parked until the real module: 380 tests green on JDK 21 and 379 on Temurin 8; the 311 cases through the server engine 93 pass / 218 stand-in on both; the spike's 31 checks pass; classifier jar built for x86_64 (4,179,407 B); `jvm-interop` and the Spring Boot smoke take the artifact as a property |
| F php | `lane/php` | Phase 6 | handed back 2026-09-29 (head 37868a0); parked until the real module: 817 tests green with the stand-in's 214 differences asserted per transport (97 of 311 pass), phpstan max 0, php-cs-fixer clean, installer proven against a local server with the right and a wrong hash, `composer validate --strict` on both manifests; only PHP 8.4 here |

## Decisions taken by the orchestrator (owner to read at the end)

- The Java `-wasm` artifact lives in `java-wasm/` beside `java/`, the
  pattern `jvm-interop/` and `java-bench/` already use, instead of moving
  `java/` into a submodule (ARCHITECTURE §7.8, MIGRATION 3.1 said "one
  reactor"). Reason: no file moves, no path changes in CI, release-please
  and docs.
- Only lane D edits `.github/`; other lanes leave `CI-NOTES.md` in their
  package for the integrator.
- The stand-in module for every host lane is round 13's canonical-ABI
  module and component (0.6 core); each lane records the cases that
  differ because of it and changes nothing to make them pass. Parity
  gates run again with the real module after G1.
- The integration checklist's fourteen owner decisions (OD-01 to OD-14
  in `integration-checklist.md`), taken 2026-09-29 so integration can
  proceed; the owner reads them at the end:
  - OD-01: `rust-wasm` runs whenever any host area is selected, and
    `aprv-server` builds and uploads the Linux x86_64 static binary as an
    artifact whenever `java-wasm/` or `php/` is selected; every host job
    downloads the module (or the binary) before its first build step. No
    job downloads a previous run's artifact.
  - OD-02: R14 stands. Exactly two committed copies of the real module
    exist, `go/internal/wasm/aprv.wasm` (Go's module zip must carry it
    for `//go:embed`) and the Swift resource (SwiftPM has no binary
    target for a `.wasm`); both land once at integration with their
    `.sha256`, and `refresh-wasm-copies` rewrites both files together on
    the release branch. Cost the owner should know: about 1 MB of packed
    history per copy per release (the module is 2.9 MB, 0.9 MB zlib).
  - OD-03: the core crate is held on crates.io at 0.7 until openssl-sys
    accepts openssl-src 400 (`publish-crates` and the crates smoke are
    skipped with that reason in the workflow); the README documents the
    `OPENSSL_NO_VENDOR=1 OPENSSL_DIR=<OpenSSL 4>` path for a source build.
    The upstream request is the owner's item.
  - OD-04: `check-one-implementation.mjs` gets a per-file allowlist;
    .NET's `X509Certificate2?` on the public 0.7 API and Go's
    `crypto/x509` in its three configuration files are listed with a
    reason each. No API break.
  - OD-05: the corpora (200 MB of generated rows) stay out of the
    repository. CI's reference is the 311 cases plus the corpus of
    generated receipts A3 builds; the nightly corpus jobs run only when
    the repository variable `APRV_CORPUS_URL` names an owner-hosted
    archive, and print a notice otherwise.
  - OD-06: PHP pins the two Linux musl binaries only, from a
    release-branch job that builds them (they are reproducible per
    `tools/reproduce-server.sh`) and writes `php/binaries.json` with `jq`
    and `sha256sum` alone, no repository code, in the same commit as the
    module copies; the macOS and Windows entries stay `null` (those
    platforms use the server URL option) until `release.yml` publishes
    the branch run's exact files.
  - OD-07: the classifier jars ship with every release; a release costs
    about 10.5 MB of the 80 MB monthly Central allowance, so the release
    budget in CLAUDE.md drops from 7 to 5 releases a month with 2 in
    reserve. Owner call to confirm.
  - OD-08: lane B's names win (`build-static.sh COMPONENT [TARGET]
    [OUTDIR]` writing `aprv-<target>`, `APRV_TEST_COMPONENT`,
    `docker-smoke.sh`); lane D's call sites are adapted at integration;
    `.exe` handling and the `prebuilt` image stage are added on lane B's
    files.
  - OD-09: the `rust` test job caches `target/` (test jobs may), the
    timeout rises to 40 minutes, the `--no-default-features` leg keeps
    running against the OpenSSL 4 lane D's toolchain script builds, and
    the job runs `--workspace` so the isolation test runs.
  - OD-10: the server-engine tests run on Linux x86_64 legs only; other
    legs run `-DexcludedGroups=server`; Temurin 8 stays as long as the
    main artifact supports Java 8.
  - OD-11: `node/licenses/` becomes the root `licenses/wasm/` (one
    source); every package copies from it at build or packaging time and
    `tools/check-licence-copies.mjs` diffs the copies in CI; the Java
    jar and the Python wheels take theirs from there.
  - OD-12: the Go-only RSA modulus cap and the other port-only rules in
    `go-inventory.md` go to A3's test inventory as fixture candidates.
  - OD-13: no 32-bit claim for Go.
  - OD-14: the integrator pins the container digests and the Playwright
    version per the CI rules.

## Hand-back findings the owner should know

- Lane D: fuzz findings in CI do **not** open an issue (the repository is
  public; an auto-opened issue would disclose a memory-safety crash). The
  job fails and keeps the input for 7 days. Owner decision if a private
  channel is wanted instead.
- Lane D: `actions/attest-sbom` is deprecated; SBOMs are attested with
  `actions/attest` and `sbom-path`.
- Lane D: `wasm-copies` is strict only on `release-please--*` branches
  (the committed Go and Swift copies lag the core between releases);
  `build-wasm` in `release.yml` enforces the match on a tag.
- Lane D: `rust/rust-toolchain.toml` pins 1.98.1; cargo commands without a
  toolchain override now use it; lane A adds the file to the crate's
  `exclude`.
- Lane Node (cross-host API decision, orchestrator): `Config.roots` in a
  wrapper is the caller's DER list or "the module's built-in roots"
  (`null`/empty); `defaults().roots` no longer lists the three Apple
  certificates, because the wrappers no longer carry a copy. "Apple's
  roots plus mine" is expressed by passing all four DERs. Every host
  follows this. Node also dropped its two Node-only test hooks
  (`decodeReceiptBase64`, `decodeX5cEntry`), which were not in the 0.7
  API document.
- Lane Node: `unknownAttributes` order across types is lost on the JSON
  wire (an object keyed by type); order within a type is kept. Inherent
  to the wire shape (SURFACE §4).
- Lane Node: jco's glue reads `process.env.JCO_DEBUG`; Deno needs
  `--allow-env=JCO_DEBUG`. Documented; no transpile flag removes it.
- Lane Node: the Bun WASI `random_get` bug is fixed in Bun 1.4.0; nothing
  to file. It never affected the package (no WASI import).
- Lane Go: wazero v1.9.0, not 1.12, because 1.12 needs Go 1.25 and R30
  keeps the floor at Go 1.22 unless wazero forces it; an A/B showed equal
  speed. Dependabot must ignore wazero at or above 1.10.0 (the "floors
  are tested claims" pattern). Owner may prefer the newer runtime for its
  fixes at the cost of the floor.
- Cross-host decision (orchestrator, from Go's report): a `Failure`'s
  cause is set only when `INTERNAL_ERROR` comes from the wrapper (a trap,
  an unreadable answer, the clock), never for the module's verdicts
  (SURFACE §8: the cause chain is Rust-only). An `Environment` value
  that is neither constant answers `{"status":21009}` rather than
  panicking (the 0.7 "never throws" contract). A clock before 1970 is
  `INTERNAL_ERROR` (`now-ms` is a `u64`).
- Lane Python: `Config` roots are DER `bytes` (the cross-host decision;
  `cryptography` is gone). The release publishes platform-tagged wheels
  and no `py3-none-any` wheel, so a platform without a wasmtime-py wheel
  falls to the sdist, which stops with the pointer to `aprv-server` and
  the C ABI (R28); `release.yml`'s Python build must become
  `python/tools/build_dist.py` plus `--check` (integrator). A libc too
  old for wasmtime-py's wheel still fails at import, not install.
  `APRV_WASM_CACHE_DIR` is the cache path variable (R27); an empty value
  turns the cache off. atheris has no CPython 3.11 wheel here, so the
  fuzz targets ran only with a stub.
- Lane F (PHP): the transport is the second argument of
  `Verifier::create`, not a `Config` field; an empty root list means the
  built-in roots and PEM roots are refused (breaking, footered); `TOO_LARGE`
  from exit 3 or 413 carries a wrapper message and no cause. `composer
  install` could not complete here (GitHub dist downloads timed out and
  Composer fell back to 3 GB of source clones); the suite ran on the
  PHPUnit phar, so the locked PHPUnit range is exercised only by CI.
  Docs still saying PHP needs `ext-openssl` (`PLAN.md`, `INVENTORY.md`)
  are Phase 7's.
- **Open for integration: how `binaries.json` gets its hashes.** The PHP
  installer verifies the downloaded server binary against hashes shipped
  in the tag's archive, but the binaries are built at the tag. Proposed
  resolution: the Linux static binaries are reproducible (lane D's
  `reproduce-server.sh`), so the release-branch run builds them and pins
  their hashes into `binaries.json` on the release PR, and the tag build
  fails if its hashes differ; for macOS and Windows, which are not
  bit-reproducible, the tag publishes the release-branch run's own
  artifacts, or their entries stay null and those platforms use the
  server URL transport. Decided at integration, recorded here for the
  owner.
- Lane E (Java server engine): the cache directory defaults to
  `~/.cache/aprv`, `~/Library/Caches/aprv` or `%USERPROFILE%\AppData\Local\aprv\cache`,
  owner-only, symlinks and foreign or other-writable directories
  refused; a noexec mount is detected from `/proc/self/mountinfo`;
  `Platform.java` reads only the JDK's `os.name`, `os.arch` and
  `user.home` (the source-rules test allows exactly those); a 413 maps to
  `TOO_LARGE` / 21002; the two cause types are package-private so the
  public API equals the main artifact's. `github()` answers 404 today
  because v0.7.0 has no release asset. Maven Central: the classifier jars
  bring a release to about 10.5 MB, so seven releases in a month would be
  about 74 MB of the 80 MB allowance. A g5 call from Java 8 measured
  8.55 ms mean here under load (spike: 3.87 ms); re-measure on a quiet
  runner.
- Lane Swift: **the WasmKit floor is 0.4.1, not 0.4.0.** 0.4.0 has a
  use-after-free under software bounds checking when a host function
  re-enters the guest and grows memory, which is exactly what
  `random-get` does through `cabi_realloc`; 0.4.1 (released 2026-09-29)
  fixes it and also stops a module from aborting the host with an
  allocation it cannot satisfy. The shipped configuration uses software
  bounds checking (THREAT-MODEL §2); mprotect would install a
  process-wide signal handler in the caller's process. No memory limit
  per instance (WasmKit's limiter is `@_spi`); instances over 64 MiB are
  dropped. The clock is read on every call; `Config.roots` is
  `[[UInt8]]?`.
- Lane Swift: **the JWS speed margin needs a re-measure.** On this
  machine, loaded by other lanes, JWS ran at about 1.0 times the 10 per
  second per core floor (9.0 to 10.1 per CPU-second), against the plan's
  1.7 to 1.9 times; round 7's own harness re-run in the same minutes was
  2.2 times slower than its recorded figures, so the machine, not the
  package, accounts for it. Re-measure on an idle runner before 0.8.0;
  R4 leaves the call to the owner if a platform falls below the floor.
- **Runtime environment overrides are not allowed in a library**
  (orchestrator, from Swift's report and CLAUDE.md): an environment
  variable that swaps the verification module inside a caller's process
  is a hole. Node, Go, Java and .NET honour `APRV_WASM`/`APRV_COMPONENT`
  at build time only; Swift copies the file into the resource path;
  Python and Ruby, which had read the variable at run time, are
  corrected: neither library reads it, only their test and build tooling,
  and a test in each greps the library for environment reads.
- Lane Swift, for the integrator: `release-please.yml`'s
  `refresh-wasm-copies` copies `aprv.wasm` but never rewrites the
  `.sha256` beside it, which would break the Go and Swift packages on the
  release branch; `.github/smoke/swiftpm-smoke` must move to tools 6.3
  and macOS 15 and drop its `roots.count == 3` check.
- Lane .NET: the public API keeps `X509Certificate2` for roots (the
  unchanged 0.7 type, which carries DER); the one-implementation gate
  will allowlist that type for `dotnet/` at integration rather than
  break the API. An out-of-range `Environment` enum value throws (a
  programmer error in C#), where Go answers 21009. Empty roots and a
  certificate with no data are refused at `Config.Builder.Build()`.
  Each Wasmtime instance reserves about 4.2 GiB of virtual address
  space by default (0.25 MiB resident); a 256 MiB reservation cost 35%
  of speed and is not shipped.
- Lane Ruby: `VerificationError` (private) removed; new public
  `AbiMismatchError`, `ModuleIntegrityError`, `TrapError`. The gemspec
  floor is open-ended (`wasmtime >= 48.0.1`), as R27's rule for Python.
  Its commits carry the Sonnet 5.5 and session trailers but not the
  orchestrator's; attribution is truthful, so the history stands. It
  wrote an evidence note (`2026-09-29-ruby-host`) that the integrator
  audits before the merge.
- Lane A1 (core): **crates.io is deferred.** `openssl-sys` 0.9.117 does
  not accept `openssl-src` 400.x, so a registry build would get OpenSSL 3
  and the adapter's `build.rs` refuses anything but OpenSSL 4 (one
  substrate everywhere, the safer choice; the plan's ARCHITECTURE §7.11
  had allowed OpenSSL 3 for registry users). The workspace carries a
  one-line `[patch.crates-io]` on a vendored `openssl-sys` manifest; the
  crates publish waits for upstream to widen its requirement (owner
  action: ask or send the change to rust-openssl), which R19 allows
  since nothing needs the crate on crates.io for 0.8.0.
- Lane A1 (core): **behaviours that changed with OpenSSL**, all recorded
  in the evidence note and to be moved into R20 at integration; none
  turns a refused Apple-signed input into a verified one, and the five
  verdict changes (a P-521 chain signature and four canonical-name
  variants, refused before, verified now) match what the Java
  implementation already does: the RSA key cap is OpenSSL's 16,384 bits
  (was 8,192); names chain by their RFC 5280 canonical form; signers
  identified by SubjectKeyIdentifier are accepted; P-521 and SHA-3 are
  accepted; garbage in `crls` is `MALFORMED`; a certificate OpenSSL
  cannot decode makes the whole envelope `MALFORMED`; the critical-
  extension list is OpenSSL's; an intermediate with keyCertSign and no
  basicConstraints passes OpenSSL's CA check; any unusable key is
  `INVALID_CERTIFICATE`. 138 corpus rows change their refusal reason in
  six explained groups; 2,971 change only the message.
- Lane A1 (core): three 0.7 refusals OpenSSL does not make were restored
  in Rust on a shallow decode (`envelope.c`): the certificate and
  SignerInfo counts before any key is decoded (a 1,057-certificate flood
  now costs 1.3 ms instead of 48 ms), constructed `eContent` with
  non-OCTET-STRING chunks, and a `signatureAlgorithm` naming a different
  hash than the digest. If a host initialises OpenSSL with its own
  config before the adapter's first call, that config applies
  (documented).
- Lane B (server): the managed roots line is mandatory (`{}` for the
  defaults); the port line is `APRV_LISTEN=127.0.0.1:<port>`; CLI exit
  code 2 means usage or configuration; the problem codes are lane B's
  names; the token is not required on `/healthz`, `/readyz`,
  `/openapi.json`; the embedded file's SHA-256 is checked at build time
  only (a start-time hash cost 50 ms, a third of a CLI call); the store
  admits exactly 3 core instances (the component's shim, module and
  fixup); the server decodes base64 only to fingerprint the configured
  roots; the corpus over HTTP splits 6,149 + 27 over-cap + 3 (MIGRATION
  2.7 said 6,153 + 25 + 1; the cap now also catches the DER-at-cap row's
  base64); the crate is outside the workspace with its own lockfile.
- Lane Java: the `-wasm` public API copies `java/`'s types rather than
  sharing them (R33); `release-please-config.json` entries for
  `java-wasm/pom.xml`, `Version.java` and `java-wasm/README.md` are the
  integrator's (listed in `java-wasm/CI-NOTES.md`); the jar ships no
  licence texts yet because the repository has no shared bundle
  (integration item: one `licenses/` bundle for every package, replacing
  Node's and Ruby's own copies); `Verifier.create(config)` on Java 8
  throws until the server engine lands; the Endive host calls
  `_initialize` once per instance (the other hosts do not; parity holds
  either way).
- Every host lane so far except Java: `_initialize` is not called, the first export
  call runs the constructors; A2 confirms the release module needs no
  start call.
- Both Node, Go and Python tell the `decodeBase64` fixture groups apart through
  the core's message text ("receipt is not valid base64", "x5c entry is
  not valid base64"); lane A2 keeps those messages stable or gives the
  runners a hook.
- **Stand-in blobs removed from lane history** (owner, 2026-09-29: a
  history rewrite on an unmerged lane branch is allowed to drop a large
  blob). Every host lane had committed the 2.83 MB stand-in module
  against R14; each lane branch is rewritten with `git filter-branch`
  to drop only that file (every commit kept, same messages and authors,
  new hashes), force-pushed with a lease, and the package reads the
  module from an ignored path with `APRV_WASM`/`APRV_COMPONENT`
  overriding it. Done for every lane: Node, Go, Python, Ruby, .NET,
  Swift, Java. A shared `pre-push` hook now refuses
  any new blob over 100 KB outside the two R14 paths; the same check
  becomes a CI job at integration. The real module is added once, in Go
  and Swift only, at integration.

## Review (step 1.10) and integration prep

- 2026-09-29: three adversarial reviewers (agents other than the
  author) reviewed lane A1's commit d5c2838: the adapter's Rust and
  `unsafe` (0 blocking, 6 fix before merge, 10 notes), the C ASN.1
  templates (1 blocking, 2 fix before merge, 5 notes) and the core's
  policy against the 0.7 contract and the threat model (1 blocking, 6 fix
  before merge, 3 notes). Every finding was reproduced with crafted input.
  Nothing in memory safety, isolation or trust broke: no double free, no
  per-call leak, no panic path, valgrind clean, no verified verdict
  without a valid signature under a pinned root, no way to move the
  chain instant. The three reviews converge on one gap: the cheap checks
  before the full CMS decode cover less than 0.7's reader did. The
  ten-certificate and four-SignerInfo bounds run only on a well-formed
  `signedData` envelope (one trailing byte, a removed `signerInfos` or an
  `envelopedData` content type skips them and the full decode builds
  every certificate's key first: about 0.7 s natively and 1.1 s under
  Wasmtime per unauthenticated 3 MiB receipt, against 8 ms when the bound
  fires); the depth-32 bound counts only SEQUENCE and SET inside
  SignerInfo values; the 100,000-node budget is gone (1.18 M empty
  SEQUENCEs in an unsigned attribute cost 0.6 s and about 140 MB before
  any signature check); the constructed-string nesting check is off by
  one (6 legal BER levels refused, which 0.7 and Java verify); foreign
  chunk types inside signed payload values are joined where 0.7 and Java
  answer `UNREADABLE_PAYLOAD`; and a few payload encodings are accepted
  or refused differently from 0.7 without a record. Docs findings: root
  `THREAT-MODEL.md` §3 cites the deleted `asn1.rs`, says seven fuzz
  targets (four) and "no port re-encodes" (OpenSSL re-encodes
  signedAttrs). The policy reviewer's blocking finding (the branch did
  not build from a clean checkout: the vendored openssl-sys `build/`
  directory fell under the root `.gitignore`) was already fixed by A2 in
  947a5bb. Decision: one `ASN1_get_object` header walk over the whole
  envelope before `d2i_CMS_ContentInfo`, carrying 0.7's depth and node
  budgets and the certificate, SignerInfo and `crls` bounds, refusing
  where the shallow decode refuses; the payload rules 0.7 had are
  restored where the walk can express them and recorded as R20
  divergences with fixture cases where they cannot. ARCHITECTURE §9's row
  forbidding `ASN1_get_object` in the adapter was wrong as worded
  (A1's `envelope.c` already used it; every reviewer proposes it as the
  fix) and becomes "not in `rust/src`; in the adapter only inside the
  documented header walk", enforced by `check-layering`. Lane A-fix
  applies all of this on `lane/core` and rebuilds the module; the
  findings files become `docs/rust-core/REVIEW-LOG.md` with each
  finding's disposition when A-fix hands back.
- A2's open question (ARCHITECTURE §9 against `envelope.c`) is answered
  by that decision.
- A2 found the 0.6 stand-in fails 184 of the 311 cases
  (`docs/evidence/2026-09-29-aprv-wasm-parity/results/standin-case-differences.txt`);
  the host lanes' stand-in lists must empty on the real module.
- The integration checklist is compiled
  (`$SCRATCH/lanes/integration-checklist.md`, about 130 KB): 236 CI-NOTES
  bullets mapped to rows per workflow file, 26 cross-lane contract rows,
  9 Phase 7 deletion rows, 14 owner decisions, 20 lane conflicts. The
  ones that change the plan: the module reaches no host CI job today
  (`rust-wasm` skipped on host-only PRs, `aprv-server` uploads no
  artifact, Go and Swift ignore the path the `wasm-copies` and
  `tag-go-module` gates look at); lane B and lane D disagree on the
  server build script's arguments, output names, the component env var,
  the Dockerfile `prebuilt` stage and the smoke script name; no workflow
  refreshes the tracked `.sha256` pins; Node's `Config.defaults().roots`
  is `null` so the npm smoke throws; `java-wasm/scripts/classpath-guard.sh`,
  `image-smoke.sh`, `tools/differential.sh` and a per-file allowlist in
  `check-one-implementation.mjs` are named by notes but written by nobody.
  All are integration work after the merges.
- G1 started 2026-09-29 10:40Z: the real module, the component, the five
  corpora as pinned call files and the module's own 6,179 reference rows
  are in a shared scratch directory; node, go, python, ruby, swift, dotnet,
  java (Endive) and the server re-run against them; php and the Java
  server engine follow once the server hands back its rebuilt binary.
  Expected everywhere: 311 of 311 and 6,179 of 6,179. A short second
  re-run (G1b) follows the review-fixed module, whose verdicts differ only
  on crafted inputs.

## Merge policy on this branch

Host lanes are parked on their branches after hand-back and merged only
after their conformance run is green on the real module (after A2), so
`rust-core`'s CI stays meaningful. Infrastructure lanes (D) merge at
hand-back.

## Gates

| Gate | State |
|---|---|
| G1 | open |
| G2 | open |
| G3 | open |
| G4 | open |
| G5 | open |
| G6 | open |
| G7 | open |
