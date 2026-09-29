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
| A2 core | `lane/core` | steps 1.3, 1.4, 1.5 (build script), 1.14: workspace, surface, wire, canonical ABI, schemas | started 2026-09-29 |
| A3 core | `lane/core` | steps 1.7, 1.8, 1.10, 1.12, 1.13 | waits on A2 |
| B server | `lane/server` | Phase 2 against the stand-in component | handed back 2026-09-29 (head 38042f0); parked until the real component: 24 tests green, clippy clean in both feature sets, static musl binary runs in an empty chroot, corpus over HTTP (fresh and pool) and the CLI 6,149 identical + 27 over-cap + 3 intended, 311 cases 119 pass / 159 stand-in / 33 not expressible, managed smoke 10/10, hostile component 6/6, Schemathesis 394 passed, Spectral 0 beside stand-in schemas; Docker not built (no daemon) |
| C node | `lane/host-node` | steps 4.1 to 4.5 | handed back 2026-09-29 (head e2d151c after the blob rewrite); parked until the real module: 90 of 311 cases pass on the stand-in, every non-conformance test passes (50 of 50); smokes on Node 20 to 26, Bun, Deno, workerd, edge-runtime, Chromium |
| C go | `lane/host-go` | steps 4.6, 4.7 | handed back 2026-09-29 (head 60ed382 after the blob rewrite, follow-up pending); parked until the real module: 90 of 311 cases on the stand-in, host-layer corpus 6,176/2/1 as expected, `-race` clean, staticcheck 0, static binary runs in an empty chroot |
| C java (Endive, API shell) | `lane/host-java` | steps 3.1, 3.2, 3.5 to 3.8 | handed back 2026-09-29 (head b4cfcb1); parked until the real module: 366 tests green on JDK 21, the 311 cases on 11, 17 and 21 with 90 passing and 221 listed stand-in differences, Java 8 leg 32 tests green, `java/` unchanged (516 tests), corpus 6,176/2/1 at 1 and 4 threads, class majors 52/55 proven, 0 native references across 475 classes, classpath guard proven with Maven and Gradle |
| C python | `lane/host-python` | steps 5.1 to 5.3 | handed back 2026-09-29 (head 64a6cfe after the blob rewrite); parked until the real module: 94 of 311 cases on the stand-in, host-layer corpus 6,176/2/1 in 13 s, CPython 3.10 to 3.14 green (218 expected failures each), ruff and mypy clean, 8 platform-tagged wheels built and the install-failure path proven with a faked platform |
| C ruby | `lane/host-ruby` | step 5.5 | handed back 2026-09-29 (head 22c464b); parked until the real module: 90 of 311 cases on the stand-in (221 differ), corpus 6,176/2/1, rubocop, steep and rbs clean, gem 1,025,024 B, clean install picks the prebuilt native gem; thread scaling and the first-create time to be re-measured on a quiet machine (5.6 s here against the spike's 1.3 s) |
| C swift | `lane/host-swift` | step 5.4 | started 2026-09-29 |
| C dotnet | `lane/host-dotnet` | step 5.6 | started 2026-09-29 |
| D supply chain | `lane/supply-chain` | steps 1.5, 1.13 to 1.15, 2.8 to 2.10 jobs, CI matrix, release.yml | **merged** 2026-09-29 (head cff064d); actionlint and zizmor at 0; jobs gated on the other lanes' files, see `.github/CI-NOTES.md` |
| E java server engine | `lane/host-java` (after C java) | step 3.3, 3.4, 3.9 | started 2026-09-29 |
| F php | `lane/php` | Phase 6 | started 2026-09-29 |

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
  overriding it. Done: Node, Go, Python. Pending: Ruby, Swift, .NET,
  Java (before their hand-backs). The real module is added once, in Go
  and Swift only, at integration.

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
