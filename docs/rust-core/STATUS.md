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
| A1 core | `lane/core` | steps 1.1, 1.2: the core on OpenSSL 4, native build | started 2026-09-29 |
| A2 core | `lane/core` | steps 1.3, 1.4, 1.5 (build script), 1.14: workspace, surface, wire, canonical ABI, schemas | waits on A1 |
| A3 core | `lane/core` | steps 1.7, 1.8, 1.10, 1.12, 1.13 | waits on A2 |
| B server | `lane/server` | Phase 2 against the stand-in component | started 2026-09-29 |
| C node | `lane/host-node` | steps 4.1 to 4.5 | handed back 2026-09-29 (head 5fd91f7); parked until the real module: 90 of 311 cases pass on the stand-in, every non-conformance test passes (50 of 50); smokes on Node 20 to 26, Bun, Deno, workerd, edge-runtime, Chromium |
| C go | `lane/host-go` | steps 4.6, 4.7 | handed back 2026-09-29 (head 6d1d069); parked until the real module: 90 of 311 cases on the stand-in, host-layer corpus 6,176/2/1 as expected, `-race` clean, staticcheck 0, static binary runs in an empty chroot |
| C java (Endive, API shell) | `lane/host-java` | steps 3.1, 3.2, 3.5 to 3.8 | started 2026-09-29 |
| C python | `lane/host-python` | steps 5.1 to 5.3 | started 2026-09-29 |
| C ruby | `lane/host-ruby` | step 5.5 | started 2026-09-29 |
| C swift | `lane/host-swift` | step 5.4 | started 2026-09-29 |
| C dotnet | `lane/host-dotnet` | step 5.6 | started 2026-09-29 |
| D supply chain | `lane/supply-chain` | steps 1.5, 1.13 to 1.15, 2.8 to 2.10 jobs, CI matrix, release.yml | **merged** 2026-09-29 (head cff064d); actionlint and zizmor at 0; jobs gated on the other lanes' files, see `.github/CI-NOTES.md` |
| E java server engine | `lane/host-java` (after C java) | step 3.3, 3.4, 3.9 | waits on B |
| F php | `lane/php` | Phase 6 | waits on B |

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
- Both Node and Go tell the `decodeBase64` fixture groups apart through
  the core's message text ("receipt is not valid base64", "x5c entry is
  not valid base64"); lane A2 keeps those messages stable or gives the
  runners a hook.
- Node's and Go's branches carry the stand-in binary with scratch build
  paths inside it in one historical blob each (no secret; the real,
  path-remapped module replaces the file). Left as is: no history
  rewrite.

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
