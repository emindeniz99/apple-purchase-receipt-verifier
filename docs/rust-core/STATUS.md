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
| C node | `lane/host-node` | steps 4.1 to 4.5 | started 2026-09-29 |
| C go | `lane/host-go` | steps 4.6, 4.7 | started 2026-09-29 |
| C java (Endive, API shell) | `lane/host-java` | steps 3.1, 3.2, 3.5 to 3.8 | started 2026-09-29 |
| C python, swift, ruby, dotnet | `lane/host-*` | Phase 5 | wave 2 |
| D supply chain | `lane/supply-chain` | steps 1.5, 1.13 to 1.15, 2.8 to 2.10 jobs, CI matrix, release.yml | started 2026-09-29 |
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
