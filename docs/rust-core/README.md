# One Rust core: the migration plan

Status on 2026-09-25: **accepted plan.** Phase 0 (inventory and spikes) is
done. The owner settled every owner call on 2026-09-25 (table below).
Implementation waits: the owner wants every open question settled before
Phase 1 starts (2026-09-25).

## The idea

Today nine implementations in nine languages repeat one security
algorithm: ASN.1, X.509, CMS, JWS, chain policy, caps and Apple's rules.
The plan keeps one of them, the Rust crate, and turns every published
package into a thin binding over it:

- UniFFI for Kotlin/Java, Swift and Python;
- wasm-bindgen for npm;
- wazero for Go;
- the existing C ABI for everything else.

A security fix then lands once, in Rust, and ships to every registry in
the next release.

## Read in this order

1. [INVENTORY.md](./INVENTORY.md): what ships today, where, and how big it
   is (Phase 0).
2. [../evidence/2026-09-25-rust-core-spikes.md](../evidence/2026-09-25-rust-core-spikes.md):
   what the spikes measured, including Java 8, workerd, Go without cgo,
   and timings against today's packages.
3. [ARCHITECTURE.md](./ARCHITECTURE.md): the target design: crates, API,
   time, panics, packaging per registry, invariants.
4. [DECISIONS.md](./DECISIONS.md): R1-R19, each with options, evidence and
   a recommendation.
5. [MIGRATION.md](./MIGRATION.md): phases 1-7 with gates, CI and release
   changes, acceptance tests, risks.
6. [SURFACE.md](./SURFACE.md): the binding-neutral contract between the
   core and every adapter, with its enforcement.

## What the spikes settled

- **Java 8 works** on the generated Kotlin, with one rule: no unsigned
  integers in the API. On JDK 21 the Rust core beats today's Maven jar
  (701 against 781 µs per receipt, 1,096 against 1,253 µs per JWS, after
  10,000 warm-up calls).
- **The core builds for wasm** once three `std` features go, and the clock
  gets a seam. It then runs on Node, Bun, Deno and Cloudflare workerd
  (static `.wasm` import).
- **Go can stay cgo-free** by running the core through wazero.
- **Python via UniFFI** gives typed exceptions, default arguments and
  docstrings from Rust doc comments.

## Owner calls (all settled)

| # | Question | Recommendation |
|---|---|---|
| R4 (**accepted**) | npm on Node runs about 5.3x slower on wasm than today's `node:crypto` build (3.5x against `/web`). Accept it, or add a napi-rs native addon? | Ship wasm. Add napi-rs only if, after the crypto work, the gap stays above 2x or a user reports throughput trouble. |
| R6 (**accepted**, plus an opt-in cgo fast path on demand) | Go: wazero (cgo-free, about 30x slower), cgo (native speed, loses `CGO_ENABLED=0`), keep the Go port, or retire it? | wazero |
| R7 (**accepted**: 6.2 everywhere) | Swift on Linux needs Swift 6.2 (SE-0482) for a prebuilt Rust library. Raise the floor or drop Linux? | Raise the floor to 6.2 |
| R18 (**accepted**, supersedes R13) | Java binding? | UniFFI engine + thin hand-written Java façade; app servers install the jars in shared `lib/` |
| R16 (**accepted**) | Keep the surface free of any binding generator? | Yes: SURFACE.md |
| R17 (**accepted**) | A local verifyReceipt server? | Yes, as a product and as a Java library mode |
| R5, R9, R15 (**accepted**) | Drop Fastly/Akamai; delete Ruby/PHP/.NET after Phase 1; Python first | As recommended |
| R19 (**accepted**) | Versions? | Every package moves to the Rust core in one 0.8.0 release, stays 0.x; crates.io waits until needed |
| R8 (**accepted**) | After the migration, keep an independent implementation to catch Rust bugs? | Keep the Java port as an unpublished test-only oracle until 1.0 |

Everything else in DECISIONS.md is either the owner's brief (R1, R2, R9) or
a technical recommendation that proceeds unless the owner objects.
