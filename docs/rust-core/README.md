# One Rust core: the migration plan

Status on 2026-09-26: **accepted plan.** Phase 0 (inventory and spikes) is
done. The owner settled every owner call on 2026-09-25, rewrote R20 and
added R21 (the OpenSSL substrate) on 2026-09-26, and split Java into two
artifacts the same day (R18; table below).
Implementation waits: the owner wants every open question settled before
Phase 1 starts (2026-09-25).

## The idea

Today nine implementations in nine languages repeat one security
algorithm: ASN.1, X.509, CMS, JWS, chain policy, caps and Apple's rules.
The plan keeps one of them, the Rust crate, and turns every published
package into a thin binding over it:

- UniFFI for Swift, Python and the Java 8 artifact (Kotlin over JNA);
- one plain wasm module, `aprv.wasm`, for npm (with a hand-written JS
  façade, no wasm-bindgen), for Go through wazero, and for the main Java
  artifact (Java 11+), which Endive compiles to JVM bytecode at build
  time;
- the existing C ABI for everything else.

The core itself sits on OpenSSL 4 (R21): OpenSSL parses the ASN.1, CMS and
X.509 and does the signature arithmetic, and the Rust code keeps Apple's
policy. The core's own ASN.1, X.509, CMS, chain and crypto modules are
deleted.

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
4. [DECISIONS.md](./DECISIONS.md): R1-R21, each with options, evidence and
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
- **The core builds for wasm** with OpenSSL inside: a `wasm32-wasip1`
  build with wasi-sdk's libc and a small link-time C file imports only
  `aprv.clock_now_ms` and `aprv.random_get`. It gave the native answers on
  all 1,179 corpus rows in Node, Bun, Deno, Chromium, Firefox, WebKitGTK,
  workerd, wazero and Wasmtime
  ([OpenSSL CMS everywhere](../evidence/2026-09-26-openssl-cms-everywhere.md)).
  `wasm32-unknown-unknown` cannot build `openssl-sys`.
- **Go can stay cgo-free** by running the same module through wazero.
- **OpenSSL 4.0.2 with the CMS API can carry the core** (R21). It answers
  as Java does on 1,028 of 1,048 rows, all 22 signature-algorithm inputs
  included; none of the other 20 is a forgery. Coverage-guided fuzzing
  with OpenSSL instrumented found nothing in any campaign
  ([substrate bake-off](../evidence/2026-09-26-security-substrate-bakeoff.md),
  [follow-up](../evidence/2026-09-26-substrate-followup.md),
  [ASN.1 payload](../evidence/2026-09-26-openssl-asn1-payload.md)).
- **Java 11+ can run `aprv.wasm` as JVM bytecode.** Endive 1.1.0
  compiled the module at build time into an ordinary jar. A clean Maven
  consumer answered all 1,179 corpus rows and 5,000 mutants the same as
  native on JDK 11, 17, 21 and 25, with no native code loaded. Receipts
  took 5.9 to 9.5 ms and JWS 20 to 29 ms on one core; an instance serves
  one thread at a time
  ([Endive build-time JVM](../evidence/2026-09-26-endive-build-time-jvm.md)).
- **Python via UniFFI** gives typed exceptions, default arguments and
  docstrings from Rust doc comments.

## Owner calls (all settled)

| # | Question | Recommendation |
|---|---|---|
| R21 (**accepted** 2026-09-26) | Security substrate? | OpenSSL 4 through rust-openssl, with the CMS API and our own chain policy. `asn1.rs`, `x509.rs`, `cms.rs`, `chain.rs` and `crypto.rs` are deleted; the payload is read with OpenSSL's ASN.1 templates. npm and Go share one `aprv.wasm`. |
| R4 (**accepted**) | npm on Node: the OpenSSL wasm module took 1,395 µs per receipt and 4,550 µs per JWS against 683 and 732 µs for today's `node:crypto` build (informational). Accept it, or add a napi-rs native addon? | Ship the plain wasm module. Add napi-rs only if a user reports throughput trouble; the 2x speed trigger was dropped on 2026-09-26. |
| R6 (**accepted**, plus an opt-in cgo fast path on demand) | Go: wazero (cgo-free; the OpenSSL module took 2,495 µs per receipt against 207 µs for today's Go port), cgo (native speed, loses `CGO_ENABLED=0`), keep the Go port, or retire it? | wazero, running the same `aprv.wasm` as npm |
| R7 (**accepted**: 6.2 everywhere) | Swift on Linux needs Swift 6.2 (SE-0482) for a prebuilt Rust library. Raise the floor or drop Linux? | Raise the floor to 6.2 |
| R18 (**accepted**, supersedes R13; two artifacts since 2026-09-26) | Java binding? | One thin hand-written Java façade API in two artifacts: `apple-purchase-receipt-verifier` (Java 11+, `aprv.wasm` compiled to bytecode by Endive, no natives) and `apple-purchase-receipt-verifier-java8` (UniFFI over JNA, 9 natives). One reactor, one Central deployment, equal versions; a classpath guard refuses both at once |
| R16 (**accepted**) | Keep the surface free of any binding generator? | Yes: SURFACE.md |
| R17 (**accepted**) | A local verifyReceipt server? | Yes, as a product and as a Java library mode |
| R5, R9, R15 (**accepted**) | Drop Fastly/Akamai; delete Ruby/PHP/.NET after Phase 1; Python first | As recommended |
| R19 (**accepted**) | Versions? | Every package moves to the Rust core in one 0.8.0 release, stays 0.x; crates.io waits until needed |
| R12 (**accepted**, incl. Swift on Windows) | Which native targets? | Every target stable Rust builds that someone still runs: 26 C ABI archives, 19 wheels, 9 natives in the Java 8 jar with the other Java 8 platforms served from GitHub Releases; the Java 11+ jar needs no natives |
| R20 (**accepted**, rewritten 2026-09-26) | Signature algorithm policy, and what a Java difference means? | Apple compatibility and failing closed; `fixtures/cases.json` is the contract and Java a reference. Accept any algorithm the pinned chain vouches for. Divergences are recorded; one that changes an Apple-signed input's verdict, or accepts something unsigned, is a bug. |
| R8 (**accepted**, revised 2026-09-26) | After the migration, keep an independent implementation to catch Rust bugs? | Compare against the published 0.7.x Java jar, pinned by version and checksum, until 1.0; no Java verifier source stays in the repository |

Everything else in DECISIONS.md is either the owner's brief (R1, R2, R9) or
a technical recommendation that proceeds unless the owner objects.
