# Simple speed options for aprv.wasm in Node and Endive

Date: 2026-09-26. Code, scripts and raw results are in
`2026-09-26-wasm-speed/`; its `README.md` has the file table and the
commands to reproduce.

The owner asked for a small, conservative round. It covers only official
switches: OpenSSL Configure options, compiler and linker optimisation
levels, `wasm-opt`, and Endive's documented runtime options. It excludes
OpenSSL source patches, anything that weakens a check, blinding,
constant-time code or the use of randomness, and any `no-*` option that
removes something the verifier uses.

The gate for every candidate is strict. It must produce output
byte-identical to round 4's template build on all 1,179 corpus rows and
the 5,000 mutants, against both round 4's native rows and its Node rows.
Its imports must be exactly `aprv.clock_now_ms` and `aprv.random_get`.

Labels: TESTED (ran here), DOCUMENTED (read in a primary source), EXPECTED
(inferred, not run). Nothing under `rust/` or any other production path
changed, and `DECISIONS.md` is untouched.

## Result

- **Every candidate passed the gate.** All 6,179 rows were identical and
  the imports unchanged.
- **Only one change helps Endive.** Endive's `ByteArrayMemory` instead of
  the default `ByteBufferMemory` is 24 to 42% faster, and it changes no
  module byte.
- **Only one change helps Node, and it hurts Endive.** OpenSSL's
  `enable-ec_nistp_64_gcc_128` makes the JWS 35% faster in Node but 2.4 to
  3.4 times slower in Endive.
- **The rest is noise.** OpenSSL `-O2` and `no-pic`, Rust opt-level 2, and
  `wasm-opt` stay within this machine's run-to-run noise of about ±10% on
  Endive. `wasm-opt -O3` may give Node about 9%.

**Best safe combination:** round 4's module unchanged, with Endive set to
`ByteArrayMemory`. It gives JWS 49 to 51 per second and a receipt 162 to
181 per second on one core. With one instance per thread it scales to 3.0
to 3.4 times at 4 threads on this 4-core machine: about 150 JWS or 460
receipts per second in total.

## Setup (TESTED)

- **Recipe.** `scripts/build.sh` is round 4's routec recipe. On round 4's
  OpenSSL install it rebuilds `new-c.wasm` byte for byte (sha256
  `db31279e…`, the `r4-repro` row).
- **Baseline.** Every OpenSSL variant is built from the same checked
  tarball with the substrate bake-off's exact options plus one argument.
  The rebuilt baseline, `base`, differs from round 4's module only in the
  embedded compiler path string.
- **Toolchain.** rustc 1.98.1, OpenSSL 4.0.2, wasi-sdk 34, binaryen 132,
  Node 22.22.2, and Endive 1.1.0 on JDK 21.0.10 and 25.0.4.1
  (`results/versions.txt`).
- **Measurement.** Round 5's method, one run at a time on a 4-core VM. The
  rows are the genuine g5 receipt and the shared-sandbox JWS.
  - Node: the bake-off's `run.mjs --bench`, 1,000 timed calls, three runs.
  - Endive: round 5's library rebuilt on each candidate, 1,000 warm-up and
    500 timed calls, one run.
  - Noise: three Node runs of the same module spread about ±10%.

## Per candidate

Warm mean latency in microseconds, as a change against `base`. Endive's
column is `ByteArrayMemory`, JDK 21 and JDK 25; `results/bench.txt` has
the default-memory columns too.

| # | Candidate | Parity | Node receipt / JWS | Endive receipt / JWS (21; 25) | Size (raw / gz) |
|---|---|---|---|---|---|
| 0 | `base` (round 4's options, rebuilt) | pass | 1,434 / 4,535 | 6,160 / 20,300; 5,514 / 19,422 | 2,973,532 / 975,754 |
| 1 | Endive `ByteArrayMemory` (no module change) | pass on JDK 21 (this round) and JDK 25 (round 5) | n/a | against the default memory: −30% / −24%; −42% / −32% | unchanged |
| 2 | OpenSSL `enable-ec_nistp_64_gcc_128` | pass | −7% / **−35%** | −3% / **+221%**; +12% / **+236%** | +10% / +9% |
| 3a | OpenSSL `-O2` (default `-O3`) | pass | −1% / −3% | −7% / −4%; +11% / 0% | −3% / −1% |
| 3b | Rust opt-level 2 (default 3; LTO fat and codegen-units 1 already) | pass | +3% / −2% | +3% / −1%; +20% / +3% | −1% / 0% |
| 4a | `wasm-opt -O2` | pass | −1% / −3% | +3% / +3%; +2% / −12% | −26% / −12% |
| 4b | `wasm-opt -O3` | pass | −10% / −9% | +3% / −7%; −5% / −3% | −25% / −12% |
| 5 | OpenSSL `no-pic` (official; drops `-fPIC`) | pass | +1% / −2% | +4% / −3%; +10% / 0% | −4% / −2% |

**1. `ByteArrayMemory`.**
- **What changed.** Endive's linear memory is backed by a `byte[]`
  (VarHandle access) instead of `ByteBuffer`s. The module is unchanged.
- **Parity.** JDK 21 matches round 4's native rows on all 6,179 rows
  (`results/endive-parity.txt`); JDK 25 matched in round 5.
- **Speed.** Receipt 30 to 42% faster and JWS 24 to 32% faster, against
  the default memory.
- **How the library would select it.** It would pass one builder option,
  which is Endive's documented API:
  `Instance.builder(module).withMemoryFactory(ByteArrayMemory::new)`.
  Round 5's `AprvWasm` already does this behind
  `-Dspike.aprv.memory=bytearray`; a real library would make it the fixed
  default.
- **Risk: low.** Endive's docs call it "an optimized memory
  implementation, recommended for recent OpenJDK systems" and keep
  `ByteBufferMemory` for other runtimes, Android in particular. Bounds
  checks and trap behaviour are the same interface. Java 11 or later is
  already required.

**2. `enable-ec_nistp_64_gcc_128`.**
- **What changed.** OpenSSL's own documented option. For P-224, P-256,
  P-384 and P-521 it switches the `EC_METHOD` from the generic `BN`
  arithmetic to OpenSSL's constant-time 64-bit-limb implementations
  (`ec_curve.c`).
- **Requirements, all met on wasm32** (INSTALL.md): little-endian storage,
  tolerance of misaligned access, and a compiler that supports
  `__uint128_t` and defines `__SIZEOF_INT128__`. wasi-sdk's clang defines
  it as 16, but a 64×64→128 multiply becomes a compiler-rt helper call
  rather than one instruction.
- **Distros.** Debian enables it on amd64, arm64, ppc64el and riscv64
  (`debian/rules` of 4.0.2-1); Fedora on x86_64, aarch64, ppc64le and
  mips64el (`results/facts.txt`).
- **Node.** JWS 35% faster; the receipt is unchanged within noise.
- **Endive.** JWS 3.2 to 3.4 times slower, because the new field code
  translates into huge JVM methods (`results/nistp-endive.txt`).
  - 17 generated methods now exceed HotSpot's 8,000-byte JIT limit, up
    from 6. `felem_inv` reaches 37,802 bytes and `point_add` 26,157. They
    are hot and run in the JVM's bytecode interpreter.
  - With `-XX:-DontCompileHugeMethods` the JWS drops from 64 ms to 37 ms,
    still slower than `base`'s 20 ms. A library cannot set that JVM flag
    for its users anyway.
- **Risk.** It weakens nothing, and it is mainstream on 64-bit distros.
- **Verdict: rejected.** One `aprv.wasm` serves Node, Go and the JVM, and
  this option would make the JVM path about 3 times slower.

**3. Optimisation levels.** The baseline is already at the top: OpenSSL
`linux-generic32` releases at `-O3`, and the Rust shim uses opt-level 3,
fat LTO, one codegen unit and `panic = "abort"`. Stepping down to `-O2` or
opt-level 2 changed nothing measurable. **Keep the current settings.**

**4. `wasm-opt` (binaryen 132).**
- **Node.** `-O3` looks about 9 to 10% faster, at the edge of the noise.
- **Endive.** No consistent change.
- **Size.** 25% smaller raw, 12% smaller gzipped.
- **Risk.** It passes the gate. But it drops the wasm name section unless
  run with `-g`, which removes the readable JVM method names round 5 got
  from `NameSectionMethodPrefixer`.
- **It adds a second optimiser to the release pipeline.** That second
  optimiser's output would need re-proving on every release.
- **Verdict: not worth it now.** Revisit only if module size matters.

**5. Other options.**
- **Tested: `no-pic`.** An official Configure option that removes
  `-fPIC`, which is pointless in a statically linked wasm module. It gave
  no measurable speed change and a 4% smaller module (2% gzipped); keep it
  in mind for size only.
- **Considered and skipped:**
  - **SIMD (`-msimd128`).** Endive's build-time compiler has no SIMD
    support (its docs: SIMD is interpreter-only, Java 21+).
  - **Cross-language LTO** (clang `-flto` in OpenSSL plus rustc's linker
    plugin). It needs matching LLVM versions and is not a simple switch.
  - **OpenSSL assembly.** There is none for wasm, so `no-asm` is
    mandatory.
  - **`OPENSSL_SMALL_FOOTPRINT`.** It trades speed for size.
  - **Extra wasm features** (tail calls, extended-const). They carry
    host-support risk with no expected gain.
  - **`wasm-opt --fast-math`.** It changes floating-point semantics.
  - **`-XX:-DontCompileHugeMethods`.** A JVM flag, not an Endive option;
    round 5 measured it at under 10% on `base`.
  - **Redline.** Native code, excluded by the brief.
  - **Node runtime flags.** Not a module change.
- **Nothing touched** blinding, constant-time code, RNG use, checks or
  features.

## Throughput across cores (TESTED, `results/scaling.txt`)

The owner's requirement is throughput that scales across cores, with a
floor of about 10 verifications per second per core and 40 to 50
comfortable.

- **Setup.** Endive on JDK 21, round 4's module, one instance per thread,
  all threads warm before the timed phase.
- **Machine.** 4 cores (Xeon @ 2.10 GHz, a VM). Nothing else was busy; the
  load average of 1.25 at the start was the previous JVM run winding down.
- **Codes.** Every result code was checked (0 wrong).

Total verifications per second, with scaling against 1 thread:

| Memory | Row | 1 thread | 2 threads | 4 threads |
|---|---|---|---|---|
| default (`ByteBufferMemory`) | g5 receipt | 97.5 | 206.4 (2.12×) | 330.6 (3.39×) |
| default | shared-sandbox JWS | 31.5 | 66.3 (2.10×) | 106.6 (3.38×) |
| `ByteArrayMemory` | g5 receipt | 153.1 | 327.0 (2.14×) | 463.7 (3.03×) |
| `ByteArrayMemory` | shared-sandbox JWS | 48.8 | 97.0 (1.99×) | 152.3 (3.12×) |

- **Scaling.** Close to linear up to 2 threads. At 4 threads it reaches
  3.0 to 3.4 times, on a machine whose 4 cores also run the JIT and GC
  threads.
- **Per core at 4 threads.** With `ByteArrayMemory`, JWS runs at 38 per
  second per core, above the floor of 10 and near the comfortable band,
  and receipts at 116 per second per core.

## What is not here, and limits

- **Architecture.** Only Linux x86-64 was measured. Go (wazero) was not
  measured.
- **Noise.** The Endive numbers are single runs, so differences under
  about 10% are not claims.
- **Node rows.** Node was checked on every candidate, but the parity gate
  for the 5,000 mutants compares with the native rows only, because round
  4 has no Node rows for them.
