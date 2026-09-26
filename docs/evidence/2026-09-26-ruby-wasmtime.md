# aprv.wasm on Ruby with wasmtime-rb

Date: 2026-09-26. Code, scripts and raw results are in
`2026-09-26-ruby-wasmtime/`. Its `README.md` has the file table and the
commands to reproduce.

**Question.** Can Ruby host the one canonical `aprv.wasm` (ABI v1, from
`2026-09-26-wasm-abi-v1`) through the official Bytecode Alliance
`wasmtime` gem, behind a minimal facade gem? The round covers:

- corpus parity;
- the ABI and trap tests;
- concurrency;
- speed;
- a clean install;
- what the gem requires of the Ruby version and the platform.

Labels: TESTED (ran here), DOCUMENTED (read in a primary source), EXPECTED
(inferred, not run).

Nothing under `rust/`, `ruby/`, `docs/rust-core` or any other production
path changed. The environment: Ubuntu 24.04 x86_64, 4 cores, Ruby 3.3.6,
wasmtime 48.0.1 (the `x86_64-linux` native gem). Every gem went into a
scratch `GEM_HOME`.

## Result

- **Parity: identical (TESTED).** All 6,179 rows run.
  - 0 answers differ from round 4's native rows.
  - Every row is byte-identical to Node, with `request_date*` masked where
    it is the wall clock.
  - 0 traps (`results/calls.txt`).
- **ABI and trap tests: 37/37 (TESTED).** That is the 33 mandatory tests
  plus 4 tests of the facade's contract. Traps surface as `Wasmtime::Trap`
  with code `:unreachable_code_reached` (`results/abi-tests.txt`).
- **Speed: far above the floor, and it scales once the facade releases the
  GVL (TESTED).** One thread takes 1.33 ms for g5 (750 per second) and
  4.71 ms for the JWS (212 per second). With one Verifier per thread:
  - g5 reaches 2,358 per second at 4 threads, and the JWS 746 (3.3× and
    3.2×);
  - forked processes reach 2,748 and 818.
  - This needs `to_func(gvl: false)`, an opt-in that wasmtime-rb added on
    2026-06-09 (#603). With the default (GVL held), threads do not scale
    at all: 716, 666 and 699 per second for g5 at 1, 2 and 4 threads.
- **The clean install works (TESTED).** RubyGems installs the facade gem
  (977 KB, pure Ruby plus `aprv.wasm`) into an empty `GEM_HOME` with
  rubygems.org as the only source. It picks the prebuilt
  `wasmtime-48.0.1-x86_64-linux` gem, so no Rust toolchain is needed, and
  the facade verifies g5 from an empty directory (`results/build.txt`).

## The wasmtime gem (DOCUMENTED, `results/facts.txt`)

| | |
|---|---|
| Version | 48.0.1, released 2026-09-03; Apache-2.0; 492,419 downloads in total |
| Cadence | 12 source-gem releases from 2025-11-14 to 2026-09-03, tracking Wasmtime majors (one behind wasmtime-py's 49.0.0) |
| Activity | 147 commits by 11 authors in the 12 months to 2026-09-26, in bytecodealliance/wasmtime-rb |
| Prebuilt native gems (Ruby `>= 3.3, < 4.1.dev`) | `x86_64-linux`, `x86_64-linux-musl`, `aarch64-linux`, `aarch64-linux-musl`, `x86_64-darwin`, `arm64-darwin`, `x64-mingw-ucrt`, and `aarch64-mingw-ucrt` (Ruby `>= 3.4`) |
| Source gem | `ruby >= 3.1.0`, built with Rust (Cranelift) at install time |
| 32-bit | excluded: the maintainers dropped `arm-linux-musl` from the native matrix on 2026-09-03 because "cranelift doesnt support 32-bit archs" |
| GVL | held during Wasm calls by default. `Extern#to_func(gvl: false)` releases it, with the rule that each thread uses its own Store (#603, 2026-06-09, in 48.0.1). Module compilation always runs without it. Host functions take it back |

The coordinator's summary is correct. These points follow from it:

- **The Ruby floor.** It is 3.3 for a prebuilt gem, 3.4 on Windows arm64,
  and 3.1 only with a Rust toolchain. Ruby 3.1 and 3.2 users need Rust at
  install time.
- **The platforms.** They match wasmtime-py's desktop and server set: Linux
  glibc and musl on x86_64 and aarch64, macOS on both, Windows on both.
  They share its gaps: no 32-bit, ppc64le, s390x or riscv64 prebuilt gem.
  On those, the source gem needs Rust and a Cranelift backend. Cranelift
  has s390x and riscv64 backends, but no 32-bit ones (EXPECTED, not built).

## Measurements

**Speed.** One instance, full bridge lifecycle, `results/bench.txt`:

| Row | Mean per call | Per second |
|---|---:|---:|
| g5 receipt (op 1), 1,000 after 200 warm-up | 1,334 µs | 750 |
| shared-sandbox JWS (op 258) | 4,709 µs | 212 |

With the GVL held (`results/bench-gvl-held.txt`) the same calls take 1,275
and 4,665 µs. Releasing the GVL costs a single thread about 1 to 5%, which
is inside the run-to-run noise.

**Scaling.** One Verifier per worker, total per second.

| Row | Workers | 1 | 2 | 4 | 4 ÷ 1 |
|---|---|---:|---:|---:|---:|
| g5 | threads, facade (`gvl: false`), `results/threads.txt` | 716 | 1,298 | 2,358 | 3.3× |
| g5 | threads, default `to_func` (GVL held), `results/threads-gvl-held.txt` | 763 | 666 | 699 | 0.9× |
| g5 | forked processes, `results/processes.txt` | 731 | 1,414 | 2,748 | 3.8× |
| JWS | threads, facade | 232 | 410 | 746 | 3.2× |
| JWS | threads, GVL held | 216 | 225 | 209 | 1.0× |
| JWS | forked processes | 229 | 399 | 818 | 3.6× |

The processes run used the GVL-held facade, which does not matter with one
thread per process.

**Start-up.** Fresh processes, `results/startup.txt`.

| Step | Time |
|---|---|
| `require` | 10 to 16 ms |
| The first Verifier | 1.22 to 1.35 s: Cranelift compiles the module |
| Later Verifiers | 0.1 ms |
| The first call | 3 to 4 ms |

`Wasmtime::Engine#precompile_module` and `Module.deserialize` exist for
short-lived processes. They were not measured here; the Python round
measured the same mechanism at 11 ms.

## Behaviour

- A trap raises `AprvWasm::WasmTrapError`, and the Verifier discards its
  instance.
- A version mismatch raises `AbiMismatchError`.
- A verification failure is a value.
- Results are copied into a Ruby `String` (`Memory#read`) before the handle
  is freed.
- Linear memory stays at 2,097,152 bytes over 2,000 further calls.
- **Isolation (`results/isolation.txt`).** Four threads with one Verifier
  each, trapping on every 7th call: 180 good calls and exactly 30 traps per
  thread. Two instances in one thread: a trap in one leaves the other
  untouched.
- **A harness pitfall the isolation test caught.** In the first version of
  `rb/concurrency.rb`, `v = ...` inside a thread block assigned to the
  script's top-level `v`, which the parser creates even in an unexecuted
  branch. So all four threads shared one Verifier. The good calls still
  verified, but the trap counts came out as 59, 89, 90 and 92 instead of
  30 each. The blocks now use block-local variables (`|; ver|`).
  - A production Ruby facade should hand out instances through a
    thread-local or a pool, never through a variable a closure can
    capture.

## Limits

- Linux x86_64 and Ruby 3.3.6 only. The prebuilt gems for other platforms
  and the source gem were not installed.
