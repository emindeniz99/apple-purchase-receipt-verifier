# aprv.wasm on Swift 6.3 with WasmKit (Linux)

Date: 2026-09-26. Code, scripts and raw results are in
`2026-09-26-swift-wasmkit/`. Its `README.md` has the file table and the
commands to reproduce.

**Question.** Can Swift host the one canonical `aprv.wasm` (ABI v1, from
`2026-09-26-wasm-abi-v1`) through WasmKit on Linux, and does it clear the
floor of 10 verifications per second per core? Answering it needs:

- the corpus parity;
- the ABI and trap tests;
- the concurrency behaviour;
- the speed;
- a clean consumer;
- a side fact about iOS.

Labels: TESTED (ran here), DOCUMENTED (read in a primary source), EXPECTED
(inferred, not run).

Nothing under `rust/`, `swift/`, `docs/rust-core` or any other production
path changed. The environment:

- the machine: Ubuntu 24.04 x86_64, 4 cores;
- the toolchain: Swift 6.3.3 from download.swift.org, with its signature
  checked (`results/facts.txt`);
- WasmKit: 0.4.0, pinned `exact`.

## Result

- **Parity: identical (TESTED).** All 6,179 rows run: the 1,179 corpus rows
  plus the 5,000 mutants.
  - 0 answers differ from round 4's native C ABI rows.
  - The categories are the ABI v1 round's.
  - Every row is byte-identical to Node, with `request_date*` masked where
    it is the wall clock.
  - 0 traps (`results/calls.txt`).
- **ABI and trap tests: 37/37 (TESTED).** That is the 33 mandatory tests
  plus 4 tests of the facade's contract. After every trap, a fresh instance
  verifies g5 (`results/abi-tests.txt`).
- **Speed: above the floor, with a thin margin for JWS (TESTED).** WasmKit is
  an interpreter. On one thread, g5 takes 13.3 ms (75 per second) and the
  JWS takes 54.7 ms (18.3 per second). Four threads with one instance each
  scale to 308 per second for g5 and 67 per second for the JWS, 4.0× and
  3.6×.
  - The JWS is 1.7 to 1.9 times the floor per core. A slower core, or a
    heavier JWS chain, eats that margin.
  - It is 8 to 10 times slower than the same module on Wasmtime through
    Python (1.7 ms for g5, 5.3 ms for the JWS;
    `2026-09-26-python-wasmtime.md`).
- **Packaging works (TESTED).** A clean consumer package depends on the
  `AprvWasm` package by path, resolves WasmKit 0.4.0 from GitHub by itself,
  builds and verifies g5.
- **The floors rise (DOCUMENTED).** WasmKit 0.4.0 declares
  `swift-tools-version:6.3` and `platforms: [.macOS(.v15), .iOS(.v18)]`. The
  repository's package today is tools 6.1 and macOS 13. Hosting through
  WasmKit raises it to Swift 6.3, macOS 15 and iOS 18.

## WasmKit (DOCUMENTED, `results/facts.txt`)

| | |
|---|---|
| Latest release | 0.4.0, tagged 2026-09-19. Before it: 0.3.1 (2026-07-08), 0.3.0 (2026-06-28), 0.2.2 (2026-04-29) |
| Activity | 307 commits by 9 authors in the 12 months to 2026-09-26; the latest on 2026-09-22 |
| Home | github.com/swiftwasm/WasmKit. Swift 6.2+ toolchains from swift.org ship its CLI; Swift 6.3.3's is 0.1.6, while the library from SwiftPM is 0.4.0 |
| Minimum Swift | 6.3 (`swift-tools-version:6.3`) |
| Execution | An interpreter only: a register-based VM with direct-threaded dispatch on x86_64 and arm64, and no JIT. The docs mention a JIT only as a possible future |
| Swift toolchains | 6.3.3 is the newest 6.3.x; 6.4.0 was released 2026-09-14. This round used 6.3.3 as the brief asked |

## Measurements

**Speed.** One instance, full bridge lifecycle, `results/bench.txt`: three
runs each; the median is shown and the range is in brackets.

| Row | Mean per call | Per second |
|---|---:|---:|
| g5 receipt (op 1), 200 timed after 20 warm-up | 13,293 µs [13,216 to 14,000] | 75.2 |
| shared-sandbox JWS (op 258), 60 timed after 10 warm-up | 54,723 µs [53,107 to 55,456] | 18.3 |

**Scaling.** One instance per thread, `results/threads.txt`, total per
second.

| Row | 1 thread | 2 threads | 4 threads | 4 threads ÷ 1 |
|---|---:|---:|---:|---:|
| g5 | 77.1 | 141.6 | 308.0 | 4.0× |
| JWS | 18.8 | 37.3 | 67.2 | 3.6× |

**Start-up.** Fresh processes, `results/startup.txt`.

| Step | Time |
|---|---|
| Parse the module | 2 to 3 ms |
| An instance | about 3 ms |
| First g5 call | 60 to 82 ms. WasmKit translates functions lazily, on first call |
| Second g5 call | 11 to 14 ms |

**Corpus run times** (`results/calls.txt`). The fuzz corpus (5,000 rows)
takes 30 s and the 1,179 rows take 12 to 13 s in total.

## Behaviour

- **Traps.** A trap surfaces as a Swift `Trap` error ("Trap: unreachable"),
  and the facade discards the instance.
  - WasmKit's `Memory.withUnsafe*BufferPointer` stops the whole process
    with a precondition failure on an out-of-range access. It does not
    throw.
  - The bridge therefore checks every range against `byteCount` before it
    touches memory. Hosts must keep that rule.
- **Concurrency (`results/isolation.txt`).** Each of four threads uses its
  own `Verifier`, with a deliberate trap on every 7th call. Every thread's
  60 good calls return the reference bytes, and each thread counts exactly
  its own 10 traps.
- **Independent instances.** Two instances in one thread: a trap in one
  leaves the other untouched.
- **Shared objects.** `Engine` and `Module` are `Sendable` and shared.
  Stores and instances are per thread.
- **Memory.** Linear memory stays at 2,097,152 bytes over 500 further calls.
  That is fewer calls than on the other hosts, because the interpreter is
  slow.

## iOS (side fact, not built)

EXPECTED to work, DOCUMENTED as a target:

- Package.swift declares iOS 18. The README lists iOS 18+, tvOS, watchOS
  and visionOS.
- WasmKit's CI builds `generic/platform=iOS`, but runs no tests there.
- WasmKit interprets and never generates machine code, so it needs neither
  JIT entitlements nor executable memory.
- mprotect-based bounds checking is compiled only for Linux and macOS
  (`Platform.h`). iOS uses software bounds checks, which is also what the
  interpreter uses on every platform today.

Nothing was built for iOS here. Speed on a phone core is unmeasured. The
thin JWS margin measured on this x86_64 server core is the question to
answer first.

## Limits

- Linux x86_64 only. macOS, arm64 and iOS did not run.
- One Swift version: 6.3.3.
- The build was release (`-c release`) with WasmKit's default engine
  configuration: direct threading, lazy translation, mprotect bounds
  checking on Linux.
