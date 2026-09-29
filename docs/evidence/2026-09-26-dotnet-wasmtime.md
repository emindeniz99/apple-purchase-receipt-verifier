# aprv.wasm on .NET with wasmtime-dotnet

Date: 2026-09-26. Code, scripts and raw results are in
`2026-09-26-dotnet-wasmtime/`. Its `README.md` has the file table and the
commands to reproduce.

**Question.** Can .NET host the one canonical `aprv.wasm` (ABI v1, from
`2026-09-26-wasm-abi-v1`) through the official Bytecode Alliance
`Wasmtime` NuGet package, behind a minimal facade library, and what
framework floor does that give? The round covers:

- corpus parity;
- the ABI and trap tests;
- concurrency;
- speed;
- a clean consumer restore.

Labels: TESTED (ran here), DOCUMENTED (read in a primary source), EXPECTED
(inferred, not run).

Nothing under `rust/`, `dotnet/`, `docs/rust-core` or any other production
path changed. The environment:

- the machine: Ubuntu 24.04 x86_64, 4 cores;
- the SDK: .NET SDK 10.0.401, installed into scratch with Microsoft's
  `dotnet-install.sh`;
- the runtimes: .NET 10.0.12 and 8.0.31;
- the package: Wasmtime 48.0.2 from nuget.org.

## Result

- **Parity: identical, on .NET 10 and .NET 8 (TESTED).** All 6,179 rows run
  on each (`results/calls.txt`, `results/calls-net8.txt`).
  - 0 answers differ from round 4's native rows.
  - Every row is byte-identical to Node, with `request_date*` masked where
    it is the wall clock.
  - 0 traps.
- **ABI and trap tests: 37/37 on both runtimes (TESTED).** That is the 33
  mandatory tests plus 4 tests of the facade's contract. Traps surface as
  `TrapException` of type `Unreachable`.
- **Speed: far above the floor, and it scales with threads (TESTED).** One
  thread takes 1.31 ms for g5 (763 per second) and 4.54 ms for the JWS (220
  per second). Four threads with one instance each reach 2,475 per second
  for g5 and 669 for the JWS (3.9× and 3.0×).
- **The clean consumer works (TESTED).**
  - `dotnet pack` makes `Aprv.Wasm.Spike.0.0.0-spike.nupkg` (1,985,780
    bytes: the facade for netstandard2.0 and net8.0, each embedding
    `aprv.wasm`).
  - A console project restores it from a local folder feed, with Wasmtime
    from nuget.org, starting from an empty `NUGET_PACKAGES`.
  - It builds, runs on .NET 10 and verifies g5
    (`results/build-consumer.txt`).

## The Wasmtime package (DOCUMENTED, `results/facts.txt`)

| | |
|---|---|
| Version | 48.0.2, published 2026-09-18; Apache-2.0 WITH LLVM-exception |
| Cadence | irregular. The last releases were 22.0.0 (2024-07-09), 34.0.2 (2025-08-05), 44.0.0 (2026-05-23) and 48.0.2 (2026-09-18): three in the last 12 months, against wasmtime-py's and wasmtime-rb's monthly releases |
| Activity | 22 commits by 6 authors in the 12 months to 2026-09-26, in bytecodealliance/wasmtime-dotnet |
| Target frameworks | net10.0, net8.0, netstandard2.1, netstandard2.0 (the last with System.Memory 4.5.5 and IndexRange 1.0.2) |
| Native libraries | `runtimes/` for linux-x64, linux-arm64, osx-x64, osx-arm64, win-x64, win-arm64; the Linux ones link against glibc (2.28 on x64, 2.18 on arm64) |

**The floor.**

- The package itself reaches netstandard2.0.
- The facade here multi-targets netstandard2.0 and net8.0. It ran on .NET 8
  and .NET 10.
- .NET 8's support ends on 2026-11-10 and .NET 10 (LTS) runs to 2028-11-14,
  per Microsoft's release index.
- A netstandard2.0 build compiles. Whether .NET Framework 4.6.2+ on Windows
  loads the native library from `runtimes/win-x64/native` depends on the
  consuming project's settings. That is EXPECTED and was not run (no
  Windows here).
- A defensible stated floor is ".NET 8+ tested; netstandard2.0 compiled,
  untested".

**Platforms.** The package has no `linux-musl-*` libraries.

- On Alpine, .NET's RID graph falls back from `linux-musl-x64` to
  `linux-x64`, whose `libwasmtime.so` needs `libc.so.6` and
  `ld-linux-x86-64.so.2`. It should therefore fail to load without
  `gcompat` (EXPECTED from the ELF `NEEDED` entries; not run).
- Python and Ruby both ship musl builds.
- No 32-bit, ppc64le, s390x or riscv64 libraries either.

## Measurements

**Speed.** One instance, full bridge lifecycle, `results/bench.txt`: three
runs; the median is shown and the range is in brackets.

| Row | Mean per call | Per second |
|---|---:|---:|
| g5 receipt (op 1), 1,000 after 200 warm-up | 1,310 µs [1,294 to 1,463] | 763 |
| shared-sandbox JWS (op 258) | 4,541 µs [4,515 to 4,875] | 220 |

**Scaling.** One instance per thread, `results/threads.txt`, total per
second.

| Row | 1 thread | 2 threads | 4 threads | 4 ÷ 1 |
|---|---:|---:|---:|---:|
| g5 | 635 | 1,359 | 2,475 | 3.9× |
| JWS | 227 | 357 | 669 | 3.0× |

**Start-up.** Fresh processes, `results/startup.txt`.

| Step | Time |
|---|---|
| Compile the module (`Module.FromBytes`) | 0.92 to 0.98 s |
| The first instance | 14 to 18 ms |
| Later instances | about 0.7 ms |
| The first call | 5 to 8 ms |

The package also has `Module.Serialize` and `Module.Deserialize`, which were
not measured here.

## Behaviour

- A trap raises `WasmTrapException`, and the Verifier disposes its Store and
  instance and starts a fresh one.
- A version mismatch raises `AbiMismatchException`.
- A verification failure is a value (`JsonDocument`).
- Results are copied into a `byte[]` before the handle is freed.
- Linear memory stays at 2,097,152 bytes over 2,000 further calls.
- **Isolation (`results/isolation.txt`).** Four threads with one Verifier
  each, trapping on every 7th call: 180 good calls and exactly 30 traps per
  thread. Two instances in one thread: a trap in one leaves the other
  untouched.
- **Shared objects.** `Engine`, `Module` and a `Linker` holding the two host
  functions are process-wide. Store and Instance are per thread.

## Limits

- Linux x86_64 only, on .NET 8 and 10.
- .NET Framework, Mono, Unity, Windows, macOS and Alpine did not run.
