# The .NET package as a host for aprv.wasm

Date: 2026-09-29. Sources and results are in `2026-09-29-dotnet-host/`; its
`README.md` has the file table and the commands to reproduce.

**Question.** Does the 0.7 .NET API, rebuilt as a thin host over the canonical
ABI and the `Wasmtime` NuGet package, keep the six outcomes apart, agree with
the reference rows on the whole corpus, pack into a package a clean project
can use, and what does each instance cost? It feeds MIGRATION step 5.6 and
gate G5.

Labels: TESTED (ran here), EXPECTED (inferred, not run).

## Versions

- Machine: Linux x86-64, 4 vCPUs shared with five other builds (load average
  8 to 18 during the timing runs).
- .NET SDK 10.0.401; runtimes 10.0.12 and 8.0.31 installed; 9.0.20 through a
  self-contained publish (the runtime pack, not the shared framework).
- `Wasmtime` 48.0.2, the newest release on nuget.org; targets netstandard2.0
  and net8.0 among others.
- The module: the release build of the 0.7 core (lane/core 05b4ad9, OpenSSL 4),
  3,005,922 bytes, SHA-256 `4cbe2b02...826e`. The first version of this note
  ran the round-13 stand-in (the 0.6 core, 221 of the 311 cases failing by
  design); this is the re-run against the real module (G1).

## Result

- **The host layer agrees with the module's own rows (TESTED).** All 6,179
  corpus calls, with every unpinned clock pinned to now-ms 1790640000000,
  through `CorpusRun` (the same `AprvInstance` the verifier uses), each
  corpus compared byte for byte with the reference rows: cases 153 of 153,
  hostile 811 of 811, algorithms 22 of 22, substrate 193 of 193, fuzz 5,000
  of 5,000: 6,179 of 6,179 identical, 0 traps (`results/corpus.txt`).
- **All 311 conformance cases pass (TESTED).** The whole suite is 524 tests
  (311 cases and 213 about the wrapper), and all 524 pass on .NET 8, 9 and 10;
  the netstandard2.0 Floor project passes 9 of 9 on .NET 8 and 10
  (`results/tests-summary.txt`). The stand-in's list of 221 differing cases
  is gone, and nothing in the tests skips or excuses a case. One adapter
  rule changed: a `decodeBase64` case is judged by reason and a message that
  says "base64", and for the empty text a message that says it is empty,
  because the core refuses `""` before decoding ("receipt is empty").
- **Start-up (TESTED, loaded machine).** Three runs at load averages of 9 to
  18 on 4 vCPUs: compile at first use 6.0 to 12.3 s (0.92 to 0.98 s on an
  idle machine in `2026-09-26-dotnet-wasmtime.md`); the first instance with
  `init` 40 to 81 ms; later instances 3.1 to 6.9 ms at the median (the stand-in
  took 0.07 to 0.4 ms: the 0.7 core's `init` reads the three built-in roots);
  1,966,080 bytes of linear memory after `init` (`results/speed-run1.txt`,
  `speed-run2.txt`, `speed-run3.txt`).
- **Throughput (TESTED, loaded machine: treat as a lower bound).** A genuine
  G5 receipt through the host layer: 215 to 524 per second on one thread and
  237 to 645 on four, one instance per thread. A JWS: 55 to 106 on one thread
  and 64 to 100 on four. The idle-machine evidence has 763 and 2,475 for the
  receipt and 227 and 669 for the JWS (`2026-09-26-dotnet-wasmtime.md`); the
  other builds took the CPUs here, so the gap is contention as much as the
  wrapper or the 0.7 core.
- **Address space (TESTED).** Each instance reserves about 4.2 GiB of virtual
  address space and holds about 1 MiB resident: 32 live instances took 188 GB
  virtual and 32 MiB more resident than none (`results/other-checks.txt`).
  That is Wasmtime's default. Setting the engine's memory reservation to
  256 MiB (an experiment on the stand-in, not shipped, not repeated on this
  module) cut it to 260 MiB of address space per instance and cost 35% of the
  single-thread speed (256 against 404 receipts per second, 76 against 105 JWS
  per second in the same run): Wasmtime then checks every memory access in
  software instead of by guard pages. An environment that caps virtual size
  has to allow for the default.
- **The package (TESTED).** `dotnet pack` makes a 2,124,630-byte nupkg: the
  assembly for netstandard2.0 and for net8.0, each embedding the module
  (3,075,584 and 3,075,072 bytes), the XML docs, the README and nine licence
  files. A console project restores it from a local folder feed, with
  `Wasmtime` from nuget.org into an empty package folder, on .NET 10, and
  prints `typed: verified` and `"status":0` from the endpoint for the genuine
  G5 receipt (`results/consumer.txt`).
- **Trim, fuzz, format (TESTED).** The trimmed self-contained publish of
  `samples/TrimAotSmoke` with `-warnaserror` has no warning and runs. All
  five SharpFuzz targets ran 15 s each without a crash (the receipt target
  now runs 44,333 times against 2,494 on the stand-in run, since the wrapper
  no longer parses in C#). `dotnet format --verify-no-changes --severity info`
  is clean.
- **One command for a new module.** `scripts/g1.sh` copies the module to the
  ignored path, refreshes the pin, builds, runs the suite on .NET 10 and 8,
  the Floor project, the five corpora against the reference rows and the
  speed run: 3 min 44 s here.

## What was learned

- The canonical-ABI call is about 90 lines of C# over `Function.Invoke` (the
  Endive host's is 35, without the checks); the return area, the pointer and
  length, and every input copy need explicit bounds checks because
  `Memory.ReadInt32` and `GetSpan` do not make them.
- The host function for `random-get` can call the guest's `cabi_realloc` from
  inside the callback (`Caller.GetFunction`), as Endive's does; wrong-length
  answers trap in the guest.
- `Module.ConvertText` turns a WAT text into a module, so the wrapper's duties
  (a trap, a return pointer outside memory, a length over 2 GiB, invalid
  UTF-8, a module of another ABI version, an extra import, the post-return
  count, `now-ms` and `env` as passed) are tested against a 100-line
  hand-assembled module, not only against whichever core is embedded.
- `Store.SetLimits(memorySize: 256 MiB)` holds: a `memory.grow` past it
  returns -1 in the stub module.
- `X509Certificate2` stays in the public API (`Config.Roots`, the builder,
  `AppleRootCertificates.Bundled()`), and `tools/check-one-implementation.mjs`
  bans it in `dotnet/src`: 14 hits, all of that one type. An owner call.

## Where this stops holding

Linux x86-64 only. Windows, macOS, Alpine, .NET Framework, Mono and Unity did
not run. The module is the build of core 05b4ad9; a later module (the core's
security fixes) needs the one command above again. The timing figures were
taken on a shared machine at a load of 9 to 18 on 4 vCPUs.
