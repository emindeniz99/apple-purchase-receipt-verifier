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
  5 to 14 during the runs).
- .NET SDK 10.0.401; runtimes 10.0.12 and 8.0.31 installed; 9.0.20 through a
  self-contained publish (the runtime pack, not the shared framework).
- `Wasmtime` 48.0.2, the newest release on nuget.org; targets netstandard2.0
  and net8.0 among others.
- The module: round 13's `aprv-cabi.core.wasm`, 2,967,116 bytes, SHA-256
  `da786ac8...fdb68`. It carries the 0.6 core, so its verdicts and payloads
  are 0.6's.

## Result

- **The host layer agrees with the reference (TESTED).** All 6,179 corpus
  rows through `CorpusRun`, the same `AprvInstance` the verifier uses:
  6,176 identical, 2 `clock-moves-chain`, 1 `init-refusal`, 0 traps: the
  expectation of round 13 (`results/corpus-classify.txt`).
- **The wrapper's own tests pass (TESTED).** 523 tests on .NET 8, 9 and 10;
  302 pass on each, and the only 221 failures on each are conformance cases
  (`results/tests-summary.txt`). The netstandard2.0 Floor project passes 9 of
  9 on all three runtimes.
- **311 cases: 90 pass, 221 differ because of the stand-in (TESTED).** The
  same 221 ids on .NET 8, 9 and 10 (`results/standin-fail-ids.txt`), by group:
  - 91 failures the 0.6 core gives a reason outside the eight, which the
    wrapper reads as `INTERNAL_ERROR` with the reason in its cause;
  - 69 verified answers in the 0.6 payload shape, read as `INTERNAL_ERROR`;
  - 39 where the module's own verdict or payload differs from 0.7 (its
    `INTERNAL_ERROR` for unreadable content, `INVALID_CERTIFICATE_PURPOSE`
    where 0.7 says `UNTRUSTED_CHAIN`, an id `"0"` that 0.7 omits);
  - 22 of the 33 `decodeBase64` cases, judged through the module by reason
    and the word "base64" in its message, which the 0.6 core spells
    differently.
  The wrapper changes nothing to make them pass. Node's lane got 90 of 311 too.
- **Start-up (TESTED, loaded machine).** Compile at first use 2.1 to 6.4 s
  (0.92 to 0.98 s on an idle machine in `2026-09-26-dotnet-wasmtime.md`); the
  first instance with `init` 28 to 51 ms; later instances 0.07 to 0.4 ms;
  1,769,472 bytes of linear memory after `init`
  (`results/speed-run1.txt`, `results/speed-run2.txt`).
- **Throughput (TESTED, loaded machine: treat as a lower bound).** A genuine
  G5 receipt through the host layer, over two 8-second runs with a load
  average of 3.5 and 5 to 6 on 4 vCPUs: 343 to 354 per second on one thread
  and 573 to 1,059 on four, one instance per thread. A JWS: 89 to 110 on one
  thread and 183 to 257 on four. The idle-machine evidence has 763 and 2,475
  for the receipt and 227 and 669 for the JWS
  (`2026-09-26-dotnet-wasmtime.md`); other builds took the rest of the CPUs
  here, so the gap is contention as much as the wrapper.
- **Address space (TESTED).** Each instance reserves about 4.2 GiB of virtual
  address space and holds about 0.25 MiB resident before its first call: 32
  live instances took 188 GB virtual and 8 MiB resident
  (`results/other-checks.txt`). That is Wasmtime's default. Setting the
  engine's memory reservation to 256 MiB (an experiment, not shipped) cut it
  to 260 MiB of address space per instance and cost 35% of the single-thread
  speed (256 against 404 receipts per second, 76 against 105 JWS per second in
  the same run): Wasmtime then checks every memory access in software instead
  of by guard pages. An environment that caps virtual size has to allow for
  the default.
- **Address space (TESTED).** Each instance reserves about 4.2 GiB of virtual
  address space and holds about 0.25 MiB resident before its first call: 32
  live instances took 188 GB virtual and 8 MiB resident
  (`results/other-checks.txt`). Wasmtime's default; an environment that caps
  virtual size has to allow for it.
- **The package (TESTED).** `dotnet pack` makes a 2,106,917-byte nupkg: the
  assembly for netstandard2.0 and for net8.0, each embedding the module
  (3,036,160 and 3,036,672 bytes), the XML docs, the README and nine licence
  files. A console project restores it from a local folder feed, with
  `Wasmtime` from nuget.org into an empty package folder, on .NET 10, and
  prints `"status":0` from the endpoint for the genuine G5 receipt
  (`results/consumer.txt`). The typed result is `INTERNAL_ERROR` there: the
  0.6 payload shape.
- **Trim, fuzz, format (TESTED).** The trimmed self-contained publish of
  `samples/TrimAotSmoke` with `-warnaserror` has no warning and runs. All
  five SharpFuzz targets ran 15 s each without a crash. `dotnet format
  --verify-no-changes --severity info` is clean.

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
not run. The module is the stand-in, so nothing here says the 0.7 payload
reading works against a real 0.7 core: it is tested against the wire's
own JSON (`ModuleAnswersTests`), and the 311 cases prove it once the release
module is in. The throughput figures were taken on a shared machine.
