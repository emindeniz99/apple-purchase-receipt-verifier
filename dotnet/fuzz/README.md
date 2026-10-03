# Fuzz targets

Four [SharpFuzz] targets under [libFuzzer], over the verifiers a consumer
calls. `run.sh` pairs each with the shared fixtures that seed it, so nothing
under `fixtures/` is copied here.

Since 0.8 the parsers behind the verifiers are inside `aprv.wasm`, and
SharpFuzz instruments only .NET IL: coverage guidance reaches the wrapper
(the host layer and its JSON code over `System.Text.Json`), and the module
is exercised as a black box. The targets keep asserting what a caller
relies on: nothing escapes, and an accepted input fails against an unrelated
anchor set. The core's own fuzz jobs cover its parsers.

```bash
sudo apt-get install -y clang          # the driver needs -fsanitize=fuzzer
./run.sh all                           # every target, 60 s each
./run.sh all 300                       # …five minutes each
JOBS=4 ./run.sh all 300                # four at a time
./run.sh receipt 600                   # one target, ten minutes
```

| target | what it reaches | invariant beyond "no exception leaks" |
|---|---|---|
| `receipt` | `IVerifier.VerifyReceipt` on the DER re-encoded as canonical base64: CMS (BER), payload, chain, signature | an accepted receipt fails against an unrelated anchor set |
| `receipt-base64` | `IVerifier.VerifyReceipt(string)` on the fuzzer's bytes as text — the string a client sends | — |
| `jws` | `IVerifier.VerifySignedData` | a JWS accepted under the fixture root is refused under Apple's bundled roots |
| `endpoint-json` | `IVerifier.VerifyReceiptEndpoint` on a request body | the answer is always JSON with a numeric `status`, and the call never throws |

The containment invariant is shared and categorical: no public verify
method throws for any input, so every failure must come back as a result
carrying a `Failure`, and any exception that escapes, whatever its type,
fails the target. Catching everything rather than a list of forbidden types
matters, because the leak that matters is always the type nobody thought to
list — `AsnContentException` derives from `Exception` and not from
`CryptographicException`, which is exactly how a type-by-type catch springs
one.

The anchor-set invariants are what let a fuzzer find "accepts what it should
not" rather than only crashes: without them, an input that verifies tells you
nothing about *why* it verified.

## Why SharpFuzz, and why libFuzzer mode

.NET has no in-box coverage-guided fuzzer, so the choice is between SharpFuzz
and running the library from a native harness. SharpFuzz is the only maintained
option and it is genuinely maintained: `SharpFuzz` and `SharpFuzz.CommandLine`
**2.3.0** shipped on 2026-06-16, and the tool package carries `tools/net8.0`,
`tools/net9.0` and `tools/net10.0` entries — so .NET 10 is supported by the
publisher, not merely by roll-forward. The library itself is `netstandard2.0`,
which loads on every runtime this repository tests.

libFuzzer mode rather than the AFL mode because libFuzzer needs no `afl-fuzz`
build, takes several corpus directories on the command line (which is what lets
the shared fixtures seed a run without being copied here), and writes crashers
to an `-artifact_prefix` directory. `driver/libfuzzer-dotnet.cc` is the libFuzzer
side; it forks the .NET process, hands each input over shared memory and copies
the .NET edge counters back into libFuzzer's `__libfuzzer_extra_counters`.

Two things about that arrangement are worth knowing before reading its output:

- **`cov: 2` is not a failure.** libFuzzer's `cov:` counts the PCs of the
  *driver*, which has almost none. The .NET coverage arrives through the extra
  counters and shows up in `ft:` (features). A target whose `ft:` climbs is
  finding new paths in the library; `cov:` will read 2 forever.
- **Instrumented code must not run before `Fuzzer.LibFuzzer.Run`.** The
  instrumentation writes edge counters through a shared-memory pointer that
  `Run` installs, so an eager `new Config()` in `Main`
  dereferences a pointer that does not exist yet and dies with an
  `AccessViolationException` that reads like a library crash. Every target here
  therefore builds its anchors and verifiers on its first execution — see the
  remarks in `Program.cs`.

The target is selected by `APRV_FUZZ_TARGET` rather than by the driver's
`--target_arg`, because `--target_arg` occupies the process's first command-line
argument and that slot is where `Fuzzer.LibFuzzer.Run` reads a single input file
from when the binary runs on its own. Keeping it free makes replaying a crasher
the obvious command:

```bash
APRV_FUZZ_TARGET=receipt ./bin/fuzz/ApplePurchaseReceiptVerifier.Fuzz \
    artifacts/receipt/crash-2f1c…
```

## Layout and what it deliberately does not touch

This project is **not** a member of `ApplePurchaseReceiptVerifier.sln`. The
`dotnet` CI job (`dotnet test`) and the `dotnet-format` job
(`dotnet format --verify-no-changes`) both resolve that solution, so staying out
of it is what keeps a fuzzing dependency, an instrumented assembly and a
harness's formatting out of the shipped package and the drift gate. For the
same reason it opts out of central package management and pins SharpFuzz
inline, leaving `Directory.Packages.props` a description of what ships.

Nothing under `fixtures/` is copied here. `run.sh` passes the fixture
directories to libFuzzer as read-only corpora, and wraps the shared base64
receipts into `verifyReceipt` request bodies at run time under
`seeds/generated/` (gitignored). Only `seeds/endpoint-json/` is committed,
and it holds hand-written edge cases, not fixtures.

`driver/libfuzzer-dotnet.cc` is vendored from upstream under MIT; see
`driver/README.md`.

## Crashers

A crasher lands under `artifacts/<target>/`, which is gitignored on purpose:
reduce it and pin it as a test under `../tests/`, where it runs on every
runtime in the matrix rather than only where a fuzzer is installed. The
corpus under `corpus/<target>/` is gitignored too — it is a cache, and
committing it would make every run's growth a diff.

CI (`dotnet-fuzz` in `.github/workflows/ci.yml`) runs each target for a fixed
budget on every push.

[SharpFuzz]: https://github.com/Metalnem/sharpfuzz
[libFuzzer]: https://llvm.org/docs/LibFuzzer.html
