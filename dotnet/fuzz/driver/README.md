# libfuzzer-dotnet

`libfuzzer-dotnet.cc` is vendored verbatim from
[Metalnem/libfuzzer-dotnet](https://github.com/Metalnem/libfuzzer-dotnet)
(MIT — see `LICENSE-upstream`), at the state of `master` on 2026-09-05.

It is the libFuzzer side of SharpFuzz's libFuzzer mode: a `LLVMFuzzerInitialize`
that forks the .NET target and wires up two pipes plus one shared-memory
segment, and a `LLVMFuzzerTestOneInput` that hands each input over that segment
and copies the coverage bitmap back into libFuzzer's
`__libfuzzer_extra_counters` section. The .NET side is
`SharpFuzz.Fuzzer.LibFuzzer.Run`.

Vendored rather than downloaded from the releases page at run time so that
`run.sh` and the CI job build the same driver from readable source, offline,
with no unpinned binary in the loop. `run.sh` compiles it:

```
clang -fsanitize=fuzzer driver/libfuzzer-dotnet.cc -o libfuzzer-dotnet
```
