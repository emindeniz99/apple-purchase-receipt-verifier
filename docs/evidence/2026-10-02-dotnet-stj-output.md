# .NET on System.Text.Json: same verdicts, same ToJson bytes (2026-10-02)

**Question.** When the .NET package drops its hand-written JSON reader and
writer (`dotnet/src/ApplePurchaseReceiptVerifier/Internal/Json.cs`, 610
lines, and `OrderedMap`) for `System.Text.Json`, does any case change its
verdict, and does `ReceiptPayload.ToJson()` still write the same text? This
feeds the owner's decision Q9 (option B), recorded in DECISIONS.md R41.

**Versions.** .NET SDK 10.0.401; runtimes 8.0.31, 9.0.20 and 10.0.12;
`System.Text.Json` 10.0.12 (the package, on netstandard2.0) and the copy in
the box on each runtime; base commit `74b328b`; `aprv.wasm` built from that
tree by `rust/bindings/abi/build.sh`, SHA-256
`ffac39976efd47cb9e5c543508fb8bb318486f53eda8a6ab0fba8798a6267f77`
(2,830,382 bytes). Code and commands are in `2026-10-02-dotnet-stj-output/`.

## What changed

- The module's answers are read with `JsonDocument` (`MaxDepth` 128; the
  deepest answer is six levels) into a name-to-`JsonElement` map per
  object, so a repeated member still counts once with its last value.
- `ToJson` is written with `Utf8JsonWriter` and a `JavaScriptEncoder`
  subclass that escapes only the quotation mark, the reverse solidus and
  the controls below U+0020 (`\b \f \n \r \t`, else `\u00xx` in lower
  case), which is what the old writer did.

## Results

`dump/` ran every case of `fixtures/cases.json` (384 cases: 187
`verifyReceipt`, 114 `verifySignedData`, 50 `verifyReceiptEndpoint`; the
33 `decodeBase64` cases call nothing whose output is JSON) on the old and
the new library, once against each library asset (net8.0 and
netstandard2.0), all on the .NET 10 runtime.

| Item | Count | Differences, net8.0 | Differences, netstandard2.0 |
|---|---|---|---|
| `verifyReceipt` verdicts | 187 | 0 | 0 |
| `ToJson()` of the 81 verified receipts, compared as UTF-16 code units | 81 | 0 | 0 |
| `verifySignedData` verdicts and payload text | 114 | 0 | 0 |
| `ToJson()` of hand-built payloads, one per string: quotes and backslashes, the five short escapes, U+0000/U+001F/U+007F, Latin-1, U+2028/U+2029, private use, U+FEFF, U+FFFD/U+FFFE/U+FFFF, U+1F600 and U+10FFFF, unassigned U+0378, `` <script>&'+` ``, soft hyphen and zero-width space | 14 | 0 | 0 |
| `ToJson()` of a payload holding a lone surrogate (`\ud800`, `a\udc00b`, `x\ud83d`) | 3 | 3 | 3 |

The endpoint's 50 answers are the module's text passed through unchanged;
they carry the wall clock (`request_date`), so they differ between any two
runs and were left out.

The three differences are the one intended change. The old writer copied a
lone surrogate into its output, a string with no UTF-8 form; the new one
writes U+FFFD, because `Utf8JsonWriter` throws on a lone surrogate it is not
told to escape. Only a payload built by hand can hold one: the module's
strings are Rust strings.

`probe/` shows why the encoder is a subclass: neither encoder the library
ships gives the old text (.NET 8.0.31 and 10.0.12 printed the same).

| Input | Old writer and the new encoder | `Default` | `UnsafeRelaxedJsonEscaping` |
|---|---|---|---|
| `` <script>&'+` `` | as is | `\u003Cscript\u003E\u0026\u0027\u002B\u0060` | as is |
| U+007F U+0080 U+00AD | as is | all three escaped | `\u007F\u0080`, U+00AD as is |
| U+2028 U+2029 | as is | escaped | escaped |
| U+E000 U+FEFF U+FFFE U+FFFF | as is | escaped | escaped |
| U+0378 U+0870 | as is | escaped | `\u0378`, U+0870 as is |
| U+00E9, U+1F600, U+10FFFF | as is | escaped, the last two as surrogate pairs | U+00E9 as is, the last two as surrogate pairs |
| U+0000 U+001F | `\u0000\u001f` | `\u0000\u001F` | `\u0000\u001F` |

## Checks run on the new code

- `dotnet test -c Release` in `dotnet/`: 1,827 tests passed, 0 failed, 0
  skipped, on net8.0, net9.0 and net10.0, the floor project
  (netstandard2.0 asset) included.
- `dotnet format --verify-no-changes --severity info`: clean.
- `dotnet publish samples/TrimAotSmoke -warnaserror` (full trim): no
  warning, and the trimmed binary verified its receipt.
- `fuzz/run.sh json 45`: 638,254 executions of the writer round trip, no
  finding.

## Where it stops holding

The comparison covers the fixtures and the strings listed; it ran on Linux
x86-64 only. The floor project runs the netstandard2.0 asset on CoreCLR, not
on .NET Framework, Mono or Unity; CI's `dotnet-mono` job only loads it.
