# .NET on System.Text.Json: same verdicts, same ToJson values (2026-10-02)

**Question.** When the .NET package drops its hand-written JSON reader and
writer (`dotnet/src/ApplePurchaseReceiptVerifier/Internal/Json.cs`, 610
lines, and `OrderedMap`) for `System.Text.Json` and writes `ToJson` with the
library's `JavaScriptEncoder.UnsafeRelaxedJsonEscaping`, does any case change
its verdict, and which `ReceiptPayload.ToJson()` texts change, and do they
still carry the same JSON value? This feeds the owner's decision Q9 (option
B) and Q20 (less hand-written code beats byte-identical output), both
recorded in DECISIONS.md R41.

**Versions.** .NET SDK 10.0.401; runtimes 8.0.31, 9.0.20 and 10.0.12;
`System.Text.Json` 10.0.12 (the package, on netstandard2.0) and the copy in
the box on each runtime; base commit `74b328b`; `aprv.wasm` built from that
tree by `rust/bindings/abi/build.sh`, SHA-256
`ffac39976efd47cb9e5c543508fb8bb318486f53eda8a6ab0fba8798a6267f77`
(2,830,382 bytes). The branch changes nothing under `rust/`, so the same
module serves both trees. Code and commands are in
`2026-10-02-dotnet-stj-output/`.

## What changed

- The module's answers are read with `JsonDocument` (`MaxDepth` 128; the
  deepest answer is six levels) into a name-to-`JsonElement` map per
  object, so a repeated member still counts once with its last value.
- `ToJson` is written with `Utf8JsonWriter` and
  `JavaScriptEncoder.UnsafeRelaxedJsonEscaping`. A first version kept 0.7's
  escaping with a `JavaScriptEncoder` subclass (the quotation mark, the
  reverse solidus and the controls, `\u00xx` in lower case, nothing else),
  which needed `AllowUnsafeBlocks`; it gave the old text for every input
  below except the lone surrogates. Q20 replaced it with the library's
  encoder the same day.

## Results

`dump/` ran the 187 `verifyReceipt` and 114 `verifySignedData` cases of
`fixtures/cases.json` and 17 hand-built payloads on the old and the new
library, once against each library asset (net8.0 and netstandard2.0), all
on the .NET 10 runtime. `compare.py` parsed each pair of differing texts as
JSON and compared the values. The 50 `verifyReceiptEndpoint` cases were run
but not compared: their answers carry the wall clock (`request_date`), so
they differ between any two runs. The 33 `decodeBase64` cases call nothing
whose output is JSON and were not run.

| Item | Count | Text differs (net8.0 / netstandard2.0) | Value differs |
|---|---|---|---|
| `verifyReceipt` verdicts | 187 | 0 / 0 | — |
| `ToJson()` of the 81 verified receipts | 81 | 3 / 3 | 0 |
| `verifySignedData` verdicts and payload text | 114 | 0 / 0 | 0 |
| `ToJson()` of hand-built payloads, one per string: plain, empty, quotes and backslashes, the five short escapes, U+0000/U+0001/U+001F/U+007F, Latin-1, U+2028/U+2029, private use, U+FEFF, U+FFFD/U+FFFE/U+FFFF, U+1F600 and U+10FFFF, unassigned U+0378 and U+0870, `` <script>&'+` ``, soft hyphen and zero-width space | 14 | 7 / 7 | 0 |
| `ToJson()` of a payload holding a lone surrogate (`\ud800`, `a\udc00b`, `x\ud83d`) | 3 | 3 / 3 | 3 |

The two assets wrote identical files. What the differing texts hold that
the other side does not (`compare.py`'s output):

| Item | 0.7 wrote | Now written |
|---|---|---|
| `receipt/to-json-non-ascii-product-id` | U+1D11E as itself | `𝄞` |
| `receipt/to-json-escapes` | `\u001f`, U+2028 as itself | `\u001F`, ` ` |
| `receipt/to-json-escapes-html-and-separators` | U+007F, U+2029 as themselves | `\u007F`, ` ` |
| controls payload | `\u001f`, U+007F as itself | `\u001F`, `\u007F` |
| U+2028/U+2029, private use, U+FEFF, U+FFFE/U+FFFF, U+0378 payloads | as themselves | `  `, ``, `﻿`, `￾￿`, `͸` |
| U+1F600 and U+10FFFF payload | as themselves | `😀`, `􏿿` |
| lone surrogates | the lone surrogate itself | `�` |

Every difference but the last is escaping: upper-case hex, and characters
the relaxed encoder escapes where 0.7 wrote them as themselves. Each of
those texts parses to the same value as 0.7's. The lone surrogates are the
one change of value. The old writer copied a lone surrogate into its
output, a string with no UTF-8 form; the new one writes U+FFFD, because
`Utf8JsonWriter` writes UTF-8 and the encoder replaces what it cannot
encode. Only a payload built by hand can hold one: the module's strings
are Rust strings.

`probe/` prints what the two encoders the library ships do to the same
strings. .NET 8.0.31 and 10.0.12 printed the same.

| Input | 0.7 | `Default` | `UnsafeRelaxedJsonEscaping` (now) |
|---|---|---|---|
| `` <script>&'+` `` | as is | `<script>&'+`` | as is |
| U+007F U+0080 U+00AD | as is | all three escaped | `\u007F\u0080`, U+00AD as is |
| U+2028 U+2029 | as is | escaped | escaped |
| U+E000 U+FEFF U+FFFE U+FFFF | as is | escaped | escaped |
| U+0378 U+0870 | as is | escaped | `͸`, U+0870 as is |
| U+00E9, U+1F600, U+10FFFF | as is | escaped, the last two as surrogate pairs | U+00E9 as is, the last two as surrogate pairs |
| U+0000 U+001F | `\u0000\u001f` | `\u0000\u001F` | `\u0000\u001F` |
| lone U+D800, U+DC00 | as is | `�` | `�` |

## Checks run on the new code

- `dotnet test -c Release` in `dotnet/`: 1,842 tests passed, 0 failed, 0
  skipped, on net8.0, net9.0 and net10.0, the floor project
  (netstandard2.0 asset) included.
- `dotnet format --verify-no-changes --severity info` on the solution, the
  fuzz project and `tools/CorpusRun`: clean.
- `dotnet publish samples/TrimAotSmoke -warnaserror` (full trim): no
  warning, and the trimmed binary verified its receipt. The library builds
  without `AllowUnsafeBlocks`.
- `fuzz/run.sh json 45`: 1,013,152 executions of the writer round trip, no
  finding.

## Where it stops holding

- The comparison covers the `verifyReceipt` and `verifySignedData` cases
  and the strings listed, not the endpoint or `decodeBase64` cases; it ran
  on Linux x86-64 only.
- The "netstandard2.0" column ran the library's netstandard2.0 asset on
  .NET 10, where the in-box `System.Text.Json` is loaded. The package's
  netstandard2.0 and net462 builds of `System.Text.Json`, which .NET
  Framework, Mono and Unity load, were not run. The floor project runs the
  netstandard2.0 asset on CoreCLR too; CI's `dotnet-mono` job only loads
  it.
- Which code points the relaxed encoder escapes follows the Unicode
  tables of the `System.Text.Encodings.Web` that runs. U+0870, assigned in
  Unicode 14, is written as itself here; a character assigned in a later
  Unicode version may be escaped on one runtime and not on another. The
  value stays the same either way.
- With the subclass gone the `json` fuzz target reaches no instrumented
  code of the package: the escaping is in `System.Text.Encodings.Web`,
  which SharpFuzz does not instrument here. The run above reports 12
  features and a corpus of one unit, where the subclass gave 413 features
  over 104 units, so libFuzzer has no coverage to steer by and the target
  only checks its invariant on mutated inputs. The target was removed on
  the owner's Q23 (2026-10-02).
