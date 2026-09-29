# The differential campaign

The Rust core, as `aprv.wasm`, and the 0.7 Java implementation (`java/`)
answer the same calls; every difference is either recorded in
DECISIONS.md R20 or fails the run (R33). `../differential.sh` is the entry
point; CI's nightly `java-differential` job runs it on `fixtures/cases.json`,
and the evidence campaigns pass the corpora as extra call files
(`docs/evidence/2026-09-29-differential-campaign.md`).

```sh
rust/bindings/abi/build.sh "$OUT"
tools/differential.sh "$OUT/aprv.wasm" "$REPORT"                  # the cases
tools/differential.sh "$OUT/aprv.wasm" "$REPORT" corpus.jsonl ... # and more
```

| File | What it does |
|---|---|
| `cases-calls.mjs` | `fixtures/cases.json` as calls: one per verify case, one per `decodeBase64` text (a receipt-data text through `verify-receipt`, an x5c text as the three entries of a JWS header), a case without a clock at one pinned instant |
| `Differential.java` | The Java implementation over a call file, printing the core's wire JSON so rows compare |
| `compare.mjs` | Classifies each pair of rows and checks the unexplained ones against the recorded ones |
| `recorded.json` | The case rows R20 records, each with its class and the R20 group that explains it |

A call file is one JSON object per line: `id`, `fn` (`verify-receipt`,
`verify-signed-data`, `verify-receipt-endpoint`), `config` (`init`'s JSON),
`now` (epoch milliseconds), `env` (0 or 1, the endpoint's), `b64` (the input
bytes), the format `tools/wasm-trap-host.mjs calls` reads.

## The classes

| Class | Meaning | Fails the run unless recorded |
|---|---|---|
| `same` | Same verdict and reason; a verified row's payload equal by value; an endpoint row's status equal, and its body for status 0 | no |
| `message-only` | Same verdict and reason, other wording | no |
| `java-no-call` | The Java API cannot make the call: its inputs are `String`s, so input bytes that are not UTF-8 have no Java spelling | no |
| `reason` | Both refuse, for different reasons | yes |
| `payload` | Both verify, with different payloads | yes |
| `verdict` | One verifies, the other refuses | yes |
| `fault` | A trap, an exception out of the Java library, or `INTERNAL_ERROR` on either side | yes |

A recorded row that answers the same again is listed as stale: remove it
from `recorded.json` and from R20.
