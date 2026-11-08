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
| `cases-calls.mjs` | `fixtures/cases.json` as calls: one per verify case (with its revocation lists, added issuers and distrust entries in the call's config), one per `buildConfig` case, one per `decodeBase64` text (a receipt-data text through `verify-receipt`, an x5c text as the three entries of a JWS header), a case without a clock at one pinned instant. No case is skipped: a case that yields no call stops the run |
| `Differential.java` | The Java implementation over a call file, printing the core's wire JSON so rows compare. It builds its `Config` from the call's roots, `revocation_lists`, `revocation_issuers` and `distrust` with the published API (`Config.builder()`, `Verifier.create`, `RevokedCertificate`) |
| `compare.mjs` | Classifies each pair of rows and checks the unexplained ones against the recorded ones |
| `recorded.json` | The case rows R20 records, each with its class and the R20 group that explains it |

A call file is one JSON object per line: `id`, `fn` (`verify-receipt`,
`verify-signed-data`, `verify-receipt-endpoint`, `build-config`), `config`
(`init`'s JSON: `roots`, `revocation_lists`, `revocation_issuers`,
`distrust`), `now` (epoch milliseconds), `env` (0 or 1, the endpoint's), `b64`
(the input bytes), the format `tools/wasm-trap-host.mjs calls` reads.

## What the revocation cases compare

A verify call with revocation settings runs on both sides under the same
lists, issuers and distrust entries, so `CERTIFICATE_REVOKED` against a
verified row is a `verdict` like any other. A `build-config` call (a
`buildConfig` case) makes each side build the configuration and answer
`{"ok":true,"revocation_urls":[...],"revocation_valid_until_ms":N|null}`, or
`{"ok":false,...}` when it refuses; the core's row is its `init` answer
without the input cap, Java's is `Verifier.create` followed by
`revocationUrls()` and `revocationValidUntil()`. Two refusals are `same`
whatever their messages (docs/design/revocation.md section 4), and a
configuration one side builds and the other refuses is a `verdict`. A
verify call whose configuration only one side refuses is a `verdict` too.
Both Verifiers are built per configuration and instant, so each
revocation case adds its own instance on both sides.

## The classes

| Class | Meaning | Fails the run unless recorded |
|---|---|---|
| `same` | Same verdict and reason; a verified row's payload equal by value; an endpoint row's status equal, and its body for status 0 | no |
| `message-only` | Same verdict and reason, other wording | no |
| `java-no-call` | The Java API cannot make the call: its inputs are `String`s, so input bytes that are not UTF-8 have no Java spelling | no |
| `reason` | Both refuse, for different reasons | yes |
| `payload` | Both verify, with different payloads; a `build-config` row: both build, with different `revocation_urls` or `revocation_valid_until_ms` | yes |
| `verdict` | One verifies, the other refuses; a `build-config` row: one builds the configuration, the other refuses it | yes |
| `fault` | A trap, an exception out of the Java library, or `INTERNAL_ERROR` on either side | yes |

A recorded row that answers the same again is listed as stale: remove it
from `recorded.json` and from R20.
