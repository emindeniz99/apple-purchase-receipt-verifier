# Fixtures

`cases.json` holds the shared conformance cases; `cases.schema.json`
describes it, and `tools/lint-cases.mjs` checks both. The revocation
cases read the test PKI and lists in `generated-0.7/revocation/`, written
by `RevocationFixtures` in `java/src/test/`, and two lists Apple serves
in `apple-crls/`, whose README gives their source.

`corpus.json` pins the calls of the parity corpus that the nightly
`corpus` job runs: a release asset of this repository, by URL and
SHA-256. The calls are about 250 MB, so they stay out of git. The job
builds the module from the commit, derives that module's own rows from
the calls (`tools/corpus.sh`) and runs every host over both; nothing
stores rows any more (docs/rust-core/DECISIONS.md R35). The pin changes
only in a reviewed PR, from the pin that `corpus-calls.yml` prints when it
publishes a repacked archive; no release job rewrites it. The job fails if
the archive's hash differs or the file is missing or malformed. Older
archives also hold a module and its rows; the tools read only their calls.

The calls are frozen and stored because they cannot be generated again
byte for byte: `substrate` and `algorithms` sign with keys made fresh on
every run. 6,179 calls in five corpora, each a file
`calls/<corpus>.pinned.jsonl`:

| corpus | calls | made by |
|---|---:|---|
| `cases` | 153 | `docs/evidence/2026-09-25-java-native-image-spike/py/requests_gen.py` (`cases`): the shared cases of `cases.json` as requests |
| `hostile` | 811 | the same script (`hostile`): seeded malformed and mutated inputs |
| `algorithms` | 22 | `AlgorithmCorpus.java` in the same spike (`gen/src/`), fresh keys on every run |
| `substrate` | 193 | `docs/evidence/2026-09-26-security-substrate-bakeoff/py/gen_corpus.py`, fresh keys on every run |
| `fuzz` | 5,000 | that spike's `py/mutate.py` over `cases` and `substrate`, seed 20260926 |

The requests became calls with
`docs/evidence/2026-09-29-canonical-abi-final/py/calls_bytes.py`, and
`docs/evidence/2026-09-29-aprv-wasm-parity/scripts/pin-now.py` pinned
every call without a clock to 2026-09-29T00:00:00Z, so every host judges
a dateless input at the same instant. Only public fixtures and test keys
went in; no production receipt.
