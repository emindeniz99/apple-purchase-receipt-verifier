# Fixtures

`cases.json` holds the shared conformance cases; `cases.schema.json`
describes it, and `tools/lint-cases.mjs` checks both.

`corpus.json` pins the generated parity corpus that the nightly `corpus`
job runs. The corpus is about 200 MB of rows, so it stays out of git and
lives as a release asset; this file records its URL, SHA-256 and
generation date. A corpus update is a PR that changes the pin; the job fails if the
archive's hash differs or the file is missing or malformed.
