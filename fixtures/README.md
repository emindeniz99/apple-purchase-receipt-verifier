# Fixtures

`cases.json` holds the shared conformance cases; `cases.schema.json`
describes it, and `tools/lint-cases.mjs` checks both.

`corpus.json` pins the generated parity corpus that the nightly `corpus`
job runs. The corpus is about 200 MB of rows, so it stays out of git and
lives as a release asset; this file records its URL, SHA-256, generation
date and the SHA-256 of the module whose rows it holds. The release PR
updates it with the module pins (release-please.yml,
`release-branch-corpus`); do not edit it by hand. The job fails if the
archive's hash differs, the file is missing or malformed, or the
archive's module is not the one the tree pins.
