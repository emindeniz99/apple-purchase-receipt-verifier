# Core coverage and mutants: sources

The scripts behind
[`../2026-10-31-core-coverage-mutants.md`](../2026-10-31-core-coverage-mutants.md).
Nothing here is built by CI.

| File | Question it answered |
|---|---|
| `install-tools.sh` | Installs cargo-llvm-cov 0.9.1 and cargo-mutants 27.1.0 from crates.io with the pinned 1.99.1 toolchain, plus `llvm-tools-preview`. |
| `coverage.sh` | Line, region and branch coverage of `rust/src` and `rust/openssl/src` under both crates' test suites; writes the summary, the JSON export, a text report and HTML to `$SCRATCH`. |
| `uncovered.py` | Every code region no copy of the code ever ran and every branch side never taken, per file, from the JSON export (counts summed over monomorphised copies and over the two builds of `aprv-openssl`). |
| `mutants.sh` | cargo-mutants over the security-critical files (`scoped`) or the rest of the two crates (`rest`), every mutant tested by both crates' suites. |
| `mutants-summary.py` | Caught, missed, timeout and unviable counts per file, and every missed mutant, from cargo-mutants' `outcomes.json`. |
| `mutants-scoped-summary.txt`, `mutants-rest-summary.txt` | That summary for the two runs of 2026-10-31. |
| `coverage-summary.txt` | `coverage.sh`'s per-file table and uncovered lines for the run of 2026-10-31, paths made relative. |
| `uncovered.txt` | `uncovered.py`'s output for the same run. |

## Reproduce

```sh
REPO=$(git rev-parse --show-toplevel)
SCRATCH=/some/dir/outside/the/repo
D=$REPO/docs/evidence/2026-10-31-core-coverage-mutants

bash $D/install-tools.sh $SCRATCH

# Coverage (rebuilds the vendored OpenSSL 4.0.3 once, under $SCRATCH).
bash $D/coverage.sh $REPO $SCRATCH
python3 -I $D/uncovered.py $SCRATCH/coverage.json $REPO/rust/ > $SCRATCH/uncovered.txt

# The OpenSSL the coverage build compiled, reused by every mutants worker.
cp -a $SCRATCH/cov-target/llvm-cov-target/debug/build/openssl-sys-*/out/openssl-build/install \
  $SCRATCH/openssl-4.0.3

bash $D/mutants.sh $REPO $SCRATCH $SCRATCH/openssl-4.0.3 scoped
bash $D/mutants.sh $REPO $SCRATCH $SCRATCH/openssl-4.0.3 rest
python3 -I $D/mutants-summary.py $SCRATCH/mutants-scoped/mutants.out/outcomes.json
python3 -I $D/mutants-summary.py $SCRATCH/mutants-rest/mutants.out/outcomes.json
```

`cp -a` picks the `openssl-sys-*` build directory that holds an
`openssl-build/install`; there is one.

Both runs need `fixtures/` (they set `APRV_FIXTURES_DIR`, since
cargo-mutants tests a copy of `rust/` that has no `fixtures/` above it).
On a four-core machine shared with other builds the scoped run took
38 minutes and the `rest` run 8.
