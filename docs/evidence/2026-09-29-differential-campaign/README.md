# The differential campaign (2026-09-29)

The code and results of `../2026-09-29-differential-campaign.md`. The
runner itself is in the repository proper, because CI runs it nightly:
`tools/differential.sh` and `tools/differential/`.

| File | What it answered |
|---|---|
| `scripts/run.sh` | The campaign end to end: seeds, a first pass, the groups, a second pass that must pass |
| `scripts/seeds-calls.mjs` | The ports' fuzz seeds as one call file, under Apple's roots and under every trust-anchor fixture |
| `scripts/classify.py` | Which R20 group explains each failing row; writes `results/recorded-corpus.json` |
| `scripts/add_cases.py` | The shared cases this step and the test inventory added (the stranger cases of §3, the inventory's cases), in `fixtures/cases.json`'s canonical form |
| `scripts/inventory.py` | The mechanical rows of `docs/rust-core/TEST-INVENTORY.md` (the Rust and Java tests) |
| `results/*.report.txt` | `compare.mjs` over each call file in the second pass: every failing row, its recorded group, the summary |
| `results/groups.txt` | `classify.py`'s table: rows per corpus and group, and how many the 0.7 core answered as the core does |
| `results/recorded-corpus.json` | The corpus and seed rows by group, the `RECORDED` file of the second pass |

## Reproduce

```sh
rust/bindings/abi/build.sh "$SCRATCH/out"
REPO="$REPO" MODULE="$SCRATCH/out/aprv.wasm" CALLS="$SCRATCH/calls" \
  OUT="$SCRATCH/campaign" TRAP_HOST="$REPO/tools/wasm-trap-host.mjs" \
  OLD="$SCRATCH/rows/old-fuzz.jsonl" \
  sh docs/evidence/2026-09-29-differential-campaign/scripts/run.sh
```

`$SCRATCH/calls/<corpus>.pinned.jsonl` are the five corpora as round 13's
call files, every unpinned clock pinned to 1790640000000
(`docs/evidence/2026-09-29-aprv-wasm-parity.md` §1 says how they were
made). `OLD` is optional: the pre-migration Rust core's rows for a
corpus (`docs/evidence/2026-09-29-openssl-core-parity.md`); the note's
table passed all five (`classify.py` takes `--old` more than once). Java
21 and Maven build the Java side; Node 22 runs the trap host.
