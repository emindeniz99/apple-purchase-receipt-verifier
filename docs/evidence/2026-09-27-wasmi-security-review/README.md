# Wasmi 2.0.0 security review — code and raw results

Backs `../2026-09-27-wasmi-security-review.md`. Everything here is a
throwaway spike: it downloads third-party sources into `$SCRATCH`, reads
and greps them, and writes the results below. No third-party source, binary
or downloaded crate is committed; each is referenced by version + sha256 in
`results/crates.txt`. CI builds none of this.

`$REPO` = repository root. `$SCRATCH` = a directory outside the repo
(e.g. a scratch dir); everything downloaded or built goes there.

## What each file answers

| file | question it answers |
|---|---|
| `scripts/fetch.sh` | Get the exact sources. Resolves `wasmi 2.0.0` + `wasmi_c_api_impl 2.0.0` (proposal features: std, validate, memory64, stable, auto-dispatch), `cargo vendor`s the graph, verifies each crate's Cargo.lock checksum against a fresh static.crates.io download, prints crates.io publish/yanked records, clones the `v2.0.0` git tag (fuzz/CI/spec harness + audit PDFs, not in the published crate), and fetches the CVE-2025-66627 fix commit. → `results/crates.txt` |
| `scripts/unsafe_inventory.py` | Count every `unsafe` keyword per crate/module, tagged kind (block/fn/impl/attr) and scope (src/test/build). → `results/unsafe-raw.tsv` |
| `scripts/classify.py` | Apply the hand-written risk classes (A-mem/ip/stack/inst/assume, B, C, D) to the core-crate `src` rows; fail loudly on any unclassified row. → `results/unsafe-classified.tsv`, `results/unsafe-summary.txt` |
| `scripts/capi_surface.py` | List every C function `wasmi_c_api_impl` exports (direct `extern "C"` + `declare_own!/ty!/ref!` + `declare_vecs!` expansions) and flag `unimplemented!`/conditional panics. → `results/capi-functions.tsv` |
| `scripts/module_surface.py` | Print a module's imports, memories, tables and start function. Run on the canonical `aprv.wasm`. → `results/aprv-module-surface.txt` |
| `scripts/advisories.sh` | RustSec/GHSA status of every crate in the graph, via OSV + a RustSec advisory-db clone. → `results/advisories.txt` |
| `scripts/audit_facts.py` | Extract the cited facts (versions covered, findings + severities, unsafe count) from the two audit PDFs shipped in the tag. Needs `pypdf` in a scratch venv. → `results/audits.txt` |
| `scripts/upstream_facts.sh` | Upstream testing facts for v2.0.0: fuzz targets + oracles, CI fuzz/Miri jobs, spec-suite harness + proposals, OSS-Fuzz enrollment, Wasmtime's `diff_wasmi` pin. → `results/upstream-testing.txt` |

## Reproduce

```sh
export REPO=/path/to/apple-purchase-receipt-verifier
export SCRATCH=/path/to/scratch          # outside the repo
V="$SCRATCH/wasm/secrev/vendor"          # fetch.sh writes here

sh  "$REPO"/docs/evidence/2026-09-27-wasmi-security-review/scripts/fetch.sh \
    > "$REPO"/docs/evidence/2026-09-27-wasmi-security-review/results/crates.txt

E="$REPO/docs/evidence/2026-09-27-wasmi-security-review"
python3 "$E"/scripts/unsafe_inventory.py "$V" \
    wasmi wasmi_core wasmi_ir wasmi_collections wasmparser \
    wasmi_c_api_impl wasmi_c_api_macros spin libm bitflags \
    > "$E"/results/unsafe-raw.tsv
python3 "$E"/scripts/classify.py           "$E"/results/unsafe-raw.tsv > "$E"/results/unsafe-classified.tsv
python3 "$E"/scripts/classify.py --summary "$E"/results/unsafe-raw.tsv > "$E"/results/unsafe-summary.txt
python3 "$E"/scripts/capi_surface.py "$V"  > "$E"/results/capi-functions.tsv
python3 "$E"/scripts/module_surface.py "$SCRATCH"/wasm/abi/art/aprv-abi1.wasm > "$E"/results/aprv-module-surface.txt

sh "$E"/scripts/advisories.sh      > "$E"/results/advisories.txt
sh "$E"/scripts/upstream_facts.sh  > "$E"/results/upstream-testing.txt

python3 -m venv "$SCRATCH"/venv && "$SCRATCH"/venv/bin/pip install -q pypdf
"$SCRATCH"/venv/bin/python "$E"/scripts/audit_facts.py "$SCRATCH"/wasm/secrev/wasmi-git > "$E"/results/audits.txt
```

## Environment when this was run (2026-09-27)

- x86-64 Linux, `cargo 1.94.1`, `rustc 1.94.1`, CPython 3.12, `pypdf 6.19.0`.
- Wasmi tag `v2.0.0` = `2970aa871cc1001b57b267ccecdcd1e42306199e` (2026-09-01).
- Sources resolved and hashed in `results/crates.txt`; every Cargo.lock
  checksum matched a fresh static.crates.io download.

## Not done / limits

- No benchmarks and no bindings built (round 11 does that). No large builds.
- The `unsafe` inventory is a lexer-light scanner, not `rustc`; per-file
  totals were cross-checked against `grep -c '\bunsafe\b'`, and the C-API
  panic flags are a grep of each function body, read by hand afterwards.
- The risk classification is hand-written and hand-checked, first-match-
  wins; the exact rules are in `scripts/classify.py`.
- Finding 3 was reported privately upstream on 2026-09-27; its details and
  any reproduction stay out of this public repo until upstream publishes a
  fix.
- GitHub's API/raw endpoints were not reachable for `wasmi-labs/wasmi` from
  this environment; Wasmi's advisory page and issues #1921/#1950 were read
  via web fetch and are marked DOCUMENTED in the note.
