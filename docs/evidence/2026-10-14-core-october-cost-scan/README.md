# The core against October's hostile shapes: source

The note is [`../2026-10-14-core-october-cost-scan.md`](../2026-10-14-core-october-cost-scan.md).

| File | Question it answered |
|---|---|
| `october_cost_scan.rs` | What one warm `Verifier::verify_receipt` (or `verify_signed_data`) costs the core, in wall time, peak live heap, bytes allocated and peak resident set, on 21 shared cases and on every shape Java began screening on 13 and 14 October, rebuilt from the test PKI at sizes from the fixture's up to the most the 3 MiB receipt cap, the 100,000-value budget or the 32-level depth bound let through |
| `results.tsv` | Its output from the run the note reports, one row per input: verdict and reason, median and minimum of the timed calls, peak heap, allocation and resident-set rise in KiB |

The harness is an example of the core crate, so it builds against the
core's Rust API with the dev-dependencies and the test seams, and reuses
`rust/tests/common` (the shared generated receipt, its pinned root, the
DER writer). It installs a counting global allocator and routes
OpenSSL's allocations into the same counters with
`CRYPTO_set_mem_functions`, so the heap figures cover both. The resident
set figure needs Linux (`/proc/self/clear_refs`, `VmHWM`) and glibc
(`malloc_trim`).

Reproduce, with `$REPO` the repository root and `$SCRATCH` a directory
outside it. Name the toolchain: rustup picks it from the working
directory, not from `--manifest-path`, so outside `rust/` it would not
read `rust/rust-toolchain.toml`.

```sh
cp "$REPO/docs/evidence/2026-10-14-core-october-cost-scan/october_cost_scan.rs" \
  "$REPO/rust/examples/"
CARGO_TARGET_DIR="$SCRATCH/target" cargo +1.99.0 run --locked --release \
  --manifest-path "$REPO/rust/Cargo.toml" -p apple-purchase-receipt-verifier \
  --example october_cost_scan > "$SCRATCH/results.tsv"
rm "$REPO/rust/examples/october_cost_scan.rs"
```

The run takes about ten minutes, most of it spent bisecting for the
largest input each bound admits and building the 2^15 hash-colliding
OIDs. Verdicts and sizes reproduce exactly; timings vary with the machine.
