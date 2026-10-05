# Redundant bounds in the core: probes

| File | Question |
|---|---|
| `crl-flood-cost.rs` | Once the ten-CRL cap is gone, what does the largest CRL flood the 100,000-value budget lets through cost, against a flood that fills the same budget with NULLs? |

Reproduce on the commit that added this folder (revert the test file
afterwards):

```sh
cat "$REPO/docs/evidence/2026-10-05-core-drop-redundant-bounds/crl-flood-cost.rs" \
  >> "$REPO/rust/tests/envelope_bounds.rs"
CARGO_TARGET_DIR="$SCRATCH/target" cargo test --locked --all-features \
  --manifest-path "$REPO/rust/Cargo.toml" -p apple-purchase-receipt-verifier \
  --test envelope_bounds crl_flood_cost -- --nocapture
git -C "$REPO" checkout -- rust/tests/envelope_bounds.rs
```

Expected (timings vary with the machine):

```
COST base 165 values, 15 values a CRL, 6655 CRLs, 99831 NULLs
COST genuine: 3376 bytes of DER, ...
COST crls: 522474 bytes of DER, ...
COST nulls: 203063 bytes of DER, ...
```
