# Redundant bounds in the core: probes

| File | Question |
|---|---|
| `crl-flood-cost.rs` | Once the ten-CRL cap is gone, what does the largest CRL flood the 100,000-value budget lets through cost, against a flood that fills the same budget with NULLs? |
| `crl-extension-cost.rs` | What do one CRL with a 2 MB AuthorityKeyIdentifier, the largest flood of minimal CRLs, and one bag certificate with a 2 MB subjectAltName cost in time and peak memory? |
| `extension-cost.txt` | Its outputs. |

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

Reproduce the extension probe the same way, one test per process so each
peak resident set is that test's own (Linux: it reads `/proc/self/status`):

```sh
cat "$REPO/docs/evidence/2026-10-05-core-drop-redundant-bounds/crl-extension-cost.rs" \
  >> "$REPO/rust/tests/envelope_bounds.rs"
for t in cost_control cost_crl_with_a_two_megabyte_authority_key_identifier \
  cost_minimal_crl_flood cost_bag_certificate_with_a_two_megabyte_subject_alt_name \
  cost_bag_certificate_with_a_two_megabyte_subject_alt_name_issued_by_nobody; do
  CARGO_TARGET_DIR="$SCRATCH/target" cargo test --quiet --locked --all-features \
    --manifest-path "$REPO/rust/Cargo.toml" -p apple-purchase-receipt-verifier \
    --test envelope_bounds "$t" -- --exact --nocapture
done
git -C "$REPO" checkout -- rust/tests/envelope_bounds.rs
```

Expected: the `COST` lines of `extension-cost.txt` (timings vary with the
machine). At 352f0d1 the flood test fails its verdict assertion: the cap
refuses it there.
