# 2026-10-03 rust-tests-asn1-rs scripts

| File | Question it answered |
|---|---|
| `reader_probe.rs` | Do the hand-written reader and writer in `rust/tests/common/` and their asn1-rs replacements read every fixture into the same tree and write the same bytes? |
| `count.sh` | How many lines of hand-written BER/DER code `rust/tests/` holds at a revision, how many calls reach the reader, and the first two arcs of every dotted OID string in the tests. |

## Reproduce

Before: `453fc7b`. After: `5fe1bfd`; the first run used `befcfae`,
before the reader's two refusals, and the probe had no `inputs=` line. `$REPO` is the repository root,
`$SCRATCH` any directory outside it. Run from inside `$REPO/rust`, so its
`rust-toolchain.toml` picks the compiler.

```sh
export CARGO_TARGET_DIR="$SCRATCH/target"

# Before: the hand-written reader, module `common::der`.
git -C "$REPO" worktree add --detach "$SCRATCH/before" 453fc7b
cp "$REPO/docs/evidence/2026-10-03-rust-tests-asn1-rs/reader_probe.rs" "$SCRATCH/before/rust/tests/"
PROBE_OUT="$SCRATCH/probe-before.txt" \
  cargo test --manifest-path "$SCRATCH/before/rust/Cargo.toml" \
  -p apple-purchase-receipt-verifier --test reader_probe

# After: asn1-rs, module `common::ber`. Edit the probe's
# `use common::der as reader;` line to `use common::ber as reader;`.
git -C "$REPO" worktree add --detach "$SCRATCH/after" 5fe1bfd
cp "$REPO/docs/evidence/2026-10-03-rust-tests-asn1-rs/reader_probe.rs" "$SCRATCH/after/rust/tests/"
sed -i 's/^use common::der as reader;/use common::ber as reader;/' "$SCRATCH/after/rust/tests/reader_probe.rs"
PROBE_OUT="$SCRATCH/probe-after.txt" \
  cargo test --manifest-path "$SCRATCH/after/rust/Cargo.toml" \
  -p apple-purchase-receipt-verifier --test reader_probe

diff "$SCRATCH/probe-before.txt" "$SCRATCH/probe-after.txt"

sh "$REPO/docs/evidence/2026-10-03-rust-tests-asn1-rs/count.sh" 453fc7b
sh "$REPO/docs/evidence/2026-10-03-rust-tests-asn1-rs/count.sh" befcfae
sh "$REPO/docs/evidence/2026-10-03-rust-tests-asn1-rs/count.sh" 5fe1bfd
```

The probe reads every `*.der` under `fixtures/`, every `*.b64`, the Xcode
receipts under `fixtures/apple-official/xcode/` and the
`fixtures/generated/receipt-b64/` files that decode as standard base64.
Its `inputs=` line counts them and those that start `30 80`, an
indefinite-length `SEQUENCE`.
