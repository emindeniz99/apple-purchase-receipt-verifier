# The header walk reduced to a counter: probes

The spike's code is the commit `refactor(rust): walk headers as an
iterative counter`, kept in the closed, unmerged [#294](https://github.com/emindeniz99/apple-purchase-receipt-verifier/pull/294).
This folder keeps what reruns from it.

| File | Question |
|---|---|
| `walk-counter.patch` | The counter itself: `git diff origin/main` of that commit over `rust/openssl/src`. The walk keeps the depth bound, the node budget, well-formed headers and lengths, the end-of-contents of an indefinite length, the trailing-bytes check and the hand-off of each constructed string at its outermost level; every grammar rule of its own is gone. |
| `walk-middle.patch` | The middle shape, applied on top of the counter: the walk also hands every primitive of a constrained universal type outside a string to OpenSSL's `ANY` decoder and refuses an end-of-contents inside a definite length. Only the payload's header-form and chunk rules stay gone. |
| `walk-probe.rs` | What does the core answer, and does `d2i_CMS_ContentInfo` alone take the envelope, for receipts valid but for one grammar deviation: in the payload under a minted P-256 PKI, in the unsigned parts of the shared generated receipt, and in a minted signer certificate? And what do the shared cases the counter moves answer? |
| `case-flips.tsv` | Every shared case whose answer changes, per shape, with its expectation, whether it is `oneOf`, and where it is judged. |
| `probe-output.txt` | The probe and the conformance failures, once per shape: `kept` (main), `counter`, `middle`. |

Reproduce on the counter commit (revert the test file and any patch
afterwards):

```sh
E="$REPO/docs/evidence/2026-10-06-core-walk-counter"
cat "$E/walk-probe.rs" >> "$REPO/rust/tests/envelope_bounds.rs"
for v in kept counter middle; do
  [ "$v" = kept ] && git -C "$REPO" apply -R "$E/walk-counter.patch"
  [ "$v" = middle ] && git -C "$REPO" apply "$E/walk-middle.patch"
  echo "== walk-$v"
  CARGO_TARGET_DIR="$SCRATCH/target" cargo test --locked \
    --manifest-path "$REPO/rust/Cargo.toml" -p apple-purchase-receipt-verifier \
    --test envelope_bounds walk_counter_probe -- --nocapture --test-threads 1 \
    2>/dev/null | grep -oE 'PROBE .*'
  echo "conformance:"
  CARGO_TARGET_DIR="$SCRATCH/target" cargo test --locked \
    --manifest-path "$REPO/rust/Cargo.toml" -p apple-purchase-receipt-verifier \
    --test conformance 2>/dev/null \
    | grep -E '^test result|^[a-z0-9-]+/[a-z0-9-]+[: ]'
  [ "$v" = kept ] && git -C "$REPO" apply "$E/walk-counter.patch"
  [ "$v" = middle ] && git -C "$REPO" apply -R "$E/walk-middle.patch"
done
git -C "$REPO" checkout -- rust/tests/envelope_bounds.rs
```

The answers match `probe-output.txt` (its timings stripped) on a 64-bit
native build, the only one these probes ran on. The conformance lines of
one shape may come in another order.

The fuzz runs in the note used the repository's own targets:

```sh
cargo +nightly fuzz run --fuzz-dir "$REPO/rust/fuzz" verify-receipt \
  "$SCRATCH/corpus/verify-receipt" "$REPO/fixtures/generated" \
  "$REPO/fixtures/generated-0.7" "$REPO/fixtures/apple-official/certs" \
  -- -max_total_time=600
cargo +nightly fuzz run --fuzz-dir "$REPO/rust/fuzz" verify-receipt-base64 \
  "$SCRATCH/corpus/verify-receipt-base64" "$REPO/fixtures/generated/receipt-b64" \
  "$REPO/fixtures/public-receipts" "$REPO/fixtures/apple-official/xcode" \
  -- -max_total_time=600
```
