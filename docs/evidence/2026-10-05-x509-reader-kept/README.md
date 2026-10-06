# The core's X.509 reader: probes

The full record of the experiment is the closed, unmerged
[#293](https://github.com/emindeniz99/apple-purchase-receipt-verifier/pull/293), commits 768e8f5 through bd1120c: the reader's rules removed and partly restored, the
shared cases made port-defined and back, the differential run's
`recorded.json`, and the review that found the two no-code divergences.
This folder keeps what reruns on main.

| File | Question |
|---|---|
| `reader-probe.rs` | What does the core answer to JWS chains minted under the test PKI (a version past v3 or past 32 bits, a marker or an unknown OID twice, a basicConstraints that does not decode on the leaf or in `x5c[2]`), and to the four shared cases whose intermediate's keyUsage or cA BOOLEAN does not decode? |
| `reader-removed.patch` | `is_readable` answers true: the whole reader gone. |
| `reader-narrowed.patch` | Only the basicConstraints and keyUsage decode check gone, the branch's final shape without its anchor check. |
| `probe-output.txt` | The probe and the conformance failures, once per variant. |

Reproduce on the commit that added this folder (revert the test file and
any patch afterwards):

```sh
E="$REPO/docs/evidence/2026-10-05-x509-reader-kept"
cat "$E/reader-probe.rs" >> "$REPO/rust/tests/jws_negative.rs"
for v in kept removed narrowed; do
  [ "$v" = kept ] || git -C "$REPO" apply "$E/reader-$v.patch"
  echo "== reader-$v"
  CARGO_TARGET_DIR="$SCRATCH/target" cargo test --locked --all-features \
    --manifest-path "$REPO/rust/Cargo.toml" -p apple-purchase-receipt-verifier \
    --test jws_negative x509_reader_probe -- --nocapture --test-threads 1 \
    2>/dev/null | grep -oE 'PROBE .*'
  CARGO_TARGET_DIR="$SCRATCH/target" cargo test --locked --all-features \
    --manifest-path "$REPO/rust/Cargo.toml" -p apple-purchase-receipt-verifier \
    --test conformance 2>/dev/null \
    | grep -E '^test result|^[a-z0-9-]+/[a-z0-9-]+: '
  [ "$v" = kept ] || git -C "$REPO" apply -R "$E/reader-$v.patch"
done
git -C "$REPO" checkout -- rust/tests/jws_negative.rs
```

The patched builds warn that the reader's helpers are unused; that is
expected. The answers match `probe-output.txt` (its timings stripped) on a
64-bit native build, the only one these probes ran on.
