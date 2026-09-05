# Releasing the Rust port

The `publish-crates` job (crates.io trusted publishing via
`rust-lang/crates-io-auth-action`) is implemented in `release.yml`, and the
`release-please-config.json` entry for `rust/Cargo.toml` is implemented.
Owner bootstrap steps and the release-budget note live in
[`BOOTSTRAP.md`](../BOOTSTRAP.md) under "crates.io" — that section is
current and this file no longer repeats it.

## `rust/Cargo.lock` is deliberately not committed

Cargo ignores a library's lockfile downstream, and the file records this
package's own version, so a bump that touched only `Cargo.toml` would make
every `--locked` CI job fail. CI generates an MSRV-pinned lockfile instead
(see the `rust` job in `.github/workflows/ci.yml`), so there is no second
file to keep in sync — which is precisely why it is not committed.

## What the published tarball contains

`exclude = ["tests/**", "fuzz/**"]` in `Cargo.toml`, so the crate ships
`src/`, `certs/`, `Cargo.toml`, `README.md` and `LICENSE` and nothing else.
The tests read `../../fixtures`, which a registry consumer does not have,
and a test suite that cannot run is worse than one that is not shipped. That
means the published file set is **not** the repository file set, which is
exactly the gap the post-publish smoke test below exists to close.

## `post-publish-smoke.yml` — not yet added

A Rust leg, in the shape the other legs use: create a scratch crate outside
the checkout, add the published version from the real registry, and verify a
genuine Apple-signed receipt with it. The receipt comes from the checkout
rather than from the crate, which is the point: the crate excludes its
fixtures, so this exercises the file set a consumer actually receives.

```yaml
  rust:
    name: cargo add from crates.io
    runs-on: ubuntu-latest
    timeout-minutes: 20
    needs: resolve
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
          ref: ${{ needs.resolve.outputs.ref }}
      - run: rustup toolchain install stable --profile minimal
      - name: verify a genuine receipt with the published crate
        env:
          VERSION: ${{ needs.resolve.outputs.version }}
        run: |
          set -euo pipefail
          RECEIPT="$PWD/fixtures/public-receipts/receipt-sandbox-g5.b64"
          cd "$(mktemp -d)"
          cargo init --name smoke --bin
          for attempt in $(seq 1 20); do
            cargo add "apple-purchase-receipt-verifier@=$VERSION" && break
            echo "not on crates.io yet (attempt $attempt of 20); waiting 30s"
            sleep 30
          done
          cat > src/main.rs <<'RS'
          use apple_purchase_receipt_verifier::{apple_receipt_roots, ReceiptVerifier};
          fn main() {
              let text = std::fs::read_to_string(std::env::args().nth(1).unwrap()).unwrap();
              let der = apple_purchase_receipt_verifier::base64::decode_lenient(text.trim());
              let verifier = ReceiptVerifier::builder()
                  .trusted_roots(apple_receipt_roots().iter().cloned())
                  .bundle_id("dev.bonzer.weeka.app")
                  .build()
                  .unwrap();
              let receipt = verifier.verify(&der).unwrap();
              assert_eq!(receipt.in_app_purchases.len(), 2);
              println!("verified {:?}", receipt.bundle_id);
          }
          RS
          cargo run -- "$RECEIPT"
```
