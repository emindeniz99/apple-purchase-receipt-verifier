# Releasing the Rust port

What `release.yml`, `release-please-config.json` and
`post-publish-smoke.yml` need for crates.io. The orchestrator owns those
files; this is the exact text and the reasoning behind each piece.

## `release-please-config.json`

One entry, the same shape as the existing Python one, because
`Cargo.toml`'s version lives at `$.package.version`:

```json
{ "type": "toml", "path": "rust/Cargo.toml", "jsonpath": "$.package.version" }
```

That is the only file this port adds to the version sweep. **`rust/Cargo.lock`
is deliberately not committed** — cargo ignores a library's lockfile
downstream, and the file records this package's own version, so a bump that
touched only `Cargo.toml` would make every `--locked` job fail. CI generates
an MSRV-pinned lockfile instead. So there is no second file to keep in sync,
which is precisely why it is not committed.

## `release.yml`

`cargo publish` runs on a `v*` tag, gated on the same `ci-passed` job every
other publish job waits for, with the same "skip loudly if the registry
already has this version" shape.

crates.io supports OIDC trusted publishing through the official
`rust-lang/crates-io-auth-action`, which exchanges the GitHub OIDC token for
a short-lived crates.io token and revokes it in a post step — so no registry
token lives in this repository. **Pin it to a full commit SHA** like every
other action here; the `# v1` comment names the tag.

```yaml
  publish-crates:
    name: publish rust to crates.io
    runs-on: ubuntu-latest
    needs: ci-passed
    timeout-minutes: 20
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - run: rustup toolchain install stable --profile minimal

      - name: Skip if this version is already on crates.io
        id: gate
        run: |
          set -euo pipefail
          VERSION=$(cat version.txt)
          if curl -fsSL https://index.crates.io/ap/pl/apple-purchase-receipt-verifier \
             | grep -q "\"vers\":\"$VERSION\""; then
            echo "crates.io already has $VERSION — skipping publish."
            echo "publish=false" >> "$GITHUB_OUTPUT"
          else
            echo "publish=true" >> "$GITHUB_OUTPUT"
          fi

      - uses: rust-lang/crates-io-auth-action@<pin to a full commit SHA> # v1
        if: steps.gate.outputs.publish == 'true'
        id: auth

      - run: cargo publish
        if: steps.gate.outputs.publish == 'true'
        working-directory: rust
        env:
          CARGO_REGISTRY_TOKEN: ${{ steps.auth.outputs.token }}
```

The sparse-index gate is the same mechanism the other jobs use:
`https://index.crates.io/<first two>/<next two>/<name>` answers 404 for an
unpublished crate and a JSON-lines version list for a published one.
Verified while writing this: the path above returns 404 today and the
control `/se/rd/serde` returns 200.

No cache anywhere in the job — a poisoned restore becomes the shipped
artifact.

Then add `publish-crates` to the `smoke` job's `needs:` list, alongside the
three that are there now.

**Never rename `release.yml`.** It is now the match key for a fourth
registry: npm, PyPI and crates.io all key their trusted publisher on this
filename.

## Bootstrapping the first publish

crates.io configures a trusted publisher on the crate's own settings page,
which means the crate has to exist first — the same chicken-and-egg npm has.
So, in order, and all three steps are the owner's:

1. One manual `cargo publish` from a clean checkout, at the version
   `version.txt` currently names, using a scoped API token.
2. Configure the trusted publisher on crates.io — repository
   `emindeniz99/apple-purchase-receipt-verifier`, workflow `release.yml`,
   and the environment if the other jobs use one — then revoke the token.
3. Let release-please cut the next version and let the automated path
   publish it, which proves the whole chain end to end.

Bootstrap at the **current** version rather than at the one release-please
is about to propose, so the automated run has a free version to take.

Before that manual publish: `git status` clean and `HEAD` pushed.
`cargo publish` packs the **working tree**, not a commit.

Worth checking before scheduling: whether crates.io now allows configuring a
*pending* trusted publisher for a crate that does not yet exist, the way
PyPI does. If it does, step 1 disappears.

## What the published tarball contains

`exclude = ["tests/**", "fuzz/**"]` in `Cargo.toml`, so the crate ships
`src/`, `certs/`, `Cargo.toml`, `README.md` and `LICENSE` and nothing else.
The tests read `../../fixtures`, which a registry consumer does not have,
and a test suite that cannot run is worse than one that is not shipped.

That means the published file set is **not** the repository file set, which
is exactly the gap the post-publish smoke test exists for.

## `post-publish-smoke.yml`

A Rust leg, in the shape the other legs use: create a scratch crate outside
the checkout, add the published version from the real registry, and verify a
genuine Apple-signed receipt with it.

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

The receipt comes from the checkout rather than from the crate, which is the
point: the crate excludes its fixtures, so this exercises the file set a
consumer actually receives.

## Release budget

crates.io has no monthly cap, but Maven Central's seven-per-calendar-month
limit governs whether a release pull request gets merged at all, and a
Rust-only fix now competes for it. crates.io publishes are also
**irrevocable** — a yank hides a version, it never deletes it — which is what
makes the version gate above load-bearing rather than a convenience.
