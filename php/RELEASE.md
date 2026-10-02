# Release wiring for the PHP port

**The package is the repository root's `composer.json`**, which autoloads
`EminDeniz99\ApplePurchaseReceiptVerifier\` from `php/src/`; Packagist reads a
repository root and nowhere else. Packagist needs no publish job in
`release.yml`: it imports tags on its own once the owner submits the
repository. That submission, and what the root manifest costs, are in
[`BOOTSTRAP.md`](../BOOTSTRAP.md) under "Packagist (PHP)" — that section is
current and this file no longer repeats it.

## `post-publish-smoke.yml` — not yet added

Blocked on the Packagist submission rather than on the layout, but the job
shape is settled. It is the only check that tests what a consumer actually
receives — the same gap that once shipped two empty npm releases. Run it on
the **floor**, 8.2, because that is the leg most likely to break on a
published artifact and the claim least exercised anywhere else.

```yaml
  packagist:
    name: composer — install the published package and verify a receipt
    needs: resolve
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: shivammathur/setup-php@f3e473d116dcccaddc5834248c87452386958240 # 2.37.2
        with:
          php-version: "8.2"
          extensions: json, curl
          coverage: none
      - name: poll Packagist for the version, then install it outside any checkout
        env:
          VERSION: ${{ needs.resolve.outputs.version }}
        run: |
          set -euo pipefail
          mkdir -p "$RUNNER_TEMP/smoke" && cd "$RUNNER_TEMP/smoke"
          for attempt in $(seq 1 40); do
            if composer show "emindeniz99/apple-purchase-receipt-verifier=$VERSION" >/dev/null 2>&1; then
              break
            fi
            echo "waiting for $VERSION on Packagist (attempt $attempt)"
            sleep 30
          done
          composer require --no-interaction \
            "emindeniz99/apple-purchase-receipt-verifier:$VERSION"
          # Downloads the release's aprv binary and checks it against the
          # SHA-256 binaries.json pins in the package.
          vendor/bin/aprv-install
          php verify-smoke.php
```

The smoke script must, at minimum, `Verifier::create(new Config())` over
the default CLI transport and verify a genuine Apple-signed receipt: that is
what catches a package that installed but shipped no `php/bin/aprv-install` or
no `php/binaries.json`, an installer that cannot fetch the release's binary,
or a pinned hash that no longer matches the published asset. It is the PHP leg
of the plan's acceptance test 8.

## Pinning the binaries' hashes at release

`php/binaries.json` names the release tag and the SHA-256 of each `aprv`
binary; `vendor/bin/aprv-install` refuses any download that does not match.
Because Composer installs the tag's tree, the hashes are committed on the
release branch before the tag, from the binaries the release will publish:

```bash
(cd dist && sha256sum aprv-* > SHA256SUMS)
php php/tools/update-binaries.php --tag "v$VERSION" --sums dist/SHA256SUMS
```

An asset the sums file lacks is reset to `null`, so its platform is told to use
the server option. `php/CI-NOTES.md` has the CI wiring and the open question
about the macOS and Windows binaries.
