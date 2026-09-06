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
the **floor**, 8.1, because that is the leg most likely to break on a
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
          php-version: "8.1"
          extensions: openssl, json
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
          php verify-smoke.php
```

The smoke script must, at minimum, load the bundled roots and verify a
genuine Apple-signed receipt — that is what catches a package that installed
but shipped no `php/certs/`, which is exactly the failure the `export-ignore`
layout option in `BOOTSTRAP.md` can cause.
