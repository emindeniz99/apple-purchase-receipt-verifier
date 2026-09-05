# Release wiring for the PHP port

**The PHP port cannot be published from this repository as it is laid out**
(Packagist reads `composer.json` from the repository root only, and this
port's manifest is `php/composer.json`), and `release.yml` already carries a
comment saying so next to the Swift line. The layout options the owner still
has to choose between, and the Packagist bootstrap steps once one is picked,
live in [`BOOTSTRAP.md`](../BOOTSTRAP.md) under "Packagist (PHP)" — that
section is current and this file no longer repeats it.

## `post-publish-smoke.yml` — not yet added

Blocked on the same packaging decision as the publish itself, but the job
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
