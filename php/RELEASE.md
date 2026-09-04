# Release wiring for the PHP port

What `release.yml`, `release-please-config.json` and `post-publish-smoke.yml`
need, and — mostly — what they do not.

## `release-please-config.json`: nothing to add

**No new `extra-files` entry.** `php/composer.json` deliberately carries no
`version` field, which is Composer's own recommendation for a library:
Packagist derives the version from the git tag. Since release-please already
tags `vX.Y.Z` on this repository, the PHP package is versioned correctly with
zero release-please configuration.

The "one version, N files" invariant in `CLAUDE.md` therefore does **not**
grow for PHP. If a `Version::VERSION` constant is ever wanted in the PHP
source, it would need a `generic` updater with an `x-release-please-version`
comment — but it would also be another file to forget, and nothing needs it
today.

## `release.yml`: no publish job, one comment

Packagist has no publish step. It never receives an artifact: it reads the
repository at the tag. That removes an entire class of risk (no token, no
OIDC, no poisoned-cache-becomes-artifact hazard) and one class of guarantee
(there is no provenance attestation for a Composer package — the git tag is
the whole chain of custody).

Add one line to the header comment block, next to the Swift line:

```
#   Packagist — nothing to publish; Packagist reads php/composer.json from
#               the tag itself, via the Packagist GitHub App.
```

**Never rename `release.yml`.** It is already the match key npm's trusted
publisher uses; that has nothing to do with PHP, but it is the file this note
lives in.

## The packaging decision the owner still has to make

This is the one genuinely repo-wide question the PHP port raises, and it is
**not settled by this branch**.

**Packagist reads `composer.json` from the repository root and nowhere else.**
There is no subdirectory field, no monorepo path support, no equivalent of
npm's `repository.directory`. This port ships its manifest at `php/composer.json`,
which is correct for a monorepo and for local development, and which
Packagist cannot see.

Three ways out:

**Option A — move (or duplicate) the manifest to the repository root.**
A root `composer.json` autoloading `EminDeniz99\ApplePurchaseReceiptVerifier\`
from `php/src/`, with `.gitattributes` `export-ignore` lines trimming the
other ports out of the published archive. The precedent exists: SwiftPM
already forces `Package.swift` to the root and the repo accepts that. Costs a
root `vendor/` in `.gitignore` and a `.gitattributes` whose `export-ignore`
lines silently decide what every PHP consumer receives — a mistake there ships
a package with no `php/certs/`.

**A caveat the plan flagged and this branch did not resolve:** whether GitHub's
zipball (which is what Composer downloads) honours `export-ignore` was
asserted from documentation, not reproduced. Verify it with a real
`git archive` before relying on it. If it does not hold, the fallback is
shipping the whole repository in the package — about 1 MB, ugly, harmless.

**Option B — a read-only mirror repository**, force-pushed from `php/` on every
tag, with Packagist watching the mirror. Gives PHP users a clean standalone
repository; costs a second repository to secure, a write credential in this
repository's secrets (which the current read-only-default-token posture
deliberately avoids), a tag-ordering hazard, and permanent drift risk.

**Option C — do not publish to Packagist.** Consumers would vendor the source.
This makes PHP a second-class member of a project whose whole premise is one
library across N registries.

**Recommendation: A**, revisited only if `export-ignore` turns out not to hold.

## Bootstrap (one-time, owner-only)

1. Land the port and whichever manifest layout Option A/B settles on.
   `composer validate --strict` runs in CI from the first commit.
2. The owner submits the repository at <https://packagist.org/packages/submit>.
   Packagist registers `emindeniz99/apple-purchase-receipt-verifier`.
   **This cannot be automated** — it needs the owner's Packagist account, the
   same shape as the first npm publish and the first Maven Central deploy.
3. The owner installs the **Packagist.org GitHub App** on the repository. Prefer
   the App over the legacy service hook: it stores no secret in this repository
   at all.
4. Packagist then imports every existing tag and every future one within
   seconds of the push. There is no OIDC to configure and no token to rotate.

## `post-publish-smoke.yml`: add a job, and it is the important one

It is the only check that tests what a consumer actually receives — the same
gap that once shipped two empty npm releases. Run it on the **floor**, 8.1,
because that is the leg most likely to break on a published artifact and the
claim least exercised anywhere else.

```yaml
  packagist:
    name: composer — install the published package and verify a receipt
    needs: resolve
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: shivammathur/setup-php@<SHA> # v2.x — same pin as ci.yml
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

The smoke script must, at minimum, load the bundled roots and verify a genuine
Apple-signed receipt — that is what catches a package that installed but
shipped no `php/certs/`, which is exactly the failure Option A's
`export-ignore` lines can cause.

## Release budget

Packagist has no release quota, so PHP adds nothing to the Maven Central
seven-releases-per-calendar-month constraint. It also means a PHP-only fix
still costs a Maven Central release, since one tag publishes everything. No
change to the existing rule — just worth stating so nobody assumes PHP
releases are free of it.
