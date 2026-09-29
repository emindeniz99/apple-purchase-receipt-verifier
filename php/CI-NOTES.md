# CI notes for the PHP package (for the integrator of `.github/`)

What the `php` jobs of MIGRATION.md's CI matrix need now that the package is a
façade over `aprv` (Phase 6). Nothing here is wired: lane F does not edit
`.github/`. The existing PHP jobs live in `.github/workflows/ci.yml`
(`php`, `php-lowest`, `php-static`, `php-mutation`, `php-fuzz`, `php-format`)
and in `benchmark.yml`.

## What every job needs that it did not before

- **The `aprv` binary**, never committed and never in the package. The suite
  finds it through `APRV_BIN` (a path); without it the suite fails loudly.
  In CI the `aprv-server` job's artifact for the runner's target is the
  input: `dist/aprv-x86_64-unknown-linux-musl` on `ubuntu-latest` (the static
  binary runs on any glibc or musl Linux). Download it, `chmod +x`, export
  `APRV_BIN=$PWD/aprv`.
- **PHP extensions:** `json`, `curl`, `posix` (the fake `aprv` of the CLI
  tests raises a signal with `posix_kill`), and `pcntl` for the fuzz job as
  before. **`openssl` is no longer needed** by the package or the suite; leave it
  out of one leg (8.2) to prove it.
- **The binary must carry the release component** (the 0.7 core). The suite
  has no allowance for any other: every shared case must pass through
  both transports. A binary that embeds an older core fails some of them.
- No secrets.

## Job `php` (matrix 8.2, 8.3, 8.4, 8.5)

Working directory `php`:

```sh
composer install --no-scripts --no-progress --no-interaction --prefer-dist
vendor/bin/phpunit --exclude-testsuite conformance   # façade, transports, installer, gates: no network
vendor/bin/phpunit tests/ConformanceCasesTest.php    # the shared cases through the CLI transport
```

**One leg (8.4) also runs the shared cases over HTTP** against a locally started
`aprv serve` (one server per root set, each on a free loopback port):

```sh
vendor/bin/phpunit tests/ConformanceHttpTest.php
```

Both conformance runs take about 45 s each with a loaded runner. The
`InstallerTest` (in the first command) serves the binary named by `APRV_BIN`
from a local `php -S` server and checks that the right hash installs an
owner-only executable, and that a wrong hash, a 404 and an unsupported
platform install nothing. It needs no network and no GitHub.

`php-lowest` runs the same `phpunit` (all suites) after `composer update
--prefer-lowest`. `php-format` is unchanged (`php-cs-fixer fix --dry-run
--diff --allow-risky=yes`; the finder now includes `bin/aprv-install`).

## Corpus through the façade (nightly or per release, with the corpus files)

`tools/rerun.sh "$APRV_BIN" "$G1_DIR"` runs everything in this file's `php` job
and then the corpus (`tools/corpus.php`, both transports, every clock pinned)
against the module's reference rows. Expected: every row identical, except the
rows whose input is over 3,145,728 bytes, which `aprv` refuses first and which
count as answered when the reference is the size refusal; 0 different. The
corpus is scratch data (COMMON.md), so the job waits for wherever lane D puts it.

## Job `php-static`

Unchanged except:

- `vendor/bin/phpstan analyse --no-progress` now also reads `bin/` and
  `tools/update-binaries.php` (already in `phpstan.neon`).
- `composer validate --strict` for both manifests (both now carry `bin` and
  `suggest`; `ext-openssl` is gone from both `require` blocks).
- `node tools/check-php-package.mjs` checks the two manifests agree on `bin`
  and `suggest`, and that the archive carries `php/bin/aprv-install` and
  `php/binaries.json`.
- `node tools/php-consumer-smoke.mjs` needs `APRV_BIN` in its environment. It
  installs the archive into a throwaway project and verifies through the
  default CLI transport.
- The `gen-roots.php` drift guard is deleted in Phase 7 (below).

## Jobs to delete or change

- **`php-mutation`: delete.** `MutationTest` mutated receipts through the
  PHP verifier; with no verifier in PHP the group no longer exists, and
  `phpunit --group mutation` would fail on an empty suite. The module's
  mutation corpus (5,000 mutants) is lane A's.
- **`php-fuzz`:** four targets now (`verify-receipt`, `verify-receipt-base64`,
  `verify-transaction`, `endpoint-json`; the `parse-*` targets went with the
  parsers). Give it `APRV_BIN`. `./run.sh all 60` unchanged; the job's comment
  says "six targets".
- **`benchmark.yml` `php`:** `php bench/bench.php --aprv "$APRV_BIN"
  > ../php-bench.json`; the JSON gained a `transport` field (`cli`, `http`)
  and lost `decodeBase64`. BENCHMARKS.md's PHP column changes accordingly.
- **`one-implementation`:** add `php` to `--enforce` (see `.github/CI-NOTES.md`).
  `tests/NoVerificationLogicTest.php` is the PHP half of the gate: no crypto
  call anywhere in `php/src`, no `ext-openssl` in either manifest, and only
  `Info`, `Text` and `Wire` under `src/Internal`.

## Release: pinning the binaries' hashes

`vendor/bin/aprv-install` checks a download against `php/binaries.json`, and
that file is in the tag's archive (Composer installs the tag's tree), so its
hashes must be committed **before** the tag while the binaries are built by
`release.yml` **at** the tag. The step that closes the gap, per the plan's
handling of the committed Go and Swift copies:

1. On the `release-please--*` branch, after `build-server` has built the
   binaries for the targets (Linux static musl x86_64 and aarch64 are
   reproducible: `tools/reproduce-server.sh`):

   ```sh
   (cd dist && sha256sum aprv-* > SHA256SUMS)
   php php/tools/update-binaries.php --tag "v$VERSION" --sums dist/SHA256SUMS
   git add php/binaries.json && git commit -m "chore(php): pin the aprv binaries of v$VERSION"
   ```

   The tool rewrites `tag` and every listed asset's hash, resets a listed asset
   the sums file lacks to `null` (the installer then says "no binary for this
   platform" and names the server option) and refuses to write when none of
   the assets is present. It never edits a version number by hand:
   release-please owns the tag it is given.
2. A check on the tag (`release.yml`, after `release-assets`): for every
   non-null hash in `php/binaries.json`, the SHA-256 of the published
   `aprv-<target>[.exe]` equals it. A mismatch fails the release before
   Packagist imports the tag.

**Open question for the orchestrator:** macOS and Windows binaries are not
reproducible bit for bit, so a hash pinned from the release branch's build
only holds if `release.yml` publishes those exact files (download the branch
run's artifacts by hash instead of rebuilding). If it rebuilds, leave those
four entries `null` (a platform gets the server option) until it is
reproducible. Linux is the platform the plan measured.

`release-please-config.json` is untouched: `binaries.json` carries no version
string of its own to bump; its `tag` is written by the step above.

## Post-publish smoke (step 6.3)

After Packagist imports the tag (job shape in `php/RELEASE.md`), on PHP 8.2
with `extensions: json, curl`:

```sh
composer require --no-interaction "emindeniz99/apple-purchase-receipt-verifier:$VERSION"
vendor/bin/aprv-install
php verify-smoke.php    # Verifier::create(Config::defaults()) verifies the genuine g5 receipt
```

This is acceptance test 8's PHP leg: `aprv install`, then g5 verifies through
the default transport.

## Phase 7

`php/certs/`, `src/Internal/RootsData.php`, `tools/gen-roots.php` and the
public `AppleRootCerts` class (its `pinnedRoots()` read `RootsData`) are
gone: Apple's three roots live only in the module `aprv` runs.
`Config::defaults()->roots` stays `null`, and an empty list is still refused
at `Verifier::create`. The root `.gitattributes` allowlist no longer names
`php/certs`, and `tools/check-php-package.mjs` no longer requires it,
`AppleRootCerts.php` or `RootsData.php` in the archive.

| Where | Change |
|---|---|
| `ci.yml` `php-static` | delete the drift step (`php php/tools/gen-roots.php && git diff --exit-code php/src/Internal/RootsData.php`) and its comment. |
| `ci.yml` `one-implementation` | nothing for PHP: `php/src` has no allowlist entry and no hit. |
| `.github/smoke/packagist-smoke.php` | nothing: it already verifies through `Config::defaults()`. |

