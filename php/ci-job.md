# CI jobs to add for the PHP port

The orchestrator wires the shared index files. This file holds the exact YAML
to paste into `.github/workflows/ci.yml`, alongside the existing `java`,
`node`, `python` and `swift` jobs, plus the one `.github/dependabot.yml` entry
that goes with it.

Conventions copied from the surrounding file: every action pinned to a full
commit SHA with the tag in a trailing comment, `persist-credentials: false` on
every checkout, `timeout-minutes` on every job, no cache in any job, and no
interpolation of event data into `run:`.

## One SHA is unresolved

`shivammathur/setup-php` is the only new action, and its SHA **could not be
resolved from the container this port was built in** — GitHub API access is
scoped to this repository. Resolve it before merging and replace all four
occurrences of `<SHA>` below:

```sh
gh api repos/shivammathur/setup-php/git/ref/tags/v2 --jq .object.sha
```

Then append the resolved tag as a comment, exactly like the other pins:
`uses: shivammathur/setup-php@<sha> # v2.35.4` (use whatever tag the SHA
actually belongs to, not a guessed one). Do not merge with `<SHA>` in place —
the workflow will not run.

## Jobs

```yaml
  # Every line the composer.json floor admits. 8.1 is the floor and is past
  # its own security-support end; it stays here for exactly as long as the
  # manifest claims it, the same rule as node 20 and python 3.9.
  #
  # The 8.1 leg is not decoration. PHP gained
  # zend.max_allowed_stack_size in 8.3, so on 8.1 an unbounded recursive
  # parser SEGFAULTS rather than raising, and this is the only leg where the
  # DER reader's depth bound is what stands between hostile input and a
  # crashed worker.
  php:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    strategy:
      fail-fast: false
      matrix:
        php: ["8.1", "8.2", "8.3", "8.4", "8.5"]
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: shivammathur/setup-php@<SHA> # v2.x — resolve before merging
        with:
          php-version: ${{ matrix.php }}
          extensions: openssl, json
          coverage: none
          ini-values: memory_limit=256M
      # composer update, not install: no lockfile is committed, because a
      # library spanning PHP 8.1-8.5 cannot express its dev toolchain in one
      # lock (a lock resolved on 8.1 pins PHPUnit 10.5 for every leg; one
      # resolved on 8.5 will not install on 8.1 at all). The php-lowest job
      # below is the substitute for the reproducibility a lock would give.
      - run: composer update --no-progress --no-interaction --prefer-dist
        working-directory: php
      - run: vendor/bin/phpunit
        working-directory: php

  # The floor is a claim about the CONSTRAINTS, not only about the runtime:
  # this leg installs the oldest version of everything the manifest allows,
  # so a change that quietly needs a newer psr/clock or PHPUnit fails here
  # rather than on a consumer's machine.
  php-lowest:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: shivammathur/setup-php@<SHA> # v2.x — resolve before merging
        with:
          php-version: "8.1"
          extensions: openssl, json
          coverage: none
      - run: composer update --no-progress --no-interaction --prefer-lowest --prefer-stable
        working-directory: php
      - run: vendor/bin/phpunit
        working-directory: php

  php-static:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: shivammathur/setup-php@<SHA> # v2.x — resolve before merging
        with:
          php-version: "8.4"
          extensions: openssl, json
          coverage: none
      - run: composer update --no-progress --no-interaction
        working-directory: php
      - run: composer validate --strict
        working-directory: php
      - run: vendor/bin/phpstan analyse --no-progress
        working-directory: php
      # php/certs/ is a copy of the repository-root certs/, and
      # src/Internal/RootsData.php is generated from that copy. A roots change
      # that forgets either step would ship stale trust anchors — the PHP
      # analogue of the node gen-roots.mjs check above.
      - run: diff -r certs php/certs
      - run: php php/tools/gen-roots.php && git diff --exit-code php/src/Internal/RootsData.php

  # The mutation pass: ~1,500 mutated receipts and ~1,000 mutated JWS
  # payloads, each verified through every public entry point. It is its own
  # job because it is the slow one (about 12 s of CPU) and because a failure
  # here means something quite different from a conformance failure.
  php-mutation:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: shivammathur/setup-php@<SHA> # v2.x — resolve before merging
        with:
          php-version: "8.4"
          extensions: openssl, json
          coverage: none
      - run: composer update --no-progress --no-interaction
        working-directory: php
      - run: vendor/bin/phpunit --group mutation
        working-directory: php
```

## `.github/dependabot.yml`

Add one entry to the existing `updates:` list. The manifest is in `php/`, and
no ignore rules are needed: the multi-line PHPUnit constraint already lets each
runtime resolve its own line, so the Java `junit 5.x` / Node `@types/node 20`
ignore-rule pattern has no analogue here.

```yaml
  - package-ecosystem: composer
    directory: /php
    schedule:
      interval: weekly
```

`shivammathur/setup-php` needs no separate entry: the existing
`package-ecosystem: github-actions` entry for `/` covers every action used by
every workflow.

## Notes for whoever wires this up

- **`php-cs-fixer` is deliberately not a CI job.** `php/.php-cs-fixer.dist.php`
  is committed so `composer exec php-cs-fixer` works locally, but the package
  is not in `require-dev` and no job runs it. Adding it is a one-line change if
  the owner wants formatting enforced; leaving it out keeps the dev dependency
  count at one.
- **PHPStan's config is plain.** The banned-function gate the port needs (no
  `openssl_cms_verify`, no `openssl_pkcs7_verify`, no
  `openssl_x509_checkpurpose`, no network call) is NOT a PHPStan rule, because
  PHPStan ships none and the alternative is a second dev dependency. It is a
  real test instead — `tests/PinnedAnchorsTest.php` tokenises every file under
  `src/` and fails on a call to any of them — so it runs on all five matrix
  legs rather than only on the static-analysis one.
- **zizmor stays at zero findings.** These jobs add no `pull_request_target`,
  no expression interpolation into `run:`, no cache, and no write permission.
