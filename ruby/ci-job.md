# CI jobs for the Ruby port

Add these to `.github/workflows/ci.yml`, alongside the existing `java`,
`node`, `python` and `swift` jobs. They follow the conventions already in that
file: every action pinned to a full commit SHA with the tag in a comment,
`persist-credentials: false` on every checkout, `timeout-minutes` on every job,
and the repository-level `permissions: contents: read` inherited from the top
of the workflow.

Action pins, resolved with `git ls-remote` on 2026-09-04:

| Action | SHA | Tag |
|---|---|---|
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1` | v7.0.1 (already used repo-wide) |
| `ruby/setup-ruby` | `95ef2b042f9d7a56d8268cba8559e2842e2ad01b` | v1.321.0 |

Ruby 3.1.7, 3.2.11, 3.3.12, 3.4.10 and 4.0.6 all exist on
`cache.ruby-lang.org`, so the matrix below is installable as written.

## `ruby` — the suite on every line the gemspec admits

```yaml
  ruby:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    strategy:
      fail-fast: false
      matrix:
        # Every supported line (endoflife.date/ruby: 4.0, 3.4, 3.3) plus 3.2
        # and 3.1. Both are EOL upstream, but 3.1 is the gemspec's
        # required_ruby_version floor and Debian 12's system Ruby, so it stays
        # tested while it is claimed — the java-runtime-8 / python-3.9 rule.
        ruby: ["3.1", "3.2", "3.3", "3.4", "4.0"]
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: ruby/setup-ruby@95ef2b042f9d7a56d8268cba8559e2842e2ad01b # v1.321.0
        with:
          ruby-version: ${{ matrix.ruby }}
          # Nothing to install: the library has no runtime dependencies and the
          # suite uses only gems that ship with Ruby (minitest, rake). Running
          # without Bundler is also the strongest form of the zero-dependency
          # claim — if anything crept in, this leg is where it fails.
          bundler-cache: false
          working-directory: ruby
      # The OpenSSL a runner links decides whether the genuine SHA-1 legacy
      # receipt chain verifies at all (see README, "One platform caveat").
      # Print it so a red leg on a distro with SHA-1 disabled is diagnosable
      # from the log rather than from a bisect.
      - run: ruby -v && ruby -ropenssl -e 'puts OpenSSL::OPENSSL_LIBRARY_VERSION'
      - run: rake test
        working-directory: ruby
      # The bundled anchors are inlined into roots_data.rb by script/gen_roots.rb.
      # A certs/ change that forgets to regenerate would ship stale trust anchors.
      - run: ruby script/gen_roots.rb && git diff --exit-code lib/apple_purchase_receipt_verifier/roots_data.rb
        working-directory: ruby
      # ruby/certs is a copy of the repository roots; they must not drift.
      - run: diff -r certs ruby/certs
```

## `ruby-gem` — test the artifact the consumer receives

Graduation lessons 1 and 15. The Ruby shape of the two broken npm releases is
`spec.files` losing `certs/`: a gem that installs and requires cleanly, then
raises the first time anyone asks for a trust anchor. `APRV_PACKAGING=1` turns
on the round trip inside `test/packaging_test.rb`, which builds the gem,
installs it into a `GEM_HOME` outside the checkout and verifies a genuine
receipt from a fresh process with no `$LOAD_PATH` help.

```yaml
  ruby-gem:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    strategy:
      fail-fast: false
      matrix:
        ruby: ["3.1", "4.0"]      # the floor and the newest line
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: ruby/setup-ruby@95ef2b042f9d7a56d8268cba8559e2842e2ad01b # v1.321.0
        with:
          ruby-version: ${{ matrix.ruby }}
          bundler-cache: false
          working-directory: ruby
      - run: APRV_PACKAGING=1 rake test TEST=test/packaging_test.rb
        working-directory: ruby
```

## `ruby-macos` — a different libcrypto

macOS links a different OpenSSL than the Linux legs, and the SHA-1 legacy
chain plus `OpenSSL::PKCS7`'s behaviour are exactly the kind of thing that
differs between them. One current-Ruby leg is enough.

```yaml
  ruby-macos:
    runs-on: macos-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: ruby/setup-ruby@95ef2b042f9d7a56d8268cba8559e2842e2ad01b # v1.321.0
        with:
          ruby-version: "3.4"
          bundler-cache: false
          working-directory: ruby
      - run: ruby -ropenssl -e 'puts OpenSSL::OPENSSL_LIBRARY_VERSION'
      - run: rake test
        working-directory: ruby
```

## `ruby-tools` — lint and types on one modern Ruby

Deliberately outside the matrix: RuboCop and Steep raise their own Ruby floors
faster than this library does, and a tool that cannot run on 3.1 must not be
able to fail the 3.1 leg. Their lockfile lives at
`ruby/gemfiles/tools.gemfile.lock` and is the only lockfile the port has.

```yaml
  ruby-tools:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    env:
      BUNDLE_GEMFILE: gemfiles/tools.gemfile
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: ruby/setup-ruby@95ef2b042f9d7a56d8268cba8559e2842e2ad01b # v1.321.0
        with:
          ruby-version: "3.4"
          bundler-cache: true
          working-directory: ruby
      - run: bundle exec rubocop
        working-directory: ruby
      - run: bundle exec rake rbs
        working-directory: ruby
      - run: bundle exec steep check
        working-directory: ruby
```

`gemfiles/tools.gemfile.lock` is not committed yet — it has to be generated on
a machine with network access (`BUNDLE_GEMFILE=gemfiles/tools.gemfile bundle
lock`) and committed before this job can use `bundler-cache: true`. Until then,
drop the cache flag and let Bundler resolve. `bundle exec steep check` has
never been run against this port's `sig/` (Steep could not be installed in the
authoring container); `rbs validate` has, and passes.

## `.github/dependabot.yml`

```yaml
  - package-ecosystem: bundler
    directory: /ruby/gemfiles       # the only Gemfile with dependencies
    schedule:
      interval: weekly
    cooldown:
      default-days: 7
```

`/ruby/gemfiles` is the only directory with a Gemfile that has dependencies.
The root `ruby/Gemfile` exists for local development and pins nothing the
matrix legs install, so it needs no dependabot entry.

No `ignore` rule is needed: the matrix legs install nothing, because the
library has no runtime dependencies and the suite uses gems that ship with
Ruby. If a tool ever has to run on the floor Ruby, it gets an `ignore` rule
with the same rationale-comment shape as the existing `@types/node` and JUnit
ones.

## zizmor

Green by construction: no `pull_request_target`, no event field interpolated
into a `run:` body, no cache in any publish job, `persist-credentials: false`
everywhere, every action pinned to a full SHA.
