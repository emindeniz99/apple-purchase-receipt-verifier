# Releasing the Ruby port

What `release.yml`, `release-please-config.json` and the RubyGems side need.
Nothing here has been applied — the shared index files are wired by whoever
lands this port, one port at a time.

## release-please

`release-please-config.json` gains one extra file:

```json
{ "type": "generic", "path": "ruby/lib/apple_purchase_receipt_verifier/version.rb" }
```

paired with the annotation already present in that file:

```ruby
VERSION = "0.3.0" # x-release-please-version
```

That is the only place the version lives; the gemspec reads the constant. The
repository's "one version, N files" invariant in `CLAUDE.md` goes up by one.

## Registry

**RubyGems.org, trusted publishing (OIDC). No API token anywhere.**

RubyGems supports **pending trusted publishers** — a publisher configured
against a gem name before the gem exists. That is strictly better than the npm
bootstrap this repository already lives with: the very first Ruby publish can
be fully automated, with no manual laptop `gem push`.

### Owner bootstrap, once, before the first tag after this port merges

1. rubygems.org → profile → **Pending trusted publishers** → Create:
   - Gem name: `apple-purchase-receipt-verifier`
   - Repository owner: `emindeniz99`
   - Repository name: `apple-purchase-receipt-verifier`
   - Workflow filename: **`release.yml`**
   - Environment: `rubygems`
2. Create the GitHub environment `rubygems`, with no secrets. Its only job is
   to constrain who can trigger a publish, the way `pypi` already does.
3. After the first successful publish, confirm on the gem's "Trusted
   publishers" page that the pending publisher has become a normal one, and
   that `gem owner apple-purchase-receipt-verifier` shows the account.
4. Then require MFA on the gem: `gem owner --otp <code> …`. RubyGems gates
   owner-side operations on 2FA per operation, so an agent can prepare the
   command but the **owner must run it**. Plan the handoff rather than
   retrying.

> **`release.yml` is now the match key for a third registry.** npm and PyPI
> already key their trusted publishers to that filename; RubyGems makes three.
> Renaming the file breaks all three silently. That belongs in `CLAUDE.md`'s
> invariant list.

## The publish job

Add to `.github/workflows/release.yml`. Deliberately **not**
`rubygems/release-gem@v1`: that action runs `bundle exec rake release`, which
builds, **creates and pushes a git tag**, and pushes the gem. release-please
has already made the tag, so a second tag push would conflict. Compose the
primitives instead, keeping this repository's version-gate-and-skip pattern.

Action pin, resolved with `git ls-remote` on 2026-09-04:
`rubygems/configure-rubygems-credentials@dc5a8d8553e6ee01fc26761a49e99e733d17954a # v2.1.0`.

```yaml
  publish-rubygems:
    name: publish ruby to RubyGems.org
    runs-on: ubuntu-latest
    needs: ci-passed
    timeout-minutes: 20
    environment: rubygems
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: ruby/setup-ruby@95ef2b042f9d7a56d8268cba8559e2842e2ad01b # v1.321.0
        with:
          ruby-version: "3.4"
          # Publish jobs never restore a cache: a poisoned cache would become
          # the published artifact.
          bundler-cache: false
      - name: Skip if this version is already on RubyGems.org
        id: gate
        run: |
          set -euo pipefail
          VERSION=$(cat version.txt)
          if curl -fsSL "https://rubygems.org/api/v2/rubygems/apple-purchase-receipt-verifier/versions/$VERSION.json" >/dev/null 2>&1; then
            echo "RubyGems already has $VERSION — skipping publish."
            echo "publish=false" >> "$GITHUB_OUTPUT"
          else
            echo "publish=true" >> "$GITHUB_OUTPUT"
          fi
      - name: Build the gem
        if: steps.gate.outputs.publish == 'true'
        working-directory: ruby
        run: gem build apple-purchase-receipt-verifier.gemspec
      - name: Refuse to publish a gem missing its entry point or its roots
        if: steps.gate.outputs.publish == 'true'
        working-directory: ruby
        run: |
          set -euo pipefail
          ruby -rrubygems/package -e '
            files = Gem::Package.new(Dir["apple-purchase-receipt-verifier-*.gem"].first).spec.files
            want  = ["lib/apple_purchase_receipt_verifier.rb",
                     "lib/apple-purchase-receipt-verifier.rb",
                     "certs/AppleIncRootCertificate.cer",
                     "certs/AppleRootCA-G2.cer",
                     "certs/AppleRootCA-G3.cer"]
            missing = want - files
            abort("refusing to publish: tarball is missing #{missing.join(", ")}") unless missing.empty?
            puts "tarball carries #{files.size} files, entry points and roots included"'
      - uses: rubygems/configure-rubygems-credentials@dc5a8d8553e6ee01fc26761a49e99e733d17954a # v2.1.0
        if: steps.gate.outputs.publish == 'true'
      - name: gem push
        if: steps.gate.outputs.publish == 'true'
        working-directory: ruby
        run: gem push apple-purchase-receipt-verifier-*.gem
```

The tarball guard is the direct descendant of the npm lesson already recorded
in this repository's `release.yml` ("0.1.1 and 0.2.0 shipped with no JavaScript
at all"). The Ruby shape of that failure is `spec.files` — a `Dir[]` glob —
losing `certs/`, which ships a gem that loads fine and then raises the moment
anyone asks for a trust anchor. `test/packaging_test.rb` asserts the same list
on every CI run, so the guard here is the second of two.

## post-publish-smoke.yml

Add a `rubygems` job matching the npm/PyPI/Maven ones: poll
`https://rubygems.org/api/v2/rubygems/apple-purchase-receipt-verifier/versions/$VERSION.json`
until it resolves, then

```sh
GEM_HOME="$RUNNER_TEMP/gems" gem install --no-document \
  apple-purchase-receipt-verifier -v "$VERSION"
GEM_HOME="$RUNNER_TEMP/gems" ruby ruby/script/consumer_smoke.rb fixtures
```

`ruby/script/consumer_smoke.rb` is the same script the packaging test runs. It
requires the gem by both the underscored and the dashed name, asserts three
bundled roots, verifies the genuine 187-purchase legacy receipt and drives the
endpoint — all from an installed gem, outside the checkout.

## Release budget

RubyGems has no per-month publish cap, so this port adds no pressure of its
own. Maven Central's seven-per-calendar-month cap still governs when a release
PR may be merged, and a Ruby-only fix is still a whole-repository release.
Nothing about that rule changes.

## Open questions for the owner

1. **Reserve the underscored gem name?** `apple_purchase_receipt_verifier` is
   free today. RubyGems rejects names that differ from an existing gem only in
   dashes, underscores or case, so publishing the dashed name may make the
   underscored one unclaimable — which is desirable, but worth confirming at
   bootstrap rather than assuming. The recommendation is not to publish an
   empty stub gem for it.
2. **RBS only, or also a generated `.rbi`?** This port ships RBS. Sorbet users
   can consume it through `tapioca`; a hand-maintained `.rbi` would be a second
   source of truth. `ROADMAP.md` is the place for it if the answer is yes.
