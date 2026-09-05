# Releasing the Ruby port

The `ruby/lib/apple_purchase_receipt_verifier/version.rb` entry in
`release-please-config.json` and the `publish-rubygems` job in
`release.yml` are both implemented. Owner bootstrap steps (the pending
trusted publisher, the `rubygems` environment, enabling MFA) live in
[`BOOTSTRAP.md`](../BOOTSTRAP.md) under "RubyGems" — that section is
current and this file no longer repeats it.

## `post-publish-smoke.yml` — not yet added

A `rubygems` job matching the npm/PyPI/Maven ones: poll
`https://rubygems.org/api/v2/rubygems/apple-purchase-receipt-verifier/versions/$VERSION.json`
until it resolves, then

```sh
GEM_HOME="$RUNNER_TEMP/gems" gem install --no-document \
  apple-purchase-receipt-verifier -v "$VERSION"
GEM_HOME="$RUNNER_TEMP/gems" ruby ruby/script/consumer_smoke.rb fixtures
```

`ruby/script/consumer_smoke.rb` is the same script `test/packaging_test.rb`
runs in the `ruby-gem` CI job. It requires the gem by both the underscored
and the dashed name, asserts three bundled roots, verifies the genuine
187-purchase legacy receipt and drives the endpoint — all from an installed
gem, outside the checkout.

## Open question for the owner

**RBS only, or also a generated `.rbi`?** This port ships RBS. Sorbet users
can consume it through `tapioca`; a hand-maintained `.rbi` would be a second
source of truth. `ROADMAP.md` is the place for it if the answer is yes.
