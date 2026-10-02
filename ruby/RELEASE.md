# Releasing the Ruby port

The `ruby/lib/apple_purchase_receipt_verifier/version.rb` entry in
`release-please-config.json` and the `publish-rubygems` job in
`release.yml` are both implemented. Owner bootstrap steps (the pending
trusted publisher, the `rubygems` environment, enabling MFA) live in
[`BOOTSTRAP.md`](../BOOTSTRAP.md) under "RubyGems" — that section is
current and this file no longer repeats it. The first publish goes through
the job, not by hand: a pending publisher authorizes it for a gem that does
not exist yet. Until the bootstrap is done, `publish-rubygems` attempts OIDC,
finds neither credentials nor a gem, and skips with a `::notice::` rather than
failing the tag run.

## `post-publish-smoke.yml` — added

The `rubygems` job installs the exact published version into a scratch
`GEM_HOME` outside the checkout, on the gemspec's 3.3 floor, and runs
`.github/smoke/rubygems-smoke.rb` against
`fixtures/public-receipts/receipt-sandbox-g5.b64`:

```sh
GEM_HOME="$RUNNER_TEMP/rubygems-smoke/gems" gem install --no-document \
  apple-purchase-receipt-verifier -v "$VERSION"
GEM_HOME=... ruby rubygems-smoke.rb
```

It requires the gem by both the underscored and the dashed name, verifies a
genuine Apple-signed receipt (which fails if `aprv.wasm` or its hash fell out
of `spec.files`, the Ruby shape of the empty-tarball incident), and expects
`INVALID_SIGNATURE` for the same receipt with one DER byte flipped in its
signature. Since 0.8 it must also see that RubyGems installed a platform
`wasmtime` gem, and it can no longer assert three roots on `Config.new`,
whose `roots` is empty: Apple's roots are inside the module. `CI-NOTES.md`
lists that change for `.github/smoke/rubygems-smoke.rb`. The install must not
use `--local`, since `wasmtime` comes from RubyGems too.

It is a new program rather than `ruby/script/consumer_smoke.rb`, which this
file used to name, because the other smoke programs all live in
`.github/smoke/` and share one fixture and one pair of assertions.
`consumer_smoke.rb` still runs in the `ruby-gem` CI job against a locally
built gem, on the legacy receipt and through the library's own
`verify_receipt_endpoint`. Neither program calls Apple.

The leg is gated on the `registries` input, so it skips rather than fails while
RubyGems is unbootstrapped (`BOOTSTRAP.md`).

## Open question for the owner

**RBS only, or also a generated `.rbi`?** This port ships RBS. Sorbet users
can consume it through `tapioca`; a hand-maintained `.rbi` would be a second
source of truth. `ROADMAP.md` is the place for it if the answer is yes.
