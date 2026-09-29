# CI needs of the Ruby gem (the wasmtime host)

For the integrator: lane D owns `.github/`, so nothing here is applied yet.
Every job keeps its current name. Job names below are the ones in
`.github/workflows/ci.yml` today.

The gem now has one runtime dependency, `wasmtime` (>= 48.0.1). Every job
that loads the library needs it, so none of them can run without installing
the bundle any more. `ruby/Gemfile.lock`, `gemfiles/tools.gemfile.lock` and
`gemfiles/fuzz.gemfile.lock` are committed with `wasmtime` in them, prebuilt
platform gems included, so `BUNDLE_FROZEN=true` works on every runner below.
No job needs a Rust toolchain: the prebuilt native gem is picked.

## Jobs

### `ruby` (Ruby 3.3, 3.4, 4.0 on ubuntu-latest)

- `ruby/setup-ruby` with `bundler-cache: true`, `working-directory: ruby`,
  and `BUNDLE_FROZEN: "true"` in the job env. It was `bundler-cache: false`,
  because nothing needed installing.
- Replace the OpenSSL version print with
  `bundle exec ruby -e 'require "wasmtime"; puts Wasmtime::VERSION'`.
- `bundle exec rake test`. This runs all 311 conformance cases and asserts
  every id ran, the facade, wire and ABI tests, and the thread test. It takes
  about a minute, most of it the module compile (once per process) and the
  2,000-call memory test.
- Add a step on the 3.3 leg only: `bundle exec ruby -Ilib bench/threads.rb
  --assert`. It prints verifications per second at 1, 2 and 4 threads and
  fails unless four threads reach twice one thread (checked only when 4 CPUs
  are usable; ubuntu-latest has 4).
- Keep `ruby script/gen_roots.rb && git diff --exit-code
  lib/apple_purchase_receipt_verifier/roots_data.rb` until Phase 7 deletes
  `roots_data.rb`, `ruby/certs` and the generator together.
- **Until the real module lands (G1) the conformance test fails for 221 of the
  311 cases**, because the module in the tree is the migration's stand-in
  (0.6 core). After the integrator overwrites
  `lib/apple_purchase_receipt_verifier/aprv.wasm` and
  `aprv.wasm.sha256` with the release build, the expectation is 0 failures.
  Every other test file passes with either module.

### `ruby-gem` (Ruby 3.3 and 4.0)

- Same `bundler-cache: true` and frozen bundle.
- Keeps `APRV_PACKAGING=1 bundle exec rake test TEST=test/packaging_test.rb`.
  The test builds the gem, installs it into an empty `GEM_HOME` outside the
  checkout (this fetches `wasmtime` from rubygems.org, so the runner needs
  network), asserts that RubyGems installed a platform gem
  (`wasmtime-<version>-x86_64-linux`) and not the source gem, and runs
  `script/consumer_smoke.rb` against the installed gem.
- Set `APRV_SMOKE_STANDIN=1` in the job env until G1 (the stand-in's typed
  payload is 0.6's); remove it afterwards.

### `ruby-macos` (macos-latest, Ruby 3.4)

- Same `bundler-cache: true`, then `bundle exec rake test`. It gets the
  `arm64-darwin` native gem. Print `Wasmtime::VERSION` instead of the OpenSSL
  version. Add `bundle exec ruby -Ilib bench/threads.rb` (no `--assert`, the
  numbers are for the log).

### `ruby-tools` (lint, types)

- No change to the commands: `rubocop`, `rake rbs`, `steep check` all pass
  with the new `sig/`. `gemfiles/tools.gemfile` now lists `wasmtime`, so the
  existing `ruby -Ilib -e 'load "bench/bench.rb"'` step still loads the
  library under that bundle.

### `ruby-fuzz`

- Now four targets, not six (`parse_der` and `parse_cms` went with the readers
  they fuzzed). `./run.sh all 60` needs no change; the comment above the job
  that says six should say four. `gemfiles/fuzz.gemfile` lists `wasmtime`.
- Ran here under ruzzy 0.8.0 with clang 18, 12 to 20 s per target, no finding.

### `smoke-rubygems` and `post-publish-smoke.yml`

- `gem install --local` cannot resolve the `wasmtime` dependency: drop
  `--local` (or install `wasmtime` first). The smoke still installs into a
  scratch `GEM_HOME` outside the checkout.
- `.github/smoke/rubygems-smoke.rb` asserts
  `APRV::Config.defaults.roots.size == 3`. That no longer holds:
  `Config.defaults.roots` is empty, because Apple's three roots are compiled
  into the module. Replace the assertion with a check that `wasmtime` is a
  platform gem, for example
  `abort unless Gem.loaded_specs.fetch("wasmtime").platform != "ruby"`.
  The rest of the smoke (a genuine receipt verifies, a flipped signature bit
  is `INVALID_SIGNATURE`) is unchanged and holds with the real module.

### Other files that mention the gem

- `dependabot.yml`: the `/ruby` bundler entry now also sees `wasmtime`. The
  gem tracks Wasmtime majors, so a dependabot PR that raises its floor changes
  the runtime under the module; treat it like the Python and .NET runtime
  bumps.
- `release-please-config.json`: `ruby/lib/apple_purchase_receipt_verifier/
  version.rb` stays the only Ruby version file. No new version constant.

## The module

`lib/apple_purchase_receipt_verifier/aprv.wasm` and `aprv.wasm.sha256` are
the release build's file and its hash (`sha256sum` format). The `wasm-copies`
job compares the module's hash with the release build's; the gem checks it
against `aprv.wasm.sha256` before it compiles it, so overwrite both together.
The shipped copy in this branch is the round-13 stand-in.
