#!/bin/sh
# Spike only (2026-09-26). Builds the facade gem with the ABI v1 module
# inside, installs it into an EMPTY GEM_HOME (wasmtime comes from
# rubygems.org; RubyGems picks the prebuilt native gem for this platform),
# and runs a smoke test from an empty directory.
set -eu
. "$(dirname "$0")/env.sh"
rm -rf "$S/gem" "$S/consumer-gems" "$S/consumer"
cp -r "$RW/gem" "$S/gem"
cp "$MOD" "$S/gem/lib/aprv_wasm/aprv.wasm"
(cd "$S/gem" && gem build --quiet aprv_wasm_spike.gemspec) > "$S/gem-build.log" 2>&1
GEMFILE=$(ls "$S"/gem/*.gem)
echo "built: $(basename "$GEMFILE") $(wc -c < "$GEMFILE") bytes"
gem install --no-document --clear-sources --source https://rubygems.org "$GEMFILE" > "$S/gem-install.log" 2>&1
echo "installed into an empty GEM_HOME: $(gem list --local | grep -v default | tr '\n' ' ')"
echo "wasmtime platform gem: $(ls "$GEM_HOME/gems" | grep '^wasmtime-')"
mkdir -p "$S/consumer"
G5=$(python3 -c "import json,base64; [print(base64.b64decode(c['input']).decode()) for c in map(json.loads, open('$CALLS/cases.jsonl')) if c['id']=='receipt/verify-genuine-sandbox-g5-against-apple-roots']")
echo "consumer run (ruby $(ruby -e 'print RUBY_VERSION')): $(cd "$S/consumer" && ruby -e 'require "aprv_wasm"; r = AprvWasm::Verifier.new.verify_receipt(ARGV[0]); print({verified: r["verified"], bundleId: r["payload"]["bundleId"]}.inspect)' "$G5")"
