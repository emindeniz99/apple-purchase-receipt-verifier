#!/usr/bin/env ruby
# frozen_string_literal: true

# The consumer smoke test: run against an INSTALLED gem, outside the source
# tree, with no $LOAD_PATH help. It is the only check that catches `aprv.wasm`
# or its hash falling out of `spec.files`, or the wasmtime dependency failing
# to resolve: a gem that loads fine and then raises the moment someone builds
# a verifier.
#
#   gem build apple-purchase-receipt-verifier.gemspec
#   GEM_HOME=/tmp/consumer gem install --no-document apple-purchase-receipt-verifier-*.gem
#   GEM_HOME=/tmp/consumer ruby ruby/script/consumer_smoke.rb path/to/fixtures
#
# APRV_SMOKE_STANDIN=1 skips the typed-payload check, for a module whose wire
# is not 0.7's (the migration's stand-in module carries the 0.6 core). The
# endpoint check, whose answer is Apple's own format in both, always runs.

require "json"
require "apple_purchase_receipt_verifier"
require "apple-purchase-receipt-verifier"

APRV = ApplePurchaseReceiptVerifier

fixtures = ARGV[0] || File.expand_path("../../fixtures", __dir__)

receipt_path = File.join(fixtures, "public-receipts", "receipt-sandbox-legacy.b64")
abort "fixture not found: #{receipt_path}" unless File.file?(receipt_path)

verifier = APRV::Verifier.create(APRV::Config.defaults)
base64 = File.read(receipt_path)

if ENV["APRV_SMOKE_STANDIN"] == "1"
  puts "skipped: the typed payload (APRV_SMOKE_STANDIN=1)"
else
  result = verifier.verify_receipt(base64)
  unless result.verified?
    abort "receipt did not verify: #{result.failure&.reason} (#{result.failure&.message})"
  end
  unless result.payload.in_app.size == 187
    abort "expected 187 in-app purchases, got #{result.payload.in_app.size}"
  end
end

request = JSON.generate({ "receipt-data" => base64.gsub(/\s+/, "") })
response_json = verifier.verify_receipt_endpoint(APRV::Environment::SANDBOX, request)
status = JSON.parse(response_json)["status"]
abort "endpoint answered #{status}" unless status.zero?

puts "ok: apple-purchase-receipt-verifier #{APRV::VERSION} " \
     "verified a genuine receipt from an installed gem (wasmtime #{Wasmtime::VERSION})"
