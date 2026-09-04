#!/usr/bin/env ruby
# frozen_string_literal: true

# The consumer smoke test: run against an INSTALLED gem, outside the source
# tree, with no $LOAD_PATH help. It is the only check that catches `certs/`
# falling out of `spec.files` — a gem that loads fine and then raises the
# moment someone asks for a trust anchor.
#
#   gem build apple-purchase-receipt-verifier.gemspec
#   GEM_HOME=/tmp/consumer gem install --no-document apple-purchase-receipt-verifier-*.gem
#   GEM_HOME=/tmp/consumer ruby ruby/script/consumer_smoke.rb path/to/fixtures

require "apple_purchase_receipt_verifier"
require "apple-purchase-receipt-verifier"

fixtures = ARGV[0] || File.expand_path("../../fixtures", __dir__)

roots = ApplePurchaseReceiptVerifier.apple_receipt_roots
abort "expected three bundled Apple roots, got #{roots.size}" unless roots.size == 3

receipt_path = File.join(fixtures, "public-receipts", "receipt-sandbox-legacy.b64")
abort "fixture not found: #{receipt_path}" unless File.file?(receipt_path)

verifier = ApplePurchaseReceiptVerifier::ReceiptVerifier.new(
  trusted_roots: roots, bundle_id: "com.nutcall.alert"
)
receipt = verifier.verify_base64(File.read(receipt_path))
unless receipt.in_app_purchases.size == 187
  abort "expected 187 in-app purchases, got #{receipt.in_app_purchases.size}"
end

endpoint = ApplePurchaseReceiptVerifier::VerifyReceiptEndpoint.new(
  trusted_roots: roots, environment: ApplePurchaseReceiptVerifier::Environment::SANDBOX
)
response = endpoint.verify_receipt({ "receipt-data" => File.read(receipt_path).gsub(/\s+/, "") })
abort "endpoint answered #{response["status"]}" unless response["status"].zero?

puts "ok: apple-purchase-receipt-verifier #{ApplePurchaseReceiptVerifier::VERSION} " \
     "verified a genuine receipt from an installed gem"
