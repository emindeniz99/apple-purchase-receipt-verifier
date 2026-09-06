#!/usr/bin/env ruby
# frozen_string_literal: true

# Smoke-tests the gem as published to RubyGems.org, required by name from a
# directory that is not the repository and with no $LOAD_PATH help:
#
#   GEM_HOME=/tmp/gems gem install --no-document \
#     apple-purchase-receipt-verifier -v 0.4.0
#   cp <repo>/fixtures/public-receipts/receipt-sandbox-g5.b64 .
#   GEM_HOME=/tmp/gems ruby <repo>/.github/smoke/rubygems-smoke.rb
#
# `ruby/script/consumer_smoke.rb` covers the same ground for a locally built
# gem in the ruby-gem CI job, but it also calls Apple's verifyReceipt endpoint,
# which a post-publish job must not depend on. This one is offline and matches
# the other four smoke programs: same fixture, same bundle id, same assertions.

require "apple_purchase_receipt_verifier"
# Both entry points ship; the dashed one is what `gem install` users type.
require "apple-purchase-receipt-verifier"

receipt_b64 = File.read("receipt-sandbox-g5.b64", encoding: "ASCII-8BIT").strip

# The Ruby shape of the empty-tarball incident is `certs/` falling out of
# spec.files: the gem loads, and then has no trust anchors.
roots = ApplePurchaseReceiptVerifier.apple_receipt_roots
abort "expected three bundled Apple roots, got #{roots.size}" unless roots.size == 3

# A real Apple-signed receipt against the real pinned root: exercises the
# packaged certs, the DER reader, the chain build and the signature check.
receipt = ApplePurchaseReceiptVerifier::ReceiptVerifier
          .new(trusted_roots: roots, bundle_id: "dev.bonzer.weeka.app")
          .verify_base64(receipt_b64)
unless receipt.receipt_type == "ProductionSandbox"
  abort "receipt_type was #{receipt.receipt_type.inspect}, expected ProductionSandbox"
end
abort "bundle_id was #{receipt.bundle_id.inspect}" unless receipt.bundle_id == "dev.bonzer.weeka.app"

# And the negative direction, so a verifier that accepted everything would fail
# here too.
begin
  ApplePurchaseReceiptVerifier::ReceiptVerifier
    .new(trusted_roots: roots, bundle_id: "com.other.app")
    .verify_base64(receipt_b64)
  abort "a receipt for another bundle id was not rejected"
rescue ApplePurchaseReceiptVerifier::VerificationError => e
  unless e.reason == ApplePurchaseReceiptVerifier::Reason::WRONG_BUNDLE_ID
    abort "rejected for #{e.reason}, expected WRONG_BUNDLE_ID"
  end
end

puts "rubygems: published gem verified a genuine Apple receipt " \
     "(#{receipt.bundle_id}, #{receipt.in_app_purchases.size} purchases) " \
     "and rejected a foreign bundle id"
