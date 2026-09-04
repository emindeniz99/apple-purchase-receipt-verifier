# frozen_string_literal: true

require_relative "lib/apple_purchase_receipt_verifier/version"

Gem::Specification.new do |spec|
  spec.name = "apple-purchase-receipt-verifier"
  spec.version = ApplePurchaseReceiptVerifier::VERSION
  spec.authors = ["emindeniz99"]
  spec.license = "MIT"

  spec.summary = "Offline verification of Apple App Store purchase receipts " \
                 "(StoreKit 2 JWS and legacy PKCS#7)"
  spec.description = <<~TEXT
    Verifies Apple App Store purchase receipts on your own servers, with no call
    to Apple: StoreKit 2 / App Store Server JWS payloads and legacy PKCS#7 app
    receipts, against pinned Apple root certificates. Includes a drop-in local
    replacement for the deprecated verifyReceipt endpoint. No runtime
    dependencies, no network access, no operating-system trust store.
  TEXT
  spec.homepage = "https://github.com/emindeniz99/apple-purchase-receipt-verifier"

  spec.metadata = {
    "homepage_uri" => spec.homepage,
    "source_code_uri" => spec.homepage,
    "changelog_uri" => "#{spec.homepage}/blob/main/CHANGELOG.md",
    "bug_tracker_uri" => "#{spec.homepage}/issues",
    "rubygems_mfa_required" => "true"
  }

  # D2, enterprise-reality floors: 3.1 is Debian 12's system Ruby and is
  # tested on every push, exactly as Python 3.9 and Java 8 are.
  spec.required_ruby_version = ">= 3.1.0"

  spec.files = Dir[
    "lib/**/*.rb",
    "sig/**/*.rbs",
    "certs/*.cer",
    "README.md",
    "LICENSE"
  ]
  spec.require_paths = ["lib"]

  # No runtime dependencies. `openssl` and `json` are default gems.
end
