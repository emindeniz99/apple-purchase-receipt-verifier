#!/usr/bin/env ruby
# frozen_string_literal: true

# Smoke-tests the gem as published to RubyGems.org, required by name from a
# directory that is not the repository and with no $LOAD_PATH help:
#
#   GEM_HOME=/tmp/gems gem install --no-document \
#     apple-purchase-receipt-verifier -v 0.7.0
#   cp <repo>/fixtures/public-receipts/receipt-sandbox-g5.b64 .
#   GEM_HOME=/tmp/gems ruby <repo>/.github/smoke/rubygems-smoke.rb
#
# `ruby/script/consumer_smoke.rb` covers the same ground for a locally built
# gem in the ruby-gem CI job, on the legacy receipt and through the library's
# own verify_receipt_endpoint. This one matches the other smoke programs: same
# fixture, same assertions. Neither calls Apple.

require "apple_purchase_receipt_verifier"
# Both entry points ship; the dashed one is what `gem install` users type.
require "apple-purchase-receipt-verifier"

receipt_b64 = File.read("receipt-sandbox-g5.b64", encoding: "ASCII-8BIT").strip

APRV = ApplePurchaseReceiptVerifier

# Apple's three roots are compiled into aprv.wasm, so the defaults name
# none of their own. What the install can get wrong now is the runtime: the
# wasmtime dependency must arrive as a prebuilt platform gem, never the
# source gem, which would need a Rust toolchain on the consumer's machine.
config = APRV::Config.new
wasmtime = Gem.loaded_specs.fetch("wasmtime")
abort "wasmtime #{wasmtime.version} was installed as the source gem" if wasmtime.platform.to_s == "ruby"
verifier = APRV::Verifier.create(config)

# A real Apple-signed receipt against the real pinned root: exercises the
# packaged certs, the DER reader, the chain build and the signature check.
result = verifier.verify_receipt(receipt_b64)
abort "verification failed: #{result.failure.reason}: #{result.failure.message}" unless result.verified?
receipt = result.payload
unless receipt.receipt_type == "ProductionSandbox"
  abort "receipt_type was #{receipt.receipt_type.inspect}, expected ProductionSandbox"
end
abort "bundle_id was #{receipt.bundle_id.inspect}" unless receipt.bundle_id == "dev.bonzer.weeka.app"

# And the negative direction, so a verifier that accepted everything would fail
# here too: the same receipt with one bit flipped in its signature, the byte
# 128 from the end of the DER (BENCHMARKS.md).
der = receipt_b64.unpack1("m0").b
der.setbyte(-128, der.getbyte(-128) ^ 0x01)
tampered = verifier.verify_receipt([der].pack("m0"))
if tampered.verified? || tampered.failure.reason != APRV::Reason::INVALID_SIGNATURE
  abort "a tampered signature was not rejected as INVALID_SIGNATURE: " \
        "#{tampered.verified? ? "verified" : tampered.failure.reason}"
end

puts "rubygems: published gem verified a genuine Apple receipt " \
     "(#{receipt.bundle_id}, #{receipt.in_app.size} purchases) " \
     "and rejected a tampered signature"
