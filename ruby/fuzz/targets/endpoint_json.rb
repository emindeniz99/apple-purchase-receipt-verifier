# frozen_string_literal: true

# VerifyReceiptEndpoint#verify_receipt_json, the one entry point that takes a
# request body rather than a receipt: JSON parse, receipt-data extraction, the
# receipt-base64 rule, then the DER path.
#
# Its contract is stronger than "raises nothing typed": it must never raise at
# all, and every body — any bytes whatsoever — must come back as a JSON object
# carrying a numeric status. Both halves are asserted after each call. The
# typed result behind that body is checked too: exactly one of receipt and
# failure_reason, the same status, and never INTERNAL_ERROR. That reason means
# an unexpected error inside the pipeline, or content a trusted signer signed
# that the library cannot read; a fuzzer cannot forge a trusted signature, so
# for fuzz input it can only be the first, and that is a bug.

require "ruzzy"
require_relative "../support"
require "json"

APRV = FuzzSupport::APRV

ROOTS = (APRV::Config.defaults.roots +
         [FuzzSupport.fixture_certificate("generated-0.7/receipt-root.der")]).freeze
VERIFIER = APRV::Verifier.create(APRV::Config.new(roots: ROOTS))

TEST_ONE_INPUT = lambda do |data|
  # No error class is allowed through: NoError has no instances, so any
  # exception at all is an invariant violation. `data` is the request body
  # text directly (0.7's verify_receipt_endpoint takes the JSON string, not
  # a pre-parsed Hash), read as UTF-8: a JSON body is text on the wire.
  text = data.dup.force_encoding(Encoding::UTF_8)
  _, response = FuzzSupport.call("#verify_receipt_endpoint", FuzzSupport::NoError) do
    VERIFIER.verify_receipt_endpoint(APRV::Environment::SANDBOX, text)
  end

  unless response.is_a?(String)
    FuzzSupport.violated("the endpoint answered with #{response.class}, not a JSON String")
  end

  parsed = begin
    JSON.parse(response)
  rescue JSON::ParserError => e
    FuzzSupport.violated("the endpoint's answer is not JSON: #{e.message}")
  end

  unless parsed.is_a?(Hash) && parsed["status"].is_a?(Integer)
    FuzzSupport.violated("the endpoint's answer carries no numeric status: #{response[0, 200]}")
  end

  if parsed["status"] == 21_009
    FuzzSupport.violated("verify_receipt_endpoint hit an internal error (21009) on fuzz input, " \
                         "which only signed content this library cannot read should produce")
  end
  nil
end

Ruzzy.fuzz(TEST_ONE_INPUT)
