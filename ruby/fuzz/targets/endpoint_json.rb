# frozen_string_literal: true

# VerifyReceiptEndpoint#verify_receipt_json, the one entry point that takes a
# request body rather than a receipt: JSON parse, receipt-data extraction, the
# receipt-base64 rule, then the DER path.
#
# Its contract is stronger than "raises nothing typed": it must never raise at
# all, and every body — any bytes whatsoever — must come back as a JSON object
# carrying a numeric status. Both halves are asserted after each call.

require "ruzzy"
require_relative "../support"
require "json"

APRV = FuzzSupport::APRV

ROOTS = (APRV.apple_receipt_roots +
         [FuzzSupport.fixture_certificate("generated/receipt-root.der")]).freeze
ENDPOINT = APRV::VerifyReceiptEndpoint.new(trusted_roots: ROOTS,
                                           environment: APRV::Environment::SANDBOX)

TEST_ONE_INPUT = lambda do |data|
  # No error class is allowed through: NoError has no instances, so any
  # exception at all is an invariant violation.
  _, response = FuzzSupport.call("#verify_receipt_json", FuzzSupport::NoError) do
    ENDPOINT.verify_receipt_json(data)
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
  nil
end

Ruzzy.fuzz(TEST_ONE_INPUT)
