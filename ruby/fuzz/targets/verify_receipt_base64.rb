# frozen_string_literal: true

# Verifier#verify_receipt — the string a client actually sends, through the
# receipt-base64 rule (canonical standard base64 only: alphabet, padding
# position and length) and then the whole DER path.
#
# Seeded from the receipt-b64 fixtures, the public receipts and the Xcode
# fixtures, so the fuzzer starts from strings that decode rather than from
# noise it would have to grow into base64 by itself.
#
# Ruby has no separate bytes type, so unlike the Rust target this one does not
# skip non-UTF-8 input: those bytes reach the same entry point a caller would
# hand them to, and rejecting them is part of the contract.

require "ruzzy"
require_relative "../support"

APRV = FuzzSupport::APRV

ROOTS = (APRV::Config.defaults.roots +
         [FuzzSupport.fixture_certificate("generated-0.7/receipt-root.der")]).freeze
VERIFIER = APRV::Verifier.create(APRV::Config.new(roots: ROOTS))

TEST_ONE_INPUT = lambda do |data|
  # verify_receipt never raises: a VerificationResult carries the verdict.
  # `allowed` is NoError (nothing may escape) rather than VerificationError.
  FuzzSupport.call("Verifier#verify_receipt", FuzzSupport::NoError) { VERIFIER.verify_receipt(data) }
  nil
end

Ruzzy.fuzz(TEST_ONE_INPUT)
