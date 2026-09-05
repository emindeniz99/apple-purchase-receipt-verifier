# frozen_string_literal: true

# ReceiptVerifier#verify_base64 — the string a client actually sends, through
# the receipt-base64 rule (alphabet, mixed alphabets, padding position and
# length, whitespace stripping) and then the whole DER path.
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

ROOTS = (APRV.apple_receipt_roots +
         [FuzzSupport.fixture_certificate("generated/receipt-root.der")]).freeze
VERIFIER = APRV::ReceiptVerifier.new(trusted_roots: ROOTS, bundle_id: "dev.bonzer.weeka.app")

TEST_ONE_INPUT = lambda do |data|
  FuzzSupport.call("ReceiptVerifier#verify_base64", APRV::VerificationError) do
    VERIFIER.verify_base64(data)
  end
  # #verify is the sniffing entry point: DER or base64, told apart by the
  # first byte. Fuzzing it as well covers the branch verify_base64 skips.
  FuzzSupport.call("ReceiptVerifier#verify", APRV::VerificationError) { VERIFIER.verify(data) }
  nil
end

Ruzzy.fuzz(TEST_ONE_INPUT)
