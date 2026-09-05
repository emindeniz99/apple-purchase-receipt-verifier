# frozen_string_literal: true

# The whole legacy-receipt path on DER bytes: CMS walk, payload parse, chain
# build, signature check.
#
# Three invariants, the ones the Go port's FuzzVerifyReceipt states:
#
#   * nothing escapes uncaught;
#   * a failure is a VerificationError, never a NoMethodError, a TypeError or
#     a SystemStackError;
#   * an accepted receipt was accepted *because of* the anchors, proven by
#     re-running it against an unrelated anchor set and requiring failure.
#
# Without the third a fuzzer can find crashes but never "accepts what it
# should not". The trusted set is the pinned Apple roots plus the generated
# fixture root, so both the shared fixture receipts and the two public Apple
# receipts get past the chain check and the fuzzer can explore what lies
# beyond it; the unrelated set is the fixture *JWS* root.

require "ruzzy"
require_relative "../support"

APRV = FuzzSupport::APRV

TRUSTED = (APRV.apple_receipt_roots +
           [FuzzSupport.fixture_certificate("generated/receipt-root.der")]).freeze
UNRELATED = [FuzzSupport.fixture_certificate("generated/jws-root.der")].freeze

TEST_ONE_INPUT = lambda do |data|
  outcome, receipt = FuzzSupport.call("verify_receipt_core", APRV::VerificationError) do
    APRV.verify_receipt_core(data, trusted_roots: TRUSTED)
  end
  next nil unless outcome == :accepted

  FuzzSupport.violated("verify_receipt_core returned nil for an accepted receipt") if receipt.nil?

  again, = FuzzSupport.call("verify_receipt_core (unrelated anchors)", APRV::VerificationError) do
    APRV.verify_receipt_core(data, trusted_roots: UNRELATED)
  end
  if again == :accepted
    FuzzSupport.violated("this input verifies against an unrelated anchor set too, " \
                         "so the anchors are not being enforced")
  end
  nil
end

Ruzzy.fuzz(TEST_ONE_INPUT)
