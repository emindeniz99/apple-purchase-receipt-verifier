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

TRUSTED = (APRV::Config.defaults.roots +
           [FuzzSupport.fixture_certificate("generated-0.7/receipt-root.der")]).freeze
UNRELATED = [FuzzSupport.fixture_certificate("generated/jws-root.der")].freeze

TEST_ONE_INPUT = lambda do |data|
  # 0.7 has no DER entry point (docs/design/0.7-api.md): Receipt.verify takes
  # the base64 text a client sends, so the raw fuzz bytes are encoded first.
  # That still reaches the same CMS/chain/signature machinery this target
  # exists to cover; only the transport encoding changed.
  base64 = [data].pack("m0")
  outcome, receipt = FuzzSupport.call("Receipt.verify", APRV::VerificationError) do
    APRV::Receipt.verify(base64, TRUSTED, APRV::ClockOnce.new(-> { Time.now.to_i * 1000 }))
  end
  next nil unless outcome == :accepted

  FuzzSupport.violated("Receipt.verify returned nil for an accepted receipt") if receipt.nil?

  again, = FuzzSupport.call("Receipt.verify (unrelated anchors)", APRV::VerificationError) do
    APRV::Receipt.verify(base64, UNRELATED, APRV::ClockOnce.new(-> { Time.now.to_i * 1000 }))
  end
  if again == :accepted
    FuzzSupport.violated("this input verifies against an unrelated anchor set too, " \
                         "so the anchors are not being enforced")
  end
  nil
end

Ruzzy.fuzz(TEST_ONE_INPUT)
