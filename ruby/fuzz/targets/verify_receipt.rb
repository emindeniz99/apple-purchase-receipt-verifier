# frozen_string_literal: true

# The whole legacy-receipt path on bytes: the fuzz bytes go in as the base64
# text a client sends, through the wasm module's decode, CMS walk, payload
# parse, chain build and signature check.
#
# Three invariants, the ones the Go port's FuzzVerifyReceipt states:
#
#   * nothing escapes uncaught;
#   * a failure is a value (a VerificationResult), never a raise;
#   * an accepted receipt was accepted *because of* the anchors, proven by
#     re-running it against an unrelated anchor set and requiring failure.
#
# Without the third a fuzzer can find crashes but never "accepts what it
# should not". The trusted set is the pinned Apple roots plus the generated
# fixture root, so both the shared fixture receipts and the two public Apple
# receipts get past the chain check and the fuzzer can explore what lies
# beyond it; the unrelated set is the fixture *JWS* root.
#
# What ruzzy's coverage sees here is the Ruby host code around the module;
# the module's own code is fuzzed by rust/fuzz.

require "ruzzy"
require_relative "../support"

APRV = FuzzSupport::APRV

TRUSTED = APRV::Verifier.create(
  APRV::Config.new(
    roots: FuzzSupport.apple_roots_der + [FuzzSupport.fixture_der("generated-0.7/receipt-root.der")]
  )
)
UNRELATED = APRV::Verifier.create(
  APRV::Config.new(roots: [FuzzSupport.fixture_der("generated/jws-root.der")])
)

TEST_ONE_INPUT = lambda do |data|
  base64 = [data].pack("m0")
  _, result = FuzzSupport.call("#verify_receipt", FuzzSupport::NoError) { TRUSTED.verify_receipt(base64) }
  next nil unless result.verified?

  _, again = FuzzSupport.call("#verify_receipt (unrelated anchors)", FuzzSupport::NoError) do
    UNRELATED.verify_receipt(base64)
  end
  if again.verified?
    FuzzSupport.violated("this input verifies against an unrelated anchor set too, " \
                         "so the anchors are not being enforced")
  end
  nil
end

Ruzzy.fuzz(TEST_ONE_INPUT)
