# frozen_string_literal: true

# The StoreKit 2 path: compact-JWS split, strict base64url, JSON header and
# payload, x5c certificates, chain and ES256 signature, through
# Verifier#verify_signed_data.
#
# Same invariants as the Go port's FuzzVerifySignedData: nothing escapes,
# and a JWS that verify_signed_data accepts under the fixture root must be
# refused under Apple's roots, or the anchors are not what decided it.

require "ruzzy"
require_relative "../support"

APRV = FuzzSupport::APRV

FIXTURE = APRV::Verifier.create(
  APRV::Config.new(roots: [FuzzSupport.fixture_certificate("generated/jws-root.der")])
)
UNRELATED = APRV::Verifier.create(APRV::Config.new(roots: APRV::Config.defaults.roots))

TEST_ONE_INPUT = lambda do |data|
  # verify_signed_data never raises: a VerificationResult carries the
  # verdict, so `allowed` is NoError (nothing may escape) and the outcome is
  # read off `result.verified?` instead of a rescued/not-rescued split. 0.7
  # has one JWS entry point, not three (no bundle id, no accepted-
  # environment set, no app Apple id claim checked); the caller reads those
  # off the returned payload instead.
  _, result = FuzzSupport.call("#verify_signed_data", FuzzSupport::NoError) { FIXTURE.verify_signed_data(data) }
  next nil unless result.verified?

  _, again = FuzzSupport.call("#verify_signed_data (Apple roots)", FuzzSupport::NoError) do
    UNRELATED.verify_signed_data(data)
  end
  if again.verified?
    FuzzSupport.violated("this input verifies against Apple's roots too, " \
                         "so the anchors are not being enforced")
  end
  nil
end

Ruzzy.fuzz(TEST_ONE_INPUT)
