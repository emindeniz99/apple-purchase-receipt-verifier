# frozen_string_literal: true

# The StoreKit 2 path: compact-JWS split, strict base64url, JSON header and
# payload, x5c certificates, chain, ES256 signature, then the claim checks of
# the three public entry points.
#
# Same invariants as the Go port's FuzzVerifyTransaction: nothing escapes but
# a VerificationError, and a JWS that verify_raw accepts under the fixture
# root must be refused under Apple's roots, or the anchors are not what
# decided it.

require "ruzzy"
require_relative "../support"

APRV = FuzzSupport::APRV

FIXTURE = APRV::JwsVerifier.new(
  trusted_roots: [FuzzSupport.fixture_certificate("generated/jws-root.der")],
  bundle_id: "com.example.app",
  accepted_environments: [APRV::Environment::SANDBOX]
)
UNRELATED = APRV::JwsVerifier.new(
  trusted_roots: APRV.apple_jws_roots,
  bundle_id: "com.example.app",
  accepted_environments: [APRV::Environment::SANDBOX]
)

TEST_ONE_INPUT = lambda do |data|
  FuzzSupport.call("#verify_transaction", APRV::VerificationError) { FIXTURE.verify_transaction(data) }
  FuzzSupport.call("#verify_app_transaction", APRV::VerificationError) do
    FIXTURE.verify_app_transaction(data)
  end
  raw, = FuzzSupport.call("#verify_raw", APRV::VerificationError) { FIXTURE.verify_raw(data) }
  next nil unless raw == :accepted

  again, = FuzzSupport.call("#verify_raw (Apple roots)", APRV::VerificationError) do
    UNRELATED.verify_raw(data)
  end
  if again == :accepted
    FuzzSupport.violated("this input verifies against Apple's roots too, " \
                         "so the anchors are not being enforced")
  end
  nil
end

Ruzzy.fuzz(TEST_ONE_INPUT)
