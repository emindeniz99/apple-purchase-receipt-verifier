# frozen_string_literal: true

require_relative "helper"
require_relative "test_pki"

# The clock seam, and its boundaries. The injected clock is read in exactly
# one place: the endpoint's request_date triple. The JWS and receipt verifiers
# take none, and no payload is rejected for its age (PLAN.md D5). Everything
# else here exists to prove the clock reaches nowhere near a
# certificate-validity verdict.
class ClockTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier

  SIGNED_AT = 1_722_945_600_000 # 2024-08-06T12:00:00Z

  def setup
    @pki = TestPki.jws_pki
    @jws = TestPki.sign_jws(@pki, TestPki.default_claims)
  end

  def verifier(**overrides)
    APRV::JwsVerifier.new(trusted_roots: [@pki.root],
                          bundle_id: "com.example.app",
                          accepted_environments: [APRV::Environment::SANDBOX], **overrides)
  end

  def test_a_payload_is_never_rejected_for_its_age
    assert_equal SIGNED_AT, verifier.verify_transaction(@jws).signed_date
  end

  def test_the_jws_verifier_takes_no_clock_and_no_max_age
    assert_raises(ArgumentError) { verifier(clock: -> { Time.utc(2020, 1, 1) }) }
    assert_raises(ArgumentError) { verifier(max_signed_age_seconds: 60) }
  end

  def test_a_dateless_payload_under_an_expired_chain_is_judged_at_now
    expired = TestPki.jws_pki(not_before: Time.utc(2019, 1, 1), not_after: Time.utc(2019, 12, 31))
    jws = TestPki.sign_jws(expired, TestPki.default_claims.except("signedDate"))
    subject = APRV::JwsVerifier.new(
      trusted_roots: [expired.root], bundle_id: "com.example.app",
      accepted_environments: [APRV::Environment::SANDBOX]
    )
    error = assert_raises(APRV::VerificationError) { subject.verify_transaction(jws) }
    assert_equal :INVALID_CHAIN, error.reason
  end

  def test_a_dateless_payload_under_a_live_chain_verifies
    jws = TestPki.sign_jws(@pki, TestPki.default_claims.except("signedDate"))
    assert_nil verifier.verify_transaction(jws).signed_date
  end

  def test_an_omitted_clock_reads_the_real_system_clock
    endpoint = APRV::VerifyReceiptEndpoint.new(
      trusted_roots: [TestSupport.fixture_certificate("receipt-root")],
      environment: APRV::Environment::SANDBOX
    )
    before = (Time.now.utc.to_r * 1000).to_i
    response = endpoint.verify_receipt_result(
      { "receipt-data" => [TestSupport.fixture_bytes("receipt")].pack("m0") }
    ).to_response
    after = (Time.now.utc.to_r * 1000).to_i
    rendered = response["receipt"]["request_date_ms"].to_i
    assert_operator rendered, :>=, before - 1000
    assert_operator rendered, :<=, after + 1000
  end

  # The seam must not be addable by accident: no receipt verdict depends on now.
  def test_receipt_verifier_rejects_a_clock_keyword
    assert_raises(ArgumentError) do
      APRV::ReceiptVerifier.new(
        trusted_roots: [TestSupport.fixture_certificate("receipt-root")],
        bundle_id: "com.example.app", clock: -> { Time.utc(2020, 1, 1) }
      )
    end
  end

  def test_verify_receipt_core_takes_no_clock
    assert_raises(ArgumentError) do
      APRV.verify_receipt_core(TestSupport.fixture_bytes("receipt"),
                               trusted_roots: [TestSupport.fixture_certificate("receipt-root")],
                               clock: -> { Time.utc(2020, 1, 1) })
    end
  end

  def test_a_clock_must_respond_to_call
    assert_raises(ArgumentError) do
      APRV::VerifyReceiptEndpoint.new(
        trusted_roots: [TestSupport.fixture_certificate("receipt-root")],
        environment: APRV::Environment::SANDBOX, clock: 42
      )
    end
  end

  def test_the_endpoint_clock_drives_only_the_request_date_triple
    receipt = TestSupport.fixture_bytes("receipt")
    roots = [TestSupport.fixture_certificate("receipt-root")]
    early = APRV::VerifyReceiptEndpoint.new(
      trusted_roots: roots, environment: APRV::Environment::SANDBOX,
      clock: -> { Time.utc(2019, 1, 1) }
    ).verify_receipt_result({ "receipt-data" => [receipt].pack("m0") }).to_response
    late = APRV::VerifyReceiptEndpoint.new(
      trusted_roots: roots, environment: APRV::Environment::SANDBOX,
      clock: -> { Time.utc(2099, 1, 1) }
    ).verify_receipt_result({ "receipt-data" => [receipt].pack("m0") }).to_response

    assert_equal 0, early["status"]
    assert_equal 0, late["status"]
    refute_equal early["receipt"]["request_date_ms"], late["receipt"]["request_date_ms"]
    assert_equal early["receipt"]["receipt_creation_date_ms"],
                 late["receipt"]["receipt_creation_date_ms"]
  end
end
