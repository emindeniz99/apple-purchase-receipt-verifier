# frozen_string_literal: true

require_relative "helper"
require_relative "test_pki"

# The clock seam, and — more importantly — its boundaries. Cross-port rule S6
# says the injected clock is read in exactly two places: the STALE_PAYLOAD
# comparison and the endpoint's request_date triple. Everything else here
# exists to prove it reaches nowhere near a certificate-validity verdict.
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

  def test_an_injected_clock_decides_the_staleness_verdict
    fresh = verifier(max_signed_age_seconds: 60, clock: -> { Time.utc(2024, 8, 6, 12, 0, 30) })
    assert_equal "com.example.app", fresh.verify_transaction(@jws).bundle_id

    stale = verifier(max_signed_age_seconds: 60, clock: -> { Time.utc(2024, 8, 6, 12, 1, 1) })
    error = assert_raises(APRV::VerificationError) { stale.verify_transaction(@jws) }
    assert_equal :STALE_PAYLOAD, error.reason
  end

  def test_age_exactly_equal_to_the_maximum_is_fresh
    exact = verifier(max_signed_age_seconds: 60, clock: -> { Time.utc(2024, 8, 6, 12, 1, 0) })
    assert_equal "com.example.app", exact.verify_transaction(@jws).bundle_id
  end

  def test_an_injected_clock_cannot_authenticate_an_expired_chain
    expired = TestPki.jws_pki(not_before: Time.utc(2019, 1, 1), not_after: Time.utc(2019, 12, 31))
    jws = TestPki.sign_jws(expired, TestPki.default_claims.except("signedDate"))
    subject = APRV::JwsVerifier.new(
      trusted_roots: [expired.root], bundle_id: "com.example.app",
      accepted_environments: [APRV::Environment::SANDBOX],
      max_signed_age_seconds: 60, clock: -> { Time.utc(2019, 6, 1) }
    )
    error = assert_raises(APRV::VerificationError) { subject.verify_transaction(jws) }
    assert_equal :INVALID_CHAIN, error.reason
  end

  def test_an_injected_clock_cannot_expire_a_valid_chain
    jws = TestPki.sign_jws(@pki, TestPki.default_claims.except("signedDate"))
    subject = verifier(max_signed_age_seconds: 60, clock: -> { Time.utc(2099, 1, 1) })
    assert_equal "com.example.app", subject.verify_transaction(jws).bundle_id
  end

  def test_an_injected_clock_is_ignored_when_max_signed_age_is_nil
    subject = verifier(clock: -> { Time.utc(2099, 1, 1) })
    assert_equal "com.example.app", subject.verify_transaction(@jws).bundle_id
  end

  def test_a_payload_without_a_signed_date_is_never_stale
    jws = TestPki.sign_jws(@pki, TestPki.default_claims.except("signedDate"))
    subject = verifier(max_signed_age_seconds: 1, clock: -> { Time.utc(2099, 1, 1) })
    assert_nil subject.verify_transaction(jws).signed_date
  end

  def test_an_omitted_clock_reads_the_real_system_clock
    endpoint = APRV::VerifyReceiptEndpoint.new(
      trusted_roots: [TestSupport.fixture_certificate("receipt-root")],
      environment: APRV::Environment::SANDBOX
    )
    before = (Time.now.utc.to_r * 1000).to_i
    response = endpoint.verify_receipt(
      { "receipt-data" => [TestSupport.fixture_bytes("receipt")].pack("m0") }
    )
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
    assert_raises(ArgumentError) { verifier(clock: Time.utc(2020, 1, 1)) }
    assert_raises(ArgumentError) do
      APRV::VerifyReceiptEndpoint.new(
        trusted_roots: [TestSupport.fixture_certificate("receipt-root")],
        environment: APRV::Environment::SANDBOX, clock: 42
      )
    end
  end

  def test_a_clock_returning_something_other_than_a_time_is_contained
    subject = verifier(max_signed_age_seconds: 60, clock: -> { "not a time" })
    error = assert_raises(APRV::VerificationError) { subject.verify_transaction(@jws) }
    assert_includes APRV::Reason::ALL, error.reason
  end

  def test_the_endpoint_clock_drives_only_the_request_date_triple
    receipt = TestSupport.fixture_bytes("receipt")
    roots = [TestSupport.fixture_certificate("receipt-root")]
    early = APRV::VerifyReceiptEndpoint.new(
      trusted_roots: roots, environment: APRV::Environment::SANDBOX,
      clock: -> { Time.utc(2019, 1, 1) }
    ).verify_receipt({ "receipt-data" => [receipt].pack("m0") })
    late = APRV::VerifyReceiptEndpoint.new(
      trusted_roots: roots, environment: APRV::Environment::SANDBOX,
      clock: -> { Time.utc(2099, 1, 1) }
    ).verify_receipt({ "receipt-data" => [receipt].pack("m0") })

    assert_equal 0, early["status"]
    assert_equal 0, late["status"]
    refute_equal early["receipt"]["request_date_ms"], late["receipt"]["request_date_ms"]
    assert_equal early["receipt"]["receipt_creation_date_ms"],
                 late["receipt"]["receipt_creation_date_ms"]
  end
end
