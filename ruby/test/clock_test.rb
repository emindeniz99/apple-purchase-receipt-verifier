# frozen_string_literal: true

require_relative "helper"
require_relative "test_pki"

# The clock seam and its boundaries. 0.7 reverses 0.6 here (docs/design/
# 0.7-api.md): the config clock is now read in TWO places — the
# chain-validity instant when a receipt's first attribute 12, or a JWS's
# signedDate, is missing or unreadable, and the endpoint's request_date
# triple — where 0.6 always used the system clock for the chain fallback and
# an injected clock could not move it.
class ClockTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier

  SIGNED_AT = 1_722_945_600_000 # 2024-08-06T12:00:00Z

  def setup
    @pki = TestPki.jws_pki
    @jws = TestPki.sign_jws(@pki, TestPki.default_claims)
  end

  def verifier(clock: nil, roots: [@pki.root])
    APRV::Verifier.create(APRV::Config.new(roots: roots, clock: clock))
  end

  def test_a_payload_is_never_rejected_for_its_age
    result = verifier.verify_signed_data(@jws)
    assert_predicate result, :verified?
    assert_equal SIGNED_AT, JSON.parse(result.payload.json)["signedDate"]
  end

  def test_a_dateless_payload_under_a_live_chain_verifies_at_the_default_clock
    jws = TestPki.sign_jws(@pki, TestPki.default_claims.except("signedDate"))
    result = verifier.verify_signed_data(jws)
    assert_predicate result, :verified?
    refute JSON.parse(result.payload.json).key?("signedDate")
  end

  def test_a_dateless_payload_under_an_expired_chain_is_judged_at_the_configured_clock
    expired = TestPki.jws_pki(not_before: Time.utc(2019, 1, 1), not_after: Time.utc(2019, 12, 31))
    jws = TestPki.sign_jws(expired, TestPki.default_claims.except("signedDate"))

    inside = verifier(clock: -> { Time.utc(2019, 6, 1).to_i * 1000 }, roots: [expired.root])
             .verify_signed_data(jws)
    assert_predicate inside, :verified?,
                     "expected verification inside the chain's window at the configured clock"

    # No clock given: falls back to the real system clock, which is well
    # outside this deliberately-expired test chain.
    outside = verifier(roots: [expired.root]).verify_signed_data(jws)
    refute_predicate outside, :verified?
    assert_equal :INVALID_CERTIFICATE, outside.failure.reason
  end

  def test_a_dateless_receipt_is_judged_at_the_configured_clock
    receipt = TestPki.receipt_pki(not_before: Time.utc(2019, 1, 1), not_after: Time.utc(2019, 12, 31))
    payload = TestPki.default_payload(creation_date: nil)
    der = TestPki.sign_receipt(receipt, payload)
    base64 = [der].pack("m0")

    inside = verifier(clock: -> { Time.utc(2019, 6, 1).to_i * 1000 }, roots: [receipt.root])
             .verify_receipt(base64)
    assert_predicate inside, :verified?,
                     "expected verification inside the chain's window at the configured clock"

    outside = verifier(clock: -> { Time.utc(2030, 1, 1).to_i * 1000 }, roots: [receipt.root])
              .verify_receipt(base64)
    refute_predicate outside, :verified?
    assert_equal :INVALID_CERTIFICATE, outside.failure.reason
  end

  def test_an_omitted_clock_reads_the_real_system_clock
    v = verifier(roots: [TestSupport.fixture_certificate("receipt-root")])
    before = (Time.now.utc.to_r * 1000).to_i
    body = JSON.generate({ "receipt-data" => [TestSupport.fixture_bytes("receipt")].pack("m0") })
    response = v.verify_receipt_endpoint(APRV::Environment::SANDBOX, body)
    after = (Time.now.utc.to_r * 1000).to_i
    rendered = JSON.parse(response)["receipt"]["request_date_ms"].to_i
    assert_operator rendered, :>=, before - 1000
    assert_operator rendered, :<=, after + 1000
  end

  def test_a_clock_must_respond_to_call
    assert_raises(ArgumentError) { APRV::Config.new(clock: 42) }
  end

  def test_the_clock_is_read_at_most_once_per_call
    reads = 0
    clock = lambda do
      reads += 1
      SIGNED_AT
    end
    receipt = TestPki.receipt_pki
    der = TestPki.sign_receipt(receipt, TestPki.default_payload(creation_date: nil))
    v = verifier(clock: clock, roots: [receipt.root])
    result = v.verify_receipt_endpoint(APRV::Environment::SANDBOX,
                                       JSON.generate({ "receipt-data" => [der].pack("m0") }))
    assert_equal 0, JSON.parse(result)["status"]
    # Read once for the dateless receipt's chain instant, and that SAME
    # value reused for request_date: never twice.
    assert_equal 1, reads
  end

  def test_a_clock_that_raises_is_internal_error_never_a_verdict_about_the_input
    receipt = TestPki.receipt_pki
    der = TestPki.sign_receipt(receipt, TestPki.default_payload(creation_date: nil))
    v = verifier(clock: -> { raise "boom" }, roots: [receipt.root])
    result = v.verify_receipt([der].pack("m0"))
    refute_predicate result, :verified?
    assert_equal :INTERNAL_ERROR, result.failure.reason
  end

  def test_a_clock_that_does_not_return_an_integer_is_internal_error
    receipt = TestPki.receipt_pki
    der = TestPki.sign_receipt(receipt, TestPki.default_payload(creation_date: nil))
    v = verifier(clock: -> { Time.utc(2024, 1, 1) }, roots: [receipt.root])
    result = v.verify_receipt([der].pack("m0"))
    refute_predicate result, :verified?
    assert_equal :INTERNAL_ERROR, result.failure.reason
  end

  def test_a_clock_that_raises_answers_endpoint_status_21009
    v = verifier(clock: -> { raise "boom" }, roots: [TestSupport.fixture_certificate("receipt-root")])
    body = JSON.generate({ "receipt-data" => [TestSupport.fixture_bytes("receipt")].pack("m0") })
    response = v.verify_receipt_endpoint(APRV::Environment::SANDBOX, body)
    assert_equal 21_009, JSON.parse(response)["status"]
  end

  def test_the_endpoint_clock_drives_request_date_and_the_chain_fallback_alike
    receipt = TestSupport.fixture_bytes("receipt")
    roots = [TestSupport.fixture_certificate("receipt-root")]
    body = JSON.generate({ "receipt-data" => [receipt].pack("m0") })

    early = JSON.parse(verifier(clock: -> { Time.utc(2019, 1, 1).to_i * 1000 }, roots: roots)
                        .verify_receipt_endpoint(APRV::Environment::SANDBOX, body))
    late = JSON.parse(verifier(clock: -> { Time.utc(2030, 1, 1).to_i * 1000 }, roots: roots)
                       .verify_receipt_endpoint(APRV::Environment::SANDBOX, body))

    assert_equal 0, early["status"]
    assert_equal 0, late["status"]
    refute_equal early["receipt"]["request_date_ms"], late["receipt"]["request_date_ms"]
    # The receipt carries its own creation date, so the chain fallback is
    # never reached and the clock only moves request_date.
    assert_equal early["receipt"]["receipt_creation_date_ms"], late["receipt"]["receipt_creation_date_ms"]
  end
end
