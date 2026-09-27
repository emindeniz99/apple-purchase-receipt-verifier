# frozen_string_literal: true

require_relative "helper"
require_relative "test_pki"

# The public surface: the names, the error vocabulary, what misconfiguration
# does, and the thread-safety claim.
class ApiShapeTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier

  def receipt_roots
    [TestSupport.fixture_certificate("receipt-root")]
  end

  def test_the_public_classes_exist
    [APRV::Config, APRV::Config::Builder, APRV::Verifier, APRV::VerificationResult, APRV::Failure,
     APRV::ReceiptPayload, APRV::InAppPurchase, APRV::JsonPayload,
     APRV::VerificationError].each do |klass|
      assert_kind_of Class, klass
    end
  end

  # docs/design/0.7-api.md: one verifier, three methods.
  def test_the_three_entry_points_exist
    %i[verify_receipt verify_signed_data verify_receipt_endpoint].each do |name|
      assert_includes APRV::Verifier.public_instance_methods, name
    end
  end

  # The canonical SCREAMING_SNAKE token is `reason.to_s`, with no mapping table
  # anywhere. This reads the vocabulary out of the shared schema, so a change
  # to the cross-language contract breaks the Ruby port loudly.
  def test_the_reason_vocabulary_equals_the_shared_schema
    schema = TestSupport.cases_schema
    expected = schema["$defs"]["reason"]["enum"]
    assert_equal expected.sort, APRV::Reason::ALL.map(&:to_s).sort
    assert_equal 8, APRV::Reason::ALL.size
    APRV::Reason::ALL.each { |reason| assert_kind_of Symbol, reason }
  end

  # 0.7 has no bundle id, no accepted-environment set: two environments,
  # Apple's own two verifyReceipt URLs, nothing else.
  def test_the_environment_vocabulary_is_production_and_sandbox_only
    assert_equal %w[PRODUCTION SANDBOX], APRV::Environment::ALL.sort
    assert_equal "PRODUCTION", APRV::Environment::PRODUCTION
    assert_equal "SANDBOX", APRV::Environment::SANDBOX
  end

  def test_a_verification_error_carries_its_reason_as_data_and_in_its_message
    error = APRV::VerificationError.new(APRV::Reason::UNTRUSTED_CHAIN, "detail")
    assert_equal :UNTRUSTED_CHAIN, error.reason
    assert_equal "detail", error.message
    assert_kind_of StandardError, error
  end

  # Misconfiguration is a programming error, not a verification verdict: a
  # caller must not be able to catch a typo as though a receipt were forged.
  def test_misconfiguration_raises_argument_error_never_verification_error
    bad_constructions = [
      -> { APRV::Config.new(roots: "x") },
      -> { APRV::Config.new(roots: [42]) },
      -> { APRV::Config.new(clock: "not callable") },
      -> { APRV::Verifier.create("not a config") },
      -> { APRV::Verifier.create(APRV::Config.new(roots: [])) },
      lambda {
        APRV::Verifier.create(APRV::Config.new(roots: receipt_roots))
                      .verify_receipt_endpoint("Sandbox", "{}")
      }
    ]
    bad_constructions.each_with_index do |construction, index|
      error = assert_raises(ArgumentError, "construction #{index}") { construction.call }
      refute_kind_of APRV::VerificationError, error
    end
  end

  # Freshness and any per-call clock override are gone: the clock lives on
  # Config, read at most once per call, never a per-call parameter.
  def test_verify_receipt_and_verify_signed_data_take_no_clock_parameter
    %i[verify_receipt verify_signed_data].each do |name|
      parameters = APRV::Verifier.instance_method(name).parameters.map(&:last)
      refute_includes parameters, :clock
      refute_includes parameters, :now
    end
  end

  def test_config_and_verifier_instances_are_frozen
    config = APRV::Config.new(roots: receipt_roots)
    verifier = APRV::Verifier.create(config)
    assert_predicate config, :frozen?
    assert_predicate verifier, :frozen?
  end

  # The "thread-safe once constructed" claim the other ports make in a doc
  # comment and never test.
  def test_one_verifier_is_usable_from_many_threads_at_once
    verifier = APRV::Verifier.create(APRV::Config.new(roots: receipt_roots))
    base64 = [TestSupport.fixture_bytes("receipt")].pack("m0")
    results = Array.new(8) do
      Thread.new { verifier.verify_receipt(base64).payload.in_app.map(&:transaction_id) }
    end.map(&:value)
    assert_equal 8, results.size
    assert_equal 1, results.uniq.size
    assert_equal %w[70000000000001 70000000000002], results.first
  end

  def test_returned_value_objects_are_frozen
    verifier = APRV::Verifier.create(APRV::Config.new(roots: receipt_roots))
    base64 = [TestSupport.fixture_bytes("receipt")].pack("m0")
    result = verifier.verify_receipt(base64)
    assert_predicate result, :frozen?
    receipt = result.payload
    assert_predicate receipt, :frozen?
    assert_predicate receipt.in_app, :frozen?
    assert_predicate receipt.in_app.first, :frozen?
    assert_predicate receipt.unknown_attributes, :frozen?
  end

  # A caller reads verified? before trusting anything, then payload or
  # failure. That only works if exactly one of the two is set for every
  # outcome the public methods can produce.
  def test_a_result_carries_exactly_one_of_payload_and_failure
    verifier = APRV::Verifier.create(APRV::Config.new(roots: receipt_roots))
    results = {
      "verified" => verifier.verify_receipt([TestSupport.fixture_bytes("receipt")].pack("m0")),
      "malformed" => verifier.verify_receipt("AQIDBA=="),
      "untrusted chain" => verifier.verify_receipt([TestSupport.fixture_bytes("receipt-foreign")].pack("m0")),
      "malformed jws" => verifier.verify_signed_data("a.b")
    }
    results.each do |label, result|
      refute_equal result.payload.nil?, result.failure.nil?, "#{label}: exactly one of payload and failure"
      assert_equal !result.payload.nil?, result.verified?, label
      assert_predicate result, :frozen?, label
    end
    assert_predicate results["verified"], :verified?
    assert_equal APRV::Reason::MALFORMED, results["malformed"].failure.reason
    assert_equal APRV::Reason::UNTRUSTED_CHAIN, results["untrusted chain"].failure.reason
    assert_equal APRV::Reason::MALFORMED, results["malformed jws"].failure.reason
  end

  # A Ruby String can carry bytes that are not valid in its encoding. The
  # public methods must treat that as malformed input, not raise on it.
  def test_input_that_is_not_valid_utf8_is_malformed_not_a_raise
    verifier = APRV::Verifier.create(APRV::Config.new(roots: receipt_roots))
    text = "QU\xffD".b
    assert_equal APRV::Reason::MALFORMED, verifier.verify_receipt(text).failure.reason
    assert_equal APRV::Reason::MALFORMED, verifier.verify_receipt(+"QU\xffD").failure.reason
    assert_equal APRV::Reason::MALFORMED, verifier.verify_signed_data(+"a\xff.b.c").failure.reason
    body = +"{\"receipt-data\":\"QU\xffD\"}"
    assert_equal 21_002, JSON.parse(verifier.verify_receipt_endpoint(APRV::Environment::SANDBOX, body))["status"]
  end

  def test_the_dashed_require_path_works_too
    path = File.expand_path("../lib/apple-purchase-receipt-verifier.rb", __dir__)
    assert_path_exists path
    output = `ruby -I#{File.expand_path("../lib",
                                        __dir__)} -e 'require "apple-purchase-receipt-verifier"; print ApplePurchaseReceiptVerifier::VERSION'`
    assert_equal APRV::VERSION, output
  end

  def test_the_version_is_a_semver_string
    assert_match(/\A\d+\.\d+\.\d+\z/, APRV::VERSION)
  end
end
