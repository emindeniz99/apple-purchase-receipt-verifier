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

  def test_the_three_entry_points_and_the_free_function_exist
    assert_kind_of Class, APRV::JwsVerifier
    assert_kind_of Class, APRV::ReceiptVerifier
    assert_kind_of Class, APRV::VerifyReceiptEndpoint
    assert_respond_to APRV, :verify_receipt_core
    assert_respond_to APRV, :apple_jws_roots
    assert_respond_to APRV, :apple_receipt_roots
  end

  def test_the_operations_are_the_six_the_other_ports_ship
    assert_respond_to APRV::JwsVerifier.instance_method(:verify_transaction), :arity
    %i[verify_transaction verify_app_transaction verify_raw].each do |name|
      assert_includes APRV::JwsVerifier.public_instance_methods, name
    end
    %i[verify verify_der verify_base64].each do |name|
      assert_includes APRV::ReceiptVerifier.public_instance_methods, name
    end
    %i[verify_receipt verify_receipt_json].each do |name|
      assert_includes APRV::VerifyReceiptEndpoint.public_instance_methods, name
    end
  end

  # The canonical SCREAMING_SNAKE token is `reason.to_s`, with no mapping table
  # anywhere. This reads the vocabulary out of the shared schema, so a change
  # to the cross-language contract breaks the Ruby port loudly.
  def test_the_reason_vocabulary_equals_the_shared_schema
    schema = TestSupport.cases_schema
    expected = schema["$defs"]["reason"]["enum"]
    assert_equal expected.sort, APRV::Reason::ALL.map(&:to_s).sort
    assert_equal 11, APRV::Reason::ALL.size
    APRV::Reason::ALL.each { |reason| assert_kind_of Symbol, reason }
  end

  def test_the_environment_vocabulary_equals_the_shared_schema
    schema = TestSupport.cases_schema
    expected = schema["$defs"]["environment"]["enum"]
    assert_equal expected.sort, APRV::Environment::ALL.sort
  end

  def test_a_verification_error_carries_its_reason_as_data_and_in_its_message
    error = APRV::VerificationError.new(APRV::Reason::INVALID_CHAIN, "detail")
    assert_equal :INVALID_CHAIN, error.reason
    assert_equal "INVALID_CHAIN: detail", error.message
    assert_kind_of StandardError, error
  end

  # Misconfiguration is a programming error, not a verification verdict: a
  # caller must not be able to catch a typo as though a receipt were forged.
  def test_misconfiguration_raises_argument_error_never_verification_error
    bad_constructions = [
      -> { APRV::JwsVerifier.new(trusted_roots: [], bundle_id: "a", accepted_environments: ["Sandbox"]) },
      -> { APRV::JwsVerifier.new(trusted_roots: "x", bundle_id: "a", accepted_environments: ["Sandbox"]) },
      lambda {
        APRV::JwsVerifier.new(trusted_roots: receipt_roots, bundle_id: "",
                              accepted_environments: ["Sandbox"])
      },
      lambda {
        APRV::JwsVerifier.new(trusted_roots: receipt_roots, bundle_id: nil,
                              accepted_environments: ["Sandbox"])
      },
      -> { APRV::JwsVerifier.new(trusted_roots: receipt_roots, bundle_id: "a", accepted_environments: []) },
      lambda {
        APRV::JwsVerifier.new(trusted_roots: receipt_roots, bundle_id: "a", accepted_environments: ["Nope"])
      },
      lambda {
        APRV::JwsVerifier.new(trusted_roots: receipt_roots, bundle_id: "a", accepted_environments: ["Sandbox"],
                              app_apple_id: "1")
      },
      lambda {
        APRV::JwsVerifier.new(trusted_roots: receipt_roots, bundle_id: "a", accepted_environments: ["Sandbox"],
                              max_signed_age_seconds: -1)
      },
      -> { APRV::ReceiptVerifier.new(trusted_roots: [], bundle_id: "a") },
      -> { APRV::ReceiptVerifier.new(trusted_roots: receipt_roots, bundle_id: nil) },
      -> { APRV::VerifyReceiptEndpoint.new(trusted_roots: receipt_roots, environment: "Xcode") },
      -> { APRV.verify_receipt_core("x", trusted_roots: []) }
    ]
    bad_constructions.each_with_index do |construction, index|
      error = assert_raises(ArgumentError, "construction #{index}") { construction.call }
      refute_kind_of APRV::VerificationError, error
    end
  end

  def test_the_unit_is_in_the_name_of_the_duration_option
    parameters = APRV::JwsVerifier.instance_method(:initialize).parameters.map(&:last)
    assert_includes parameters, :max_signed_age_seconds
    refute_includes parameters, :max_signed_age
    refute_includes parameters, :max_signed_age_millis
  end

  def test_verifier_instances_are_frozen
    jws = APRV::JwsVerifier.new(trusted_roots: receipt_roots, bundle_id: "a",
                                accepted_environments: ["Sandbox"])
    receipt = APRV::ReceiptVerifier.new(trusted_roots: receipt_roots, bundle_id: "a")
    endpoint = APRV::VerifyReceiptEndpoint.new(trusted_roots: receipt_roots, environment: "Sandbox")
    [jws, receipt, endpoint].each { |instance| assert_predicate instance, :frozen? }
  end

  # The "thread-safe once constructed" claim the other ports make in a doc
  # comment and never test.
  def test_one_verifier_is_usable_from_many_threads_at_once
    verifier = APRV::ReceiptVerifier.new(trusted_roots: receipt_roots, bundle_id: "com.example.app")
    der = TestSupport.fixture_bytes("receipt")
    results = 8.times.map do
      Thread.new { verifier.verify_der(der).in_app_purchases.map(&:transaction_id) }
    end.map(&:value)
    assert_equal 8, results.size
    assert_equal 1, results.uniq.size
    assert_equal %w[70000000000001 70000000000002], results.first
  end

  def test_returned_value_objects_are_frozen
    receipt = APRV.verify_receipt_core(TestSupport.fixture_bytes("receipt"),
                                       trusted_roots: receipt_roots)
    assert_predicate receipt, :frozen?
    assert_predicate receipt.in_app_purchases, :frozen?
    assert_predicate receipt.in_app_purchases.first, :frozen?
    assert_predicate receipt.unknown_attributes, :frozen?
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
