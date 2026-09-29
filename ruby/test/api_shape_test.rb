# frozen_string_literal: true

require_relative "helper"
require_relative "fake_module"

# The public surface: the names, the error vocabulary, what misconfiguration
# does, the values a result carries, and that the library holds no
# verification code of its own.
class ApiShapeTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier
  FAKE = APRV::Runtime.new(FakeModule.wat)

  def fake_verifier
    APRV::Verifier.send(:new, APRV::Config.defaults, runtime: FAKE)
  end

  def test_the_public_classes_exist
    [APRV::Config, APRV::Config::Builder, APRV::Verifier, APRV::VerificationResult, APRV::Failure,
     APRV::ReceiptPayload, APRV::InAppPurchase, APRV::JsonPayload,
     APRV::AbiMismatchError, APRV::ModuleIntegrityError, APRV::TrapError].each do |klass|
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

  # Misconfiguration is a programming error, not a verification verdict: a
  # caller must not be able to catch a typo as though a receipt were forged.
  def test_misconfiguration_raises_argument_error
    bad_constructions = [
      -> { APRV::Config.new(roots: "x") },
      -> { APRV::Config.new(roots: [42]) },
      -> { APRV::Config.new(clock: "not callable") },
      -> { APRV::Verifier.create("not a config") },
      -> { APRV::Verifier.create(APRV::Config.new(roots: [])) },
      -> { fake_verifier.verify_receipt_endpoint("Sandbox", "{}") },
      -> { fake_verifier.verify_receipt_endpoint(nil, "{}") }
    ]
    bad_constructions.each_with_index do |construction, index|
      assert_raises(ArgumentError, "construction #{index}") { construction.call }
    end
  end

  # Freshness and any per-call clock override are gone: the clock lives on
  # Config, read once per call, never a per-call parameter.
  def test_verify_receipt_and_verify_signed_data_take_no_clock_parameter
    %i[verify_receipt verify_signed_data].each do |name|
      parameters = APRV::Verifier.instance_method(name).parameters.map(&:last)
      refute_includes parameters, :clock
      refute_includes parameters, :now
    end
  end

  def test_config_and_verifier_instances_are_frozen
    config = APRV::Config.new(roots: ["der".b])
    assert_predicate config, :frozen?
    assert_predicate config.roots, :frozen?
    assert_predicate fake_verifier, :frozen?
  end

  def test_returned_value_objects_are_frozen
    result = fake_verifier.verify_receipt("v")
    assert_predicate result, :frozen?
    receipt = result.payload
    assert_predicate receipt, :frozen?
    assert_predicate receipt.in_app, :frozen?
    assert_predicate receipt.in_app.first, :frozen?
    assert_predicate receipt.unknown_attributes, :frozen?
    assert_predicate receipt.in_app.first.unknown_attributes, :frozen?
    assert_predicate fake_verifier.verify_signed_data("v").payload, :frozen?
  end

  # A caller reads verified? before trusting anything, then payload or
  # failure. That only works if exactly one of the two is set for every
  # outcome the public methods can produce.
  def test_a_result_carries_exactly_one_of_payload_and_failure
    verifier = fake_verifier
    results = {
      "verified receipt" => verifier.verify_receipt("v"),
      "verified jws" => verifier.verify_signed_data("v"),
      "refused" => verifier.verify_receipt("f"),
      "malformed" => verifier.verify_receipt(""),
      "not a string" => verifier.verify_receipt(nil),
      "trap" => verifier.verify_receipt("t")
    }
    results.each do |label, result|
      refute_equal result.payload.nil?, result.failure.nil?, "#{label}: exactly one of payload and failure"
      assert_equal !result.payload.nil?, result.verified?, label
      assert_predicate result, :frozen?, label
    end
    assert_predicate results["verified receipt"], :verified?
    assert_equal APRV::Reason::UNTRUSTED_CHAIN, results["refused"].failure.reason
    assert_equal APRV::Reason::MALFORMED, results["malformed"].failure.reason
    assert_equal APRV::Reason::MALFORMED, results["not a string"].failure.reason
    assert_equal APRV::Reason::INTERNAL_ERROR, results["trap"].failure.reason
  end

  # A Ruby String can carry bytes that are not valid in its encoding. The
  # public methods pass the bytes on and answer with a value, never a raise.
  def test_input_that_is_not_valid_utf8_is_passed_on_and_answered_as_a_value
    verifier = fake_verifier
    ["QU\xffD".b, +"QU\xffD", +"a\xff.b.c"].each do |text|
      assert_kind_of APRV::VerificationResult, verifier.verify_receipt(text)
      assert_kind_of APRV::VerificationResult, verifier.verify_signed_data(text)
    end
    body = +"{\"receipt-data\":\"QU\xffD\"}"
    assert_equal({ "status" => 0 }, JSON.parse(verifier.verify_receipt_endpoint(APRV::Environment::SANDBOX, body)))
  end

  # The 0.7 rule for a null or non-String input: MALFORMED, not a raise, and
  # nothing reaches the module.
  def test_an_input_that_is_not_a_string_is_malformed
    verifier = fake_verifier
    [nil, 42, :sym, ["v"]].each do |input|
      assert_equal APRV::Reason::MALFORMED, verifier.verify_receipt(input).failure.reason
      assert_equal APRV::Reason::MALFORMED, verifier.verify_signed_data(input).failure.reason
      assert_equal({ "status" => 21_002 },
                   JSON.parse(verifier.verify_receipt_endpoint(APRV::Environment::SANDBOX, input)))
    end
  end

  def test_the_dashed_require_path_works_too
    path = File.expand_path("../lib/apple-purchase-receipt-verifier.rb", __dir__)
    assert_path_exists path
    output = `ruby -I#{File.expand_path("../lib", __dir__)} -e 'require "apple-purchase-receipt-verifier"; print ApplePurchaseReceiptVerifier::VERSION'`
    assert_equal APRV::VERSION, output
  end

  def test_the_version_is_a_semver_string
    assert_match(/\A\d+\.\d+\.\d+\z/, APRV::VERSION)
  end

  # No wrapper holds verification logic (docs/rust-core/ARCHITECTURE.md, the
  # invariants): nothing under lib/ may reach for a crypto, X.509, ASN.1,
  # CMS or JWS API. The CI job `one-implementation` greps for the same names
  # across every wrapper.
  FORBIDDEN = [
    /require\s+["']openssl["']/, /OpenSSL/, /\bOpenSSL::/, /\bX509\b/i, /\bPKCS7\b/i, /\bASN1\b/i,
    /\bCMS\b/, /\bx5c\b/i, /base64url/i, /\bECDSA\b/i, /Signature/
  ].freeze

  def test_the_library_holds_no_verification_code
    files = Dir[File.expand_path("../lib/**/*.rb", __dir__)].reject { |f| f.end_with?("roots_data.rb") }
    refute_empty files
    files.each do |file|
      File.readlines(file, chomp: true, encoding: "UTF-8").each_with_index do |line, index|
        code = line.sub(/#.*\z/, "")
        FORBIDDEN.each do |pattern|
          refute_match pattern, code, "#{File.basename(file)}:#{index + 1} looks like verification code"
        end
      end
    end
  end
end
