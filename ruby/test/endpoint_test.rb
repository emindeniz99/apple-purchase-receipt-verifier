# frozen_string_literal: true

require_relative "helper"
require_relative "test_pki"

# The verifyReceipt-compatible endpoint: the wire contract, the routing that
# has to fail closed, and the "never raises" promise.
class EndpointTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier

  def setup
    @roots = [TestSupport.fixture_certificate("receipt-root")]
    @receipt = TestSupport.fixture_bytes("receipt")
  end

  def endpoint(environment: APRV::Environment::SANDBOX, clock: nil, roots: @roots)
    APRV::VerifyReceiptEndpoint.new(trusted_roots: roots, environment: environment, clock: clock)
  end

  def body(der)
    { "receipt-data" => [der].pack("m0") }
  end

  def test_status_zero_body_matches_the_documented_contract
    response = endpoint(clock: -> { Time.utc(2025, 1, 1) }).verify_receipt(body(@receipt))
    assert_equal 0, response["status"]
    assert_equal "Sandbox", response["environment"]
    receipt = response["receipt"]
    assert_equal "ProductionSandbox", receipt["receipt_type"]
    assert_equal "com.example.app", receipt["bundle_id"]
    assert_equal "1.2.3", receipt["application_version"]
    assert_equal "1.0", receipt["original_application_version"]
    assert_equal "2024-08-06 12:00:00 Etc/GMT", receipt["receipt_creation_date"]
    assert_equal "1722945600000", receipt["receipt_creation_date_ms"]
    assert_equal "2024-08-06 05:00:00 America/Los_Angeles", receipt["receipt_creation_date_pst"]
    assert_equal "2025-01-01 00:00:00 Etc/GMT", receipt["request_date"]
    assert_equal 2, receipt["in_app"].size
  end

  # Apple's wire types: everything numeric in `in_app` is a String, and only
  # `status` is an Integer.
  def test_wire_types_are_apples_wire_types
    response = endpoint.verify_receipt(body(@receipt))
    entry = response["receipt"]["in_app"].find { |i| i["product_id"] == "com.example.app.vip" }
    assert_kind_of Integer, response["status"]
    assert_kind_of String, entry["quantity"]
    assert_equal "1", entry["quantity"]
    assert_equal "42", entry["web_order_line_item_id"]
    assert_kind_of String, entry["expires_date_ms"]
  end

  def test_is_in_intro_offer_period_is_the_string_true_or_false
    pki = TestPki.receipt_pki
    [[1, "true"], [0, "false"]].each do |value, expected|
      in_app = TestPki.receipt_payload([[1702, TestPki.utf8("p")],
                                        [1719, TestPki.integer(value)]])
      payload = TestPki.receipt_payload([[0, TestPki.utf8("ProductionSandbox")],
                                         [2, TestPki.utf8("com.example.app")],
                                         [17, in_app]])
      response = endpoint(roots: [pki.root])
                 .verify_receipt(body(TestPki.sign_receipt(pki, payload)))
      assert_equal expected, response["receipt"]["in_app"][0]["is_in_intro_offer_period"]
    end
  end

  def test_malformed_receipt_data_answers_21002
    [nil, {}, { "receipt-data" => nil }, { "receipt-data" => "" }, { "receipt-data" => 42 },
     { "receipt-data" => [] }, "not a hash", 42, []].each do |request|
      assert_equal 21_002, endpoint.verify_receipt(request)["status"], request.inspect
    end
  end

  def test_undecodable_base64_answers_21002
    assert_equal 21_002, endpoint.verify_receipt({ "receipt-data" => "!!!!" })["status"]
  end

  def test_unauthenticated_receipt_answers_21003
    assert_equal 21_003,
                 endpoint.verify_receipt(body(TestSupport.fixture_bytes("receipt-foreign")))["status"]
  end

  def test_environment_routing_both_directions
    production = TestSupport.fixture_bytes("receipt-type-production")
    assert_equal 21_007, endpoint(environment: APRV::Environment::PRODUCTION)
      .verify_receipt(body(@receipt))["status"]
    assert_equal 21_008, endpoint(environment: APRV::Environment::SANDBOX)
      .verify_receipt(body(production))["status"]
    assert_equal 0, endpoint(environment: APRV::Environment::PRODUCTION)
      .verify_receipt(body(production))["status"]
  end

  # The fail-closed case that drove PLAN D10: ProductionVPPSandbox is sandbox.
  def test_vpp_sandbox_routes_as_sandbox
    vpp_sandbox = TestSupport.fixture_bytes("receipt-type-vpp-sandbox")
    assert_equal 0, endpoint(environment: APRV::Environment::SANDBOX)
      .verify_receipt(body(vpp_sandbox))["status"]
    assert_equal 21_007, endpoint(environment: APRV::Environment::PRODUCTION)
      .verify_receipt(body(vpp_sandbox))["status"]
  end

  def test_a_missing_receipt_type_routes_as_sandbox
    no_type = TestSupport.fixture_bytes("receipt-no-type")
    assert_equal 0, endpoint.verify_receipt(body(no_type))["status"]
    assert_equal 21_007, endpoint(environment: APRV::Environment::PRODUCTION)
      .verify_receipt(body(no_type))["status"]
  end

  def test_non_zero_status_bodies_carry_neither_receipt_nor_environment
    [endpoint.verify_receipt({}),
     endpoint.verify_receipt(body(TestSupport.fixture_bytes("receipt-foreign"))),
     endpoint(environment: APRV::Environment::PRODUCTION).verify_receipt(body(@receipt))]
      .each do |response|
      refute response.key?("receipt"), response.inspect
      refute response.key?("environment"), response.inspect
      refute_equal 0, response["status"]
    end
  end

  def test_verify_receipt_json_agrees_with_verify_receipt
    [body(@receipt), {}, { "receipt-data" => "!!!!" },
     body(TestSupport.fixture_bytes("receipt-foreign"))].each do |request|
      clock = -> { Time.utc(2025, 1, 1) }
      expected = endpoint(clock: clock).verify_receipt(request)
      actual = JSON.parse(endpoint(clock: clock).verify_receipt_json(JSON.generate(request)))
      assert_equal expected, actual
    end
  end

  def test_verify_receipt_json_answers_21002_for_anything_that_is_not_a_json_object
    ["[]", "\"x\"", "42", "null", "not json at all", "", "{"].each do |text|
      assert_equal 21_002, JSON.parse(endpoint.verify_receipt_json(text))["status"], text
    end
  end

  def test_password_and_exclude_old_transactions_are_accepted_and_ignored
    request = body(@receipt).merge("password" => "shared secret",
                                   "exclude-old-transactions" => true)
    assert_equal 0, endpoint.verify_receipt(request)["status"]
  end

  def test_the_endpoint_never_raises_for_hostile_input
    hostile = ["\x30\x80" * 100_000, "\x00" * 1000, "\xff" * 10, ""]
    hostile.each do |bytes|
      response = endpoint.verify_receipt({ "receipt-data" => [bytes].pack("m0") })
      assert_includes [0, 21_002, 21_003, 21_009], response["status"]
    end
  end

  def test_environment_must_be_production_or_sandbox
    [APRV::Environment::XCODE, APRV::Environment::LOCAL_TESTING, "production", "", nil, 1]
      .each do |bad|
      assert_raises(ArgumentError) { endpoint(environment: bad) }
    end
  end

  def test_status_codes_out_of_scope_are_never_produced
    responses = [
      endpoint.verify_receipt(body(@receipt)),
      endpoint.verify_receipt({}),
      endpoint.verify_receipt(body(TestSupport.fixture_bytes("receipt-foreign"))),
      endpoint(environment: APRV::Environment::PRODUCTION).verify_receipt(body(@receipt))
    ]
    responses.each do |response|
      assert_includes [0, 21_002, 21_003, 21_007, 21_008, 21_009], response["status"]
      refute response.key?("is_retryable")
      refute response.key?("latest_receipt")
    end
  end
end
