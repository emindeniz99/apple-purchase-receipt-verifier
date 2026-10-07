# frozen_string_literal: true

require_relative "helper"

# The typed copy of the module's JSON (aprv-wire, the 0.7 "Our JSON"): every
# field of the receipt payload, and what a wrapper does with an answer that is
# not shaped as the contract says. Nothing here calls the module.
class WireTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier
  WIRE = Internals::Wire

  def receipt_json(environment: "Production", **overrides)
    payload = {
      "receipt_type" => "Production", "app_item_id" => "1", "bundle_id" => "com.example",
      "bundle_id_bytes" => "AQI=", "application_version" => "3", "opaque_value" => "",
      "sha1_hash" => "AAAA", "receipt_creation_date_ms" => 1000, "download_id" => "0",
      "version_external_identifier" => "0", "in_app" => [], "original_purchase_date_ms" => nil,
      "preorder_date_ms" => nil, "original_application_version" => nil, "expiration_date_ms" => nil,
      "unknown_attributes" => {}
    }.merge(overrides.transform_keys(&:to_s))
    JSON.generate("verified" => true, "payload" => payload, "environment" => environment)
  end

  def refused(text)
    assert_raises(APRV::TrapError) { yield text }
  end

  def test_the_preorder_date_is_an_integer_or_null_and_sits_next_to_the_original_purchase_date
    payload = WIRE.receipt_result(receipt_json(preorder_date_ms: 1_719_913_520_000)).payload
    assert_equal 1_719_913_520_000, payload.preorder_date_ms
    keys = JSON.parse(payload.to_json).keys
    assert_equal keys.index("original_purchase_date_ms") + 1, keys.index("preorder_date_ms")
    assert_nil WIRE.receipt_result(receipt_json).payload.preorder_date_ms
    refused(receipt_json(preorder_date_ms: "1719913520000")) { |text| WIRE.receipt_result(text) }
  end

  def test_a_payload_built_by_hand_without_a_preorder_date_has_none
    payload = WIRE.receipt_result(receipt_json).payload
    members = payload.to_h.except(:preorder_date_ms)
    rebuilt = APRV::ReceiptPayload.new(**members)
    assert_nil rebuilt.preorder_date_ms
    assert_equal payload, rebuilt
  end

  def test_ids_are_decimal_strings_and_keep_every_bit
    payload = WIRE.receipt_result(receipt_json(app_item_id: "9223372036854775807",
                                               download_id: "-5")).payload
    assert_equal 9_223_372_036_854_775_807, payload.app_item_id
    assert_equal(-5, payload.download_id)
    assert_nil payload.original_application_version
  end

  def test_bytes_are_padded_standard_base64_and_an_empty_value_is_an_empty_string
    payload = WIRE.receipt_result(receipt_json).payload
    assert_equal "\x01\x02".b, payload.bundle_id_bytes
    assert_equal "".b, payload.opaque_value
    assert_equal Encoding::BINARY, payload.bundle_id_bytes.encoding
  end

  def test_unknown_attributes_are_keyed_by_the_integer_type_with_values_in_receipt_order
    unknown = { "25" => %w[AgED AAAA], "6" => ["/w=="] }
    payload = WIRE.receipt_result(receipt_json(unknown_attributes: unknown)).payload
    assert_equal({ 25 => ["\x02\x01\x03".b, "\x00\x00\x00".b], 6 => ["\xff".b] },
                 payload.unknown_attributes)
    assert_equal %w[AgED AAAA], JSON.parse(payload.to_json)["unknown_attributes"]["25"]
  end

  def test_a_missing_field_is_nil_and_to_json_writes_null
    payload = WIRE.receipt_result(receipt_json(bundle_id: nil, expiration_date_ms: nil)).payload
    assert_nil payload.bundle_id
    parsed = JSON.parse(payload.to_json)
    assert parsed.key?("bundle_id")
    assert_nil parsed["bundle_id"]
    assert_equal "1", parsed["app_item_id"], "ids are written as strings"
  end

  def test_an_in_app_purchase_carries_every_field
    purchase = { "quantity" => 2, "product_id" => "p", "transaction_id" => "t", "purchase_date_ms" => 5,
                 "original_transaction_id" => "o", "original_purchase_date_ms" => 4,
                 "expires_date_ms" => 9, "web_order_line_item_id" => "18446744073709551",
                 "cancellation_date_ms" => nil, "is_trial_period" => true,
                 "is_in_intro_offer_period" => false, "unknown_attributes" => { "1799" => ["AQ=="] } }
    payload = WIRE.receipt_result(receipt_json(in_app: [purchase])).payload
    item = payload.in_app.fetch(0)
    assert_equal [2, "p", "t", 5, "o", 4, 9, 18_446_744_073_709_551, nil, true, false,
                  { 1799 => ["\x01".b] }], item.to_h.values
    assert_equal purchase, JSON.parse(payload.to_json)["in_app"].fetch(0)
  end

  def test_a_failure_takes_the_reason_and_message_of_the_module
    APRV::Reason::ALL.each do |reason|
      text = JSON.generate("verified" => false, "reason" => reason.to_s, "message" => "why")
      failure = WIRE.receipt_result(text).failure
      assert_equal reason, failure.reason
      assert_equal "why", failure.message
      assert_nil failure.cause
    end
  end

  def test_a_signed_payload_is_the_string_exactly_as_signed
    signed = %({ "a" : 1e400,\n "b":"\\u00e9" })
    text = JSON.generate("verified" => true, "payload" => signed, "environment" => nil)
    assert_equal signed, WIRE.signed_data_result(text).payload.json
  end

  # The environment the module states beside the payload (DECISIONS.md R42),
  # in this gem's Environment values; the payload's own JSON is unchanged.
  def test_the_environment_beside_the_payload_is_read_into_the_payload
    { "Production" => APRV::Environment::PRODUCTION, "Sandbox" => APRV::Environment::SANDBOX,
      nil => nil }.each do |stated, environment|
      receipt = WIRE.receipt_result(receipt_json(environment: stated)).payload
      jws = WIRE.signed_data_result(JSON.generate("verified" => true, "payload" => "{}",
                                                  "environment" => stated)).payload
      [receipt, jws].each do |payload|
        environment.nil? ? assert_nil(payload.environment) : assert_equal(environment, payload.environment)
      end
      refute JSON.parse(receipt.to_json).key?("environment"), "to_json writes the receipt's own fields"
    end
  end

  # A verified answer without the member, or with a value that is not one of
  # the three, comes from a module this wrapper cannot read.
  def test_a_verified_answer_without_a_known_environment_is_refused
    payload = JSON.parse(receipt_json)["payload"]
    [{}, { "environment" => "PRODUCTION" }, { "environment" => "Xcode" }, { "environment" => "" },
     { "environment" => 1 }, { "environment" => false }, { "environment" => {} }].each do |member|
      refused(JSON.generate({ "verified" => true, "payload" => payload }.merge(member))) do |t|
        WIRE.receipt_result(t)
      end
      refused(JSON.generate({ "verified" => true, "payload" => "{}" }.merge(member))) do |t|
        WIRE.signed_data_result(t)
      end
    end
  end

  def test_init_answers
    assert_equal 3_145_729, WIRE.init_answer('{"ok":true,"max_input_bytes":3145729}')
    assert_equal 1, WIRE.init_answer('{"ok":true,"max_input_bytes":1}')
    no = assert_raises(Internals::RootsRejected) { WIRE.init_answer('{"ok":false,"message":"no"}') }
    assert_equal "no", no.message
    unnamed = assert_raises(Internals::RootsRejected) { WIRE.init_answer('{"ok":false}') }
    assert_equal "the roots were refused", unnamed.message
    refused("{}") { |t| WIRE.init_answer(t) }
    refused("[]") { |t| WIRE.init_answer(t) }
  end

  # `{"ok":true}` alone is the answer of a module older than this wrapper,
  # which states no input length: a module failure, never a usable instance.
  def test_an_accepting_init_answer_without_a_positive_integer_length_is_refused
    ['{"ok":true}', '{"ok":true,"max_input_bytes":0}', '{"ok":true,"max_input_bytes":-1}',
     '{"ok":true,"max_input_bytes":"3145729"}', '{"ok":true,"max_input_bytes":3145729.0}',
     '{"ok":true,"max_input_bytes":1.5}', '{"ok":true,"max_input_bytes":null}'].each do |text|
      refused(text) { |t| WIRE.init_answer(t) }
    end
  end

  # An answer that is not the shape the contract says is the module
  # misbehaving, not a verdict: TrapError, which the verifier turns into
  # INTERNAL_ERROR and a discarded instance.
  def test_answers_that_break_the_contract_are_refused
    [
      "", "nope", "[]", "null", "{}", '{"verified":"yes"}', '{"verified":false}',
      '{"verified":false,"reason":"MALFORMED"}', '{"verified":false,"reason":"NOT_A_REASON","message":"m"}',
      '{"verified":false,"reason":"malformed","message":"m"}',
      '{"verified":false,"reason":5,"message":"m"}',
      '{"verified":true}', '{"verified":true,"payload":[]}', "\xff".b
    ].each do |text|
      refused(text) { |t| WIRE.receipt_result(t) }
      refused(text) { |t| WIRE.signed_data_result(t) }
    end
    refused('{"verified":true,"payload":{}}') { |t| WIRE.signed_data_result(t) }
  end

  def test_fields_of_the_wrong_type_are_refused
    [
      { app_item_id: 1 }, { app_item_id: "1.5" }, { app_item_id: "abc" }, { bundle_id: 5 },
      { bundle_id_bytes: "not base64!" }, { bundle_id_bytes: 5 }, { receipt_creation_date_ms: "1000" },
      { receipt_creation_date_ms: 1.5 }, { in_app: {} }, { in_app: [5] }, { in_app: [{}] },
      { unknown_attributes: [] }, { unknown_attributes: { "x" => [] } },
      { unknown_attributes: { "1" => "AA==" } },
      { unknown_attributes: { "1" => [5] } }, { unknown_attributes: { "-1" => [] } }
    ].each do |overrides|
      refused(receipt_json(**overrides)) { |t| WIRE.receipt_result(t) }
    end
    purchase = {
      "quantity" => 1, "product_id" => "p", "transaction_id" => "t", "purchase_date_ms" => 1,
      "original_transaction_id" => "o", "original_purchase_date_ms" => 1, "expires_date_ms" => nil,
      "web_order_line_item_id" => nil, "cancellation_date_ms" => nil, "is_trial_period" => false,
      "is_in_intro_offer_period" => false, "unknown_attributes" => {}
    }
    [{ "is_trial_period" => "false" }, { "quantity" => "1" }, { "web_order_line_item_id" => 5 },
     { "unknown_attributes" => nil }].each do |bad|
      refused(receipt_json(in_app: [purchase.merge(bad)])) { |t| WIRE.receipt_result(t) }
    end
    assert_predicate WIRE.receipt_result(receipt_json(in_app: [purchase])), :verified?
  end
end
