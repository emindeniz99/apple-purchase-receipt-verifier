# frozen_string_literal: true

require_relative "helper"
require_relative "test_pki"

# The receipt path beyond fixtures/cases-0.7.json: CMS shapes no fixture
# carries, the attribute grammar's edges, and the pinning properties (marker
# OID after the chain, anchors only) stated as security rules rather than
# vectors. 0.7 takes no bundle id and no device GUID (docs/design/
# 0.7-api.md): the receipt verifies and the caller reads bundle_id and
# computes the device hash from the returned payload itself.
class ReceiptTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier

  def setup
    @pki = TestPki.receipt_pki
  end

  def verifier(pki: @pki)
    APRV::Verifier.create(APRV::Config.new(roots: [pki.root]))
  end

  def verify(base64, pki: @pki)
    verifier(pki: pki).verify_receipt(base64)
  end

  def assert_reason(reason, base64, pki: @pki)
    result = verify(base64, pki: pki)
    refute_predicate result, :verified?, "expected #{reason} but it verified"
    assert_equal reason, result.failure.reason, "wrong reason: #{result.failure.message}"
  end

  def genuine_sandbox
    TestSupport.fixture_bytes("public-receipt-sandbox-g5")
  end

  def test_verifies_the_genuine_sandbox_receipt
    v = APRV::Verifier.create(APRV::Config.defaults)
    result = v.verify_receipt([genuine_sandbox].pack("m0"))
    assert_predicate result, :verified?
    assert_equal "dev.bonzer.weeka.app", result.payload.bundle_id
    assert_equal 2, result.payload.in_app.size
  end

  def test_verifies_the_genuine_legacy_sha1_receipt
    v = APRV::Verifier.create(APRV::Config.defaults)
    base64 = [TestSupport.fixture_bytes("public-receipt-sandbox-legacy")].pack("m0")
    result = v.verify_receipt(base64)
    assert_predicate result, :verified?
    assert_equal 187, result.payload.in_app.size
  end

  # The device-hash formula: SHA1(device id + opaqueValue + bundleIdBytes),
  # the README's documented pattern, run against a real fixture.
  def test_the_caller_can_compute_the_device_hash_from_the_returned_fields
    subject = APRV::Verifier.create(
      APRV::Config.new(roots: [TestSupport.fixture_certificate("receipt-root")])
    )
    der = TestSupport.fixture_bytes("receipt")
    result = subject.verify_receipt([der].pack("m0"))
    assert_predicate result, :verified?
    payload = result.payload

    genuine_guid = [TestSupport.fixture_bytes("device-guid")].pack("H*")
    computed = OpenSSL::Digest::SHA1.digest(genuine_guid + payload.opaque_value + payload.bundle_id_bytes)
    assert_equal computed, payload.sha1_hash

    flipped = genuine_guid.dup
    flipped.setbyte(0, flipped.getbyte(0) ^ 0x01)
    wrong = OpenSSL::Digest::SHA1.digest(flipped + payload.opaque_value + payload.bundle_id_bytes)
    refute_equal wrong, payload.sha1_hash
  end

  def test_rejects_trailing_bytes_after_the_cms_blob
    der = TestPki.sign_receipt(@pki, TestPki.default_payload)
    assert_reason(:MALFORMED, ["#{der}\x00"].pack("m0"))
    assert_reason(:MALFORMED, ["#{der}junk"].pack("m0"))
  end

  def test_rejects_zero_signer_infos
    der = TestPki.sign_receipt(@pki, TestPki.default_payload)
    assert_reason(:MALFORMED, [TestPki.without_signer_infos(der)].pack("m0"))
  end

  # Every SignerInfo signs the same content, so a genuine one duplicated
  # still verifies: at least one succeeding is the rule
  # (docs/design/0.7-api.md).
  def test_a_duplicated_genuine_signer_info_still_verifies
    der = TestPki.sign_receipt(@pki, TestPki.default_payload)
    result = verify([TestPki.with_duplicated_signer_info(der)].pack("m0"))
    assert_predicate result, :verified?
  end

  def test_accepts_an_ec_signer_key
    key = TestPki.ec_key
    pki = TestPki.receipt_pki(leaf_key: key)
    der = TestPki.sign_receipt(pki, TestPki.default_payload)
    result = verify([der].pack("m0"), pki: pki)
    assert_predicate result, :verified?, "expected #{result.failure&.reason}: #{result.failure&.message}"
  end

  def test_rejects_a_signer_certificate_that_is_not_embedded
    der = OpenSSL::PKCS7.sign(
      @pki.leaf, @pki.leaf_key, TestPki.default_payload, [@pki.intermediate, @pki.root],
      OpenSSL::PKCS7::BINARY | OpenSSL::PKCS7::NOCERTS
    ).to_der
    assert_reason(:MALFORMED, [der].pack("m0"))
  end

  # Matching a signer on the serial alone would let a receipt carry a decoy
  # certificate that borrows the real signer's serial under another issuer.
  def test_twin_certificate_with_the_signers_serial_is_not_accepted_as_the_signer
    twin_key = TestPki.fresh_rsa_key
    twin = TestPki.certificate(subject: "Twin", key: twin_key, serial: @pki.leaf.serial.to_i,
                               oids: [TestPki::LEAF_OID])
    der = OpenSSL::PKCS7.sign(
      @pki.leaf, @pki.leaf_key, TestPki.default_payload,
      [@pki.intermediate, @pki.root, twin],
      OpenSSL::PKCS7::BINARY | OpenSSL::PKCS7::NOCERTS
    ).to_der
    assert_reason(:MALFORMED, [der].pack("m0"))
  end

  # The marker OID is checked AFTER the chain, so a foreign chain still
  # reports UNTRUSTED_CHAIN. The JWS path checks the two in the same order
  # in 0.7 (jws_test.rb).
  def test_chain_is_reported_before_the_signer_marker_oid
    foreign = TestPki.receipt_pki(leaf_oids: [])
    der = [TestPki.sign_receipt(foreign, TestPki.default_payload)].pack("m0")
    assert_reason(:UNTRUSTED_CHAIN, der)
    assert_reason(:INVALID_CERTIFICATE_PURPOSE, der, pki: foreign)
  end

  def test_attribute_integers_at_the_edges
    eight = OpenSSL::ASN1::Integer.new(2**56).to_der
    nine = OpenSSL::ASN1::Integer.new(2**64).to_der
    negative = OpenSSL::ASN1::Integer.new(-1).to_der

    accepted = verify([in_app_receipt([[1711, eight]])].pack("m0"))
    assert_predicate accepted, :verified?
    assert_equal 2**56, accepted.payload.in_app[0].web_order_line_item_id

    # A negative INTEGER fits the signed 64-bit range this reads DER
    # integers into, so it decodes to -1 rather than being kept raw; only
    # nine content octets overruns that range (matches Rust's
    # integer_value, which has no unsigned-only carve-out for 1711).
    negative_result = verify([in_app_receipt([[1711, negative]])].pack("m0"))
    assert_predicate negative_result, :verified?
    assert_equal(-1, negative_result.payload.in_app[0].web_order_line_item_id)

    nine_result = verify([in_app_receipt([[1711, nine]])].pack("m0"))
    assert_predicate nine_result, :verified?
    purchase = nine_result.payload.in_app[0]
    assert_nil purchase.web_order_line_item_id
    assert purchase.unknown_attributes.key?(1711)
  end

  # Cross-port decision: an attribute type above 2^31-1 makes the whole
  # attribute SET unreadable, never clamped onto a sentinel and filed under
  # unknown attributes.
  def test_rejects_an_attribute_type_above_the_32_bit_signed_range
    payload = TestPki.receipt_payload([[2**31, TestPki.utf8("x")]])
    assert_reason(:UNREADABLE_PAYLOAD, [TestPki.sign_receipt(@pki, payload)].pack("m0"))

    ok = TestPki.receipt_payload([[(2**31) - 1, TestPki.utf8("x")],
                                  [2, TestPki.utf8("com.example.app")]])
    result = verify([TestPki.sign_receipt(@pki, ok)].pack("m0"))
    assert_predicate result, :verified?
    assert_equal(["x"], result.payload.unknown_attributes[(2**31) - 1].map { |v| v[2..] })
  end

  # Legacy receipt ids: app-level attributes 1 (app item id), 15 (download
  # id) and 16 (version external identifier), and in-app attribute 1713 (is
  # trial period). None is on Apple's archived Receipt Fields chapter; their
  # meaning was established by comparing a genuine production receipt with
  # Apple's own verifyReceipt answer for it (measured 2026-09-21). The
  # download id is 2^63-1, a nineteen-digit, eight-byte integer an
  # IEEE-754 double rounds to 2^63, so asserting on its String form proves
  # Ruby's arbitrary-precision Integer carries it digit for digit rather
  # than rounding it.
  def test_legacy_receipt_ids_are_decoded
    root = TestSupport.fixture_certificate("receipt-ids-root")
    v = APRV::Verifier.create(APRV::Config.new(roots: [root]))
    result = v.verify_receipt([TestSupport.fixture_bytes("receipt-ids")].pack("m0"))
    assert_predicate result, :verified?
    payload = result.payload

    assert_equal 1_234_567_890, payload.app_item_id
    assert_equal 9_223_372_036_854_775_807, payload.download_id
    assert_equal "9223372036854775807", payload.download_id.to_s
    assert_equal 456_789_012, payload.version_external_identifier

    coins = payload.in_app.find { |p| p.product_id == "com.example.app.coins100" }
    vip = payload.in_app.find { |p| p.product_id == "com.example.app.vip" }
    refute coins.is_trial_period
    assert vip.is_trial_period

    # The four types leave unknown_attributes; the fixture's other unknown
    # attribute, 9999, must still be there.
    refute payload.unknown_attributes.key?(1)
    refute payload.unknown_attributes.key?(15)
    refute payload.unknown_attributes.key?(16)
    assert payload.unknown_attributes.key?(9999)
    refute coins.unknown_attributes.key?(1713)
    refute vip.unknown_attributes.key?(1713)
  end

  # Absent and present-but-zero are different answers: a receipt that carries
  # none of the four attributes reports them nil rather than 0.
  def test_legacy_receipt_ids_are_absent_when_the_receipt_does_not_carry_them
    v = APRV::Verifier.create(APRV::Config.new(roots: [TestSupport.fixture_certificate("receipt-root")]))
    result = v.verify_receipt([TestSupport.fixture_bytes("receipt")].pack("m0"))
    assert_predicate result, :verified?
    payload = result.payload

    assert_nil payload.app_item_id
    assert_nil payload.download_id
    assert_nil payload.version_external_identifier
    coins = payload.in_app.find { |p| p.product_id == "com.example.app.coins100" }
    assert_nil coins.is_trial_period
  end

  def test_dates_outside_the_exact_grammar_are_kept_raw_not_an_error
    ["2024-08-06T12:00:00", "2024-08-06 12:00:00Z", "2024-08-06T12:00:00.000Z",
     "0000-00-00T00:00:00Z", "not a date"].each do |text|
      payload = TestPki.receipt_payload([[2, TestPki.utf8("com.example.app")],
                                         [12, TestPki.ia5(text)]])
      result = verify([TestPki.sign_receipt(@pki, payload)].pack("m0"))
      assert_predicate result, :verified?, "#{text}: #{result.failure&.reason} #{result.failure&.message}"
      assert_nil result.payload.receipt_creation_date_ms, text
      assert_includes result.payload.unknown_attributes.keys, 12, text
    end
  end

  def test_an_empty_date_string_means_absent_and_is_not_kept_raw
    payload = TestPki.receipt_payload([[2, TestPki.utf8("com.example.app")],
                                       [21, TestPki.ia5("")]])
    result = verify([TestPki.sign_receipt(@pki, payload)].pack("m0"))
    assert_predicate result, :verified?
    assert_nil result.payload.expiration_date_ms
    refute result.payload.unknown_attributes.key?(21)
  end

  def test_an_attribute_value_that_is_not_valid_utf8_is_kept_raw
    payload = TestPki.receipt_payload([[2, TestPki.utf8("com.example.app")], [3, "\x0c\x02\xff\xfe".b]])
    result = verify([TestPki.sign_receipt(@pki, payload)].pack("m0"))
    assert_predicate result, :verified?
    assert_nil result.payload.application_version
    assert result.payload.unknown_attributes.key?(3)
  end

  def test_a_string_attribute_whose_value_is_the_wrong_asn1_type_is_kept_raw
    payload = TestPki.receipt_payload([[2, TestPki.utf8("com.example.app")], [3, TestPki.integer(7)]])
    result = verify([TestPki.sign_receipt(@pki, payload)].pack("m0"))
    assert_predicate result, :verified?
    assert_nil result.payload.application_version
    assert result.payload.unknown_attributes.key?(3)
  end

  def test_the_library_takes_no_bundle_id_and_judges_no_claim
    payload = TestPki.default_payload(bundle_id: "com.somebody.else")
    result = verify([TestPki.sign_receipt(@pki, payload)].pack("m0"))
    assert_predicate result, :verified?
    assert_equal "com.somebody.else", result.payload.bundle_id
  end

  # Cross-port rule: byte fields handed back are copies, so a caller reusing
  # its input buffer cannot mutate an already-verified receipt.
  def test_byte_fields_are_frozen_copies_of_the_input
    der = TestSupport.fixture_bytes("receipt").dup
    v = APRV::Verifier.create(APRV::Config.new(roots: [TestSupport.fixture_certificate("receipt-root")]))
    result = v.verify_receipt([der].pack("m0"))
    assert_predicate result, :verified?
    before = result.payload.opaque_value.dup
    assert_predicate result.payload.opaque_value, :frozen?
    assert_predicate result.payload.sha1_hash, :frozen?
    der.bytesize.times { |i| der.setbyte(i, 0) }
    assert_equal before, result.payload.opaque_value
  end

  def test_receipt_dates_are_epoch_millisecond_integers
    v = APRV::Verifier.create(APRV::Config.new(roots: [TestSupport.fixture_certificate("receipt-root")]))
    result = v.verify_receipt([TestSupport.fixture_bytes("receipt")].pack("m0"))
    assert_predicate result, :verified?
    assert_kind_of Integer, result.payload.receipt_creation_date_ms
    assert_kind_of Integer, result.payload.in_app[0].purchase_date_ms
  end

  # A trust anchor is trusted by fiat: its own validity window is not
  # examined. The historical-receipt conformance case depends on this.
  def test_an_anchor_is_not_rejected_for_being_expired
    pki = TestPki.receipt_pki(not_before: Time.utc(2020, 1, 1), not_after: Time.utc(2021, 1, 1))
    payload = TestPki.default_payload(creation_date: "2020-06-01T00:00:00Z")
    der = TestPki.sign_receipt(pki, payload)
    result = verify([der].pack("m0"), pki: pki)
    assert_predicate result, :verified?
    assert_equal "com.example.app", result.payload.bundle_id
  end

  def test_rejects_input_that_is_not_a_string_or_is_empty
    [nil, 42, [], ""].each { |bad| assert_reason(:MALFORMED, bad) }
  end

  def test_rejects_text_that_is_not_canonical_base64
    assert_reason(:MALFORMED, "not base64 at all!!")
  end

  def test_rejects_base64_that_does_not_hold_a_cms_blob
    assert_reason(:MALFORMED, ["\x30\x03\x02\x01\x01".b].pack("m0"))
    assert_reason(:MALFORMED, ["hello world"].pack("m0"))
  end

  private

  def in_app_receipt(in_app_attributes)
    in_app = TestPki.receipt_payload(
      [[1702, TestPki.utf8("com.example.app.pro")]] + in_app_attributes
    )
    payload = TestPki.receipt_payload([[2, TestPki.utf8("com.example.app")], [17, in_app]])
    TestPki.sign_receipt(@pki, payload)
  end
end
