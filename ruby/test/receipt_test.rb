# frozen_string_literal: true

require_relative "helper"
require_relative "test_pki"
require "tempfile"

# The receipt path beyond fixtures/cases.json: CMS shapes no fixture carries,
# the attribute grammar's edges, and the two pinning properties (marker OID
# after the chain, anchors only) stated as security rules rather than vectors.
class ReceiptTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier

  def setup
    @pki = TestPki.receipt_pki
  end

  def verifier(pki: @pki, bundle_id: "com.example.app")
    APRV::ReceiptVerifier.new(trusted_roots: [pki.root], bundle_id: bundle_id)
  end

  def assert_reason(reason, &)
    error = assert_raises(APRV::VerificationError, &)
    assert_equal reason, error.reason, "wrong reason: #{error.message}"
    error
  end

  def genuine_sandbox
    TestSupport.fixture_bytes("public-receipt-sandbox-g5")
  end

  def test_verifies_the_genuine_sandbox_receipt_from_bytes_and_from_base64
    from_der = APRV::ReceiptVerifier.new(
      trusted_roots: APRV.apple_receipt_roots, bundle_id: "dev.bonzer.weeka.app"
    ).verify_der(genuine_sandbox)
    from_base64 = APRV::ReceiptVerifier.new(
      trusted_roots: APRV.apple_receipt_roots, bundle_id: "dev.bonzer.weeka.app"
    ).verify_base64([genuine_sandbox].pack("m0"))
    auto_der = APRV::ReceiptVerifier.new(
      trusted_roots: APRV.apple_receipt_roots, bundle_id: "dev.bonzer.weeka.app"
    ).verify(genuine_sandbox)
    auto_base64 = APRV::ReceiptVerifier.new(
      trusted_roots: APRV.apple_receipt_roots, bundle_id: "dev.bonzer.weeka.app"
    ).verify([genuine_sandbox].pack("m0"))

    [from_der, from_base64, auto_der, auto_base64].each do |receipt|
      assert_equal "dev.bonzer.weeka.app", receipt.bundle_id
      assert_equal 2, receipt.in_app_purchases.size
    end
  end

  def test_verifies_the_genuine_legacy_sha1_receipt
    receipt = APRV::ReceiptVerifier.new(
      trusted_roots: APRV.apple_receipt_roots, bundle_id: "com.nutcall.alert"
    ).verify_der(TestSupport.fixture_bytes("public-receipt-sandbox-legacy"))
    assert_equal 187, receipt.in_app_purchases.size
  end

  # The whole device-GUID matrix: every input form reachable with and without
  # the GUID.
  def test_device_guid_is_reachable_from_every_input_form
    guid = ["112233445566778899aabbccddeeff00"].pack("H*")
    der = TestSupport.fixture_bytes("receipt")
    subject = APRV::ReceiptVerifier.new(
      trusted_roots: [TestSupport.fixture_certificate("receipt-root")],
      bundle_id: "com.example.app"
    )
    base64 = [der].pack("m0")

    assert_equal "com.example.app", subject.verify_der(der, device_guid: guid).bundle_id
    assert_equal "com.example.app", subject.verify_base64(base64, device_guid: guid).bundle_id
    assert_equal "com.example.app", subject.verify(der, device_guid: guid).bundle_id
    assert_equal "com.example.app", subject.verify(base64, device_guid: guid).bundle_id
    assert_equal "com.example.app", subject.verify_der(der).bundle_id
    assert_equal "com.example.app", subject.verify_base64(base64).bundle_id
  end

  def test_device_hash_rejects_a_one_bit_different_guid
    guid = ["112233445566778899aabbccddeeff00"].pack("H*")
    flipped = guid.dup
    flipped.setbyte(0, flipped.getbyte(0) ^ 0x01)
    subject = APRV::ReceiptVerifier.new(
      trusted_roots: [TestSupport.fixture_certificate("receipt-root")],
      bundle_id: "com.example.app"
    )
    assert_reason(:DEVICE_HASH_MISMATCH) do
      subject.verify_der(TestSupport.fixture_bytes("receipt"), device_guid: flipped)
    end
  end

  # A missing attribute 4/5 must be a verdict, not a NoMethodError on nil.
  def test_device_hash_on_a_receipt_without_the_needed_attributes
    payload = TestPki.receipt_payload([[2, TestPki.utf8("com.example.app")]])
    der = TestPki.sign_receipt(@pki, payload)
    assert_reason(:DEVICE_HASH_MISMATCH) { verifier.verify_der(der, device_guid: "\x00" * 16) }
  end

  def test_rejects_trailing_bytes_after_the_cms_blob
    der = TestPki.sign_receipt(@pki, TestPki.default_payload)
    assert_reason(:INVALID_RECEIPT_FORMAT) { verifier.verify_der("#{der}\x00") }
    assert_reason(:INVALID_RECEIPT_FORMAT) { verifier.verify_der("#{der}junk") }
  end

  def test_rejects_zero_and_two_signer_infos
    der = TestPki.sign_receipt(@pki, TestPki.default_payload)
    assert_reason(:INVALID_RECEIPT_FORMAT) { verifier.verify_der(TestPki.without_signer_infos(der)) }
    assert_reason(:INVALID_RECEIPT_FORMAT) do
      verifier.verify_der(TestPki.with_duplicated_signer_info(der))
    end
  end

  def test_rejects_an_ec_signer_key
    key = TestPki.ec_key
    pki = TestPki.receipt_pki(leaf_key: key)
    der = TestPki.sign_receipt(pki, TestPki.default_payload)
    assert_reason(:INVALID_SIGNATURE) { verifier(pki: pki).verify_der(der) }
  end

  # An allow-list, not a deny-list: a digest nobody reviewed cannot arrive by
  # way of a new OpenSSL release.
  def test_rejects_a_digest_outside_sha1_and_sha256
    der = TestPki.sign_receipt_with_digest(@pki, TestPki.default_payload, "SHA512")
    assert_reason(:INVALID_RECEIPT_FORMAT) { verifier.verify_der(der) }
  end

  def test_rejects_a_signer_certificate_that_is_not_embedded
    der = OpenSSL::PKCS7.sign(
      @pki.leaf, @pki.leaf_key, TestPki.default_payload, [@pki.intermediate, @pki.root],
      OpenSSL::PKCS7::BINARY | OpenSSL::PKCS7::NOCERTS
    ).to_der
    assert_reason(:INVALID_RECEIPT_FORMAT) { verifier.verify_der(der) }
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
    assert_reason(:INVALID_RECEIPT_FORMAT) { verifier.verify_der(der) }
  end

  # PLAN D13: the marker OID is checked AFTER the chain, so a foreign chain
  # still reports INVALID_CHAIN. The JWS path is deliberately the opposite.
  def test_chain_is_reported_before_the_signer_marker_oid
    foreign = TestPki.receipt_pki(leaf_oids: [])
    der = TestPki.sign_receipt(foreign, TestPki.default_payload)
    assert_reason(:INVALID_CHAIN) { verifier.verify_der(der) }
    assert_reason(:INVALID_CERTIFICATE_PURPOSE) { verifier(pki: foreign).verify_der(der) }
  end

  def test_attribute_integers_at_the_edges
    eight = OpenSSL::ASN1::Integer.new(2**56).to_der
    nine = OpenSSL::ASN1::Integer.new(2**64).to_der
    negative = OpenSSL::ASN1::Integer.new(-1).to_der

    accepted = in_app_receipt([[1711, eight]])
    assert_equal 2**56, verifier.verify_der(accepted).in_app_purchases[0].web_order_line_item_id

    [nine, negative].each do |value|
      assert_reason(:INVALID_RECEIPT_FORMAT) { verifier.verify_der(in_app_receipt([[1711, value]])) }
    end
  end

  # Cross-port decision C5: an attribute type above 2^31-1 is rejected, never
  # clamped onto a sentinel and filed under unknown attributes.
  def test_rejects_an_attribute_type_above_the_32_bit_signed_range
    payload = TestPki.receipt_payload([[2**31, TestPki.utf8("x")]])
    assert_reason(:INVALID_RECEIPT_FORMAT) { verifier.verify_der(TestPki.sign_receipt(@pki, payload)) }

    ok = TestPki.receipt_payload([[(2**31) - 1, TestPki.utf8("x")],
                                  [2, TestPki.utf8("com.example.app")]])
    receipt = verifier.verify_der(TestPki.sign_receipt(@pki, ok))
    assert_equal(["x"], receipt.unknown_attributes[(2**31) - 1].map { |v| v[2..] })
  end

  def test_rejects_dates_without_a_timezone_designator_or_out_of_range
    ["2024-08-06T12:00:00", "2024-08-06 12:00:00Z", "0000-00-00T00:00:00Z", "not a date"]
      .each do |text|
      payload = TestPki.receipt_payload([[2, TestPki.utf8("com.example.app")],
                                         [12, TestPki.ia5(text)]])
      assert_reason(:INVALID_RECEIPT_FORMAT) { verifier.verify_der(TestPki.sign_receipt(@pki, payload)) }
    end
  end

  def test_an_empty_date_string_means_absent
    payload = TestPki.receipt_payload([[2, TestPki.utf8("com.example.app")],
                                       [21, TestPki.ia5("")]])
    receipt = verifier.verify_der(TestPki.sign_receipt(@pki, payload))
    assert_nil receipt.expiration_date
  end

  def test_rejects_an_attribute_value_that_is_not_valid_utf8
    payload = TestPki.receipt_payload([[2, "\x0c\x02\xff\xfe".b]])
    assert_reason(:INVALID_RECEIPT_FORMAT) { verifier.verify_der(TestPki.sign_receipt(@pki, payload)) }
  end

  def test_rejects_a_string_attribute_whose_value_is_the_wrong_asn1_type
    payload = TestPki.receipt_payload([[2, TestPki.integer(7)]])
    assert_reason(:INVALID_RECEIPT_FORMAT) { verifier.verify_der(TestPki.sign_receipt(@pki, payload)) }
  end

  def test_verify_receipt_core_skips_the_bundle_id_check
    payload = TestPki.default_payload(bundle_id: "com.somebody.else")
    der = TestPki.sign_receipt(@pki, payload)
    receipt = APRV.verify_receipt_core(der, trusted_roots: [@pki.root])
    assert_equal "com.somebody.else", receipt.bundle_id
    assert_reason(:WRONG_BUNDLE_ID) { verifier.verify_der(der) }
  end

  # Cross-port rule S13: byte fields handed back are copies, so a caller
  # reusing its input buffer cannot mutate an already-verified receipt.
  def test_byte_fields_are_frozen_copies_of_the_input
    der = TestSupport.fixture_bytes("receipt").dup
    receipt = APRV.verify_receipt_core(
      der, trusted_roots: [TestSupport.fixture_certificate("receipt-root")]
    )
    before = receipt.opaque_value.dup
    assert_predicate receipt.opaque_value, :frozen?
    assert_predicate receipt.sha1_hash, :frozen?
    der.bytesize.times { |i| der.setbyte(i, 0) }
    assert_equal before, receipt.opaque_value
  end

  def test_receipt_dates_are_times_and_are_utc
    receipt = APRV.verify_receipt_core(
      TestSupport.fixture_bytes("receipt"),
      trusted_roots: [TestSupport.fixture_certificate("receipt-root")]
    )
    assert_kind_of Time, receipt.creation_date
    assert_predicate receipt.creation_date, :utc?
    assert_kind_of Time, receipt.in_app_purchases[0].purchase_date
  end

  def test_a_receipt_with_no_creation_date_is_judged_at_the_system_clock
    payload = TestPki.default_payload(creation_date: nil)
    receipt = verifier.verify_der(TestPki.sign_receipt(@pki, payload))
    assert_nil receipt.creation_date

    expired = TestPki.receipt_pki(not_before: Time.utc(2020, 1, 1), not_after: Time.utc(2021, 1, 1))
    der = TestPki.sign_receipt(expired, payload)
    assert_reason(:INVALID_CHAIN) { verifier(pki: expired).verify_der(der) }
  end

  # A trust anchor is trusted by fiat: its own validity window is not examined.
  # The historical-receipt conformance case depends on this.
  def test_an_anchor_is_not_rejected_for_being_expired
    pki = TestPki.receipt_pki(not_before: Time.utc(2020, 1, 1), not_after: Time.utc(2021, 1, 1))
    payload = TestPki.default_payload(creation_date: "2020-06-01T00:00:00Z")
    der = TestPki.sign_receipt(pki, payload)
    assert_equal "com.example.app", verifier(pki: pki).verify_der(der).bundle_id
  end

  def test_rejects_input_that_is_not_a_string_or_is_empty
    [nil, 42, [], ""].each do |bad|
      assert_reason(:INVALID_RECEIPT_FORMAT) { verifier.verify(bad) }
    end
  end

  def test_rejects_bytes_that_are_not_a_cms_blob
    assert_reason(:INVALID_RECEIPT_FORMAT) { verifier.verify_der("\x30\x03\x02\x01\x01".b) }
    assert_reason(:INVALID_RECEIPT_FORMAT) { verifier.verify_der("hello world") }
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
