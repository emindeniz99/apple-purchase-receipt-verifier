# frozen_string_literal: true

require_relative "helper"
require_relative "test_pki"

# Inputs where this port was found to answer differently from the shipped
# node, java, python and swift ports, or where 0.7 changed the rule and the
# old divergence stopped applying.
#
# 0.6's lenient receipt-date grammar (timezone offsets, leap seconds,
# fractional seconds, civil-date rollover) is the reason most of this file
# used to exist. 0.7 replaced all of it with one exact grammar,
# `YYYY-MM-DDTHH:MM:SSZ` (docs/design/0.7-api.md), and anything else is kept
# raw rather than parsed leniently or rejected — there is no longer a
# port-divergent lenient parse to pin. That "kept raw" behaviour is covered
# in receipt_test.rb (`test_dates_outside_the_exact_grammar_are_kept_raw_
# not_an_error`), not here. What remains here is the BER-chunked-attribute
# parity (still a real cross-port disagreement) and the JWS `signedDate`
# numeric edge cases (still real, and 0.7 changed the answer: a `signedDate`
# no instant can hold is now "not stated", not a failure).
class PortDivergenceTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier

  def setup
    @pki = TestPki.receipt_pki
  end

  def clock
    APRV::ClockOnce.new(-> { Time.now.to_i * 1000 })
  end

  def verify_der(der, roots: [@pki.root])
    APRV::Receipt.verify([der].pack("m0"), roots, clock)
  end

  def assert_reason(reason, &)
    error = assert_raises(APRV::VerificationError, &)
    assert_equal reason, error.reason, "wrong reason: #{error.message}"
    error
  end

  # A definite-length TLV, used to build encodings OpenSSL::ASN1 will not emit.
  def tlv(tag, body)
    length =
      if body.bytesize < 0x80
        [body.bytesize].pack("C")
      else
        octets = []
        remaining = body.bytesize
        while remaining.positive?
          octets.unshift(remaining & 0xff)
          remaining >>= 8
        end
        [0x80 | octets.size].pack("C") + octets.pack("C*")
      end
    [tag].pack("C") + length + body
  end

  # Splits a DER value into a constructed (BER) OCTET STRING of two chunks —
  # the encoding `each_attribute` admits tag 0x24 for.
  def chunked_octet_string(value, at: 5)
    tlv(0x24, tlv(0x04, value.byteslice(0, at)) +
              tlv(0x04, value.byteslice(at, value.bytesize - at)))
  end

  # node concatenates the chunks (`octetStringValue`) and java does too
  # (BouncyCastle's `ASN1OctetString.getInstance(...).getOctets()`); python and
  # swift require a primitive OCTET STRING and reject. This port took node and
  # java's side — its outer double-wrap path already accepts BER chunking, and
  # `each_attribute` admits tag 0x24 in the value position for exactly this —
  # so the two BER paths have to agree with each other.
  def test_a_ber_chunked_attribute_value_reads_as_its_concatenation
    value = TestPki.utf8("com.example.app")
    attribute = tlv(0x30, TestPki.integer(2) + TestPki.integer(1) + chunked_octet_string(value))
    receipt = verify_der(TestPki.sign_receipt(@pki, tlv(0x31, attribute)))

    assert_equal "com.example.app", receipt.bundle_id
  end

  def test_a_ber_chunked_attribute_value_survives_a_single_chunk_and_an_empty_one
    value = TestPki.utf8("1.2.3")
    [tlv(0x24, tlv(0x04, value)),
     tlv(0x24, tlv(0x04, "") + tlv(0x04, value) + tlv(0x04, ""))].each do |encoded|
      attribute = tlv(0x30, TestPki.integer(3) + TestPki.integer(1) + encoded)
      payload = tlv(0x31, tlv(0x30, TestPki.integer(2) + TestPki.integer(1) +
                                    tlv(0x04, TestPki.utf8("com.example.app"))) + attribute)
      receipt = verify_der(TestPki.sign_receipt(@pki, payload))

      assert_equal "1.2.3", receipt.application_version
    end
  end

  # `octet_value` concatenates every chunk's content bytes regardless of the
  # chunk's own tag (asn1.rb): a chunk that is not itself an OCTET STRING is
  # not a structural error, it just contributes bytes that make the
  # concatenation not a well-formed value for this attribute type — kept
  # raw, same as any other attribute value this port cannot decode.
  def test_a_ber_chunked_attribute_value_with_a_non_octet_string_chunk_is_kept_raw
    bad = tlv(0x24, tlv(0x04, "ab") + tlv(0x02, "\x01".b))
    attribute = tlv(0x30, TestPki.integer(2) + TestPki.integer(1) + bad)

    receipt = verify_der(TestPki.sign_receipt(@pki, tlv(0x31, attribute)))
    assert_nil receipt.bundle_id
    assert_equal "ab\x01".b, receipt.bundle_id_bytes
  end

  # `signedDate` is a JSON number, and a JSON number is not necessarily an
  # integer. node (`typeof === 'number'`), java (`canConvertToLong`), python
  # (`isinstance(..., (int, float))`) and swift (`as? Double`) all use a
  # non-integer value; dropping it silently would judge the chain at "now"
  # instead.
  def test_a_non_integer_signed_date_still_drives_the_chain_instant
    pki = TestPki.jws_pki(not_before: Time.utc(2020, 1, 1), not_after: Time.utc(2035, 1, 1))
    jws = TestPki.sign_jws(pki, TestPki.default_claims("signedDate" => 1.5))

    error = assert_raises(APRV::VerificationError) { APRV::Jws.verify(jws, [pki.root], clock) }
    assert_equal :INVALID_CERTIFICATE, error.reason, error.message
  end

  # The claim itself is not truncated or rewritten: `json` is Apple's payload
  # text unchanged, so a caller reading `signedDate` with its own JSON
  # library sees exactly what Apple signed.
  def test_a_non_integer_signed_date_is_reported_unchanged_in_the_payload
    pki = TestPki.jws_pki
    claims = TestPki.default_claims("signedDate" => 1_722_945_600_000.0)
    jws = TestPki.sign_jws(pki, claims)

    result = APRV::Jws.verify(jws, [pki.root], clock)
    assert_in_delta 1_722_945_600_000.0, JSON.parse(result.json)["signedDate"], 0
  end

  # A JSON number can also be non-finite (`1e400` parses to Infinity) or
  # outside anything a 64-bit instant can hold. 0.7 treats every one of these
  # as "signedDate not stated" rather than a failure (owner, 2026-09-27,
  # jws.rb): the chain falls back to the configured clock, and a JWS that is
  # otherwise genuine still verifies.
  def test_a_non_finite_or_out_of_range_signed_date_falls_back_to_the_clock
    pki = TestPki.jws_pki
    ["1e400", "-1e400", "1e300", "-1e300", (2**70).to_s, (-(2**70)).to_s].each do |literal|
      claims = TestPki.default_claims.merge("signedDate" => 0)
      json = JSON.generate(claims).sub('"signedDate":0', "\"signedDate\":#{literal}")
      jws = TestPki.sign_jws(pki, claims, payload_json: json)

      result = APRV::Jws.verify(jws, [pki.root], clock)
      assert_includes result.json, "\"signedDate\":#{literal}", literal
    end
  end
end
