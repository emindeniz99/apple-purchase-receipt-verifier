# frozen_string_literal: true

require_relative "helper"
require_relative "test_pki"

# Inputs where this port was found to answer differently from the shipped
# node, java, python and swift ports. Nothing in fixtures/cases.json reaches
# them — every fixture date ends in `Z`, and no fixture encodes an attribute
# value as a BER-chunked OCTET STRING — so they are pinned here instead.
#
# Each test names the ports it is holding this port to. Where the four shipped
# ports disagree among themselves the test pins the fail-closed answer and
# says so, rather than inventing a fifth behaviour.
class PortDivergenceTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier

  def setup
    @pki = TestPki.receipt_pki
  end

  def verifier
    APRV::ReceiptVerifier.new(trusted_roots: [@pki.root], bundle_id: "com.example.app")
  end

  def assert_reason(reason, &)
    error = assert_raises(APRV::VerificationError, &)
    assert_equal reason, error.reason, "wrong reason: #{error.message}"
    error
  end

  def receipt_with(attributes)
    TestPki.sign_receipt(@pki, TestPki.receipt_payload(attributes))
  end

  def date_receipt(text)
    receipt_with([[2, TestPki.utf8("com.example.app")], [12, TestPki.ia5(text)]])
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
    receipt = verifier.verify_der(TestPki.sign_receipt(@pki, tlv(0x31, attribute)))

    assert_equal "com.example.app", receipt.bundle_id
  end

  def test_a_ber_chunked_attribute_value_survives_a_single_chunk_and_an_empty_one
    value = TestPki.utf8("1.2.3")
    [tlv(0x24, tlv(0x04, value)),
     tlv(0x24, tlv(0x04, "") + tlv(0x04, value) + tlv(0x04, ""))].each do |encoded|
      attribute = tlv(0x30, TestPki.integer(3) + TestPki.integer(1) + encoded)
      payload = tlv(0x31, tlv(0x30, TestPki.integer(2) + TestPki.integer(1) +
                                    tlv(0x04, TestPki.utf8("com.example.app"))) + attribute)
      receipt = verifier.verify_der(TestPki.sign_receipt(@pki, payload))

      assert_equal "1.2.3", receipt.app_version
    end
  end

  # The chunks are still bounded ASN.1: a chunk that is not an OCTET STRING,
  # or a value that is not a chunk container at all, stays a format error.
  def test_a_ber_chunked_attribute_value_is_still_parsed_strictly
    bad = tlv(0x24, tlv(0x04, "ab") + tlv(0x02, "\x01".b))
    attribute = tlv(0x30, TestPki.integer(2) + TestPki.integer(1) + bad)

    assert_reason(:INVALID_RECEIPT_FORMAT) do
      verifier.verify_der(TestPki.sign_receipt(@pki, tlv(0x31, attribute)))
    end
  end

  # The offset is arithmetic on the chain-validity instant, so an unchecked
  # one moves it by days. node, java, python and swift all reject an offset
  # whose hour field is 24 or more; node, java and swift also reject a minute
  # field of 60 or more (python accepts it, being the outlier).
  def test_rejects_a_timezone_offset_outside_a_real_one
    ["2024-08-06T12:00:00+99:99", "2024-08-06T12:00:00-45:00",
     "2024-08-06T12:00:00+24:00", "2024-08-06T12:00:00+00:99"].each do |text|
      assert_reason(:INVALID_RECEIPT_FORMAT) { verifier.verify_der(date_receipt(text)) }
    end
  end

  def test_accepts_the_largest_real_timezone_offsets
    { "2024-08-06T12:00:00+14:00" => Time.utc(2024, 8, 5, 22, 0, 0),
      "2024-08-06T12:00:00-12:00" => Time.utc(2024, 8, 7, 0, 0, 0),
      "2024-08-06T12:00:00+23:59" => Time.utc(2024, 8, 5, 12, 1, 0) }.each do |text, expected|
      assert_equal expected, verifier.verify_der(date_receipt(text)).creation_date
    end
  end

  # A leap second: node, python and swift reject it; java clamps it back to
  # :59. This port used to roll it FORWARD to the next minute, which is the
  # one answer no other port gives. Rejecting is the fail-closed choice and
  # matches three of the four.
  def test_rejects_a_leap_second
    assert_reason(:INVALID_RECEIPT_FORMAT) { verifier.verify_der(date_receipt("2024-06-30T23:59:60Z")) }
  end

  # An ambiguity the shipped ports do not resolve, pinned so it is a decision
  # rather than an accident: an overflowing day (February 30th) rolls forward
  # in node and here, and is rejected by java and python. Two against two, and
  # this port already matched node, so it keeps matching node. The same holds
  # for hour 24, which every port but python reads as the following midnight.
  def test_an_overflowing_day_rolls_forward_the_way_node_does
    { "2024-02-30T00:00:00Z" => Time.utc(2024, 3, 1),
      "2024-08-06T24:00:00Z" => Time.utc(2024, 8, 7) }.each do |text, expected|
      assert_equal expected, verifier.verify_der(date_receipt(text)).creation_date
    end
  end

  # The components around those two stay refused, which is what keeps the
  # rolling narrow.
  def test_out_of_range_date_components_are_still_refused
    ["2024-08-06T25:00:00Z", "2024-08-06T12:60:00Z", "2024-13-06T12:00:00Z",
     "2024-00-06T12:00:00Z", "2024-08-00T12:00:00Z"].each do |text|
      assert_reason(:INVALID_RECEIPT_FORMAT) { verifier.verify_der(date_receipt(text)) }
    end
  end

  # Fractional seconds are kept, but only to the nanosecond — the finest
  # precision any port represents (java's `Instant.parse` ceiling; node
  # truncates to milliseconds and python to microseconds). Digits past that
  # are dropped rather than turned into an exact Rational, which is what made
  # a long fraction superlinear.
  def test_keeps_fractional_seconds_to_the_nanosecond_and_drops_the_rest
    exact = verifier.verify_der(date_receipt("2024-08-06T12:00:00.123456789Z")).creation_date

    assert_equal 123_456_789, exact.nsec
    assert_equal Time.utc(2024, 8, 6, 12, 0, 0).to_i, exact.to_i

    truncated = verifier.verify_der(date_receipt("2024-08-06T12:00:00.1234567891Z")).creation_date

    assert_equal 123_456_789, truncated.nsec

    short = verifier.verify_der(date_receipt("2024-08-06T12:00:00.5Z")).creation_date

    assert_equal 500_000_000, short.nsec

    long = verifier.verify_der(date_receipt("2024-08-06T12:00:00.#{"1" * 5_000}Z")).creation_date

    assert_equal 111_111_111, long.nsec
  end

  # `signedDate` and `receiptCreationDate` are JSON numbers, and a JSON number
  # is not necessarily an integer. node (`typeof === 'number'`), java
  # (`canConvertToLong`), python (`isinstance(..., (int, float))`) and swift
  # (`as? Double`) all use a non-integer value; dropping it silently would
  # judge the chain at "now" instead and skip the staleness check entirely.
  def test_a_non_integer_signed_date_still_drives_the_chain_instant
    pki = TestPki.jws_pki(not_before: Time.utc(2020, 1, 1), not_after: Time.utc(2035, 1, 1))
    verifier = APRV::JwsVerifier.new(trusted_roots: [pki.root], bundle_id: "com.example.app",
                                     accepted_environments: [APRV::Environment::SANDBOX])
    jws = TestPki.sign_jws(pki, TestPki.default_claims("signedDate" => 1.5))

    error = assert_raises(APRV::VerificationError) { verifier.verify_transaction(jws) }
    assert_equal :INVALID_CHAIN, error.reason, error.message
  end

  # The staleness rule is step 11 for all three JWS operations, and a claim
  # this port declined to read meant it never ran at all.
  #
  # `TransactionPayload#signed_date` still reads `nil` here: the payload models
  # Apple's wire contract, where these claims are Integer epoch milliseconds,
  # and a claim of an unexpected JSON type reads as nil rather than being
  # coerced (the same policy every other reader on that class follows). What
  # changed is the verifier, which now judges and ages the payload at the
  # stated instant like the other four ports.
  def test_a_non_integer_signed_date_is_reported_and_ages
    pki = TestPki.jws_pki
    claims = TestPki.default_claims("signedDate" => 1_722_945_600_000.0)
    jws = TestPki.sign_jws(pki, claims)

    fresh = APRV::JwsVerifier.new(trusted_roots: [pki.root], bundle_id: "com.example.app",
                                  accepted_environments: [APRV::Environment::SANDBOX],
                                  max_signed_age_seconds: 60,
                                  clock: -> { Time.at(1_722_945_600) })
    assert_in_delta 1_722_945_600_000.0, fresh.verify_transaction(jws)["signedDate"], 0

    stale = APRV::JwsVerifier.new(trusted_roots: [pki.root], bundle_id: "com.example.app",
                                  accepted_environments: [APRV::Environment::SANDBOX],
                                  max_signed_age_seconds: 60,
                                  clock: -> { Time.at(1_722_945_600 + 3_600) })
    error = assert_raises(APRV::VerificationError) { stale.verify_transaction(jws) }
    assert_equal :STALE_PAYLOAD, error.reason, error.message
  end

  # A JSON number can also be non-finite (`1e400` parses to Infinity) or
  # outside anything Time can hold. Those must stay VerificationErrors rather
  # than escaping as FloatDomainError or RangeError.
  def test_a_non_finite_or_out_of_range_signed_date_stays_a_verification_error
    pki = TestPki.jws_pki
    verifier = APRV::JwsVerifier.new(trusted_roots: [pki.root], bundle_id: "com.example.app",
                                     accepted_environments: [APRV::Environment::SANDBOX])
    ["1e400", "-1e400", "1e300", "-1e300", (2**70).to_s, (-(2**70)).to_s,
     "0", "-1"].each do |literal|
      claims = TestPki.default_claims.merge("signedDate" => 0)
      json = JSON.generate(claims).sub('"signedDate":0', "\"signedDate\":#{literal}")
      jws = TestPki.sign_jws(pki, claims, payload_json: json)
      error = assert_raises(APRV::VerificationError) { verifier.verify_transaction(jws) }

      assert_includes APRV::Reason::ALL, error.reason, "unmapped reason for #{literal}"
    end
  end
end
