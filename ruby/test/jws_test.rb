# frozen_string_literal: true

require_relative "helper"
require_relative "test_pki"

# The JWS path beyond what fixtures/cases.json pins: shapes the shared
# vectors have no fixture for, and the exact check order the cross-port
# contract makes observable. 0.7 takes no bundle id, accepted-environment set
# or app Apple id (docs/design/0.7-api.md): the JWS verifies and the caller
# reads those claims off the returned payload itself.
class JwsTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier

  def setup
    @pki = TestPki.jws_pki
  end

  def verifier(pki: @pki)
    APRV::Verifier.create(APRV::Config.new(roots: [pki.root]))
  end

  def claims_of(jws, pki: @pki)
    result = verifier(pki: pki).verify_signed_data(jws)
    unless result.verified?
      raise "expected #{jws.inspect} to verify: #{result.failure&.reason} (#{result.failure&.message})"
    end

    JSON.parse(result.payload.json)
  end

  def assert_reason(reason, jws, pki: @pki)
    result = verifier(pki: pki).verify_signed_data(jws)
    refute_predicate result, :verified?, "expected #{reason} but it verified"
    assert_equal reason, result.failure.reason, "wrong reason: #{result.failure.message}"
  end

  RootOnly = Struct.new(:root)
  private_constant :RootOnly

  def test_verifies_the_apple_official_transaction_info_mock
    jws = TestSupport.fixture_bytes("apple-transaction-info").dup.force_encoding(Encoding::UTF_8)
    claims = claims_of(jws, pki: RootOnly.new(TestSupport.fixture_certificate("apple-test-ca")))
    assert_equal "com.example", claims["bundleId"]
    assert_equal 1_672_956_154_000, claims["signedDate"]
  end

  def test_rejects_a_non_es256_alg
    jws = TestPki.sign_jws(@pki, TestPki.default_claims, header_overrides: { "alg" => "RS256" })
    assert_reason(:MALFORMED, jws)
  end

  def test_rejects_x5c_with_two_or_four_entries
    two = [@pki.leaf, @pki.intermediate].map { |c| [c.to_der].pack("m0") }
    four = [@pki.leaf, @pki.intermediate, @pki.root, @pki.root].map { |c| [c.to_der].pack("m0") }
    [two, four].each do |x5c|
      jws = TestPki.sign_jws(@pki, TestPki.default_claims, header_overrides: { "x5c" => x5c })
      assert_reason(:MALFORMED, jws)
    end
  end

  def test_rejects_x5c_entries_that_are_not_strings
    [[1, 2, 3], [{ "a" => 1 }, "b", "c"], [%w[a], "b", "c"]].each do |x5c|
      jws = TestPki.sign_jws(@pki, TestPki.default_claims, header_overrides: { "x5c" => x5c })
      assert_reason(:MALFORMED, jws)
    end
  end

  def test_rejects_an_x5c_entry_that_is_base64_but_not_a_certificate
    x5c = [["not a certificate" * 4].pack("m0")] +
          [@pki.intermediate, @pki.root].map { |c| [c.to_der].pack("m0") }
    jws = TestPki.sign_jws(@pki, TestPki.default_claims, header_overrides: { "x5c" => x5c })
    assert_reason(:INVALID_CERTIFICATE, jws)
  end

  # RFC 5280 4.2 forbids a second instance of any extension, and OpenSSL hands
  # the list back with both copies in it rather than objecting — so every
  # reader downstream picks one, and which one it picks is not stated
  # anywhere. The leaf's own extension list is rebuilt here with a
  # byte-identical second copy of its first extension; the certificate's
  # signature is stale afterwards and nothing reaches it, because the x5c
  # entries are decoded before any chain or signature check.
  def test_rejects_an_x5c_certificate_carrying_one_extension_twice
    cert = OpenSSL::ASN1.decode(@pki.leaf.to_der)
    holder = cert.value[0].value.find do |field|
      field.is_a?(OpenSSL::ASN1::ASN1Data) && field.tag_class == :CONTEXT_SPECIFIC && field.tag == 3
    end
    list = holder.value[0]
    list.value += [list.value[0]]
    duplicated = cert.to_der

    # The premise: OpenSSL takes the certificate and reports both copies.
    oids = OpenSSL::X509::Certificate.new(duplicated).extensions.map(&:oid)
    assert_equal oids.size, oids.uniq.size + 1

    x5c = [duplicated, @pki.intermediate.to_der, @pki.root.to_der].map { |der| [der].pack("m0") }
    jws = TestPki.sign_jws(@pki, TestPki.default_claims, header_overrides: { "x5c" => x5c })
    assert_reason(:INVALID_CERTIFICATE, jws)
  end

  def test_rejects_a_segment_outside_the_base64url_alphabet
    jws = TestPki.sign_jws(@pki, TestPki.default_claims)
    header, payload, signature = jws.split(".")
    ["#{header}+", "#{header}/", "#{header}="].each do |bad|
      assert_reason(:MALFORMED, "#{bad}.#{payload}.#{signature}")
    end
  end

  def test_rejects_a_segment_that_is_base64url_but_not_json
    jws = TestPki.sign_jws(@pki, TestPki.default_claims)
    _, payload, signature = jws.split(".")
    garbage = TestPki.base64url("not json at all")
    assert_reason(:MALFORMED, "#{garbage}.#{payload}.#{signature}")
  end

  # A payload that is not a JSON object is carried past the signature check
  # (docs/design/0.7-api.md): with a made-up 64-byte signature it fails as
  # INVALID_SIGNATURE, never as a format error.
  def test_rejects_a_payload_that_is_json_but_not_an_object
    header = TestPki.base64url(JSON.generate({
                                               "alg" => "ES256",
                                               "x5c" => [@pki.leaf, @pki.intermediate, @pki.root].map do |c|
                                                 [c.to_der].pack("m0")
                                               end
                                             }))
    ["[1,2,3]", "\"a string\"", "42", "null"].each do |json|
      body = TestPki.base64url(json)
      assert_reason(:INVALID_SIGNATURE, "#{header}.#{body}.#{TestPki.base64url("x" * 64)}")
    end
  end

  def test_rejects_a_leaf_without_the_apple_marker_oid
    pki = TestPki.jws_pki(leaf_oids: [])
    jws = TestPki.sign_jws(pki, TestPki.default_claims)
    assert_reason(:INVALID_CERTIFICATE_PURPOSE, jws, pki: pki)
  end

  def test_rejects_an_intermediate_without_the_wwdr_marker_oid
    pki = TestPki.jws_pki(intermediate_oids: [])
    jws = TestPki.sign_jws(pki, TestPki.default_claims)
    assert_reason(:INVALID_CERTIFICATE_PURPOSE, jws, pki: pki)
  end

  # The chain is checked BEFORE the marker OIDs on the JWS path in 0.7
  # (docs/design/0.7-api.md: "the chain comes before the markers"), the
  # opposite of 0.6: a chain to a foreign root whose certificates lack the
  # markers is UNTRUSTED_CHAIN, not INVALID_CERTIFICATE_PURPOSE.
  def test_chain_is_reported_before_the_marker_oid
    pki = TestPki.jws_pki(leaf_oids: [])
    other = TestPki.jws_pki
    jws = TestPki.sign_jws(pki, TestPki.default_claims)
    assert_reason(:UNTRUSTED_CHAIN, jws, pki: other)
  end

  def test_rejects_an_intermediate_that_is_not_a_ca
    pki = TestPki.jws_pki(intermediate_ca: false)
    jws = TestPki.sign_jws(pki, TestPki.default_claims)
    assert_reason(:UNTRUSTED_CHAIN, jws, pki: pki)
  end

  def test_rejects_signatures_that_are_not_sixty_four_bytes
    jws = TestPki.sign_jws(@pki, TestPki.default_claims)
    header, payload, signature = jws.split(".")
    raw = signature.tr("-_", "+/").then { |s| s + ("=" * ((4 - (s.bytesize % 4)) % 4)) }.unpack1("m0")
    [raw.byteslice(0, 63), "#{raw}\x00"].each do |bad|
      assert_reason(:INVALID_SIGNATURE, "#{header}.#{payload}.#{TestPki.base64url(bad)}")
    end
  end

  def test_rejects_a_signature_whose_scalars_are_zero_or_out_of_range
    jws = TestPki.sign_jws(@pki, TestPki.default_claims)
    header, payload, = jws.split(".")
    order = ["ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"].pack("H*")
    [("\x00" * 64).b, ("\x01" * 32) + ("\x00" * 32), order + order].each do |bad|
      assert_reason(:INVALID_SIGNATURE, "#{header}.#{payload}.#{TestPki.base64url(bad)}")
    end
  end

  def test_rejects_a_tampered_payload
    jws = TestPki.sign_jws(@pki, TestPki.default_claims)
    header, _, signature = jws.split(".")
    forged = TestPki.base64url(JSON.generate(TestPki.default_claims("quantity" => 99)))
    assert_reason(:INVALID_SIGNATURE, "#{header}.#{forged}.#{signature}")
  end

  def test_x5c_third_element_is_ignored
    other = TestPki.jws_pki
    x5c = [@pki.leaf, @pki.intermediate, other.root].map { |c| [c.to_der].pack("m0") }
    jws = TestPki.sign_jws(@pki, TestPki.default_claims, header_overrides: { "x5c" => x5c })
    assert_equal "com.example.app", claims_of(jws)["bundleId"]
  end

  # No claim is enforced: the caller reads bundleId, environment and the app
  # Apple id off the returned payload itself.
  def test_no_claim_is_enforced_only_the_signature
    jws = TestPki.sign_jws(@pki, TestPki.default_claims("bundleId" => "com.somebody.else",
                                                        "environment" => "Production"))
    claims = claims_of(jws)
    assert_equal "com.somebody.else", claims["bundleId"]
    assert_equal "Production", claims["environment"]

    header, payload, = jws.split(".")
    assert_reason(:INVALID_SIGNATURE, "#{header}.#{payload}.#{TestPki.base64url("\x01" * 64)}")
  end

  def test_dates_are_epoch_millisecond_numbers_not_strings
    jws = TestPki.sign_jws(@pki, TestPki.default_claims("expiresDate" => 1_896_168_600_000,
                                                        "purchaseDate" => 1_722_945_600_000))
    claims = claims_of(jws)
    %w[signedDate expiresDate purchaseDate].each { |key| assert_kind_of Numeric, claims[key] }
    assert_equal 1_896_168_600_000, claims["expiresDate"]
  end

  def test_json_exposes_every_claim_unchanged_including_ones_this_library_does_not_model
    jws = TestPki.sign_jws(@pki, TestPki.default_claims("somethingAppleAddsLater" => "x"))
    assert_equal "x", claims_of(jws)["somethingAppleAddsLater"]
  end

  def test_the_json_payload_is_frozen
    jws = TestPki.sign_jws(@pki, TestPki.default_claims)
    result = verifier.verify_signed_data(jws)
    assert_predicate result.payload, :frozen?
  end

  def test_rejects_inputs_that_are_not_three_segments
    ["", "a", "a.b", "a.b.c.d", "....", "a.b.c."].each { |bad| assert_reason(:MALFORMED, bad) }
  end

  def test_rejects_a_non_string_input
    [nil, 42, [], { "a" => 1 }].each { |bad| assert_reason(:MALFORMED, bad) }
  end
end
