# frozen_string_literal: true

require_relative "helper"
require_relative "test_pki"

# The JWS path beyond what fixtures/cases.json pins: shapes the shared vectors
# have no fixture for, and the exact check order the cross-port contract makes
# observable.
class JwsTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier

  def setup
    @pki = TestPki.jws_pki
  end

  def verifier(pki: @pki, **overrides)
    APRV::JwsVerifier.new(trusted_roots: [pki.root],
                          bundle_id: "com.example.app",
                          accepted_environments: [APRV::Environment::SANDBOX], **overrides)
  end

  def assert_reason(reason, &)
    error = assert_raises(APRV::VerificationError, &)
    assert_equal reason, error.reason, "wrong reason: #{error.message}"
    error
  end

  def test_verifies_the_apple_official_transaction_info_mock
    jws = TestSupport.fixture_bytes("apple-transaction-info").force_encoding(Encoding::UTF_8)
    payload = APRV::JwsVerifier.new(
      trusted_roots: [TestSupport.fixture_certificate("apple-test-ca")],
      bundle_id: "com.example",
      accepted_environments: [APRV::Environment::SANDBOX]
    ).verify_transaction(jws)
    assert_equal "com.example", payload.bundle_id
    assert_equal 1_672_956_154_000, payload.signed_date
    assert_kind_of Integer, payload.signed_date
  end

  def test_rejects_a_non_es256_alg
    jws = TestPki.sign_jws(@pki, TestPki.default_claims, header_overrides: { "alg" => "RS256" })
    assert_reason(:INVALID_JWS_FORMAT) { verifier.verify_transaction(jws) }
  end

  def test_rejects_x5c_with_two_or_four_entries
    two = [@pki.leaf, @pki.intermediate].map { |c| [c.to_der].pack("m0") }
    four = [@pki.leaf, @pki.intermediate, @pki.root, @pki.root].map { |c| [c.to_der].pack("m0") }
    [two, four].each do |x5c|
      jws = TestPki.sign_jws(@pki, TestPki.default_claims, header_overrides: { "x5c" => x5c })
      assert_reason(:INVALID_JWS_FORMAT) { verifier.verify_transaction(jws) }
    end
  end

  def test_rejects_x5c_entries_that_are_not_strings
    [[1, 2, 3], [{ "a" => 1 }, "b", "c"], [%w[a], "b", "c"]].each do |x5c|
      jws = TestPki.sign_jws(@pki, TestPki.default_claims, header_overrides: { "x5c" => x5c })
      assert_reason(:INVALID_JWS_FORMAT) { verifier.verify_transaction(jws) }
    end
  end

  def test_rejects_an_x5c_entry_that_is_base64_but_not_a_certificate
    x5c = [["not a certificate" * 4].pack("m0")] +
          [@pki.intermediate, @pki.root].map { |c| [c.to_der].pack("m0") }
    jws = TestPki.sign_jws(@pki, TestPki.default_claims, header_overrides: { "x5c" => x5c })
    assert_reason(:INVALID_CERTIFICATE) { verifier.verify_transaction(jws) }
  end

  def test_rejects_a_segment_outside_the_base64url_alphabet
    jws = TestPki.sign_jws(@pki, TestPki.default_claims)
    header, payload, signature = jws.split(".")
    ["#{header}+", "#{header}/", "#{header}="].each do |bad|
      assert_reason(:INVALID_JWS_FORMAT) do
        verifier.verify_transaction("#{bad}.#{payload}.#{signature}")
      end
    end
  end

  def test_rejects_a_segment_that_is_base64url_but_not_json
    jws = TestPki.sign_jws(@pki, TestPki.default_claims)
    _, payload, signature = jws.split(".")
    garbage = TestPki.base64url("not json at all")
    assert_reason(:INVALID_JWS_FORMAT) { verifier.verify_transaction("#{garbage}.#{payload}.#{signature}") }
  end

  def test_rejects_a_payload_that_is_json_but_not_an_object
    header = TestPki.base64url(JSON.generate({
                                               "alg" => "ES256",
                                               "x5c" => [@pki.leaf, @pki.intermediate, @pki.root].map do |c|
                                                 [c.to_der].pack("m0")
                                               end
                                             }))
    ["[1,2,3]", "\"a string\"", "42", "null"].each do |json|
      body = TestPki.base64url(json)
      assert_reason(:INVALID_JWS_FORMAT) do
        verifier.verify_transaction("#{header}.#{body}.#{TestPki.base64url("x" * 64)}")
      end
    end
  end

  def test_rejects_a_leaf_without_the_apple_marker_oid
    pki = TestPki.jws_pki(leaf_oids: [])
    jws = TestPki.sign_jws(pki, TestPki.default_claims)
    assert_reason(:INVALID_CERTIFICATE_PURPOSE) { verifier(pki: pki).verify_transaction(jws) }
  end

  def test_rejects_an_intermediate_without_the_wwdr_marker_oid
    pki = TestPki.jws_pki(intermediate_oids: [])
    jws = TestPki.sign_jws(pki, TestPki.default_claims)
    assert_reason(:INVALID_CERTIFICATE_PURPOSE) { verifier(pki: pki).verify_transaction(jws) }
  end

  # The marker OIDs are checked BEFORE the chain on the JWS path, so a payload
  # that is wrong in both ways reports the purpose, not the chain. The receipt
  # path is deliberately the opposite; receipt_test.rb pins that side.
  def test_marker_oid_is_reported_before_the_chain
    pki = TestPki.jws_pki(leaf_oids: [])
    other = TestPki.jws_pki
    jws = TestPki.sign_jws(pki, TestPki.default_claims)
    assert_reason(:INVALID_CERTIFICATE_PURPOSE) { verifier(pki: other).verify_transaction(jws) }
  end

  def test_rejects_an_intermediate_that_is_not_a_ca
    pki = TestPki.jws_pki(intermediate_ca: false)
    jws = TestPki.sign_jws(pki, TestPki.default_claims)
    assert_reason(:INVALID_CHAIN) { verifier(pki: pki).verify_transaction(jws) }
  end

  def test_rejects_signatures_that_are_not_sixty_four_bytes
    jws = TestPki.sign_jws(@pki, TestPki.default_claims)
    header, payload, signature = jws.split(".")
    raw = signature.tr("-_", "+/").then { |s| s + ("=" * ((4 - (s.bytesize % 4)) % 4)) }.unpack1("m0")
    [raw.byteslice(0, 63), "#{raw}\x00"].each do |bad|
      assert_reason(:INVALID_SIGNATURE) do
        verifier.verify_transaction("#{header}.#{payload}.#{TestPki.base64url(bad)}")
      end
    end
  end

  def test_rejects_a_signature_whose_scalars_are_zero_or_out_of_range
    jws = TestPki.sign_jws(@pki, TestPki.default_claims)
    header, payload, = jws.split(".")
    order = ["ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"].pack("H*")
    [("\x00" * 64).b, ("\x01" * 32) + ("\x00" * 32), order + order].each do |bad|
      assert_reason(:INVALID_SIGNATURE) do
        verifier.verify_transaction("#{header}.#{payload}.#{TestPki.base64url(bad)}")
      end
    end
  end

  def test_rejects_a_tampered_payload
    jws = TestPki.sign_jws(@pki, TestPki.default_claims)
    header, _, signature = jws.split(".")
    forged = TestPki.base64url(JSON.generate(TestPki.default_claims("quantity" => 99)))
    assert_reason(:INVALID_SIGNATURE) { verifier.verify_transaction("#{header}.#{forged}.#{signature}") }
  end

  def test_x5c_third_element_is_ignored
    other = TestPki.jws_pki
    x5c = [@pki.leaf, @pki.intermediate, other.root].map { |c| [c.to_der].pack("m0") }
    jws = TestPki.sign_jws(@pki, TestPki.default_claims, header_overrides: { "x5c" => x5c })
    assert_equal "com.example.app", verifier.verify_transaction(jws).bundle_id
  end

  def test_verify_raw_skips_claim_checks_but_not_the_signature
    jws = TestPki.sign_jws(@pki, TestPki.default_claims("bundleId" => "com.somebody.else",
                                                        "environment" => "Production"))
    claims = verifier.verify_raw(jws)
    assert_equal "com.somebody.else", claims["bundleId"]

    header, payload, = jws.split(".")
    assert_reason(:INVALID_SIGNATURE) do
      verifier.verify_raw("#{header}.#{payload}.#{TestPki.base64url("\x01" * 64)}")
    end
  end

  def test_production_app_transaction_requires_a_matching_app_apple_id
    claims = { "bundleId" => "com.example.app", "receiptType" => "Production",
               "appAppleId" => 123_456_789, "receiptCreationDate" => 1_722_945_600_000 }
    jws = TestPki.sign_jws(@pki, claims)
    production = { accepted_environments: [APRV::Environment::PRODUCTION] }

    assert_reason(:WRONG_APP_APPLE_ID) { verifier(**production).verify_app_transaction(jws) }
    assert_reason(:WRONG_APP_APPLE_ID) do
      verifier(**production, app_apple_id: 999).verify_app_transaction(jws)
    end
    payload = verifier(**production, app_apple_id: 123_456_789).verify_app_transaction(jws)
    assert_equal 123_456_789, payload.app_apple_id
  end

  def test_sandbox_app_transaction_does_not_require_an_app_apple_id
    claims = { "bundleId" => "com.example.app", "receiptType" => "Sandbox" }
    payload = verifier.verify_app_transaction(TestPki.sign_jws(@pki, claims))
    assert_nil payload.app_apple_id
  end

  def test_environment_claim_outside_the_known_four_is_rejected
    jws = TestPki.sign_jws(@pki, TestPki.default_claims("environment" => "Staging"))
    assert_reason(:WRONG_ENVIRONMENT) { verifier.verify_transaction(jws) }
  end

  def test_bundle_id_is_checked_before_environment
    jws = TestPki.sign_jws(@pki, TestPki.default_claims("bundleId" => "com.other",
                                                        "environment" => "Production"))
    assert_reason(:WRONG_BUNDLE_ID) { verifier.verify_transaction(jws) }
  end

  def test_dates_are_epoch_millisecond_integers_not_times
    jws = TestPki.sign_jws(@pki, TestPki.default_claims("expiresDate" => 1_896_168_600_000,
                                                        "purchaseDate" => 1_722_945_600_000))
    payload = verifier.verify_transaction(jws)
    [payload.signed_date, payload.expires_date, payload.purchase_date].each do |value|
      assert_kind_of Integer, value
    end
    assert_equal 1_896_168_600_000, payload.expires_date
  end

  def test_active_at_reads_expiry_and_revocation
    jws = TestPki.sign_jws(@pki, TestPki.default_claims("expiresDate" => 1_896_168_600_000))
    payload = verifier.verify_transaction(jws)
    assert payload.active_at?(Time.utc(2025, 1, 1))
    refute payload.active_at?(Time.utc(2031, 1, 1))

    revoked = verifier.verify_transaction(
      TestPki.sign_jws(@pki, TestPki.default_claims("revocationDate" => 1_722_945_600_000))
    )
    refute revoked.active_at?(Time.utc(2025, 1, 1))
    assert revoked.active_at?(Time.utc(2024, 1, 1))
  end

  def test_claims_escape_hatch_exposes_unmodelled_claims
    jws = TestPki.sign_jws(@pki, TestPki.default_claims("somethingAppleAddsLater" => "x"))
    payload = verifier.verify_transaction(jws)
    assert_equal "x", payload.claims["somethingAppleAddsLater"]
    assert_equal "x", payload["somethingAppleAddsLater"]
    assert_predicate payload.claims, :frozen?
  end

  def test_rejects_inputs_that_are_not_three_segments
    ["", "a", "a.b", "a.b.c.d", "....", "a.b.c."].each do |bad|
      assert_reason(:INVALID_JWS_FORMAT) { verifier.verify_transaction(bad) }
    end
  end

  def test_rejects_a_non_string_input
    [nil, 42, [], { "a" => 1 }].each do |bad|
      assert_reason(:INVALID_JWS_FORMAT) { verifier.verify_transaction(bad) }
    end
  end
end
