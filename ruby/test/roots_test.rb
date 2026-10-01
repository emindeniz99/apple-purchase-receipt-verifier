# frozen_string_literal: true

require_relative "helper"
require "openssl"

# A caller's roots on the shipped aprv.wasm: the module reads each root as
# DER or PEM and tells them apart by the bytes (docs/rust-core/DECISIONS.md
# R39, amended). The gem passes Strings on as given, so a PEM file read from
# disk is a root as it stands, and a verdict under it is the verdict under
# its DER.
class RootsTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier
  APPLE_ROOTS = %w[AppleIncRootCertificate.cer AppleRootCA-G2.cer AppleRootCA-G3.cer].freeze

  def apple_ders
    APPLE_ROOTS.map { |name| File.binread(File.join(TestSupport.repo_root, "certs", name)) }
  end

  def pem_of(der)
    OpenSSL::X509::Certificate.new(der).to_pem
  end

  def receipt_base64
    [TestSupport.fixture_bytes("public-receipt-sandbox-g5")].pack("m0")
  end

  def verify_under(roots)
    APRV::Verifier.create(APRV::Config.new(roots: roots)).verify_receipt(receipt_base64)
  end

  def test_a_receipt_verifies_under_pem_roots_as_under_their_der
    under_der = verify_under(apple_ders)
    assert_predicate under_der, :verified?
    # One PEM per root, and one bundle String holding all three.
    pems = apple_ders.map { |der| pem_of(der) }
    [pems, [pems.join]].each do |roots|
      under_pem = verify_under(roots)
      assert_predicate under_pem, :verified?
      assert_equal under_der.payload, under_pem.payload
    end
  end

  def test_a_pem_string_with_no_certificate_is_refused_by_the_module_at_create
    empty = "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"
    error = assert_raises(ArgumentError) { verify_under([pem_of(apple_ders.first), empty]) }
    assert_match(/refused config\.roots/, error.message)
  end
end
