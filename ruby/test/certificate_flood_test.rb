# frozen_string_literal: true

require_relative "helper"
require_relative "test_pki"

# The embedded-certificate bound. Every certificate a receipt carries is
# otherwise decoded and tried as a candidate issuer before any signature is
# verified, so the count is what a hostile receipt would inflate.
class CertificateFloodTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier

  def setup
    @pki = TestPki.receipt_pki
    @der = TestPki.sign_receipt(@pki, TestPki.default_payload)
    @roots = [@pki.root]
    @clock = APRV::ClockOnce.new(-> { Time.now.to_i * 1000 })
  end

  def verify(der)
    APRV::Receipt.verify([der].pack("m0"), @roots, @clock)
  end

  def filler(count)
    Array.new(count) { |i| TestPki.certificate(subject: "Filler #{i}", key: TestPki.rsa_key) }
  end

  def test_exactly_ten_embedded_certificates_is_admitted
    chain = [@pki.leaf, @pki.intermediate, @pki.root]
    der = TestPki.with_certificates(@der, chain + filler(7))
    assert_equal "com.example.app", verify(der).bundle_id
  end

  def test_eleven_embedded_certificates_is_rejected_as_malformed
    chain = [@pki.leaf, @pki.intermediate, @pki.root]
    der = TestPki.with_certificates(@der, chain + filler(8))
    error = assert_raises(APRV::VerificationError) { verify(der) }
    assert_equal :MALFORMED, error.reason
  end

  # Counts how many certificates OpenSSL is asked to decode while the block
  # runs. This is what the bound is really about, so it is what gets
  # asserted; comparing elapsed times instead made the claim depend on how
  # fast the host decodes RSA relative to how fast it scans bytes, and that
  # ratio differs per machine.
  def count_certificate_decodes
    decoded = 0
    original = OpenSSL::X509::Certificate.method(:new)
    OpenSSL::X509::Certificate.define_singleton_method(:new) do |*args, &block|
      decoded += 1
      original.call(*args, &block)
    end
    begin
      yield
    ensure
      OpenSSL::X509::Certificate.singleton_class.remove_method(:new)
    end
    decoded
  end

  # The bound is on parsing, not on the walk: a thousand-certificate receipt
  # must be refused without any of them being turned into an X509 object.
  def test_a_thousand_certificate_flood_is_refused_before_the_certificates_are_decoded
    flood = TestPki.with_certificates(@der, filler(1000) + [@pki.leaf, @pki.intermediate])
    assert_equal 1002, APRV::Cms.parse(flood).certificate_ders.size

    error = nil
    decoded = count_certificate_decodes do
      error = assert_raises(APRV::VerificationError) { verify(flood) }
    end

    assert_equal :MALFORMED, error.reason
    assert_equal 0, decoded,
                 "the flood was refused only after decoding #{decoded} of its certificates"
  end

  # The counter above proves nothing unless it can also count, so: a receipt
  # this verifier accepts does decode certificates.
  def test_the_decode_counter_sees_a_receipt_that_is_actually_verified
    assert_operator count_certificate_decodes { verify(@der) }, :>, 0
  end

  def test_the_bound_clears_every_genuine_chain_in_the_corpus
    %w[public-receipt-sandbox-g5 public-receipt-sandbox-legacy].each do |id|
      count = APRV::Cms.parse(TestSupport.fixture_bytes(id)).certificate_ders.size
      assert_operator count, :<=, APRV::Receipt::MAX_EMBEDDED_CERTIFICATES, id
    end
  end

  # A cross-signed mesh is where a backtracking path builder goes
  # exponential. The top-down walk does not backtrack: each certificate is
  # tried against the current round's trusted issuers at most once per
  # round, and the walk stops after MAX_PATH_LENGTH rounds.
  def test_a_cross_signed_certificate_mesh_is_rejected_in_bounded_time
    mesh = Array.new(9) do |i|
      key = TestPki.rsa_key
      TestPki.certificate(subject: "Mesh #{i}", key: key, ca: true,
                          issuer_certificate: nil, issuer_key: nil)
    end
    der = TestPki.with_certificates(@der, mesh + [@pki.leaf])
    started = Process.clock_gettime(Process::CLOCK_PROCESS_CPUTIME_ID)
    error = assert_raises(APRV::VerificationError) { verify(der) }
    elapsed = Process.clock_gettime(Process::CLOCK_PROCESS_CPUTIME_ID) - started
    assert_equal :UNTRUSTED_CHAIN, error.reason
    assert_operator elapsed, :<, 1.0, "mesh took #{(elapsed * 1000).round(2)}ms"
  end

  def test_the_bound_is_reported_before_the_signer_lookup
    # The signer is absent from the set entirely; with eleven certificates the
    # count is still what gets reported, because it is checked first.
    der = TestPki.with_certificates(@der, filler(11))
    error = assert_raises(APRV::VerificationError) { verify(der) }
    assert_equal :MALFORMED, error.reason
  end
end
