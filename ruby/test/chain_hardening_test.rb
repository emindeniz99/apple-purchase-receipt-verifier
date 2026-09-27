# frozen_string_literal: true

require_relative "helper"
require_relative "test_pki"

# docs/design/0.7-hardening-parity.md, "Reverse gaps": Ruby's keyUsage check
# used to answer "allowed" when the extension was present but did not
# decode. Fixed to fail CLOSED (chain.rb, `cert_sign_permitted?`, in the
# `rescue StandardError, Asn1::Error` branch, which the 0.6 code answered
# `true`); this pins that exact branch with a unit test.
class ChainHardeningTest < Minitest::Test
  APRV = ApplePurchaseReceiptVerifier

  FakeCertificate = Struct.new(:extension) do
    def find_extension(_name)
      extension
    end
  end

  # A lone BIT STRING tag byte, no length octet at all: `Asn1.parse` cannot
  # read it (truncated), which is exactly the "present but does not decode"
  # case the fix targets. `cert_sign_permitted?` is called on a vouched-for
  # certificate's own extension, never on attacker-controlled bytes still
  # being scanned, so this reaches straight for the method under test rather
  # than going through a certificate this port's other checks (bounded ASN.1
  # scanning, `CertificateStructure.sound?`) might also reject first for
  # unrelated reasons.
  def test_a_key_usage_extension_that_does_not_decode_fails_closed
    extension = OpenSSL::X509::Extension.new("keyUsage", "\x03".b, true)
    cert = FakeCertificate.new(extension)

    refute APRV::Chain.send(:cert_sign_permitted?, cert),
           "a keyUsage extension that does not decode must not be read as unrestricted"
  end

  # The absence of a keyUsage extension is a different case entirely — no
  # restriction stated at all — and stays permissive; the fix is specific to
  # a keyUsage that is present but unreadable.
  def test_no_key_usage_extension_at_all_is_still_permitted
    cert = FakeCertificate.new(nil)
    assert APRV::Chain.send(:cert_sign_permitted?, cert)
  end

  # End to end: an intermediate whose keyUsage does not decode is refused
  # somewhere on the path to a verdict — not necessarily by
  # `cert_sign_permitted?` itself, since `CertificateStructure.sound?`
  # already screens out a certificate carrying any extension neither
  # `OpenSSL::ASN1.decode` can read (fixtures/cases.json lists this
  # combination's outcomes as port-defined, `oneOf`, for exactly that reason:
  # the two checks overlap on this shape). What must hold regardless of
  # which check catches it first: the receipt is refused, not accepted, and
  # refused with a real reason rather than crashing.
  def test_an_intermediate_with_a_malformed_key_usage_is_refused_end_to_end
    root_key = TestPki.fresh_rsa_key
    root = TestPki.certificate(subject: "Test Root", key: root_key, ca: true)

    intermediate_key = TestPki.fresh_rsa_key
    intermediate = OpenSSL::X509::Certificate.new
    intermediate.version = 2
    intermediate.serial = 1
    intermediate.subject = OpenSSL::X509::Name.parse("/CN=Test WWDR Malformed KeyUsage")
    intermediate.issuer = root.subject
    intermediate.public_key = intermediate_key.public_key
    intermediate.not_before = Time.utc(2020, 1, 1)
    intermediate.not_after = Time.utc(2035, 1, 1)
    intermediate.add_extension(OpenSSL::X509::Extension.new("basicConstraints", "CA:TRUE", true))
    intermediate.add_extension(OpenSSL::X509::Extension.new("keyUsage", "\x03\x05\x00\xA0".b, true))
    intermediate.add_extension(
      OpenSSL::X509::Extension.new(TestPki::INTERMEDIATE_OID, OpenSSL::ASN1::Null.new(nil).to_der, false)
    )
    intermediate.sign(root_key, OpenSSL::Digest.new("SHA256"))

    leaf_key = TestPki.fresh_rsa_key
    leaf = TestPki.certificate(subject: "Test Signer", key: leaf_key,
                               issuer_certificate: intermediate, issuer_key: intermediate_key,
                               oids: [TestPki::LEAF_OID])
    pki = TestPki::ReceiptPki.new(root: root, root_key: root_key, intermediate: intermediate,
                                  intermediate_key: intermediate_key, leaf: leaf, leaf_key: leaf_key)

    der = TestPki.sign_receipt(pki, TestPki.default_payload)
    clock = APRV::ClockOnce.new(-> { Time.now.to_i * 1000 })
    error = assert_raises(APRV::VerificationError) do
      APRV::Receipt.verify([der].pack("m0"), [pki.root], clock)
    end
    refute_equal :INTERNAL_ERROR, error.reason, error.message
  end
end
