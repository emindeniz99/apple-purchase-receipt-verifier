# frozen_string_literal: true

require "openssl"
require "json"

# A throwaway "Apple" PKI, generated fresh for each run — the same technique
# Apple's own libraries use in their tests, and the same one java/TestPki.java
# uses here. It lets the native suite build inputs the shared fixtures cannot
# express (a signer with an EC key, a SHA-512 digest, a twin certificate that
# borrows the real signer's serial) without any real Apple secret.
module TestPki
  LEAF_OID = "1.2.840.113635.100.6.11.1"
  INTERMEDIATE_OID = "1.2.840.113635.100.6.2.1"

  module_function

  def rsa_key(bits = 2048)
    @rsa_keys ||= {}
    @rsa_keys[bits] ||= OpenSSL::PKey::RSA.generate(bits)
  end

  def fresh_rsa_key(bits = 2048)
    OpenSSL::PKey::RSA.generate(bits)
  end

  def ec_key
    OpenSSL::PKey::EC.generate("prime256v1")
  end

  def certificate(subject:, key:, issuer_certificate: nil, issuer_key: nil, ca: false,
                  oids: [], not_before: Time.utc(2020, 1, 1), not_after: Time.utc(2035, 1, 1),
                  serial: rand(1..(2**32)), digest: "SHA256")
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = serial
    cert.subject = OpenSSL::X509::Name.parse("/CN=#{subject}")
    cert.issuer = issuer_certificate ? issuer_certificate.subject : cert.subject
    cert.public_key = public_key_of(key)
    cert.not_before = not_before
    cert.not_after = not_after

    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = issuer_certificate || cert
    cert.add_extension(factory.create_extension("basicConstraints", ca ? "CA:TRUE" : "CA:FALSE", true))
    oids.each do |oid|
      cert.add_extension(OpenSSL::X509::Extension.new(oid, OpenSSL::ASN1::Null.new(nil).to_der, false))
    end
    cert.sign(issuer_key || key, OpenSSL::Digest.new(digest))
    cert
  end

  def public_key_of(key)
    key.is_a?(OpenSSL::PKey::EC) ? OpenSSL::PKey.read(key.public_to_der) : key.public_key
  end

  # --- receipt PKI ---------------------------------------------------------

  ReceiptPki = Struct.new(:root, :root_key, :intermediate, :intermediate_key, :leaf, :leaf_key,
                          keyword_init: true)

  # Key generation dominates the suite's wall time, so PKIs with the same shape
  # are built once and shared. Certificates are immutable, and every test that
  # needs a genuinely distinct authority asks for one by passing a different
  # shape or its own key.
  def receipt_pki(leaf_oids: [LEAF_OID], not_before: Time.utc(2020, 1, 1),
                  not_after: Time.utc(2035, 1, 1), leaf_key: nil)
    @receipt_pki_cache ||= {}
    key = [leaf_oids, not_before, not_after]
    return @receipt_pki_cache[key] if leaf_key.nil? && @receipt_pki_cache.key?(key)

    pki = build_receipt_pki(leaf_oids, not_before, not_after, leaf_key)
    @receipt_pki_cache[key] = pki if leaf_key.nil?
    pki
  end

  def build_receipt_pki(leaf_oids, not_before, not_after, leaf_key)
    root_key = fresh_rsa_key
    root = certificate(subject: "Test Apple Root", key: root_key, ca: true,
                       not_before: not_before, not_after: not_after)
    intermediate_key = fresh_rsa_key
    intermediate = certificate(subject: "Test WWDR", key: intermediate_key,
                               issuer_certificate: root, issuer_key: root_key, ca: true,
                               oids: [INTERMEDIATE_OID],
                               not_before: not_before, not_after: not_after)
    key = leaf_key || fresh_rsa_key
    leaf = certificate(subject: "Test Receipt Signing", key: key,
                       issuer_certificate: intermediate, issuer_key: intermediate_key,
                       oids: leaf_oids, not_before: not_before, not_after: not_after)
    ReceiptPki.new(root: root, root_key: root_key, intermediate: intermediate,
                   intermediate_key: intermediate_key, leaf: leaf, leaf_key: key)
  end

  # Builds `SET OF SEQUENCE { INTEGER type, INTEGER version, OCTET STRING value }`.
  def receipt_payload(attributes)
    OpenSSL::ASN1::Set.new(
      attributes.map do |type, value|
        OpenSSL::ASN1::Sequence.new([
                                      OpenSSL::ASN1::Integer.new(type),
                                      OpenSSL::ASN1::Integer.new(1),
                                      OpenSSL::ASN1::OctetString.new(value)
                                    ])
      end
    ).to_der
  end

  def utf8(value)
    OpenSSL::ASN1::UTF8String.new(value).to_der
  end

  def ia5(value)
    OpenSSL::ASN1::IA5String.new(value).to_der
  end

  def integer(value)
    OpenSSL::ASN1::Integer.new(value).to_der
  end

  DEFAULT_ATTRIBUTES = [
    [0, "ProductionSandbox"], [2, "com.example.app"], [3, "1.2.3"], [19, "1.0"]
  ].freeze

  def default_payload(bundle_id: "com.example.app", creation_date: "2024-08-06T12:00:00Z",
                      opaque: "\x01\x02\x03\x04\x05\x06\x07\x08".b, extra: [])
    attributes = [
      [0, utf8("ProductionSandbox")],
      [2, utf8(bundle_id)],
      [3, utf8("1.2.3")],
      [4, OpenSSL::ASN1::OctetString.new(opaque).to_der],
      [19, utf8("1.0")]
    ]
    attributes << [12, ia5(creation_date)] unless creation_date.nil?
    receipt_payload(attributes + extra)
  end

  # A CMS SignedData over `payload`, signed by `pki`'s leaf.
  def sign_receipt(pki, payload, extra_certificates: [], certificates: nil)
    chain = certificates || ([pki.intermediate, pki.root] + extra_certificates)
    OpenSSL::PKCS7.sign(pki.leaf, pki.leaf_key, payload, chain, OpenSSL::PKCS7::BINARY).to_der
  end

  def sign_receipt_with_digest(pki, payload, digest)
    signer = OpenSSL::PKCS7.sign(pki.leaf, pki.leaf_key, payload,
                                 [pki.intermediate, pki.root], OpenSSL::PKCS7::BINARY)
    return signer.to_der if digest == "SHA256"

    # OpenSSL::PKCS7.sign always uses SHA-256 here, so a different digest OID
    # is spliced in structurally. The point of the test is the allow-list, not
    # the arithmetic.
    replace_digest_oid(signer.to_der, digest)
  end

  DIGEST_OIDS = {
    "SHA1" => "1.3.14.3.2.26",
    "SHA256" => "2.16.840.1.101.3.4.2.1",
    "SHA512" => "2.16.840.1.101.3.4.2.3"
  }.freeze

  def replace_digest_oid(der, digest)
    from = OpenSSL::ASN1::ObjectId.new(DIGEST_OIDS.fetch("SHA256")).to_der
    to = OpenSSL::ASN1::ObjectId.new(DIGEST_OIDS.fetch(digest)).to_der
    raise "digest OIDs differ in length" unless from.bytesize == to.bytesize

    der.b.gsub(from, to)
  end

  # --- JWS PKI -------------------------------------------------------------

  JwsPki = Struct.new(:root, :root_key, :intermediate, :intermediate_key, :leaf, :leaf_key,
                      keyword_init: true)

  def jws_pki(leaf_oids: [LEAF_OID], intermediate_oids: [INTERMEDIATE_OID],
              intermediate_ca: true, not_before: Time.utc(2020, 1, 1),
              not_after: Time.utc(2035, 1, 1))
    @jws_pki_cache ||= {}
    @jws_pki_cache[[leaf_oids, intermediate_oids, intermediate_ca, not_before, not_after]] ||=
      build_jws_pki(leaf_oids, intermediate_oids, intermediate_ca, not_before, not_after)
  end

  def build_jws_pki(leaf_oids, intermediate_oids, intermediate_ca, not_before, not_after)
    root_key = ec_key
    root = certificate(subject: "Test Apple Root G3", key: root_key, ca: true,
                       not_before: not_before, not_after: not_after)
    intermediate_key = ec_key
    intermediate = certificate(subject: "Test WWDR G6", key: intermediate_key,
                               issuer_certificate: root, issuer_key: root_key,
                               ca: intermediate_ca, oids: intermediate_oids,
                               not_before: not_before, not_after: not_after)
    leaf_key = ec_key
    leaf = certificate(subject: "Test Signing Leaf", key: leaf_key,
                       issuer_certificate: intermediate, issuer_key: intermediate_key,
                       oids: leaf_oids, not_before: not_before, not_after: not_after)
    JwsPki.new(root: root, root_key: root_key, intermediate: intermediate,
               intermediate_key: intermediate_key, leaf: leaf, leaf_key: leaf_key)
  end

  def base64url(bytes)
    [bytes].pack("m0").tr("+/", "-_").delete("=")
  end

  # `payload_json` takes the payload segment verbatim, for JSON that
  # `JSON.generate` refuses to emit but `JSON.parse` happily reads back —
  # `1e400`, which parses to Float::INFINITY.
  def sign_jws(pki, claims, header_overrides: {}, payload_json: nil)
    header = {
      "alg" => "ES256",
      "x5c" => [pki.leaf, pki.intermediate, pki.root].map { |c| [c.to_der].pack("m0") }
    }.merge(header_overrides)
    header_b64 = base64url(JSON.generate(header))
    payload_b64 = base64url(payload_json || JSON.generate(claims))
    signing_input = "#{header_b64}.#{payload_b64}"
    der = pki.leaf_key.sign(OpenSSL::Digest.new("SHA256"), signing_input)
    r, s = OpenSSL::ASN1.decode(der).value.map(&:value)
    raw = [r.to_s(2).rjust(32, "\x00"), s.to_s(2).rjust(32, "\x00")].join
    "#{signing_input}.#{base64url(raw)}"
  end

  def default_claims(overrides = {})
    {
      "bundleId" => "com.example.app",
      "environment" => "Sandbox",
      "productId" => "com.example.app.pro",
      "transactionId" => "2000000000000001",
      "signedDate" => 1_722_945_600_000,
      "quantity" => 1
    }.merge(overrides)
  end
end

module TestPki
  module_function

  # Structural surgery on our own generated CMS blobs, so the native suite can
  # build shapes `OpenSSL::PKCS7.sign` will not produce (no signer, two
  # signers). Only ever applied to bytes this file just created.
  def rewrite_signer_infos(der)
    content_info = OpenSSL::ASN1.decode(der)
    signed_data = content_info.value[1].value[0]
    signer_infos = signed_data.value[-1]
    signer_infos.value = yield(signer_infos.value)
    content_info.to_der
  end

  def without_signer_infos(der)
    rewrite_signer_infos(der) { |_| [] }
  end

  def with_duplicated_signer_info(der)
    rewrite_signer_infos(der) { |values| values + [values[0]] }
  end
end

module TestPki
  module_function

  # Replaces the CMS certificate set, so a flood can be built by repeating one
  # certificate rather than generating a thousand keys.
  def with_certificates(der, certificates)
    content_info = OpenSSL::ASN1.decode(der)
    signed_data = content_info.value[1].value[0]
    index = signed_data.value.index do |element|
      element.respond_to?(:tag_class) && element.tag_class == :CONTEXT_SPECIFIC && element.tag.zero?
    end
    raise "no certificate set" if index.nil?

    signed_data.value[index] = OpenSSL::ASN1::ASN1Data.new(
      certificates.map { |cert| OpenSSL::ASN1.decode(cert.to_der) }, 0, :CONTEXT_SPECIFIC
    )
    content_info.to_der
  end
end
