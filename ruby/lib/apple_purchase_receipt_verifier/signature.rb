# frozen_string_literal: true

require "openssl"

module ApplePurchaseReceiptVerifier
  # CMS `SignerInfo` signature verification: RSASSA-PKCS1-v1_5, RSASSA-PSS
  # and ECDSA, with any digest OpenSSL implements. OpenSSL itself does the
  # arithmetic (RSA and EC key decoding, PKCS1/PSS padding, ECDSA); this
  # module only decides which of them a `SignerInfo` names and that its
  # `signatureAlgorithm` does not contradict its `digestAlgorithm`
  # (docs/design/0.7-hardening-parity.md, change 3, Q14 and Q15). No key type,
  # digest or signature algorithm is restricted: a receipt signer is already
  # pinned to an Apple root and carries Apple's receipt-signing marker, so a
  # change of algorithm on Apple's side must not reject a genuine receipt.
  #
  # A certificate's own signature (the chain walk in {Chain}) needs none of
  # this: `OpenSSL::X509::Certificate#verify` already reads a certificate's
  # `signatureAlgorithm` itself and accepts whatever the linked OpenSSL
  # verifies. This module exists only because a CMS `SignerInfo` is not a
  # certificate, so nothing decodes and dispatches its algorithm identifiers
  # for us.
  #
  # @api private
  module Signature
    OID_RSASSA_PSS = "1.2.840.113549.1.1.10"
    OID_MGF1 = "1.2.840.113549.1.1.8"

    # `signatureAlgorithm` OIDs that name their own digest, mapped to the
    # OpenSSL digest name they name. A signature under one of these must be
    # checked with exactly that digest (docs/design/0.7-hardening-parity.md,
    # "reject-relabelled-signature-algorithm"); `rsaEncryption`,
    # `id-ecPublicKey`, RSASSA-PSS (handled separately, its own parameters
    # name its digest) and any OID not in this table name no hash and take
    # the `SignerInfo`'s `digestAlgorithm`.
    NAMED_DIGEST_SCHEMES = {
      "1.2.840.113549.1.1.4" => "MD5",
      "1.2.840.113549.1.1.5" => "SHA1",
      "1.2.840.113549.1.1.14" => "SHA224",
      "1.2.840.113549.1.1.11" => "SHA256",
      "1.2.840.113549.1.1.12" => "SHA384",
      "1.2.840.113549.1.1.13" => "SHA512"
    }.freeze

    class << self
      # The OpenSSL digest name an algorithm OID names, e.g.
      # `"2.16.840.1.101.3.4.2.1"` to `"SHA256"`, or `nil` for an OID
      # OpenSSL's own object database does not resolve or whose digest this
      # build does not implement.
      #
      # @param oid [String] dotted-decimal
      # @return [String, nil]
      def digest_name_for_oid(oid)
        object_id = OpenSSL::ASN1::ObjectId.new(oid)
        name = object_id.sn || object_id.ln
        return nil if name.nil?

        OpenSSL::Digest.new(name) # proves OpenSSL can actually compute it
        name
      rescue OpenSSL::ASN1::ASN1Error, RuntimeError
        nil
      end

      # Verifies a CMS `SignerInfo` signature.
      #
      # @param public_key [OpenSSL::PKey::RSA, OpenSSL::PKey::EC, Object]
      # @param digest_name [String] the `SignerInfo`'s `digestAlgorithm`,
      #   resolved by {digest_name_for_oid}
      # @param signature_algorithm_oid [String] dotted-decimal
      # @param signature_algorithm_params [String, nil] the DER of the
      #   `signatureAlgorithm`'s parameters, when present
      # @param signature [String]
      # @param data [String] the exact bytes the signature covers
      # @return [Boolean]
      def verify_signer_signature(public_key:, digest_name:, signature_algorithm_oid:,
                                  signature_algorithm_params:, signature:, data:)
        if signature_algorithm_oid == OID_RSASSA_PSS
          return verify_pss(public_key, digest_name, signature_algorithm_params, signature, data)
        end

        named_digest = NAMED_DIGEST_SCHEMES[signature_algorithm_oid]
        return false if named_digest && named_digest != digest_name

        case public_key
        when OpenSSL::PKey::RSA, OpenSSL::PKey::EC then verify_generic(public_key, digest_name, signature,
                                                                       data)
        else false
        end
      rescue StandardError
        false
      end

      private

      def verify_generic(key, digest_name, signature, data)
        key.verify(digest_name, signature, data)
      rescue OpenSSL::OpenSSLError
        false
      end

      # RSASSA-PSS. Its own parameters name the digest, so it is checked
      # against the `SignerInfo`'s `digestAlgorithm` the same way a named
      # scheme is: a PSS signature hashed with one digest and labelled with
      # another is not one signature under two names.
      def verify_pss(public_key, digest_name, params_der, signature, data)
        return false unless public_key.is_a?(OpenSSL::PKey::RSA)

        pss_digest, mgf1_digest, salt_length = pss_parameters(params_der)
        return false if pss_digest.nil? || pss_digest != mgf1_digest || pss_digest != digest_name

        # `pss_parameters` returns either three nils or three real values
        # together; `pss_digest` being set proves the other two are too.
        mask = mgf1_digest #: String
        bytes = salt_length #: Integer
        public_key.verify_pss(pss_digest, signature, data, salt_length: bytes, mgf1_hash: mask)
      rescue OpenSSL::OpenSSLError, ArgumentError
        false
      end

      # RSASSA-PSS-params (RFC 4055 3.1): the hash, MGF1 over that same hash
      # (the only mask this reads; a different one, or a missing MGF1
      # algorithm identifier, does not resolve), the salt length and the
      # trailer field, each with its DEFAULT when absent (`nil` params).
      #
      # @return [Array(String, String, Integer)] digest name, MGF1 digest
      #   name, salt length; each `nil` when the parameters do not resolve
      def pss_parameters(params_der)
        return ["SHA1", "SHA1", 20] if params_der.nil?

        node = Asn1.parse(params_der)
        return [nil, nil, nil] unless node.tag == Asn1::TAG_SEQUENCE

        digest_name = "SHA1"
        mgf1_digest_name = "SHA1"
        salt_length = 20
        last_tag = nil
        node.kids.each do |field|
          seen = last_tag #: Integer?
          return [nil, nil, nil] if !seen.nil? && field.tag <= seen

          last_tag = field.tag
          inner = field.kids.first
          return [nil, nil, nil] if inner.nil?

          case field.tag
          when 0xA0 then digest_name = hash_algorithm_name(inner) or return [nil, nil, nil]
          when 0xA1
            mgf_oid = inner.kids.first
            return [nil, nil, nil] unless mgf_oid && mgf_oid.tag == Asn1::TAG_OID &&
                                          Asn1.oid_string(mgf_oid.content) == OID_MGF1

            mgf1_digest_name = hash_algorithm_name(inner.kids[1]) or return [nil, nil, nil]
          when 0xA2
            salt_length = small_integer(inner) or return [nil, nil, nil]
          when 0xA3
            return [nil, nil, nil] unless small_integer(inner) == 1
          else
            return [nil, nil, nil]
          end
        end
        [digest_name, mgf1_digest_name, salt_length]
      rescue Asn1::Error
        [nil, nil, nil]
      end

      def hash_algorithm_name(node)
        return nil unless node.tag == Asn1::TAG_SEQUENCE

        oid_node = node.kids.first
        return nil unless oid_node && oid_node.tag == Asn1::TAG_OID

        digest_name_for_oid(Asn1.oid_string(oid_node.content))
      rescue Asn1::Error
        nil
      end

      def small_integer(node)
        return nil unless node.tag == Asn1::TAG_INTEGER

        content = node.content
        return nil if content.empty? || content.bytesize > 2

        first = content.getbyte(0) #: Integer
        return nil if first >= 0x80

        content.each_byte.reduce(0) { |value, byte| (value << 8) | byte }
      end
    end
  end
end
