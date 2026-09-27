# frozen_string_literal: true

module ApplePurchaseReceiptVerifier
  # Structural reading of the CMS/PKCS#7 `SignedData` a legacy app receipt is.
  #
  # This is deliberately *our* parse rather than `OpenSSL::PKCS7`'s, and it
  # runs first, because several decisions have to be made before OpenSSL sees
  # a byte:
  #
  # * trailing bytes after the blob must be rejected — `OpenSSL::PKCS7.new`
  #   accepts them (measured: three junk bytes appended to a genuine receipt
  #   parse fine and yield the same three certificates);
  # * the embedded-certificate count must be bounded *before* any certificate
  #   is decoded, which `PKCS7.new` has already done by the time you can ask;
  # * every `SignerInfo`'s digest and signature algorithm, and its
  #   `signedAttrs` if it carries any, must be read structurally so the
  #   library can check any of them, any digest, any key type (#160),
  #   which `OpenSSL::PKCS7::SignerInfo`
  #   does not expose at all (its public instance methods are `issuer`,
  #   `serial` and `signed_time`).
  #
  # OpenSSL still owns the signature mathematics — see {Signature} and
  # {Receipt}.
  #
  # @api private
  module Cms
    OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
    OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
    OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"

    SignerInfo = Struct.new(
      :issuer_der, :serial, :digest_oid, :digest_name,
      :signature_algorithm_oid, :signature_algorithm_params,
      :signed_attrs, :content_type_attribute, :message_digest_attribute,
      :signed_attrs_duplicate_attribute, :signature,
      keyword_init: true
    ) do
      # Whether this signer's `signedAttrs` are present and either
      # well-formed but missing `contentType` or `messageDigest`, or carry
      # either one twice (RFC 5652 5.3 makes both mandatory exactly once
      # whenever `signedAttrs` are present at all): a signature that cannot
      # be checked, INVALID_SIGNATURE for this signer, never a structural
      # defect of the receipt.
      def signed_attrs_incomplete? # steep:ignore UndeclaredMethodDefinition
        # @type self: Cms::SignerInfo
        !signed_attrs.nil? &&
          (content_type_attribute.nil? || message_digest_attribute.nil? || signed_attrs_duplicate_attribute)
      end
    end

    Parsed = Struct.new(:content_type, :content, :certificate_ders, :signer_infos, keyword_init: true)

    class << self
      # @param der [String] receipt bytes, already scanned by {Asn1.scan!}
      # @return [Parsed]
      # @raise [VerificationError] MALFORMED on any structural defect,
      #   including a `signedAttrs` set in any `SignerInfo` that is not a
      #   well-formed RFC 5652 5.3 attribute set (checked for every
      #   `SignerInfo`, before any signature is verified, whichever position
      #   it holds).
      def parse(der)
        content_info = Asn1.parse(der, depth_limit: 4)
        info = content_info.kids
        raise malformed("not a CMS SignedData") unless signed_data?(content_info, info)

        wrapper = Asn1.parse_scanned(info[1].raw, depth_limit: 4)
        signed_data = wrapper.kids.first
        raise malformed("no SignedData") if signed_data.nil? || signed_data.tag != Asn1::TAG_SEQUENCE

        parts = signed_data.kids
        raise malformed("truncated SignedData") if parts.size < 4

        content_type, content = encapsulated_content(parts[2])
        Parsed.new(
          content_type: content_type,
          content: content,
          certificate_ders: certificate_ders(parts),
          signer_infos: signer_infos(parts.last)
        )
      rescue Asn1::Error => e
        # `Asn1.scan!` (run by every caller before this) only proves the TLV
        # shape is well-formed and bounded; an OID's own base-128 content
        # encoding is a grammar `Asn1.oid_string` checks separately, so a
        # structurally sound but truncated OID surfaces only here. Every
        # defect this method finds is a VerificationError, this one included.
        raise malformed(e.message)
      end

      # The bytes a `SignerInfo` signature covers when `signedAttrs` are
      # present (RFC 5652 5.4): the attributes re-encoded as an EXPLICIT
      # SET, which is the implicit `[0]` tag octet (0xA0) swapped for SET
      # (0x31) and nothing else. Swapping one octet rather than re-encoding
      # the structure is deliberate: the signature covers the original
      # length and content octets, and a re-encode could produce different
      # ones.
      def signed_attrs_signed_bytes(signed_attrs)
        rest = signed_attrs.byteslice(1..) #: String
        ("\x31".b + rest).b
      end

      private

      def signed_data?(content_info, info)
        content_info.tag == Asn1::TAG_SEQUENCE && info.size >= 2 &&
          info[0].tag == Asn1::TAG_OID && Asn1.oid_string(info[0].content) == OID_SIGNED_DATA &&
          info[1].tag == Asn1::TAG_CONTEXT_0
      end

      # @return [Array(String, String)] the eContentType OID (dotted-decimal)
      #   and the encapsulated content bytes
      def encapsulated_content(encap)
        raise malformed("no encapsulated content") if encap.nil? || encap.tag != Asn1::TAG_SEQUENCE

        full = Asn1.parse_scanned(encap.raw)
        content_type_node = full.kids[0]
        if content_type_node.nil? || content_type_node.tag != Asn1::TAG_OID
          raise malformed("no eContentType")
        end

        holder = full.kids[1]
        raise malformed("no encapsulated payload") if holder.nil? || holder.tag != Asn1::TAG_CONTEXT_0

        node = holder.kids.first
        raise malformed("encapsulated payload is not an OCTET STRING") if node.nil? || !node.octet_string?

        [Asn1.oid_string(content_type_node.content), node.octet_value]
      end

      # The certificate set is `[0] IMPLICIT` between encapContentInfo and
      # signerInfos. Members are returned as raw DER, undecoded: the count is
      # bounded before any of them becomes an X509 object.
      def certificate_ders(parts)
        node = parts[3...-1].find { |child| child.tag == Asn1::TAG_CONTEXT_0 } # steep:ignore NoMethod
        return [] if node.nil?

        node.kids.map(&:raw)
      end

      def signer_infos(node)
        raise malformed("no signer info") if node.nil? || node.tag != Asn1::TAG_SET

        infos = node.kids
        raise malformed("no signer info") if infos.empty?

        infos.map { |info| signer_info(info) }
      end

      def signer_info(node)
        fields = Asn1.parse_scanned(node.raw).kids
        raise malformed("truncated SignerInfo") if fields.size < 5

        sid = fields[1]
        unless sid.tag == Asn1::TAG_SEQUENCE && sid.kids.size == 2 &&
               sid.kids[1].tag == Asn1::TAG_INTEGER
          raise malformed("unsupported signer identifier")
        end

        digest_algorithm = fields[2]
        digest_oid_node = digest_algorithm.kids.first
        unless digest_algorithm.tag == Asn1::TAG_SEQUENCE && digest_oid_node &&
               digest_oid_node.tag == Asn1::TAG_OID
          raise malformed("unexpected digestAlgorithm layout")
        end

        digest_oid = Asn1.oid_string(digest_oid_node.content)

        index = 3
        signed_attrs = nil
        content_type_attribute = nil
        message_digest = nil
        duplicate_attribute = false
        if fields[index]&.tag == Asn1::TAG_CONTEXT_0
          attrs_node = fields[index]
          # The syntax of every SignerInfo's signedAttrs is judged here,
          # before any key is used, so a broken one is MALFORMED whichever
          # position it holds; a well-formed set lacking a mandatory
          # attribute, or carrying one twice, is left to the signature
          # check, INVALID_SIGNATURE for that signer only (docs/design/
          # 0.7-api.md, Reading certificates and signed attributes).
          content_type_attribute, message_digest, duplicate_attribute = signed_attributes(attrs_node)
          signed_attrs = attrs_node.raw
          index += 1
        end

        signature_algorithm = fields[index]
        raise malformed("truncated SignerInfo") if signature_algorithm.nil?

        sig_oid_node = signature_algorithm.kids.first
        unless signature_algorithm.tag == Asn1::TAG_SEQUENCE && sig_oid_node &&
               sig_oid_node.tag == Asn1::TAG_OID
          raise malformed("unexpected signatureAlgorithm layout")
        end

        signature_algorithm_oid = Asn1.oid_string(sig_oid_node.content)
        signature_algorithm_params = signature_algorithm.kids[1]&.raw
        index += 1

        signature_node = fields[index]
        raise malformed("truncated SignerInfo") if signature_node.nil? || !signature_node.octet_string?

        SignerInfo.new(
          issuer_der: sid.kids[0].raw,
          serial: unsigned_integer(sid.kids[1].content),
          digest_oid: digest_oid,
          digest_name: Signature.digest_name_for_oid(digest_oid),
          signature_algorithm_oid: signature_algorithm_oid,
          signature_algorithm_params: signature_algorithm_params,
          signed_attrs: signed_attrs,
          content_type_attribute: content_type_attribute,
          message_digest_attribute: message_digest,
          signed_attrs_duplicate_attribute: duplicate_attribute,
          signature: signature_node.octet_value
        )
      end

      # `signedAttrs [0] IMPLICIT SET OF Attribute`: implicit tagging means
      # the content octets are exactly a SET's content, so the node's own
      # children are the individual `Attribute`s directly.
      #
      # RFC 5652 5.3 permits at most one instance of any particular
      # attribute; a `contentType` or `messageDigest` attribute repeated is
      # tracked as a duplicate, not silently resolved to its first (or
      # last) occurrence, and the caller treats a duplicate the same as a
      # missing one (`SignerInfo#signed_attrs_incomplete?`).
      #
      # @return [Array(String?, String?, bool)] the `contentType`
      #   attribute's value (its OID's dotted-decimal form, or `""` when the
      #   value is not itself an OID — never a real `eContentType`), or
      #   `nil` if there is no `contentType` attribute; the `messageDigest`
      #   attribute's value octets, or `nil` if there is none; whether
      #   either was seen more than once
      # @raise [VerificationError] MALFORMED when an attribute is not
      #   `SEQUENCE { OID, SET OF value }`
      def signed_attributes(node)
        content_type = nil
        message_digest = nil
        duplicate = false
        node.kids.each do |attribute|
          raise malformed("malformed signed attribute") unless attribute.tag == Asn1::TAG_SEQUENCE

          fields = attribute.kids
          type_node = fields[0]
          values_node = fields[1]
          unless type_node && type_node.tag == Asn1::TAG_OID && values_node && values_node.tag == Asn1::TAG_SET
            raise malformed("malformed signed attribute")
          end

          value = values_node.kids.first
          raise malformed("malformed signed attribute") if value.nil?

          oid = Asn1.oid_string(type_node.content)
          if oid == OID_CONTENT_TYPE
            duplicate ||= !content_type.nil?
            content_type = value.tag == Asn1::TAG_OID ? Asn1.oid_string(value.content) : ""
          end
          if oid == OID_MESSAGE_DIGEST
            duplicate ||= !message_digest.nil?
            message_digest = value.content
          end
        end
        [content_type, message_digest, duplicate]
      end

      def unsigned_integer(bytes)
        raise malformed("empty serial number") if bytes.empty?

        negative = bytes.getbyte(0) >= 0x80 # steep:ignore NoMethod
        value = 0
        bytes.each_byte { |b| value = (value << 8) | b }
        return value unless negative

        value - (1 << (bytes.bytesize * 8))
      end

      def malformed(message)
        VerificationError.new(Reason::MALFORMED, message)
      end
    end
  end
end
