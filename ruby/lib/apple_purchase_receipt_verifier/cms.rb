# frozen_string_literal: true

module ApplePurchaseReceiptVerifier
  # Structural reading of the CMS/PKCS#7 `SignedData` a legacy app receipt is.
  #
  # This is deliberately *our* parse rather than `OpenSSL::PKCS7`'s, and it
  # runs first, because three decisions have to be made before OpenSSL sees a
  # byte:
  #
  # * trailing bytes after the blob must be rejected — `OpenSSL::PKCS7.new`
  #   accepts them (measured: three junk bytes appended to a genuine receipt
  #   parse fine and yield the same three certificates);
  # * the embedded-certificate count must be bounded *before* any certificate
  #   is decoded, which `PKCS7.new` has already done by the time you can ask;
  # * the digest algorithm OID has to be checked against an allow-list, and
  #   `OpenSSL::PKCS7::SignerInfo` does not expose it at all (its public
  #   instance methods are `issuer`, `serial` and `signed_time`).
  #
  # OpenSSL still owns the signature mathematics — see {ReceiptVerifier}.
  #
  # @api private
  module Cms
    OID_SIGNED_DATA = "1.2.840.113549.1.7.2"

    SHA1_OID   = "1.3.14.3.2.26"
    SHA256_OID = "2.16.840.1.101.3.4.2.1"

    # Only the digests Apple signs receipts with. An allow-list, so a digest
    # nobody reviewed cannot arrive by way of a new OpenSSL release.
    DIGESTS = { SHA1_OID => "SHA1", SHA256_OID => "SHA256" }.freeze

    SignerInfo = Struct.new(:issuer_der, :serial, :digest_oid, :digest_name, keyword_init: true)

    Parsed = Struct.new(:content, :certificate_ders, :signer_info, keyword_init: true)

    class << self
      # @param der [String] receipt bytes, already scanned by {Asn1.scan!}
      # @return [Parsed]
      # @raise [VerificationError] INVALID_RECEIPT_FORMAT on any structural defect
      def parse(der)
        content_info = Asn1.parse(der, depth_limit: 4)
        info = content_info.kids
        raise malformed("not a CMS SignedData") unless signed_data?(content_info, info)

        wrapper = Asn1.parse_scanned(info[1].raw, depth_limit: 4)
        signed_data = wrapper.kids.first
        raise malformed("no SignedData") if signed_data.nil? || signed_data.tag != Asn1::TAG_SEQUENCE

        parts = signed_data.kids
        raise malformed("truncated SignedData") if parts.size < 4

        Parsed.new(
          content: encapsulated_content(parts[2]),
          certificate_ders: certificate_ders(parts),
          signer_info: signer_info(parts.last)
        )
      end

      private

      def signed_data?(content_info, info)
        content_info.tag == Asn1::TAG_SEQUENCE && info.size >= 2 &&
          info[0].tag == Asn1::TAG_OID && oid_string(info[0].content) == OID_SIGNED_DATA &&
          info[1].tag == Asn1::TAG_CONTEXT_0
      end

      def encapsulated_content(encap)
        raise malformed("no encapsulated content") if encap.nil? || encap.tag != Asn1::TAG_SEQUENCE

        full = Asn1.parse_scanned(encap.raw)
        holder = full.kids[1]
        raise malformed("no encapsulated payload") if holder.nil? || holder.tag != Asn1::TAG_CONTEXT_0

        node = holder.kids.first
        raise malformed("encapsulated payload is not an OCTET STRING") if node.nil? || !node.octet_string?

        node.octet_value
      end

      # The certificate set is `[0] IMPLICIT` between encapContentInfo and
      # signerInfos. Members are returned as raw DER, undecoded: the count is
      # bounded before any of them becomes an X509 object.
      def certificate_ders(parts)
        node = parts[3...-1].find { |child| child.tag == Asn1::TAG_CONTEXT_0 }
        return [] if node.nil?

        node.kids.map(&:raw)
      end

      def signer_info(node)
        raise malformed("no signer info") if node.nil? || node.tag != Asn1::TAG_SET

        infos = node.kids
        raise malformed("no signer info") if infos.empty?
        # Apple signs a receipt exactly once. Accepting a second SignerInfo
        # would mean choosing which one the verdict is about, and a receipt
        # whose signers disagree is not a receipt this library can answer for.
        raise malformed("receipt carries more than one signer") if infos.size > 1

        fields = Asn1.parse_scanned(infos.first.raw).kids
        raise malformed("truncated SignerInfo") if fields.size < 5

        sid = fields[1]
        unless sid.tag == Asn1::TAG_SEQUENCE && sid.kids.size == 2 &&
               sid.kids[1].tag == Asn1::TAG_INTEGER
          raise malformed("unsupported signer identifier")
        end

        digest_algorithm = fields[2]
        oid_node = digest_algorithm.kids.first
        unless digest_algorithm.tag == Asn1::TAG_SEQUENCE && oid_node && oid_node.tag == Asn1::TAG_OID
          raise malformed("unexpected digestAlgorithm layout")
        end

        # The allow-list decision lives in ReceiptVerifier, not here: the
        # cross-port check order puts "unsupported digest" after the chain and
        # signer-purpose checks, so a foreign chain must still report
        # INVALID_CHAIN first.
        oid = oid_string(oid_node.content)

        SignerInfo.new(
          issuer_der: sid.kids[0].raw,
          serial: unsigned_integer(sid.kids[1].content),
          digest_oid: oid,
          digest_name: DIGESTS[oid]
        )
      end

      def unsigned_integer(bytes)
        raise malformed("empty serial number") if bytes.empty?

        negative = bytes.getbyte(0) >= 0x80
        value = 0
        bytes.each_byte { |b| value = (value << 8) | b }
        return value unless negative

        value - (1 << (bytes.bytesize * 8))
      end

      def oid_string(contents)
        raise malformed("empty OBJECT IDENTIFIER") if contents.empty?

        first = contents.getbyte(0)
        parts = [[first / 40, 2].min]
        parts << (first - (parts[0] * 40))
        value = 0
        started = false
        contents.each_byte.with_index do |byte, index|
          next if index.zero?

          value = (value << 7) | (byte & 0x7F)
          started = true
          next unless (byte & 0x80).zero?

          parts << value
          value = 0
          started = false
        end
        raise malformed("truncated OBJECT IDENTIFIER") if started

        parts.join(".")
      end

      def malformed(message)
        VerificationError.new(Reason::INVALID_RECEIPT_FORMAT, message)
      end
    end
  end
end
