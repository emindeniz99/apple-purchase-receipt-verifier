# frozen_string_literal: true

require "openssl"
require "digest"

module ApplePurchaseReceiptVerifier
  # Apple marker OID the receipt-signing leaf must carry. Without this check
  # any Apple developer's own distribution certificate — which chains through
  # the same WWDR intermediate to the same pinned root — could sign a fully
  # forged receipt.
  RECEIPT_SIGNER_OID = "1.2.840.113635.100.6.11.1"
  # Apple marker OID: the Worldwide Developer Relations intermediate CA,
  # checked on the certificate that issued the receipt signer. New in 0.7:
  # it brings the receipt path level with the JWS path, which has always
  # checked both (docs/design/0.7-api.md).
  WWDR_INTERMEDIATE_OID = "1.2.840.113635.100.6.2.1"

  # @api private
  module Receipt
    # The receipt's base64 text, in UTF-8 bytes: 3 MiB, Apple's own
    # verifyReceipt limit (docs/design/0.7-api.md, Bounds), checked before
    # anything is decoded.
    MAX_RECEIPT_BASE64_BYTES = 3_145_728

    # Genuine receipts embed one to three certificates; the public fixtures
    # carry 1, 3 and 3. Ten leaves room for a longer Apple chain while
    # bounding what a hostile embedded set can cost.
    MAX_EMBEDDED_CERTIFICATES = 10

    # Apple signs a receipt with one SignerInfo. The library accepts a
    # receipt when at least one SignerInfo verifies under a pinned chain,
    # which keeps a future dual-signed receipt working; a fifth is refused
    # before any signature is checked (docs/design/0.7-api.md).
    MAX_SIGNER_INFOS = 4

    # Everything but the standard alphabet and "=", as a String#count
    # pattern: on a receipt up to 3 MiB a `\A...\z` Regexp match is far
    # slower than #count and #index.
    BASE64_DISALLOWED = "^A-Za-z0-9+/="

    class << self
      # @param base64 [String] the receipt's base64 text, as a client sends it
      # @param roots [Array<OpenSSL::X509::Certificate>]
      # @param clock [ClockOnce]
      # @return [ReceiptPayload]
      # @raise [VerificationError]
      def verify(base64, roots, clock)
        contained(Reason::MALFORMED, "receipt") do
          unless base64.is_a?(String) && !base64.empty?
            raise VerificationError.new(Reason::MALFORMED, "receipt must be a non-empty String")
          end
          # Before the decode, which would otherwise allocate the bytes it
          # decodes to; none of this is behind a signature check.
          if base64.bytesize > MAX_RECEIPT_BASE64_BYTES
            raise VerificationError.new(
              Reason::TOO_LARGE,
              "receipt exceeds the maximum accepted size of #{MAX_RECEIPT_BASE64_BYTES} bytes"
            )
          end

          der = decode_canonical_base64(base64)
          if der.nil?
            raise VerificationError.new(Reason::MALFORMED, "receipt is not canonical standard base64")
          end

          content = verify_signature(der, roots, clock)
          parse_signed_payload(content)
        end
      end

      # The rule Apple's verifyReceipt applies to `receipt-data` (measured
      # 2026-09-23, see docs/evidence/2026-09-23-verifyreceipt-base64.md):
      # non-empty standard base64 with exactly the canonical padding, and
      # nothing else. Whitespace anywhere, base64url, omitted or extra
      # padding and anything after the padding are refused. Unused low bits
      # in the last data character are accepted, as Apple accepts them. An
      # `x5c` entry is held to the same rule (Jws), with its own verdict.
      #
      # `unpack1("m0")`, Ruby's strict RFC 4648 decoder, refuses the unused
      # trailing bits Apple accepts, so the shape is checked here instead and
      # `unpack1("m")` decodes what passes.
      #
      # @param text [String]
      # @return [String, nil] the decoded bytes, or nil for anything that is
      #   not canonical standard base64
      def decode_canonical_base64(text)
        return nil unless text.is_a?(String)

        bytes = text.b
        size = bytes.bytesize
        return nil if size.zero? || !(size % 4).zero? || bytes.count(BASE64_DISALLOWED).positive?

        pad_at = bytes.index("=")
        return nil unless pad_at.nil? || (pad_at >= size - 2 && bytes.count("=") == size - pad_at)

        bytes.unpack1("m") #: String
      end

      private

      # Only VerificationError escapes. `SystemStackError` is named
      # explicitly because it is not a `StandardError` and would otherwise
      # walk straight through a caller's `rescue`. `fallback_reason` is the
      # reason for anything unexpected THIS stage produces
      # (docs/design/0.7-hardening-parity.md, change 4): input nobody has
      # vouched for yet must never raise INTERNAL_ERROR at will.
      def contained(fallback_reason, what)
        yield
      rescue VerificationError
        raise
      rescue SystemStackError
        raise VerificationError.new(fallback_reason, "#{what} nesting exhausted the stack")
      rescue StandardError => e
        raise VerificationError.new(fallback_reason, "malformed #{what}: #{e.class}")
      end

      # Every check up to and including a signature; returns the signed
      # content, not yet decoded.
      def verify_signature(der, roots, clock)
        begin
          Asn1.scan!(der)
        rescue Asn1::Error => e
          raise VerificationError.new(Reason::MALFORMED, e.message)
        end

        cms = Cms.parse(der)
        if cms.signer_infos.size > MAX_SIGNER_INFOS
          raise VerificationError.new(
            Reason::MALFORMED,
            "receipt carries #{cms.signer_infos.size} SignerInfos, more than the maximum of " \
            "#{MAX_SIGNER_INFOS}"
          )
        end
        # Bounded before a single embedded certificate is decoded or tried
        # as an issuer, all of which an unverified receipt would otherwise
        # get to pay for out of the caller's CPU.
        if cms.certificate_ders.size > MAX_EMBEDDED_CERTIFICATES
          raise VerificationError.new(
            Reason::MALFORMED,
            "receipt embeds #{cms.certificate_ders.size} certificates, more than the maximum of " \
            "#{MAX_EMBEDDED_CERTIFICATES}"
          )
        end

        # Only the creation date is read before trust is established,
        # because it is the instant the chain's validity is judged at;
        # nothing else in the payload is decoded until the chain and a
        # signature have passed.
        creation_date_ms = ReceiptAttributes.creation_date(cms.content)

        embedded, unreadable = decode_embedded_certificates(cms.certificate_ders)

        # Signer-independent, so walked once for all SignerInfos, and only
        # once one of them has named an embedded certificate that decodes.
        authenticated = nil
        first_failure = nil

        cms.signer_infos.each do |info|
          authenticated ||= Chain.authenticated_top_down(embedded, roots)
          at_millis = creation_date_ms || clock.millis
          candidates = signer_certificates(info, embedded, unreadable)

          # More than one embedded certificate can carry this SignerInfo's
          # identity (issuer + serial) — a twin cloning a genuine signer's
          # identity onto another key, say. Each is tried in bag order; one
          # whose chain, markers and signature all pass is enough, and a
          # candidate's key is used only once its own chain has passed
          # (still top-down: {Chain.authenticated_top_down} above never
          # touches an untrusted key). Otherwise this SignerInfo's verdict
          # is the first candidate's failure.
          signer_failure = nil
          candidates.each do |signer|
            verify_one_signer(cms: cms, info: info, signer: signer, roots: roots,
                              authenticated: authenticated, # steep:ignore ArgumentTypeMismatch
                              at_millis: at_millis)
            assert_content_agrees_with_openssl(der, cms.content)
            return cms.content
          rescue VerificationError => e
            raise e if e.reason == Reason::INTERNAL_ERROR

            signer_failure ||= e
          end
          first_failure ||= signer_failure
        rescue VerificationError => e
          # A clock failure is the library's own dependency breaking, not a
          # verdict about this signer: it does not get shadowed by "first
          # signer wins" and does not improve by trying another one.
          raise e if e.reason == Reason::INTERNAL_ERROR

          first_failure ||= e
        end
        raise first_failure # steep:ignore UnresolvedOverloading
      end

      # The certificates `info` names, in bag order, or the verdict for the
      # bag. The signer's own entry not decoding is INVALID_CERTIFICATE, as
      # an unreadable `x5c` entry is on the JWS path; any OTHER entry not
      # decoding is MALFORMED, because the bag is unsigned and bytes that
      # cannot be read there are a defect of the receipt, not of a
      # certificate. A broken signer outranks a broken stranger.
      def signer_certificates(info, embedded, unreadable)
        if unreadable.any? { |der| names_the_signer?(der, info) }
          raise VerificationError.new(Reason::INVALID_CERTIFICATE,
                                      "receipt signer certificate does not decode")
        end
        unless unreadable.empty?
          raise VerificationError.new(Reason::MALFORMED,
                                      "an embedded certificate is not a valid certificate")
        end

        candidates = embedded.select do |cert|
          cert.serial.to_i == info.serial && cert.issuer.to_der == info.issuer_der
        end
        return candidates unless candidates.empty?

        raise VerificationError.new(Reason::MALFORMED, "signer certificate not embedded")
      end

      def verify_one_signer(cms:, info:, signer:, authenticated:, roots:, at_millis:)
        path = Chain.build_and_validate_path(signer, authenticated, roots, at_millis)
        # Checked after the chain, so a foreign chain still reports
        # UNTRUSTED_CHAIN rather than INVALID_CERTIFICATE_PURPOSE.
        if signer.find_extension(RECEIPT_SIGNER_OID).nil?
          raise VerificationError.new(
            Reason::INVALID_CERTIFICATE_PURPOSE,
            "receipt signer certificate lacks Apple marker OID #{RECEIPT_SIGNER_OID}"
          )
        end
        # The certificate after the signer on the path. A signer issued
        # straight by a root has no WWDR certificate to carry the marker.
        intermediate = path[1]
        if intermediate.nil? || intermediate.find_extension(WWDR_INTERMEDIATE_OID).nil?
          raise VerificationError.new(
            Reason::INVALID_CERTIFICATE_PURPOSE,
            "receipt intermediate certificate lacks Apple marker OID #{WWDR_INTERMEDIATE_OID}"
          )
        end
        # The signer's key is used to check the CMS signature, so a key
        # this build cannot decode is a defect of the certificate. Judged
        # only now, once the chain has vouched for it.
        Chain.decode_public_key!(signer)

        verify_cms_signature(cms, info, signer)
      end

      # No key type, digest or signature algorithm allow-list beyond what
      # this port's OpenSSL implements: the signer is already pinned to an
      # Apple root and carries Apple's receipt-signing marker (change 3, Q14,
      # Q15). The chain is checked BEFORE the signature on purpose: checking
      # the signature first would run the attacker's own key (their choice of
      # RSA size and exponent) before anything about it is trusted.
      def verify_cms_signature(cms, info, signer)
        if info.digest_name.nil?
          raise VerificationError.new(Reason::INVALID_SIGNATURE,
                                      "unsupported digest algorithm #{info.digest_oid}")
        end

        signed_bytes, message_digest, content_type = signing_input(cms, info)
        # RFC 5652 11.1: the contentType attribute names the content the
        # signature covers, so one that names another type is a signature
        # over something else.
        if !content_type.nil? && content_type != cms.content_type
          raise VerificationError.new(Reason::INVALID_SIGNATURE,
                                      "contentType attribute differs from the eContentType")
        end
        unless message_digest.nil?
          content_digest = OpenSSL::Digest.digest(info.digest_name, cms.content)
          unless secure_equal?(message_digest, content_digest)
            raise VerificationError.new(Reason::INVALID_SIGNATURE,
                                        "messageDigest attribute does not match content")
          end
        end

        ok = Signature.verify_signer_signature(
          public_key: signer.public_key, digest_name: info.digest_name,
          signature_algorithm_oid: info.signature_algorithm_oid,
          signature_algorithm_params: info.signature_algorithm_params,
          signature: info.signature, data: signed_bytes
        )
        raise VerificationError.new(Reason::INVALID_SIGNATURE, "CMS signature check failed") unless ok
      end

      # @return [Array(String, String?, String?)] the exact bytes the
      #   signature covers, the `messageDigest` attribute value to check
      #   against the content digest, and the `contentType` attribute's
      #   value to check against the SignedData's own eContentType (both
      #   nil when there are no signedAttrs: the signature then covers the
      #   content directly and there is no separate attribute to check)
      def signing_input(cms, info)
        signed_attrs = info.signed_attrs
        return [cms.content, nil, nil] if signed_attrs.nil?

        if info.signed_attrs_incomplete?
          raise VerificationError.new(
            Reason::INVALID_SIGNATURE,
            "signedAttrs lack a contentType or messageDigest attribute, or carry one twice"
          )
        end

        [Cms.signed_attrs_signed_bytes(signed_attrs), info.message_digest_attribute,
         info.content_type_attribute]
      end

      # The bytes this library parsed as the encapsulated content must be
      # the same bytes an independent parser (OpenSSL's own PKCS7 reader)
      # finds there. Without this, a disagreement between the two readers
      # about where the content is would be a forgery primitive. Run only
      # structurally (NOVERIFY/NOINTERN/NOSIGS — no certificate path, no
      # signer identification and no signature mathematics), so it applies
      # to every signer algorithm this library accepts, not only the ones
      # `OpenSSL::PKCS7#verify`'s own crypto can check.
      def assert_content_agrees_with_openssl(der, content)
        pkcs7 = OpenSSL::PKCS7.new(der)
        flags = OpenSSL::PKCS7::NOVERIFY | OpenSSL::PKCS7::NOINTERN | OpenSSL::PKCS7::NOSIGS
        pkcs7.verify(pkcs7.certificates, OpenSSL::X509::Store.new, nil, flags) # steep:ignore
        agrees = pkcs7.data&.b == content.b
        return if agrees

        raise VerificationError.new(Reason::MALFORMED, "verified content does not match the parsed payload")
      rescue OpenSSL::OpenSSLError
        raise VerificationError.new(Reason::MALFORMED, "verified content does not match the parsed payload")
      end

      def secure_equal?(one, other)
        one.bytesize == other.bytesize && OpenSSL.fixed_length_secure_compare(one, other)
      end

      # A certificate that OpenSSL parses but {CertificateStructure} finds
      # unsound is bucketed with the ones OpenSSL refused outright: both are
      # a defect of the receipt's certificate bag, not a chain verdict
      # (docs/design/0.7-hardening-parity.md, "reject-a-stranger-whose-
      # signature-bit-string-is-unaligned").
      def decode_embedded_certificates(ders)
        certificates = [] #: Array[OpenSSL::X509::Certificate]
        unreadable = [] #: Array[String]
        ders.each do |der|
          certificate = OpenSSL::X509::Certificate.new(der)
          if CertificateStructure.sound?(certificate)
            certificates << certificate
          else
            unreadable << der
          end
        rescue OpenSSL::OpenSSLError
          unreadable << der
        end
        [certificates, unreadable]
      end

      # Whether `der` carries the issuer Name and serialNumber `info` names,
      # read as generic ASN.1 rather than as a certificate: the entries this
      # is asked about are the ones OpenSSL refused, and an identity is
      # still legible in bytes that are not a certificate all the way down.
      #
      #   TBSCertificate ::= SEQUENCE { [0] version DEFAULT v1, serialNumber
      #   INTEGER, signature AlgorithmIdentifier, issuer Name, ... }
      def names_the_signer?(der, info)
        certificate = Asn1.parse(der)
        return false unless certificate.tag == Asn1::TAG_SEQUENCE

        tbs = certificate.kids.first
        return false if tbs.nil? || tbs.tag != Asn1::TAG_SEQUENCE

        fields = tbs.kids
        index = fields.first&.tag == Asn1::TAG_CONTEXT_0 ? 1 : 0
        serial = fields[index]
        issuer = fields[index + 2]
        return false if serial.nil? || issuer.nil?
        return false if serial.tag != Asn1::TAG_INTEGER || issuer.tag != Asn1::TAG_SEQUENCE

        OpenSSL::ASN1.decode(serial.raw).value.to_i == info.serial && issuer.raw == info.issuer_der
      rescue Asn1::Error, OpenSSL::OpenSSLError
        false
      end

      # The full payload parse, run only after the chain and the signature
      # have passed. A trusted signer signed these bytes, so anything that
      # stops the parse (this library's grammar, a bound, a foreign error, a
      # SystemStackError) is the library's failure or a format Apple added,
      # not the client's: UNREADABLE_PAYLOAD, never MALFORMED.
      def parse_signed_payload(content)
        ReceiptAttributes.parse(content)
      rescue VerificationError => e
        # Our own error, whose message is already log-safe: kept as the
        # cause so an operator can see why the content did not parse
        # (docs/design/0.7-api.md, `cause`).
        raise VerificationError.new(Reason::UNREADABLE_PAYLOAD, "signed receipt content could not be read",
                                    cause_error: e)
      rescue SystemStackError
        raise VerificationError.new(Reason::UNREADABLE_PAYLOAD,
                                    "signed receipt content could not be read: stack exhausted")
      rescue StandardError => e
        # A foreign exception's own message is not trusted with a caller's
        # log line (docs/design/0.7-hardening-parity.md, change 6): only its
        # class name is quoted, never `e.message`.
        raise VerificationError.new(Reason::UNREADABLE_PAYLOAD,
                                    "signed receipt content could not be read: #{e.class}")
      end
    end
  end
end
