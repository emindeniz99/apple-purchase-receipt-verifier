# frozen_string_literal: true

require "openssl"

module ApplePurchaseReceiptVerifier
  # Apple marker OID the receipt-signing leaf must carry. Without this check
  # any Apple developer's own distribution certificate — which chains through
  # the same WWDR intermediate to the same pinned root — could sign a fully
  # forged receipt (PLAN.md D13).
  RECEIPT_SIGNER_OID = "1.2.840.113635.100.6.11.1"

  # Genuine receipts embed one to three certificates; the public fixtures carry
  # 1, 3 and 3. Ten leaves room for a longer Apple chain while bounding what
  # rejecting a hostile receipt costs — every embedded certificate is otherwise
  # decoded and RSA-checked as a candidate issuer before any signature is
  # verified. The bound is applied to the raw DER count, before a single
  # certificate becomes an object.
  MAX_EMBEDDED_CERTIFICATES = 10

  class << self
    # Chain and signature verification **without** the bundle-id check — the
    # primitive underneath both {ReceiptVerifier} and {VerifyReceiptEndpoint}
    # (which, like Apple's endpoint, answers for any bundle).
    #
    # Public on purpose, and the caveat is the whole reason it is documented:
    # **it does not check `bundle_id`.** A caller that unlocks products from
    # the result must compare `receipt.bundle_id` itself, or use
    # {ReceiptVerifier}, which does it.
    #
    # @param der [String] the receipt's DER bytes
    # @param trusted_roots [Array<OpenSSL::X509::Certificate, String>]
    # @return [AppReceipt]
    # @raise [VerificationError]
    def verify_receipt_core(der, trusted_roots:)
      roots = Chain.normalize_roots(trusted_roots)
      Receipt.verify(der, roots)
    end
  end

  # @api private
  module Receipt
    class << self
      def verify(der, roots)
        contained do
          bytes = binary(der)
          raise VerificationError.new(Reason::INVALID_RECEIPT_FORMAT, "receipt is empty") if bytes.empty?

          begin
            Asn1.scan!(bytes)
          rescue Asn1::Error => e
            raise VerificationError.new(Reason::INVALID_RECEIPT_FORMAT, e.message)
          end

          cms = Cms.parse(bytes)

          # Parsed before the signature is checked, and only to learn the
          # creation date the chain's validity is judged at. Nothing from it is
          # returned or acted on until every check below has passed.
          receipt = ReceiptPayload.parse(cms.content)

          # A receipt with no creation date falls back to the SYSTEM clock,
          # never to an injected one — which is why ReceiptVerifier takes no
          # clock parameter at all. A caller injecting a clock must not be able
          # to authenticate a chain that expired.
          instant = receipt.creation_date || Time.now.utc

          if cms.certificate_ders.size > MAX_EMBEDDED_CERTIFICATES
            raise VerificationError.new(
              Reason::INVALID_CHAIN,
              "receipt embeds more than #{MAX_EMBEDDED_CERTIFICATES} certificates"
            )
          end

          embedded = decode_certificates(cms.certificate_ders)
          signer = find_signer(embedded, cms.signer_info)
          if signer.nil?
            raise VerificationError.new(Reason::INVALID_RECEIPT_FORMAT,
                                        "signer certificate is not embedded in the receipt")
          end

          Chain.build_path(signer, embedded, roots, instant)

          if signer.find_extension(RECEIPT_SIGNER_OID).nil?
            raise VerificationError.new(
              Reason::INVALID_CERTIFICATE_PURPOSE,
              "receipt signer certificate lacks Apple marker OID #{RECEIPT_SIGNER_OID}"
            )
          end

          unless signer.public_key.is_a?(OpenSSL::PKey::RSA)
            raise VerificationError.new(Reason::INVALID_SIGNATURE, "receipt signer key is not RSA")
          end

          if cms.signer_info.digest_name.nil?
            raise VerificationError.new(
              Reason::INVALID_RECEIPT_FORMAT,
              "unsupported receipt digest algorithm #{cms.signer_info.digest_oid}"
            )
          end

          verify_cms_signature(bytes, signer, cms.content)

          receipt
        end
      end

      # Only VerificationError escapes. Containment is categorical, and
      # `SystemStackError` is named explicitly because it is not a
      # `StandardError`: the bounded scanner is the first line of defence and
      # this is the net under it. A library that can kill a caller's request
      # with a non-StandardError is broken, however loudly it fails.
      def contained
        yield
      rescue VerificationError
        raise
      rescue SystemStackError
        raise VerificationError.new(Reason::INVALID_RECEIPT_FORMAT,
                                    "receipt nesting exhausted the stack")
      rescue StandardError => e
        raise VerificationError.new(Reason::INVALID_RECEIPT_FORMAT,
                                    "malformed receipt: #{e.class}")
      end

      def binary(input)
        unless input.is_a?(String)
          raise VerificationError.new(Reason::INVALID_RECEIPT_FORMAT,
                                      "receipt must be a String of DER bytes")
        end

        input.b
      end

      def decode_certificates(ders)
        ders.map do |der|
          OpenSSL::X509::Certificate.new(der)
        rescue OpenSSL::OpenSSLError
          raise VerificationError.new(Reason::INVALID_RECEIPT_FORMAT,
                                      "embedded certificate is not parseable")
        end
      end

      # Both halves of issuerAndSerialNumber must match. Matching on the serial
      # alone would let a receipt carry a second certificate that borrows the
      # real signer's serial under a different issuer.
      def find_signer(embedded, signer_info)
        embedded.find do |cert|
          cert.serial.to_i == signer_info.serial &&
            cert.issuer.to_der == signer_info.issuer_der
        end
      end

      # OpenSSL owns the signature mathematics — it already implements the
      # RFC 5652 5.4 signedAttrs re-encode and the messageDigest comparison —
      # while this library owns every policy decision above.
      #
      # Two measured Ruby traps are handled here by construction:
      #
      # * `OpenSSL::PKCS7#verify` is NOT safely re-runnable. On one object, a
      #   failing strict call followed by a lenient one returns false with
      #   "bad signature", while the identical lenient call on a fresh object
      #   returns true. So: a freshly constructed PKCS7, exactly one #verify,
      #   never a retry.
      # * `X509::Store#time=` is silently ignored by `PKCS7#verify` (it judges
      #   certificates against wall-clock time regardless), which would reject
      #   every receipt Apple signed with the now-expired legacy chain. NOVERIFY
      #   turns that check off; this library already did it, at the right
      #   instant. NOINTERN makes OpenSSL identify the signer only from the
      #   certificate handed to it, so it cannot fall back to a different
      #   embedded one. The store passed in is empty and is never consulted.
      def verify_cms_signature(der, signer, content)
        pkcs7 = begin
          OpenSSL::PKCS7.new(der)
        rescue OpenSSL::OpenSSLError, ArgumentError
          raise VerificationError.new(Reason::INVALID_RECEIPT_FORMAT, "not a parseable PKCS#7 blob")
        end

        flags = OpenSSL::PKCS7::NOVERIFY | OpenSSL::PKCS7::NOINTERN
        ok = begin
          pkcs7.verify([signer], OpenSSL::X509::Store.new, nil, flags)
        rescue OpenSSL::PKCS7::PKCS7Error
          false
        end
        raise VerificationError.new(Reason::INVALID_SIGNATURE, "CMS signature check failed") unless ok

        # The bytes OpenSSL authenticated must be the bytes this library
        # parsed. Without this, a disagreement between the two readers about
        # where the content is would be a forgery primitive.
        verified = begin
          pkcs7.data
        rescue OpenSSL::OpenSSLError
          nil
        end
        return if verified && verified.b == content.b

        raise VerificationError.new(Reason::INVALID_RECEIPT_FORMAT,
                                    "verified content does not match the parsed payload")
      end
    end
  end

  # Verifies legacy PKCS#7 app receipts — the exact blob an app sends to
  # Apple's `verifyReceipt` — completely offline, against trust anchors the
  # caller pins (PLAN.md 2.2).
  #
  #   verifier = ApplePurchaseReceiptVerifier::ReceiptVerifier.new(
  #     trusted_roots: ApplePurchaseReceiptVerifier.apple_receipt_roots,
  #     bundle_id: "com.example.app"
  #   )
  #   receipt = verifier.verify_base64(receipt_data)
  #
  # There is no `clock:` here, and there must never be one: no receipt verdict
  # depends on "now". The single instant this path needs is the chain-validity
  # instant, which comes from the receipt's own creation date and, failing
  # that, from the system clock.
  class ReceiptVerifier
    # @param trusted_roots [Array<OpenSSL::X509::Certificate, String>]
    # @param bundle_id [String] the bundle id the receipt must carry
    def initialize(trusted_roots:, bundle_id:)
      @roots = Chain.normalize_roots(trusted_roots)
      unless bundle_id.is_a?(String) && !bundle_id.empty?
        raise ArgumentError,
              "bundle_id must be a non-empty String"
      end

      @bundle_id = bundle_id.dup.freeze
      freeze
    end

    # Verifies a receipt supplied either as raw DER bytes or as the base64 text
    # clients transport. The two are told apart by the first byte: DER always
    # begins with 0x30 (SEQUENCE), which is never the first character of
    # base64. Use {#verify_der} or {#verify_base64} where being explicit reads
    # better.
    #
    # @param receipt [String] DER bytes or base64 text
    # @param device_guid [String, nil] raw `identifierForVendor` bytes. When
    #   given, `SHA1(guid + opaqueValue + bundleIdBytes)` must equal
    #   attribute 5 (PLAN.md D4 — optional, because servers do not always have
    #   the GUID).
    # @return [AppReceipt]
    # @raise [VerificationError]
    def verify(receipt, device_guid: nil)
      unless receipt.is_a?(String)
        raise VerificationError.new(Reason::INVALID_RECEIPT_FORMAT,
                                    "receipt must be a String")
      end

      bytes = receipt.b
      if !bytes.empty? && bytes.getbyte(0) == Asn1::TAG_SEQUENCE
        verify_der(bytes, device_guid: device_guid)
      else
        verify_base64(receipt, device_guid: device_guid)
      end
    end

    # @param der [String] raw receipt bytes
    # @param device_guid [String, nil]
    # @return [AppReceipt]
    def verify_der(der, device_guid: nil)
      receipt = Receipt.verify(der, @roots)
      Receipt.contained do
        require_bundle_id(receipt)
        verify_device_hash(receipt, device_guid) unless device_guid.nil?
      end
      receipt
    end

    # @param base64 [String] the receipt's base64 text, as clients send it
    # @param device_guid [String, nil]
    # @return [AppReceipt]
    def verify_base64(base64, device_guid: nil)
      unless base64.is_a?(String)
        raise VerificationError.new(Reason::INVALID_RECEIPT_FORMAT,
                                    "receipt must be a base64 String")
      end

      der = begin
        base64.unpack1("m") || ""
      rescue ArgumentError
        raise VerificationError.new(Reason::INVALID_RECEIPT_FORMAT, "receipt is not base64")
      end
      verify_der(der, device_guid: device_guid)
    end

    private

    def require_bundle_id(receipt)
      return if receipt.bundle_id == @bundle_id

      raise VerificationError.new(Reason::WRONG_BUNDLE_ID,
                                  "receipt bundle id does not match the configured one")
    end

    def verify_device_hash(receipt, device_guid)
      unless device_guid.is_a?(String)
        raise VerificationError.new(Reason::DEVICE_HASH_MISMATCH,
                                    "device_guid must be a String of raw bytes")
      end
      if receipt.opaque_value.nil? || receipt.sha1_hash.nil? || receipt.bundle_id_bytes.nil?
        raise VerificationError.new(
          Reason::DEVICE_HASH_MISMATCH,
          "receipt lacks the attributes the device-hash check needs"
        )
      end

      computed = OpenSSL::Digest::SHA1.digest(
        device_guid.b + receipt.opaque_value + receipt.bundle_id_bytes
      )
      return if secure_equal?(computed, receipt.sha1_hash)

      raise VerificationError.new(Reason::DEVICE_HASH_MISMATCH,
                                  "computed device hash does not match attribute 5")
    end

    # Length is public; the bytes are not.
    def secure_equal?(one, other)
      one.bytesize == other.bytesize && OpenSSL.fixed_length_secure_compare(one, other)
    end
  end
end
