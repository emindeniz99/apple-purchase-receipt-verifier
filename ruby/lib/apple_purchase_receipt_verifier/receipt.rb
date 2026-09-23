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
          # Measured before the binary copy below, so an oversized input is
          # refused without being duplicated, scanned or parsed.
          if der.is_a?(String) && der.bytesize > ReceiptVerifier::MAX_RECEIPT_BYTES
            raise VerificationError.new(
              Reason::INVALID_RECEIPT_FORMAT,
              "receipt exceeds the maximum accepted size of #{ReceiptVerifier::MAX_RECEIPT_BYTES} bytes"
            )
          end

          bytes = binary(der)
          raise VerificationError.new(Reason::INVALID_RECEIPT_FORMAT, "receipt is empty") if bytes.empty?

          begin
            Asn1.scan!(bytes)
          rescue Asn1::Error => e
            raise VerificationError.new(Reason::INVALID_RECEIPT_FORMAT, e.message)
          end

          cms = Cms.parse(bytes)

          # Only the creation date is read before trust is established,
          # because it is the instant the chain's validity is judged at;
          # nothing else in the payload is decoded until the chain and the
          # signature have passed. A date that is missing, empty, unreadable
          # or stated twice cannot blame anyone yet, so it only moves the chain
          # instant to "now" and never rejects by itself.
          #
          # "Now" is the SYSTEM clock, never an injected one — which is why
          # ReceiptVerifier takes no clock parameter at all. A caller injecting
          # a clock must not be able to authenticate a chain that expired.
          instant = ReceiptPayload.creation_date(cms.content) || Time.now.utc

          if cms.certificate_ders.size > MAX_EMBEDDED_CERTIFICATES
            raise VerificationError.new(
              Reason::INVALID_CHAIN,
              "receipt embeds more than #{MAX_EMBEDDED_CERTIFICATES} certificates"
            )
          end

          embedded, unreadable, unreadable_signer =
            decode_certificates(cms.certificate_ders, cms.signer_info)
          signer = find_signer(embedded, cms.signer_info)
          if signer.nil?
            # Which entry is unreadable changes the verdict: a stranger the
            # receipt merely carries is a defect of the receipt, while the
            # SIGNER being unreadable is a defect of a certificate and gets
            # the verdict an unreadable x5c entry gets on the JWS path. Only
            # the identity an unreadable entry carries says which of the two
            # it is — asking instead whether anything failed to decode blames
            # a malformed stranger for a signer that is simply absent.
            if unreadable_signer
              raise VerificationError.new(
                Reason::INVALID_CERTIFICATE,
                "receipt signer certificate is not a valid certificate"
              )
            end

            if unreadable
              raise VerificationError.new(Reason::INVALID_RECEIPT_FORMAT,
                                          "embedded certificate is not parseable")
            end

            raise VerificationError.new(Reason::INVALID_RECEIPT_FORMAT,
                                        "signer certificate is not embedded in the receipt")
          end
          if unreadable
            raise VerificationError.new(Reason::INVALID_RECEIPT_FORMAT,
                                        "embedded certificate is not parseable")
          end
          assert_signer_is_readable(signer)

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

          # The chain is checked BEFORE the signature on purpose: checking
          # the signature first would run the attacker's own key (their choice
          # of RSA size and exponent) before anything about it is trusted.
          verify_cms_signature(bytes, signer, cms.content)

          parse_signed_payload(cms.content)
        end
      end

      # The full payload parse, run only after the chain and the signature
      # have passed. A trusted signer signed these bytes, so anything that
      # stops the parse (this library's grammar, a bound, a foreign error, a
      # SystemStackError) is the library's failure or a format Apple added,
      # not the client's: INTERNAL_ERROR, never INVALID_RECEIPT_FORMAT, which
      # the endpoint answers as 21002 and an app server reads as "deny". The
      # parser's error is kept as the raised error's `cause`.
      def parse_signed_payload(content)
        ReceiptPayload.parse(content)
      rescue SystemStackError, StandardError => e
        detail = e.is_a?(VerificationError) ? e.message.delete_prefix("#{e.reason}: ") : e.class.name
        raise VerificationError.new(Reason::INTERNAL_ERROR,
                                    "signed receipt content could not be read: #{detail}")
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

      # Everything but the standard alphabet and "=", as a String#count
      # pattern. A receipt is attacker-controlled and up to 3 MiB, so its
      # shape is checked with #count and #index rather than a Regexp: on a
      # string that size a `\A...\z` match measured about 85 ms where #count
      # takes under 2.
      BASE64_DISALLOWED = "^A-Za-z0-9+/="
      private_constant :BASE64_DISALLOWED

      # Decodes the base64 text a client sends as `receipt-data` by the rule
      # Apple's verifyReceipt applies (measured 2026-09-23, see
      # docs/evidence/2026-09-23-verifyreceipt-base64.md): non-empty standard
      # base64 with exactly the canonical padding, and nothing else.
      # Whitespace anywhere, base64url, omitted or extra padding and anything
      # after the padding are rejected. Unused low bits in the last data
      # character are accepted, as Apple accepts them.
      #
      # @param text [String] the receipt's base64 text, as a client sent it
      # @return [String] the decoded DER bytes
      # @raise [VerificationError]
      def decode_base64(text)
        unless text.is_a?(String)
          raise VerificationError.new(Reason::INVALID_RECEIPT_FORMAT,
                                      "receipt must be a base64 String")
        end
        # Before the decode: it allocates in proportion to the input, and
        # none of it is behind a signature check. Bytes, as Apple counts
        # them; for base64 the count equals the character count.
        if text.bytesize > ReceiptVerifier::MAX_RECEIPT_BYTES
          raise VerificationError.new(
            Reason::INVALID_RECEIPT_FORMAT,
            "receipt exceeds the maximum accepted size of #{ReceiptVerifier::MAX_RECEIPT_BYTES} bytes"
          )
        end

        decode_canonical_base64(text) ||
          raise(VerificationError.new(Reason::INVALID_RECEIPT_FORMAT,
                                      "receipt is not canonical standard base64"))
      end

      # The rule above as a plain decoder: the bytes, or nil. An x5c entry is
      # held to it too (Jws), with its own verdict.
      #
      # `unpack1("m0")`, Ruby's strict RFC 4648 decoder, refuses the unused
      # trailing bits Apple accepts, so the shape is checked here instead
      # and `unpack1("m")` decodes what passes: a non-empty length that is
      # a multiple of four, only the standard alphabet and "=", and "=" only
      # as a run of at most two at the end. That leaves exactly the canonical
      # padding, and "m" skips nothing in such a string.
      def decode_canonical_base64(text)
        bytes = text.b
        size = bytes.bytesize
        return nil if size.zero? || !(size % 4).zero? || bytes.count(BASE64_DISALLOWED).positive?

        pad_at = bytes.index("=")
        return nil unless pad_at.nil? || (pad_at >= size - 2 && bytes.count("=") == size - pad_at)

        bytes.unpack1("m") #: String
      end

      # Returns the entries OpenSSL could read, the first error from one it
      # could not, and whether any of the entries it could not read is the one
      # the SignerInfo names. The error is held rather than raised because
      # which entry it belongs to decides the verdict; see the caller.
      def decode_certificates(ders, signer_info)
        certificates = [] #: Array[OpenSSL::X509::Certificate]
        unreadable = nil
        unreadable_signer = false
        ders.each do |der|
          certificates << OpenSSL::X509::Certificate.new(der)
        rescue OpenSSL::OpenSSLError => e
          unreadable ||= e
          unreadable_signer ||= names_the_signer?(der, signer_info)
        end
        [certificates, unreadable, unreadable_signer]
      end

      # Whether `der` carries the issuer Name and serialNumber the SignerInfo
      # names, read as generic ASN.1 rather than as a certificate. The entries
      # this is asked about are the ones OpenSSL refused, and an identity is
      # still legible in bytes that are not a certificate all the way down —
      # which is what says whether the SignerInfo means this entry. Node,
      # Swift and Go resolve the signer the same way.
      #
      #   TBSCertificate ::= SEQUENCE { [0] version DEFAULT v1, serialNumber
      #   INTEGER, signature AlgorithmIdentifier, issuer Name, ... }
      #
      # Anything without that shape is not an identity and cannot match.
      def names_the_signer?(der, signer_info)
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

        OpenSSL::ASN1.decode(serial.raw).value.to_i == signer_info.serial &&
          issuer.raw == signer_info.issuer_der
      rescue Asn1::Error, OpenSSL::OpenSSLError
        false
      end

      # The same three things OpenSSL decodes more leniently than the checks
      # below assume that Jws#certificates settles for an x5c entry, plus the
      # extension VALUES, which it never looks inside: an unknown X.509
      # version, a repeated extension, an extnValue that stops decoding
      # partway through, and a public key on a curve this build does not
      # implement. Each is a defect of the certificate, so each is
      # INVALID_CERTIFICATE, and each is settled BEFORE the chain so it
      # cannot come out as a verdict about the path (receipt/reject-signer-*).
      def assert_signer_is_readable(signer)
        unless (0..2).cover?(signer.version)
          raise VerificationError.new(Reason::INVALID_CERTIFICATE,
                                      "receipt signer certificate has an unknown X.509 version")
        end

        oids = signer.extensions.map(&:oid)
        unless oids.uniq.size == oids.size
          raise VerificationError.new(Reason::INVALID_CERTIFICATE,
                                      "receipt signer certificate carries a duplicate extension")
        end

        signer.extensions.each do |extension|
          OpenSSL::ASN1.decode(OpenSSL::ASN1.decode(extension.to_der).value.last.value)
        end
        signer.public_key
      rescue OpenSSL::OpenSSLError
        raise VerificationError.new(Reason::INVALID_CERTIFICATE,
                                    "receipt signer certificate is not a valid certificate")
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
          pkcs7.verify([signer], OpenSSL::X509::Store.new, nil, flags) # steep:ignore ArgumentTypeMismatch
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
    # Ceiling on the receipt this library will look at: the base64 text at
    # every entry point that takes it ({#verify}, {#verify_base64} and the
    # endpoint's `receipt-data`), in bytes, and the DER at every entry point
    # that takes bytes, {ApplePurchaseReceiptVerifier.verify_receipt_core}
    # included. A larger receipt is {Reason::INVALID_RECEIPT_FORMAT}.
    #
    # 3 MiB: Apple's verifyReceipt refuses a request body over 3,145,728
    # bytes (measured 2026-09-23), so no receipt it would accept is larger.
    # A fixed constant, the same in every port. Checked before anything is
    # decoded: base64 decoding allocates about three quarters of the input
    # again, the CMS parse allocates in proportion to the DER, and none of
    # that is behind a signature check.
    MAX_RECEIPT_BYTES = 3_145_728

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
    # @param device_guid [String, nil] raw device GUID bytes — the raw bytes
    #   of `identifierForVendor` on iOS, iPadOS, tvOS and watchOS, including
    #   an iOS app running on an Apple silicon Mac, or the primary network
    #   interface's MAC address from `copy_mac_address` on macOS and Mac
    #   Catalyst. When given, `SHA1(guid + opaqueValue + bundleIdBytes)` must
    #   equal attribute 5 (PLAN.md D4 — optional, because servers do not
    #   always have the GUID).
    # @return [AppReceipt]
    # @raise [VerificationError]
    def verify(receipt, device_guid: nil)
      unless receipt.is_a?(String)
        raise VerificationError.new(Reason::INVALID_RECEIPT_FORMAT,
                                    "receipt must be a String")
      end

      # The first byte is read in place: a copy of the whole input here would
      # be made before either path could apply MAX_RECEIPT_BYTES to it.
      if receipt.getbyte(0) == Asn1::TAG_SEQUENCE
        verify_der(receipt, device_guid: device_guid)
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
      verify_der(Receipt.decode_base64(base64), device_guid: device_guid)
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
        device_guid.b + receipt.opaque_value + receipt.bundle_id_bytes # steep:ignore ArgumentTypeMismatch
      )
      return if secure_equal?(computed, receipt.sha1_hash) # steep:ignore ArgumentTypeMismatch

      raise VerificationError.new(Reason::DEVICE_HASH_MISMATCH,
                                  "computed device hash does not match attribute 5")
    end

    # Length is public; the bytes are not.
    def secure_equal?(one, other)
      one.bytesize == other.bytesize && OpenSSL.fixed_length_secure_compare(one, other)
    end
  end
end
