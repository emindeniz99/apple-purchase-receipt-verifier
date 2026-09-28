# frozen_string_literal: true

require "openssl"

module ApplePurchaseReceiptVerifier
  # Apple marker OID carried by App Store signing leaf certificates.
  LEAF_MARKER_OID = "1.2.840.113635.100.6.11.1"
  # Apple marker OID carried by the Worldwide Developer Relations intermediate.
  INTERMEDIATE_MARKER_OID = "1.2.840.113635.100.6.2.1"

  # @api private
  #
  # {Verifier#verify_signed_data}: any Apple-signed compact JWS (StoreKit 2
  # `jwsRepresentation`, App Store Server `signedTransactionInfo` /
  # `signedRenewalInfo`, app transactions, Server Notifications V2), verified
  # entirely offline against trust anchors the caller pins.
  #
  # ES256 only, exactly three `x5c` certificates, the chain to a pinned root
  # at the payload's `signedDate` (the clock when it states none), Apple's
  # marker OIDs on leaf and intermediate, then the signature. The order of
  # the checks is observable: an input that fails an early check reports
  # that check's reason, and the shared cases pin it.
  module Jws
    # Ceiling on a compact JWS, in UTF-8 bytes (docs/design/0.7-api.md,
    # Bounds). A longer one is MALFORMED before it is split or decoded:
    # splitting copies it, base64url decoding allocates three quarters of it
    # again and JSON parsing a multiple of that, none of it behind a
    # signature check.
    MAX_JWS_BYTES = 262_144

    # A JSON number as epoch milliseconds: an integer must fit a signed
    # 64-bit range; a number with a fraction or exponent is read as a float
    # and truncated when it lies within that range (2^63 itself saturates to
    # the largest representable instant, matching a `f64 as i64` cast);
    # anything else, `1e300` say, is no instant.
    I64_MIN = -(2**63)
    I64_MAX = (2**63) - 1

    class << self
      # @param jws [String]
      # @param roots [Array<OpenSSL::X509::Certificate>]
      # @param clock [ClockOnce]
      # @return [JsonPayload]
      # @raise [VerificationError]
      def verify(jws, roots, clock)
        contained do
          verify_signature(jws, roots, clock)
        end
      end

      private

      # Only VerificationError escapes an exported entry point —
      # categorically, not by listing types. `SystemStackError` is named
      # explicitly because it is not a `StandardError` and would otherwise
      # walk straight through a caller's `rescue`.
      def contained
        yield
      rescue VerificationError
        raise
      rescue SystemStackError
        raise VerificationError.new(Reason::MALFORMED, "input nesting exhausted the stack")
      rescue StandardError => e
        raise VerificationError.new(Reason::MALFORMED, "malformed JWS: #{e.class}")
      end

      def verify_signature(jws, roots, clock)
        header_b64, payload_b64, signature_b64 = split_segments(jws)
        header = read_header(base64url_decode(header_b64, "header"))

        unless header["alg"] == "ES256"
          raise VerificationError.new(Reason::MALFORMED,
                                      "alg must be ES256, got #{SafeText.quote(header["alg"])}")
        end

        x5c = header["x5c"]
        unless x5c.is_a?(Array) && x5c.size == 3 && x5c.all?(String)
          raise VerificationError.new(Reason::MALFORMED, "x5c must contain exactly 3 certificates")
        end

        leaf = parse_x5c_certificate(x5c[0])
        intermediate = parse_x5c_certificate(x5c[1])
        # Parsed and then dropped: the third entry is trusted by nobody, and
        # reading it decides only whether it IS a certificate
        # (transaction/reject-x5c-root-that-is-not-a-certificate).
        parse_x5c_certificate(x5c[2])

        # Never raises: a payload that does not read as a JSON object is
        # carried past the chain and signature checks, with the clock
        # standing in for the missing date, and decided only afterwards.
        payload_text, signed_date_millis, payload_ok = read_payload(base64url_decode(payload_b64,
                                                                                     "payload"))

        # Chain validity is judged at signing time, so payloads Apple signed
        # with a since-rotated certificate keep verifying.
        at_millis = signed_date_millis || clock.millis
        # The chain, top-down (#161): the intermediate against a pinned
        # anchor first, and only once that has vouched for it, the leaf
        # against the intermediate's key.
        Chain.validate_pair(leaf, intermediate, roots, at_millis)

        # Checked after the chain: a chain to a foreign root whose
        # certificates lack the markers is UNTRUSTED_CHAIN, not this.
        if leaf.find_extension(LEAF_MARKER_OID).nil?
          raise VerificationError.new(Reason::INVALID_CERTIFICATE_PURPOSE,
                                      "leaf certificate lacks Apple marker OID #{LEAF_MARKER_OID}")
        end
        if intermediate.find_extension(INTERMEDIATE_MARKER_OID).nil?
          raise VerificationError.new(
            Reason::INVALID_CERTIFICATE_PURPOSE,
            "intermediate certificate lacks Apple marker OID #{INTERMEDIATE_MARKER_OID}"
          )
        end

        verify_es256(leaf, "#{header_b64}.#{payload_b64}", base64url_decode(signature_b64, "signature"))

        return JsonPayload.new(json: payload_text) if payload_ok

        raise VerificationError.new(Reason::UNREADABLE_PAYLOAD, "signed payload is not a JSON object")
      end

      def split_segments(jws)
        unless jws.is_a?(String) && !jws.empty?
          raise VerificationError.new(Reason::MALFORMED, "jws must be a non-empty String")
        end
        if jws.bytesize > MAX_JWS_BYTES
          raise VerificationError.new(Reason::TOO_LARGE,
                                      "jws exceeds the maximum accepted size of #{MAX_JWS_BYTES} bytes")
        end

        parts = jws.split(".", -1)
        unless parts.size == 3
          raise VerificationError.new(Reason::MALFORMED,
                                      "expected 3 dot-separated segments, got #{parts.size}")
        end

        [parts[0], parts[1], parts[2]] #: [String, String, String]
      end

      # Strict base64url: the JWS alphabet only, no padding, no whitespace,
      # no standard-base64 `+` or `/`. A lenient decoder that skips what it
      # does not recognise turns a corrupted segment into a differently
      # corrupted one.
      def base64url_decode(segment, what)
        unless segment.match?(/\A[A-Za-z0-9_-]*\z/) && (segment.bytesize % 4) != 1
          raise VerificationError.new(Reason::MALFORMED, "#{what} is not base64url")
        end

        padded = segment.tr("-_", "+/")
        padded += "=" * ((4 - (padded.bytesize % 4)) % 4)
        begin
          padded.unpack1("m0") #: String
        rescue ArgumentError
          raise VerificationError.new(Reason::MALFORMED, "#{what} is not base64url")
        end
      end

      # The header is outer structure, so anything that stops the read is
      # MALFORMED: bytes that are not strict UTF-8, a byte-order mark (RFC
      # 8259 8.1 forbids one), and anything but whitespace after the object.
      def read_header(bytes)
        Json.parse_whole_object(bytes)
      rescue Json::Error => e
        raise VerificationError.new(Reason::MALFORMED, "header is not a JSON object: #{e.message}")
      end

      # The payload text and its last top-level `signedDate`, or why it is
      # not a JSON object in UTF-8. Reading it never raises: a `signedDate`
      # that is not a number, or a number no instant can hold (`1e300`),
      # counts as not stated (owner, 2026-09-27) and the clock stands in.
      #
      # @return [Array(String, Integer?, bool)] the payload text verbatim,
      #   the signing instant in epoch milliseconds (or nil), and whether the
      #   payload read as a JSON object at all
      def read_payload(bytes)
        text = bytes.dup.force_encoding(Encoding::UTF_8)
        return [text, nil, false] unless text.valid_encoding?

        object = Json.parse_whole_object(text)
        [text, numeric_instant(object["signedDate"]), true]
      rescue Json::Error
        [bytes.dup.force_encoding(Encoding::UTF_8), nil, false]
      end

      def numeric_instant(value)
        case value
        when Integer
          value if value.between?(I64_MIN, I64_MAX)
        when Float
          return nil unless value.finite? && value >= I64_MIN.to_f && value <= I64_MAX.to_f + 1024.0

          truncated = value.truncate
          [truncated, I64_MAX].min
        end
      end

      # All three entries are read; only the first two are returned. `x5c[2]`
      # is trusted by nobody. {CertificateStructure} settles what OpenSSL
      # decodes more leniently than this library assumes, for every entry.
      # The public key is deliberately NOT touched here (#161): a curve
      # this build does not implement is judged only once a pinned anchor
      # has vouched for the certificate (Chain.decode_public_key!).
      def parse_x5c_certificate(entry)
        der = Receipt.decode_canonical_base64(entry)
        raise VerificationError.new(Reason::INVALID_CERTIFICATE, "x5c entry is not base64") if der.nil?

        begin
          certificate = OpenSSL::X509::Certificate.new(der)
        rescue OpenSSL::OpenSSLError
          raise VerificationError.new(Reason::INVALID_CERTIFICATE, "x5c entry is not a valid certificate")
        end
        unless CertificateStructure.sound?(certificate)
          raise VerificationError.new(Reason::INVALID_CERTIFICATE, "x5c entry is not a valid certificate")
        end

        certificate
      end

      # P-256 order; r and s outside [1, n-1] are not a signature.
      EC_ORDER = OpenSSL::BN.new(
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
      ).freeze
      private_constant :EC_ORDER

      def verify_es256(leaf, signing_input, signature)
        key = Chain.decode_public_key!(leaf)
        unless key.is_a?(OpenSSL::PKey::EC) && key.group.curve_name == "prime256v1" # steep:ignore NoMethod
          raise VerificationError.new(Reason::INVALID_SIGNATURE, "leaf key is not a P-256 EC key")
        end
        unless signature.bytesize == 64
          raise VerificationError.new(Reason::INVALID_SIGNATURE,
                                      "ES256 signature must be 64 bytes, got #{signature.bytesize}")
        end

        r = OpenSSL::BN.new(signature.byteslice(0, 32), 2) # steep:ignore ArgumentTypeMismatch
        s = OpenSSL::BN.new(signature.byteslice(32, 32), 2) # steep:ignore ArgumentTypeMismatch
        if r.zero? || s.zero? || r >= EC_ORDER || s >= EC_ORDER
          raise VerificationError.new(Reason::INVALID_SIGNATURE, "ES256 signature scalar out of range")
        end

        der = OpenSSL::ASN1::Sequence.new(
          [OpenSSL::ASN1::Integer.new(r), OpenSSL::ASN1::Integer.new(s)]
        ).to_der
        ok = begin
          key.verify("SHA256", der, signing_input.b) # steep:ignore ArgumentTypeMismatch
        rescue OpenSSL::OpenSSLError
          false
        end
        return if ok

        raise VerificationError.new(Reason::INVALID_SIGNATURE, "ES256 signature check failed")
      end
    end
  end
end
