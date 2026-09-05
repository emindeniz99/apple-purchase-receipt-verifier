# frozen_string_literal: true

require "json"
require "openssl"

module ApplePurchaseReceiptVerifier
  # Apple marker OID carried by App Store signing leaf certificates.
  LEAF_MARKER_OID = "1.2.840.113635.100.6.11.1"
  # Apple marker OID carried by the Worldwide Developer Relations intermediate.
  INTERMEDIATE_MARKER_OID = "1.2.840.113635.100.6.2.1"

  # Verifies Apple-signed JWS payloads — StoreKit 2 `jwsRepresentation`,
  # `signedTransactionInfo` / `signedRenewalInfo`, App Store Server
  # Notifications V2 — entirely offline, against trust anchors the caller
  # pins. Nothing here reaches the network or the operating system's trust
  # store (PLAN.md 2.1).
  #
  #   verifier = ApplePurchaseReceiptVerifier::JwsVerifier.new(
  #     trusted_roots: ApplePurchaseReceiptVerifier.apple_jws_roots,
  #     bundle_id: "com.example.app",
  #     accepted_environments: [ApplePurchaseReceiptVerifier::Environment::PRODUCTION,
  #                             ApplePurchaseReceiptVerifier::Environment::SANDBOX],
  #     app_apple_id: 123456789
  #   )
  #   payload = verifier.verify_transaction(jws)
  class JwsVerifier
    # @param trusted_roots [Array<OpenSSL::X509::Certificate, String>] pinned
    #   anchors; in production {ApplePurchaseReceiptVerifier.apple_jws_roots}
    # @param bundle_id [String] the bundle id every payload must carry
    # @param accepted_environments [Array<String>] see {Environment}. Include
    #   Sandbox on endpoints App Review can reach (PLAN.md D3).
    # @param app_apple_id [Integer, nil] required to accept Production
    #   AppTransactions
    # @param max_signed_age_seconds [Numeric, nil] reject payloads signed
    #   longer ago than this. The unit is in the name on purpose: a bare
    #   `300` at a call site has to say what it means.
    # @param clock [#call, nil] source of "now" for the staleness rule only.
    #   Certificate validity is judged at the payload's own signing date, and
    #   its fallback reads the system clock — an injected clock must never be
    #   able to authenticate an expired chain.
    def initialize(trusted_roots:, bundle_id:, accepted_environments:,
                   app_apple_id: nil, max_signed_age_seconds: nil, clock: nil)
      @roots = Chain.normalize_roots(trusted_roots)

      unless bundle_id.is_a?(String) && !bundle_id.empty?
        raise ArgumentError,
              "bundle_id must be a non-empty String"
      end

      unless accepted_environments.is_a?(Array) && !accepted_environments.empty? &&
             accepted_environments.all? { |e| Environment::ALL.include?(e) }
        raise ArgumentError,
              "accepted_environments must be a non-empty Array of #{Environment::ALL.join(", ")}"
      end

      unless app_apple_id.nil? || app_apple_id.is_a?(Integer)
        raise ArgumentError, "app_apple_id must be an Integer or nil"
      end

      if !max_signed_age_seconds.nil? &&
         (!max_signed_age_seconds.is_a?(Numeric) || max_signed_age_seconds.negative?)
        raise ArgumentError, "max_signed_age_seconds must be a non-negative Numeric or nil"
      end

      raise ArgumentError, "clock must respond to #call" if !clock.nil? && !clock.respond_to?(:call)

      @bundle_id = bundle_id.dup.freeze
      @accepted_environments = accepted_environments.dup.freeze
      @app_apple_id = app_apple_id
      @max_signed_age_seconds = max_signed_age_seconds
      @clock = clock
      freeze
    end

    # Verifies a signed transaction and enforces bundle id and environment.
    #
    # @param jws [String]
    # @return [TransactionPayload]
    # @raise [VerificationError]
    def verify_transaction(jws)
      contained do
        claims = verify_signature(jws)
        require_bundle_id(claims["bundleId"])
        require_accepted_environment(claims["environment"])
        TransactionPayload.new(claims)
      end
    end

    # Verifies a signed AppTransaction and enforces bundle id, environment
    # (`receiptType`) and — in Production — the app Apple id.
    #
    # @param jws [String]
    # @return [AppTransactionPayload]
    # @raise [VerificationError]
    def verify_app_transaction(jws)
      contained do
        claims = verify_signature(jws)
        require_bundle_id(claims["bundleId"])
        environment = require_accepted_environment(claims["receiptType"])
        require_app_apple_id(environment, claims["appAppleId"])
        AppTransactionPayload.new(claims)
      end
    end

    # Verifies the chain and signature only and returns every claim — for
    # payload types this library does not model (renewal info, notification
    # envelopes). **No claim is enforced**: the caller checks bundle id,
    # environment and app Apple id itself.
    #
    # @param jws [String]
    # @return [Hash{String => Object}] frozen
    # @raise [VerificationError]
    def verify_raw(jws)
      contained { verify_signature(jws) }
    end

    private

    # Only VerificationError escapes an exported entry point — categorically,
    # not by listing types. `SystemStackError` is named explicitly because it
    # is not a `StandardError` and would otherwise walk straight through a
    # caller's `rescue`, killing their request.
    def contained
      yield
    rescue VerificationError
      raise
    rescue SystemStackError
      raise VerificationError.new(Reason::INVALID_JWS_FORMAT, "input nesting exhausted the stack")
    rescue StandardError => e
      raise VerificationError.new(Reason::INVALID_JWS_FORMAT, "malformed JWS: #{e.class}")
    end

    def verify_signature(jws)
      header_b64, payload_b64, signature_b64 = split_segments(jws)
      header = json_segment(header_b64, "header")

      unless header["alg"] == "ES256"
        raise VerificationError.new(Reason::INVALID_JWS_FORMAT,
                                    "alg must be ES256, got #{header["alg"].inspect}")
      end

      x5c = header["x5c"]
      unless x5c.is_a?(Array) && x5c.size == 3 && x5c.all?(String)
        raise VerificationError.new(Reason::INVALID_JWS_FORMAT,
                                    "x5c must contain exactly 3 certificates")
      end

      leaf, intermediate = certificates(x5c)

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

      claims = json_segment(payload_b64, "payload")

      # Chain validity is judged at signing time, so payloads Apple signed with
      # a since-rotated certificate keep verifying. When the payload states no
      # date, the fallback is the SYSTEM clock and never the injected one: a
      # caller injecting a clock to test staleness, or to paper over skew, must
      # not thereby be able to authenticate an expired chain.
      signed_at_millis = signed_at_millis_of(claims)
      instant = signed_at_millis.nil? ? Time.now.utc : Time.at(signed_at_millis / 1000.0).utc
      Chain.validate_pair(leaf, intermediate, @roots, instant)

      verify_es256(leaf, "#{header_b64}.#{payload_b64}", signature_b64)
      require_fresh(signed_at_millis)

      claims
    end

    def split_segments(jws)
      unless jws.is_a?(String) && !jws.empty?
        raise VerificationError.new(Reason::INVALID_JWS_FORMAT, "jws must be a non-empty String")
      end

      parts = jws.split(".", -1)
      unless parts.size == 3
        raise VerificationError.new(Reason::INVALID_JWS_FORMAT,
                                    "expected 3 dot-separated segments, got #{parts.size}")
      end

      parts
    end

    # Strict base64url: the JWS alphabet only, no padding, no whitespace, no
    # standard-base64 `+` or `/`. A lenient decoder that skips what it does not
    # recognise turns a corrupted segment into a differently corrupted one.
    def base64url_decode(segment, what)
      unless segment.match?(/\A[A-Za-z0-9_-]*\z/) && (segment.bytesize % 4) != 1
        raise VerificationError.new(Reason::INVALID_JWS_FORMAT, "#{what} is not base64url")
      end

      padded = segment.tr("-_", "+/")
      padded += "=" * ((4 - (padded.bytesize % 4)) % 4)
      begin
        padded.unpack1("m0")
      rescue ArgumentError
        raise VerificationError.new(Reason::INVALID_JWS_FORMAT, "#{what} is not base64url")
      end
    end

    def json_segment(segment, what)
      bytes = base64url_decode(segment, what)
      begin
        parsed = JSON.parse(bytes)
      rescue JSON::ParserError, EncodingError
        raise VerificationError.new(Reason::INVALID_JWS_FORMAT, "#{what} is not valid JSON")
      end
      unless parsed.is_a?(Hash)
        raise VerificationError.new(Reason::INVALID_JWS_FORMAT,
                                    "#{what} is not a JSON object")
      end

      parsed.freeze
    end

    # All three entries are read; only the first two are returned. `x5c[2]`
    # is trusted by nobody — only "the intermediate is signed by one of our
    # pinned anchors" counts, so an attacker swapping in their own third
    # element still changes nothing. Reading it settles the other question:
    # an entry that is not a certificate is INVALID_CERTIFICATE at every
    # index (transaction/reject-x5c-root-that-is-not-a-certificate).
    def certificates(x5c)
      x5c.map do |entry|
        begin
          der = entry.unpack1("m")
        rescue ArgumentError
          raise VerificationError.new(Reason::INVALID_CERTIFICATE, "x5c entry is not base64")
        end
        raise VerificationError.new(Reason::INVALID_CERTIFICATE, "x5c entry is empty") if der.nil?

        begin
          certificate = OpenSSL::X509::Certificate.new(der)
          # Three things OpenSSL decodes more leniently than the checks that
          # follow assume, settled here so all three are INVALID_CERTIFICATE:
          #
          #   - the version, which it keeps as whatever integer it found.
          #     X.509 defines v1, v2 and v3 (0, 1, 2) and nothing else, and
          #     nothing downstream reads the field, so without this a
          #     certificate claiming version 11 verifies like any other.
          #   - a repeated extension, which RFC 5280 4.2 forbids. OpenSSL
          #     hands the list back with both copies in it and every reader
          #     picks one, so without this the marker-OID lookup, the CA check
          #     and another port's answer can be about different copies.
          #   - the public key, which it decodes lazily, so a namedCurve this
          #     build does not implement would otherwise surface in the issuer
          #     check and be reported as a chain failure.
          unless (0..2).cover?(certificate.version)
            raise VerificationError.new(Reason::INVALID_CERTIFICATE,
                                        "x5c entry has an unknown X.509 version")
          end

          oids = certificate.extensions.map(&:oid)
          unless oids.uniq.size == oids.size
            raise VerificationError.new(Reason::INVALID_CERTIFICATE,
                                        "x5c entry carries a duplicate extension")
          end

          #   - the extension VALUES, which it never looks inside, so one that
          #     stops decoding partway through is the difference between
          #     parsing a certificate and scanning it for a marker OID.
          certificate.extensions.each do |extension|
            OpenSSL::ASN1.decode(OpenSSL::ASN1.decode(extension.to_der).value.last.value)
          end

          certificate.public_key
          certificate
        rescue OpenSSL::OpenSSLError
          raise VerificationError.new(Reason::INVALID_CERTIFICATE,
                                      "x5c entry is not a valid certificate")
        end
      end
    end

    # P-256 order; r and s outside [1, n-1] are not a signature.
    EC_ORDER = OpenSSL::BN.new(
      "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
    ).freeze
    private_constant :EC_ORDER

    def verify_es256(leaf, signing_input, signature_b64)
      key = leaf.public_key
      unless key.is_a?(OpenSSL::PKey::EC) && key.group.curve_name == "prime256v1"
        raise VerificationError.new(Reason::INVALID_SIGNATURE, "leaf key is not a P-256 EC key")
      end

      signature = base64url_decode(signature_b64, "signature")
      unless signature.bytesize == 64
        raise VerificationError.new(Reason::INVALID_SIGNATURE,
                                    "ES256 signature must be 64 bytes, got #{signature.bytesize}")
      end

      r = OpenSSL::BN.new(signature.byteslice(0, 32), 2)
      s = OpenSSL::BN.new(signature.byteslice(32, 32), 2)
      if r.zero? || s.zero? || r >= EC_ORDER || s >= EC_ORDER
        raise VerificationError.new(Reason::INVALID_SIGNATURE, "ES256 signature scalar out of range")
      end

      der = OpenSSL::ASN1::Sequence.new(
        [OpenSSL::ASN1::Integer.new(r), OpenSSL::ASN1::Integer.new(s)]
      ).to_der
      ok = begin
        key.verify(OpenSSL::Digest.new("SHA256"), der, signing_input.b)
      rescue OpenSSL::OpenSSLError
        false
      end
      return if ok

      raise VerificationError.new(Reason::INVALID_SIGNATURE, "ES256 signature check failed")
    end

    # When the payload says it was signed, in epoch milliseconds:
    # `signedDate` for transactions, `receiptCreationDate` for AppTransactions.
    #
    # A JSON number is not necessarily an integer, and every other port takes a
    # fractional one: node tests `typeof === 'number'`, java `canConvertToLong`,
    # python `isinstance(..., (int, float))`, swift `as? Double`. Treating it as
    # absent would judge the chain at "now" rather than at the stated instant
    # AND skip the staleness rule (PLAN.md §2.1 step 11) entirely — the wrong
    # instant plus a check silently not run.
    #
    # A non-finite number gets that same treatment for the same reason and in
    # the other direction: Ruby's JSON parser turns `1e400` into Infinity, and
    # quietly reading it back as "no claim" would reinterpret a stated signing
    # time as absence, so it is a malformed payload instead. (node and python
    # also refuse it; java reads it as absent.) Left alone it would reach
    # `Time.at` as a FloatDomainError.
    def signed_at_millis_of(claims)
      [claims["signedDate"], claims["receiptCreationDate"]].each do |value|
        next unless value.is_a?(Numeric)

        unless value.is_a?(Integer) || value.finite?
          raise VerificationError.new(Reason::INVALID_JWS_FORMAT,
                                      "payload signing date is not a finite number")
        end

        return value
      end
      nil
    end

    def require_bundle_id(actual)
      return if actual == @bundle_id

      raise VerificationError.new(Reason::WRONG_BUNDLE_ID,
                                  "payload bundle id does not match the configured one")
    end

    def require_accepted_environment(claim)
      return claim if claim.is_a?(String) && @accepted_environments.include?(claim)

      raise VerificationError.new(Reason::WRONG_ENVIRONMENT,
                                  "payload environment #{claim.inspect} is not in the accepted set")
    end

    def require_app_apple_id(environment, actual)
      return unless environment == Environment::PRODUCTION
      return if !@app_apple_id.nil? && @app_apple_id == actual

      raise VerificationError.new(Reason::WRONG_APP_APPLE_ID,
                                  "payload app Apple id does not match the configured one")
    end

    # The one verdict in this library that legitimately moves with wall-clock
    # time, and therefore the one the injected clock drives.
    def require_fresh(signed_at_millis)
      return if @max_signed_age_seconds.nil? || signed_at_millis.nil?

      now = @clock.nil? ? Time.now : @clock.call
      unless now.is_a?(Time)
        raise VerificationError.new(Reason::STALE_PAYLOAD,
                                    "clock did not return a Time")
      end

      age_seconds = ((now.to_r * 1000).to_i - signed_at_millis) / 1000.0
      return if age_seconds <= @max_signed_age_seconds

      raise VerificationError.new(Reason::STALE_PAYLOAD,
                                  "payload is older than the configured max signed age")
    end
  end
end
