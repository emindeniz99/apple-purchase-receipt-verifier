# frozen_string_literal: true

require "openssl"

module ApplePurchaseReceiptVerifier
  # Certificate path validation against caller-supplied, pinned anchors.
  #
  # There is no `OpenSSL::X509::Store` here, and that is deliberate. A store is
  # the one object in Ruby's OpenSSL binding that can be made to consult the
  # operating system's trust store — one stray `set_default_paths` copied from
  # a TLS example and this library would accept anything a public CA signed.
  # This module never constructs one, so the failure mode does not exist; the
  # only store in the whole gem is the empty one handed to `PKCS7#verify`
  # under `NOVERIFY`, where it is never consulted. A test greps `lib/` for
  # `set_default_paths`, `add_path` and `add_file`.
  #
  # **Top-down walk (#161).**
  # {authenticated_top_down} walks DOWN from the pinned anchors: a certificate
  # is only ever asked to verify a signature with the key of an anchor, or of
  # a certificate an anchor has already vouched for, directly or transitively.
  # No key a pinned root has not vouched for is ever decoded or used to check
  # a signature — a receipt or an `x5c` chain padded with a certificate whose
  # key is enormous, or does not decode at all, costs one name comparison per
  # round and is simply left out (Q16). This replaces the 0.6 walk, which
  # went the other way: from the target UP, trying every embedded certificate
  # as a candidate issuer and decoding and using ITS key to check a
  # signature before anything vouched for it.
  module Chain
    # Genuine receipt chains are three certificates deep, and the JWS chain
    # is fixed at three. Six bounds what a hostile embedded set can cost
    # while leaving room for a longer Apple chain (docs/design/0.7-api.md,
    # Bounds: "six certificates below the anchor, anchor excluded").
    MAX_PATH_LENGTH = 6

    # keyUsage bit 5 (RFC 5280 4.2.1.3) — keyCertSign.
    KEY_CERT_SIGN_BIT = 5

    # The extensions a certificate on the path may mark critical: the ones a
    # PKIX validator processes (RFC 5280 6.1), and for the leaf also
    # cRLDistributionPoints and extKeyUsage. Any other extension marked
    # critical makes the certificate unusable, so the path fails, as a PKIX
    # validator fails it.
    PROCESSED_EXTENSIONS = %w[
      2.5.29.15
      2.5.29.32
      2.5.29.33
      2.5.29.54
      2.5.29.28
      2.5.29.27
      2.5.29.36
      2.5.29.19
      2.5.29.17
      2.5.29.30
    ].freeze
    PROCESSED_LEAF_EXTENSIONS = %w[2.5.29.31 2.5.29.37].freeze

    class << self
      # Validates and copies the caller's anchors. Misconfiguration is a
      # programming error, so it raises ArgumentError, never VerificationError.
      def normalize_roots(roots)
        raise ArgumentError, "roots must be a non-empty array" unless roots.is_a?(Array)
        raise ArgumentError, "roots must be a non-empty array" if roots.empty?

        roots.map do |root|
          case root
          when OpenSSL::X509::Certificate then root
          when String then OpenSSL::X509::Certificate.new(root)
          else
            raise ArgumentError,
                  "roots entries must be OpenSSL::X509::Certificate or DER/PEM String, got #{root.class}"
          end
        end.freeze
      end

      # @param at_millis [Integer] epoch milliseconds, matching every other
      #   instant this library passes around, so a caller cannot pass a
      #   `Time` to one chain method and an Integer to another
      def valid_at?(cert, at_millis)
        instant = Time.at(Rational(at_millis, 1000)).utc # steep:ignore ArgumentTypeMismatch
        instant.between?(cert.not_before, cert.not_after)
      rescue StandardError
        false
      end

      # Name chaining plus a real signature check. Never a path builder: the
      # only thing OpenSSL is asked for is "does this public key sign these
      # bytes", and that key is always `issuer`'s. Callers of this module
      # never pass an unauthenticated certificate as `issuer` (that is the
      # whole point of the top-down walk below), so recording `issuer` here
      # is a true record of which keys a verification actually used.
      def issued_by?(cert, issuer)
        return false unless cert.issuer.to_der == issuer.subject.to_der

        record_key_use(issuer)
        cert.verify(issuer.public_key)
      rescue StandardError
        false
      end

      # `X509_check_ca`-equivalent: basicConstraints present with cA TRUE and,
      # where a keyUsage extension exists, keyCertSign permitted.
      def ca?(cert)
        extension = cert.find_extension("basicConstraints")
        return false if extension.nil?

        sequence = Asn1.parse(extension.to_der)
        value = sequence.kids.last
        return false if value.nil? || !value.octet_string?

        inner = Asn1.parse(value.octet_value)
        flag = inner.kids.first
        return false unless flag && flag.tag == 0x01 && flag.content_length.positive?
        return false if flag.content.getbyte(0).zero? # steep:ignore NoMethod

        cert_sign_permitted?(cert)
      rescue StandardError, Asn1::Error
        false
      end

      # The embedded certificates (or `x5c` entries) whose signature
      # verifies under a pinned anchor, or under a certificate already
      # accepted this way, walking DOWN from the anchors in at most
      # {MAX_PATH_LENGTH} rounds. Only these are handed to
      # {build_and_validate_path}. An embedded copy of an anchor itself is
      # accepted without a signature check (its DER equals the anchor's).
      #
      # @param embedded [Array<OpenSSL::X509::Certificate>]
      # @param anchors [Array<OpenSSL::X509::Certificate>]
      # @return [Array<OpenSSL::X509::Certificate>] the authenticated
      #   certificates, in the order they were accepted
      def authenticated_top_down(embedded, anchors)
        anchor_ders = anchors.map(&:to_der)
        authenticated = [] #: Array[OpenSSL::X509::Certificate]
        pending = embedded.reject { |cert| anchor_ders.include?(cert.to_der) }
        authenticated.concat(embedded.select { |cert| anchor_ders.include?(cert.to_der) })
        issuers = anchors + authenticated

        MAX_PATH_LENGTH.times do
          break if pending.empty?

          accepted, pending = pending.partition do |candidate|
            issuers.any? do |issuer|
              issued_by?(candidate, issuer)
            end
          end
          break if accepted.empty?

          authenticated.concat(accepted)
          issuers = accepted
        end
        authenticated
      end

      # Builds a path from `target` through `authenticated` (the result of
      # {authenticated_top_down}) to one of the pinned `anchors` — the shape
      # a legacy receipt uses, where the intermediates are embedded in the
      # CMS blob — then checks every certificate on it is inside its
      # validity window at `instant`. Returns the path, target first, anchor
      # excluded.
      #
      # The depth bound is {MAX_PATH_LENGTH}, and each candidate is tried at
      # most once per hop, so a cross-signed certificate mesh cannot make
      # this exponential.
      #
      # @raise [VerificationError] UNTRUSTED_CHAIN when no path reaches an
      #   anchor, an intermediate is not a CA, or the path is too long;
      #   INVALID_CERTIFICATE when a certificate on the path is outside its
      #   validity window
      def build_and_validate_path(target, authenticated, anchors, instant)
        path = [target]
        current = target
        loop do
          if path.size > 1 && !ca?(current)
            raise VerificationError.new(Reason::UNTRUSTED_CHAIN, "an intermediate is not a CA")
          end
          break if anchors.any? { |anchor| issued_by?(current, anchor) }
          if path.size >= MAX_PATH_LENGTH
            raise VerificationError.new(Reason::UNTRUSTED_CHAIN, "chain exceeds the maximum length")
          end

          issuer = authenticated.find do |candidate|
            path.none? { |on_path| on_path.equal?(candidate) } && issued_by?(current, candidate)
          end
          if issuer.nil?
            raise VerificationError.new(Reason::UNTRUSTED_CHAIN, "chain does not reach a pinned root")
          end

          path << issuer
          current = issuer
        end
        path.each do |cert|
          next if valid_at?(cert, instant)

          raise VerificationError.new(Reason::INVALID_CERTIFICATE,
                                      "certificate is outside its validity window at the chain instant")
        end
        # The leaf is the first certificate on the path; the anchor is not
        # on it.
        path.each_with_index do |cert, index|
          next unless unprocessed_critical_extension?(cert, leaf: index.zero?)

          raise VerificationError.new(Reason::UNTRUSTED_CHAIN,
                                      "a certificate on the path has an unsupported critical extension")
        end
        path
      end

      # The fixed JWS path: leaf -> intermediate -> a pinned anchor. `instant`
      # is required and has no default: "forgot to pass the signing time"
      # must not be spellable.
      #
      # The two signatures are checked from the anchor down first (#161): the
      # intermediate against a pinned anchor's key, and only once that has
      # vouched for it, the leaf against the intermediate's key. Validity and
      # the CA flag are judged only once the certificate they are about has
      # been vouched for.
      def validate_pair(leaf, intermediate, anchors, instant)
        unless anchors.any? { |anchor| issued_by?(intermediate, anchor) }
          raise VerificationError.new(Reason::UNTRUSTED_CHAIN, "intermediate not issued by a pinned root")
        end

        # Vouched for, and its key is about to check the leaf: a key this
        # build cannot decode (an unimplemented curve) is the certificate's
        # own defect, not a chain mismatch. Judged only now, never before
        # the intermediate was trusted.
        decode_public_key!(intermediate)
        unless issued_by?(leaf, intermediate)
          raise VerificationError.new(Reason::UNTRUSTED_CHAIN, "leaf not issued by the intermediate")
        end
        unless valid_at?(intermediate, instant)
          raise VerificationError.new(Reason::INVALID_CERTIFICATE,
                                      "certificate is outside its validity window at the chain instant")
        end
        unless ca?(intermediate)
          raise VerificationError.new(Reason::UNTRUSTED_CHAIN, "intermediate is not a CA")
        end
        if unprocessed_critical_extension?(intermediate, leaf: false)
          raise VerificationError.new(Reason::UNTRUSTED_CHAIN,
                                      "a certificate on the path has an unsupported critical extension")
        end
        unless valid_at?(leaf, instant)
          raise VerificationError.new(Reason::INVALID_CERTIFICATE,
                                      "certificate is outside its validity window at the chain instant")
        end
        return unless unprocessed_critical_extension?(leaf, leaf: true)

        raise VerificationError.new(Reason::UNTRUSTED_CHAIN,
                                    "a certificate on the path has an unsupported critical extension")
      end

      # --- the key-use seam (test-only instrumentation) -----------------

      # Runs `block` and returns `[result, ders]`, `ders` the DER of every
      # certificate whose key {issued_by?} used to check a signature while
      # `block` ran. The seam the hardening tests use to assert directly that
      # no verification ever used an untrusted key, rather than inferring it
      # from timing alone.
      def keys_used_during
        previous = Thread.current[:aprv_chain_keys_used]
        Thread.current[:aprv_chain_keys_used] = []
        result = yield
        used = Thread.current[:aprv_chain_keys_used] #: Array[String]
        [result, used]
      ensure
        Thread.current[:aprv_chain_keys_used] = previous
      end

      # Decodes `cert`'s public key, raising INVALID_CERTIFICATE for one
      # this build cannot build (an EC key on a curve OpenSSL does not
      # implement, most likely). Callers use this once a certificate has
      # been vouched for and its own key is about to be used for something
      # other than a chain-walk signature check ({issued_by?} decodes only
      # the issuer's key and needs no probe of its own).
      #
      # @return [OpenSSL::PKey::PKey]
      def decode_public_key!(cert)
        cert.public_key
      rescue OpenSSL::OpenSSLError
        raise VerificationError.new(Reason::INVALID_CERTIFICATE, "certificate key does not decode")
      end

      private

      # Whether `cert` marks critical an extension no step here processes
      # (RFC 5280 4.2: a certificate-using system MUST reject one it does
      # not recognize).
      def unprocessed_critical_extension?(cert, leaf:)
        cert.extensions.any? do |extension|
          next false unless extension.critical?

          # `Extension#oid` answers OpenSSL's short name for a recognized
          # extension ("basicConstraints") and the dotted form only for one
          # it does not recognize; normalize so the table below, written in
          # dotted OIDs, matches either way.
          oid = OpenSSL::ASN1::ObjectId.new(extension.oid).oid
          processed = PROCESSED_EXTENSIONS.include?(oid) ||
                      (leaf && PROCESSED_LEAF_EXTENSIONS.include?(oid))
          !processed
        rescue OpenSSL::ASN1::ASN1Error
          true
        end
      end

      def record_key_use(issuer)
        list = Thread.current[:aprv_chain_keys_used]
        list << issuer.to_der if list
      end

      def cert_sign_permitted?(cert)
        extension = cert.find_extension("keyUsage")
        return true if extension.nil?

        sequence = Asn1.parse(extension.to_der)
        value = sequence.kids.last
        return true if value.nil? || !value.octet_string?

        bits = Asn1.parse(value.octet_value)
        return true unless bits.tag == 0x03

        raw = bits.content
        return false if raw.bytesize < 2

        unused = raw.getbyte(0) #: Integer
        index = KEY_CERT_SIGN_BIT
        byte_index = 1 + (index / 8)
        return false if byte_index >= raw.bytesize

        available = ((raw.bytesize - 1) * 8) - unused
        return false if index >= available

        (raw.getbyte(byte_index) & (0x80 >> (index % 8))) != 0 # steep:ignore NoMethod
      rescue StandardError, Asn1::Error
        # Fail CLOSED: a keyUsage extension that is present but does not
        # decode must not be read as "no restriction". The 0.6 behaviour returned
        # true here.
        false
      end
    end
  end
end
