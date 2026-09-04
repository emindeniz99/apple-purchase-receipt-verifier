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
  # The walk itself mirrors the Java, Node, Python and Swift ports check for
  # check, including the trust-anchor rule that matters here: an anchor is
  # trusted **by fiat**, so its own validity window is not examined. Standard
  # PKIX trust-anchor semantics, and `receipt/accept-historical-creation-date-
  # under-expired-chain` depends on it.
  module Chain
    # Genuine receipt chains are three certificates deep. Six bounds what a
    # hostile embedded set can cost while leaving room for a longer Apple chain.
    MAX_PATH_LENGTH = 6

    # keyUsage bit 5 (RFC 5280 4.2.1.3) — keyCertSign.
    KEY_CERT_SIGN_BIT = 5

    class << self
      # Validates and copies the caller's anchors. Misconfiguration is a
      # programming error, so it raises ArgumentError, never VerificationError.
      def normalize_roots(roots)
        raise ArgumentError, "trusted_roots must be a non-empty array" unless roots.is_a?(Array)
        raise ArgumentError, "trusted_roots must be a non-empty array" if roots.empty?

        roots.map do |root|
          case root
          when OpenSSL::X509::Certificate then root
          when String then OpenSSL::X509::Certificate.new(root)
          else
            raise ArgumentError,
                  "trusted_roots entries must be OpenSSL::X509::Certificate or DER/PEM String, " \
                  "got #{root.class}"
          end
        end.freeze
      end

      def valid_at?(cert, instant)
        instant.between?(cert.not_before, cert.not_after)
      rescue StandardError
        false
      end

      # Name chaining plus a real signature check. Never a path builder: the
      # only thing OpenSSL is asked for is "does this public key sign these
      # bytes".
      def issued_by?(cert, issuer)
        return false unless cert.issuer.to_der == issuer.subject.to_der

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
        return false if flag.content.getbyte(0).zero?

        cert_sign_permitted?(cert)
      rescue StandardError, Asn1::Error
        false
      end

      # The fixed JWS path: leaf -> intermediate -> a pinned anchor. `instant`
      # is required and has no default: "forgot to pass the signing time" must
      # not be spellable.
      def validate_pair(leaf, intermediate, anchors, instant)
        unless valid_at?(leaf, instant) && valid_at?(intermediate, instant)
          raise VerificationError.new(Reason::INVALID_CHAIN,
                                      "certificate not valid at signing time")
        end
        unless ca?(intermediate)
          raise VerificationError.new(Reason::INVALID_CHAIN,
                                      "intermediate is not a CA")
        end
        unless issued_by?(leaf, intermediate)
          raise VerificationError.new(Reason::INVALID_CHAIN, "leaf not issued by intermediate")
        end
        return if anchors.any? { |anchor| issued_by?(intermediate, anchor) }

        raise VerificationError.new(Reason::INVALID_CHAIN, "intermediate not issued by a pinned root")
      end

      # Builds and validates a path from `target` through `candidates` (the
      # certificates a receipt embeds) to one of the pinned `anchors`.
      def build_path(target, candidates, anchors, instant)
        current = target
        MAX_PATH_LENGTH.times do |depth|
          unless valid_at?(current, instant)
            raise VerificationError.new(Reason::INVALID_CHAIN,
                                        "certificate not valid at signing time")
          end
          if depth.positive? && !ca?(current)
            raise VerificationError.new(Reason::INVALID_CHAIN, "intermediate is not a CA")
          end
          # A non-local exit on purpose: reaching a pinned anchor ends the
          # whole walk, and there is no partially-validated path to return.
          return if anchors.any? { |anchor| issued_by?(current, anchor) } # rubocop:disable Lint/NonLocalExitFromIterator

          issuer = candidates.find do |candidate|
            !candidate.equal?(current) && issued_by?(current, candidate)
          end
          unless issuer
            raise VerificationError.new(Reason::INVALID_CHAIN,
                                        "chain does not reach a pinned root")
          end

          current = issuer
        end
        raise VerificationError.new(Reason::INVALID_CHAIN, "chain exceeds maximum length")
      end

      private

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

        unused = raw.getbyte(0)
        index = KEY_CERT_SIGN_BIT
        byte_index = 1 + (index / 8)
        return false if byte_index >= raw.bytesize

        available = ((raw.bytesize - 1) * 8) - unused
        return false if index >= available

        (raw.getbyte(byte_index) & (0x80 >> (index % 8))) != 0
      rescue StandardError, Asn1::Error
        true
      end
    end
  end
end
