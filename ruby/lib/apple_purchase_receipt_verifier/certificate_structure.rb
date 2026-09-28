# frozen_string_literal: true

require "openssl"

module ApplePurchaseReceiptVerifier
  # Structural soundness checks OpenSSL itself decodes more leniently than
  # this library assumes: three of them are the JWS path's `x5c` checks
  # carried over unchanged (an unknown X.509 version, a repeated extension,
  # and an extension VALUE that stops decoding partway through), and the
  # fourth is new in 0.7 — a `signatureValue` BIT STRING with nonzero
  # unused bits, which cannot be a genuine byte-aligned signature.
  #
  # Every check here reads structure only: nothing decodes the
  # certificate's own public key, so a caller may run this before the
  # certificate has been vouched for by anything (#161).
  #
  # @api private
  module CertificateStructure
    class << self
      # @param certificate [OpenSSL::X509::Certificate]
      # @return [Boolean]
      def sound?(certificate)
        return false unless (0..2).cover?(certificate.version)

        oids = certificate.extensions.map(&:oid)
        return false unless oids.uniq.size == oids.size

        certificate.extensions.each do |extension|
          OpenSSL::ASN1.decode(OpenSSL::ASN1.decode(extension.to_der).value.last.value)
        end

        signature_bit_string_aligned?(certificate)
      rescue OpenSSL::OpenSSLError
        false
      end

      private

      def signature_bit_string_aligned?(certificate)
        signature_value = OpenSSL::ASN1.decode(certificate.to_der).value[2]
        signature_value.is_a?(OpenSSL::ASN1::BitString) && signature_value.unused_bits.zero?
      end
    end
  end
end
