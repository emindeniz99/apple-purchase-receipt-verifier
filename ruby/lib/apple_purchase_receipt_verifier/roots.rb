# frozen_string_literal: true

require "openssl"
require "digest"
require_relative "roots_data"

module ApplePurchaseReceiptVerifier
  # @api private
  module Roots
    # The SHA-256 of each entry of {APPLE_ROOT_DER_BASE64}, in the same
    # order, as Apple publishes them. Checked every time the bundled roots
    # are loaded, so a `roots_data.rb` regenerated from a swapped `certs/`
    # file does not silently become a trust anchor.
    APPLE_ROOT_SHA256 = %w[
      b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024
      c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050
      63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179
    ].freeze

    class << self
      # Apple's three bundled roots, each only when it parses and its
      # SHA-256 matches the pinned {APPLE_ROOT_SHA256} entry; an empty array
      # when any one does not, so a set silently one root short never
      # becomes an anchor set at all (`Config.defaults`'s "all three or
      # none").
      #
      # @return [Array<OpenSSL::X509::Certificate>] fresh objects on every
      #   call, so a caller mutating the array cannot poison another config
      def apple_roots
        ders = APPLE_ROOT_DER_BASE64.map do |b64|
          b64.unpack1("m0") #: String
        end
        return none unless ders.size == APPLE_ROOT_SHA256.size
        unless ders.zip(APPLE_ROOT_SHA256).all? { |der, fp| Digest::SHA256.hexdigest(der) == fp }
          return none
        end

        ders.map { |der| OpenSSL::X509::Certificate.new(der) }.freeze
      rescue OpenSSL::OpenSSLError
        none
      end

      private

      def none
        empty = [] #: Array[OpenSSL::X509::Certificate]
        empty.freeze
      end
    end
  end
end
