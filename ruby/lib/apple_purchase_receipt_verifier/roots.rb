# frozen_string_literal: true

require "openssl"
require_relative "roots_data"

module ApplePurchaseReceiptVerifier
  class << self
    # Trust anchors for StoreKit 2 / App Store Server JWS chains.
    #
    # All three published Apple roots, not just the one production chains end
    # at today. Apple documents the third `x5c` element only as "an Apple root
    # certificate" and an App Store Commerce engineer's answer to "always G3?"
    # was "use all Apple Root CAs" — pinning one root would fail closed and
    # silently the day Apple re-anchored a path (PLAN.md D15).
    #
    # @return [Array<OpenSSL::X509::Certificate>] a fresh array of fresh
    #   certificate objects, so a caller mutating it cannot poison another
    #   verifier.
    def apple_jws_roots
      apple_roots
    end

    # Trust anchors for legacy PKCS#7 app-receipt chains. Same three roots, for
    # the same reason.
    #
    # @return [Array<OpenSSL::X509::Certificate>]
    def apple_receipt_roots
      apple_roots
    end

    private

    def apple_roots
      APPLE_ROOT_DER_BASE64.map { |b64| OpenSSL::X509::Certificate.new(b64.unpack1("m0")) }
    end
  end
end
