# frozen_string_literal: true

module ApplePurchaseReceiptVerifier
  # Common behaviour for the two JWS payload models.
  #
  # Apple's date claims stay exactly as Apple ships them: **Integer epoch
  # milliseconds**. Converting them to `Time` here would lose the raw value and
  # invite a timezone bug, and it is the cross-port contract — all nine ports
  # return numbers for `signedDate`, `purchaseDate`, `expiresDate`,
  # `revocationDate`, `originalPurchaseDate`, `receiptCreationDate` and
  # `preorderDate`. Only receipt attributes (`AppReceipt`, `InAppPurchase`)
  # become `Time`.
  class Payload
    # Every claim in the verified payload, as Apple sent it. The escape hatch
    # for claims this library does not model (PLAN.md D10, forward
    # compatibility).
    #
    # @return [Hash{String => Object}] frozen
    attr_reader :claims

    def initialize(claims)
      @claims = claims
      freeze
    end

    # @return [Hash{String => Object}] the claims, Apple's own key spelling
    def to_h
      claims
    end

    def [](key)
      claims[key]
    end

    def inspect
      "#<#{self.class.name} claims=#{claims.keys.sort.inspect}>"
    end

    private

    def string_claim(name)
      value = claims[name]
      value.is_a?(String) ? value : nil
    end

    def integer_claim(name)
      value = claims[name]
      value.is_a?(Integer) ? value : nil
    end

    def numeric_claim(name)
      value = claims[name]
      value.is_a?(Numeric) ? value : nil
    end

    # Defines a snake_case reader over a camelCase Apple claim.
    def self.claim(ruby_name, wire_name, kind)
      define_method(ruby_name) { send(:"#{kind}_claim", wire_name) }
    end
    private_class_method :claim
  end

  # A verified `JWSTransactionDecodedPayload`. Readers are snake_case views
  # over {#claims}; a claim of an unexpected JSON type reads as `nil` rather
  # than being coerced.
  class TransactionPayload < Payload
    %w[bundleId environment productId transactionId originalTransactionId
       webOrderLineItemId subscriptionGroupIdentifier appAccountToken
       inAppOwnershipType type transactionReason storefront storefrontId
       currency offerIdentifier appTransactionId].each do |wire|
      define_method(wire.gsub(/([a-z\d])([A-Z])/, '\1_\2').downcase) { string_claim(wire) }
    end

    %w[signedDate purchaseDate originalPurchaseDate expiresDate revocationDate
       quantity offerType revocationReason].each do |wire|
      define_method(wire.gsub(/([a-z\d])([A-Z])/, '\1_\2').downcase) { integer_claim(wire) }
    end

    # @return [Numeric, nil] Apple ships this in milli-units of the currency
    def price
      numeric_claim("price")
    end

    # Point-in-time entitlement check over the signed claims alone: not
    # revoked, and — for a subscription — not yet expired at `now`.
    #
    # It cannot see a refund or a renewal that happened after this payload was
    # signed; that needs Apple's server API (INTENT.md).
    #
    # @param now [Time]
    # @return [Boolean]
    def active_at?(now)
      millis = (now.to_r * 1000).to_i
      revoked = revocation_date
      return false if revoked && millis >= revoked

      expires = expires_date
      return millis < expires if expires

      true
    end
  end

  # A verified `AppTransaction`. The environment lives in `receipt_type`.
  class AppTransactionPayload < Payload
    %w[bundleId receiptType applicationVersion originalApplicationVersion
       deviceVerification deviceVerificationNonce appTransactionId].each do |wire|
      define_method(wire.gsub(/([a-z\d])([A-Z])/, '\1_\2').downcase) { string_claim(wire) }
    end

    %w[appAppleId receiptCreationDate originalPurchaseDate preorderDate
       versionExternalIdentifier].each do |wire|
      define_method(wire.gsub(/([a-z\d])([A-Z])/, '\1_\2').downcase) { integer_claim(wire) }
    end
  end
end
