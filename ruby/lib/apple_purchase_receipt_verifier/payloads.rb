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

    # The typed read the verifier runs after the chain and the signature pass
    # and before any claim is enforced. A modelled claim is absent, JSON null,
    # or of its model type: a String, or a JSON number holding a whole number
    # (`1.0` is 1). Anything else was written by a trusted signer, so it is the
    # library's failure or a format Apple changed, not the client's:
    # INTERNAL_ERROR, never read as absent. Unmodelled claims are not looked at.
    def self.read(claims)
      self::STRING_CLAIMS.each do |name| # steep:ignore UnknownConstant
        value = claims[name]
        next if value.nil? || value.is_a?(String)

        raise VerificationError.new(Reason::INTERNAL_ERROR,
                                    "signed payload claim #{name} is not a string")
      end
      self::INTEGER_CLAIMS.each do |name| # steep:ignore UnknownConstant
        value = claims[name]
        next if value.nil? || !whole_number(value).nil?

        raise VerificationError.new(Reason::INTERNAL_ERROR,
                                    "signed payload claim #{name} is not an integer")
      end
      new(claims)
    end

    # An Integer, or a finite Float with no fractional part as that Integer;
    # `nil` for anything else. A boolean is not a number in Ruby.
    def self.whole_number(value)
      return value if value.is_a?(Integer)

      value.to_i if value.is_a?(Float) && value.finite? && (value % 1).zero?
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
      Payload.whole_number(claims[name])
    end

    # Defines a snake_case reader over a camelCase Apple claim.
    def self.claim(ruby_name, wire_name, kind)
      define_method(ruby_name) { send(:"#{kind}_claim", wire_name) } # steep:ignore NoMethod
    end
    private_class_method :claim
  end

  # A verified `JWSTransactionDecodedPayload`. Readers are snake_case views
  # over {#claims}; the verifier has already refused a modelled claim of the
  # wrong JSON type ({Payload.read}), so a reader returns the claim or `nil`.
  class TransactionPayload < Payload
    STRING_CLAIMS = %w[bundleId environment productId transactionId originalTransactionId
                       webOrderLineItemId subscriptionGroupIdentifier appAccountToken
                       inAppOwnershipType type transactionReason storefront storefrontId
                       currency offerIdentifier appTransactionId].freeze
    # `price` is in milli-units of the currency, an integer like the dates.
    INTEGER_CLAIMS = %w[signedDate purchaseDate originalPurchaseDate expiresDate revocationDate
                        quantity offerType revocationReason price].freeze

    STRING_CLAIMS.each do |wire|
      define_method(wire.gsub(/([a-z\d])([A-Z])/, '\1_\2').downcase) { string_claim(wire) } # steep:ignore
    end

    INTEGER_CLAIMS.each do |wire|
      define_method(wire.gsub(/([a-z\d])([A-Z])/, '\1_\2').downcase) { integer_claim(wire) } # steep:ignore
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
    STRING_CLAIMS = %w[bundleId receiptType applicationVersion originalApplicationVersion
                       deviceVerification deviceVerificationNonce appTransactionId].freeze
    INTEGER_CLAIMS = %w[appAppleId receiptCreationDate originalPurchaseDate preorderDate
                        versionExternalIdentifier].freeze

    STRING_CLAIMS.each do |wire|
      define_method(wire.gsub(/([a-z\d])([A-Z])/, '\1_\2').downcase) { string_claim(wire) } # steep:ignore
    end

    INTEGER_CLAIMS.each do |wire|
      define_method(wire.gsub(/([a-z\d])([A-Z])/, '\1_\2').downcase) { integer_claim(wire) } # steep:ignore
    end
  end
end
