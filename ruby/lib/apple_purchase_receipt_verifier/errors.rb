# frozen_string_literal: true

module ApplePurchaseReceiptVerifier
  # The machine-readable failure vocabulary. Eight reasons, closed by the
  # cross-port contract: `fixtures/cases-0.7.schema.json` holds the same enum
  # and every port mirrors it. A ninth reason is a change to that file, to
  # docs/design/0.7-api.md and to every port in one pull request.
  #
  # The values are Symbols spelled in SCREAMING_SNAKE so that
  # `failure.reason.to_s` *is* the canonical token, with no mapping table
  # anywhere. `Reason::ALL` is asserted against the schema by the test suite.
  module Reason
    MALFORMED                   = :MALFORMED
    TOO_LARGE                   = :TOO_LARGE
    INVALID_SIGNATURE           = :INVALID_SIGNATURE
    UNTRUSTED_CHAIN             = :UNTRUSTED_CHAIN
    INVALID_CERTIFICATE         = :INVALID_CERTIFICATE
    INVALID_CERTIFICATE_PURPOSE = :INVALID_CERTIFICATE_PURPOSE
    UNREADABLE_PAYLOAD          = :UNREADABLE_PAYLOAD
    # Not the client's fault. The library failed before it could decide:
    # alert and escalate, never retry. Deterministic for the same input.
    INTERNAL_ERROR = :INTERNAL_ERROR

    ALL = [
      MALFORMED, TOO_LARGE, INVALID_SIGNATURE, UNTRUSTED_CHAIN, INVALID_CERTIFICATE,
      INVALID_CERTIFICATE_PURPOSE, UNREADABLE_PAYLOAD, INTERNAL_ERROR
    ].freeze
  end

  # Apple's two verifyReceipt endpoints. The 0.6 `XCODE` and `LOCAL_TESTING`
  # values are gone: they only ever named JWS `environment` claim strings,
  # never Apple-signed values, and are read straight off the verified
  # payload now instead.
  module Environment
    PRODUCTION = "PRODUCTION"
    SANDBOX    = "SANDBOX"

    ALL = [PRODUCTION, SANDBOX].freeze

    class << self
      # Maps a legacy receipt's `receipt_type` attribute to the environment it
      # names: `Production` and `ProductionVPP` to {PRODUCTION},
      # `ProductionSandbox` and `ProductionVPPSandbox` to {SANDBOX}, anything
      # else (including `nil`) to `nil`. States what Apple's value means and
      # decides nothing; the endpoint uses this rule for status 21007/21008.
      #
      # @param receipt_type [String, nil]
      # @return [String, nil]
      def from_receipt_type(receipt_type)
        case receipt_type
        when "Production", "ProductionVPP" then PRODUCTION
        when "ProductionSandbox", "ProductionVPPSandbox" then SANDBOX
        end
      end

      # Maps a JWS `environment` claim the same way: `Production` and
      # `Sandbox`, anything else to `nil`.
      #
      # @param claim [String, nil]
      # @return [String, nil]
      def from_jws_environment(claim)
        case claim
        when "Production" then PRODUCTION
        when "Sandbox" then SANDBOX
        end
      end
    end
  end

  # Named constants for every status code Apple documents for verifyReceipt
  # (21000 to 21010, and the 21100-21199 range), so a caller matching on
  # {Verifier#verify_receipt_endpoint}'s response does not write `21007` by
  # hand. This local endpoint can answer only OK, MALFORMED_RECEIPT_DATA,
  # RECEIPT_NOT_AUTHENTICATED, SANDBOX_RECEIPT_ON_PRODUCTION,
  # PRODUCTION_RECEIPT_ON_SANDBOX and INTERNAL_DATA_ACCESS_ERROR; the rest
  # exist only so callers do not need Apple's table open beside this one.
  module AppleStatus
    OK                              = 0
    REQUEST_NOT_POST                = 21_000
    NO_LONGER_SENT                  = 21_001
    MALFORMED_RECEIPT_DATA          = 21_002
    RECEIPT_NOT_AUTHENTICATED       = 21_003
    SHARED_SECRET_MISMATCH          = 21_004
    SERVER_UNAVAILABLE              = 21_005
    SUBSCRIPTION_EXPIRED            = 21_006
    SANDBOX_RECEIPT_ON_PRODUCTION   = 21_007
    PRODUCTION_RECEIPT_ON_SANDBOX   = 21_008
    INTERNAL_DATA_ACCESS_ERROR      = 21_009
    ACCOUNT_NOT_FOUND               = 21_010
    INTERNAL_DATA_ACCESS_ERROR_RANGE_FIRST = 21_100
    INTERNAL_DATA_ACCESS_ERROR_RANGE_LAST  = 21_199

    class << self
      # The status {Verifier#verify_receipt_endpoint} answers for a given
      # verification {Reason}, the same table in every port.
      #
      # @param reason [Symbol] one of {Reason::ALL}
      # @return [Integer]
      def for_reason(reason)
        case reason
        when Reason::MALFORMED, Reason::TOO_LARGE
          MALFORMED_RECEIPT_DATA
        when Reason::INVALID_SIGNATURE, Reason::UNTRUSTED_CHAIN, Reason::INVALID_CERTIFICATE,
             Reason::INVALID_CERTIFICATE_PURPOSE
          RECEIPT_NOT_AUTHENTICATED
        else # UNREADABLE_PAYLOAD, INTERNAL_ERROR
          INTERNAL_DATA_ACCESS_ERROR
        end
      end
    end
  end

  # Raised internally to unwind to the nearest {Reason} the moment a check
  # fails; never escapes {Verifier}, which turns every one into a
  # {VerificationResult}. Kept as an exception rather than threaded through
  # every return value because the checks are a strict "first failure wins"
  # pipeline (base64, then CMS/JWS structure, then chain, then marker OIDs,
  # then signature): a `raise` at the first broken step is what makes that
  # order the code's actual control flow instead of an invariant every
  # caller has to maintain by hand.
  #
  # @api private
  class VerificationError < StandardError
    # @return [Symbol] one of {Reason::ALL}
    attr_reader :reason

    # @return [Exception, nil] the parser or provider exception behind
    #   {Reason::UNREADABLE_PAYLOAD} or {Reason::INTERNAL_ERROR}, when there
    #   is one
    attr_reader :cause_error

    def initialize(reason, detail, cause_error: nil)
      @reason = reason
      @cause_error = cause_error
      super(detail)
    end
  end
end
