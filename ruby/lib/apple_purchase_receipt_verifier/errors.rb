# frozen_string_literal: true

module ApplePurchaseReceiptVerifier
  # The machine-readable failure vocabulary. Eight reasons, closed by the
  # cross-port contract: `fixtures/cases.schema.json` holds the same enum
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

  # The wasm module this gem carries does not speak the ABI this wrapper was
  # built for: it lacks the `aprv:verifier/verify@0.1.0` exports, imports
  # something other than `random-get`, or is not a valid module. Raised by
  # {Verifier.create}, never answered as a verdict; the message names the
  # version the wrapper expects and the exports the module has.
  class AbiMismatchError < StandardError; end

  # The wasm module on disk does not match the SHA-256 recorded beside it.
  # Raised by {Verifier.create} before the module is compiled.
  class ModuleIntegrityError < StandardError; end

  # A guest trap or a runtime failure while calling the module. Never raised
  # to a caller of a verify method: it is the `cause` of the
  # {Reason::INTERNAL_ERROR} failure that call answers, so the category stays
  # visible (docs/rust-core/ARCHITECTURE.md, "Six outcomes"). The instance
  # that raised it has been discarded.
  class TrapError < StandardError; end
end
