# frozen_string_literal: true

module ApplePurchaseReceiptVerifier
  # The machine-readable failure vocabulary. Eleven reasons in `ALL`, closed
  # by the cross-port contract: `fixtures/cases.schema.json` holds the same enum and
  # every port mirrors it. A twelfth reason is a change to that file, to
  # PLAN.md and to every port in one pull request.
  #
  # The values are Symbols spelled in SCREAMING_SNAKE so that
  # `error.reason.to_s` *is* the canonical token, with no mapping table
  # anywhere. `Reason::ALL` is asserted against the schema by the test suite.
  module Reason
    INVALID_JWS_FORMAT          = :INVALID_JWS_FORMAT
    INVALID_CERTIFICATE         = :INVALID_CERTIFICATE
    INVALID_CERTIFICATE_PURPOSE = :INVALID_CERTIFICATE_PURPOSE
    INVALID_CHAIN               = :INVALID_CHAIN
    INVALID_SIGNATURE           = :INVALID_SIGNATURE
    WRONG_BUNDLE_ID             = :WRONG_BUNDLE_ID
    WRONG_ENVIRONMENT           = :WRONG_ENVIRONMENT
    WRONG_APP_APPLE_ID          = :WRONG_APP_APPLE_ID
    INVALID_RECEIPT_FORMAT      = :INVALID_RECEIPT_FORMAT
    DEVICE_HASH_MISMATCH        = :DEVICE_HASH_MISMATCH
    STALE_PAYLOAD               = :STALE_PAYLOAD

    ALL = [
      INVALID_JWS_FORMAT, INVALID_CERTIFICATE, INVALID_CERTIFICATE_PURPOSE,
      INVALID_CHAIN, INVALID_SIGNATURE, WRONG_BUNDLE_ID, WRONG_ENVIRONMENT,
      WRONG_APP_APPLE_ID, INVALID_RECEIPT_FORMAT, DEVICE_HASH_MISMATCH,
      STALE_PAYLOAD
    ].freeze

    # The three reasons below are not in ALL: no verifier raises them, so no
    # {VerificationError} ever carries one. They exist only as a
    # {VerifyReceiptResult#failure_reason}.

    # The verifyReceipt request envelope is unusable: the body is not a JSON
    # object or nests deeper than 64, or `receipt-data` is missing, empty or
    # not a String.
    MALFORMED_REQUEST = :MALFORMED_REQUEST
    # An unexpected error inside the verifyReceipt endpoint, answered as
    # status 21009. {VerifyReceiptResult#failure_cause} holds the error.
    INTERNAL_ERROR = :INTERNAL_ERROR
    # The raw verifyReceipt request body is over
    # {VerifyReceiptEndpoint::MAX_REQUEST_BYTES} (3,145,728 bytes), the size
    # at which Apple's endpoint answers HTTP 413. Status 21002 in the
    # response body; an HTTP layer can map it to 413 as Apple does.
    REQUEST_TOO_LARGE = :REQUEST_TOO_LARGE
  end

  # The four environment names, spelled as Apple's claims spell them.
  module Environment
    PRODUCTION    = "Production"
    SANDBOX       = "Sandbox"
    XCODE         = "Xcode"
    LOCAL_TESTING = "LocalTesting"

    ALL = [PRODUCTION, SANDBOX, XCODE, LOCAL_TESTING].freeze
  end

  # Raised when a signed payload fails verification. Everything the caller
  # needs to branch on is in {#reason}; the message is for humans and
  # deliberately carries no receipt bytes, claims or key material (PLAN D11).
  #
  # A payload that raises this must be treated as entirely untrusted: the
  # library never returns a partially-verified result.
  class VerificationError < StandardError
    # @return [Symbol] one of {Reason::ALL}
    attr_reader :reason

    def initialize(reason, message)
      @reason = reason
      super("#{reason}: #{message}")
    end
  end
end
