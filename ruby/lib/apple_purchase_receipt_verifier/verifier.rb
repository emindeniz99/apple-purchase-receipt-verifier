# frozen_string_literal: true

module ApplePurchaseReceiptVerifier
  # Verifies what Apple signed, offline, against the pinned roots of a
  # {Config}. Immutable, thread-safe once created, and cheap to share across
  # threads.
  #
  #   verifier = ApplePurchaseReceiptVerifier::Verifier.create(Config.defaults)
  #   result = verifier.verify_receipt(base64)
  #   if result.verified?
  #     puts result.payload.to_json
  #   else
  #     warn "rejected: #{result.failure.reason}"
  #   end
  #
  # The verify methods never raise for any input: every failure comes back
  # as a {VerificationResult} whose {VerificationResult#failure} carries a
  # {Failure}. Only `SystemStackError` and a genuine VM-level exception
  # (`NoMemoryError` and friends, neither of which this library ever
  # provokes on its own) escape.
  class Verifier
    class << self
      # @param config [Config]
      # @return [Verifier]
      # @raise [ArgumentError] `config` is not a {Config}, or its roots are
      #   empty — a verifier with no roots would answer UNTRUSTED_CHAIN to
      #   everything and nobody would notice until production
      def create(config)
        raise ArgumentError, "config must be a Config" unless config.is_a?(Config)
        raise ArgumentError, "config.roots must not be empty" if config.roots.empty?

        new(config)
      end
    end

    private_class_method :new

    def initialize(config)
      @roots = config.roots
      @clock_proc = config.clock
      freeze
    end

    # Verifies a legacy PKCS#7 app receipt, given as the base64 string a
    # client sends, and decodes its payload.
    #
    # @param base64 [String]
    # @return [VerificationResult] of {ReceiptPayload}
    def verify_receipt(base64)
      contained { |clock| Receipt.verify(base64, @roots, clock) }
    end

    # Verifies any Apple-signed compact JWS (StoreKit 2 `jwsRepresentation`,
    # `signedTransactionInfo` / `signedRenewalInfo`, an app transaction, an
    # App Store Server Notifications V2 envelope or nested payload) and
    # returns it unchanged.
    #
    # @param jws [String]
    # @return [VerificationResult] of {JsonPayload}
    def verify_signed_data(jws)
      contained { |clock| Jws.verify(jws, @roots, clock) }
    end

    # The response body Apple's `verifyReceipt` endpoint at `environment`
    # would return for `request_json`. Never returns a failure: every
    # verdict is the `status` inside the body (docs/design/0.7-api.md).
    #
    # @param environment [String] {Environment::PRODUCTION} or
    #   {Environment::SANDBOX}
    # @param request_json [String] `{"receipt-data": "...", ...}`, or the
    #   raw request body an HTTP framework hands over
    # @return [String]
    # @raise [ArgumentError] `environment` is neither {Environment::PRODUCTION}
    #   nor {Environment::SANDBOX}
    def verify_receipt_endpoint(environment, request_json)
      unless Environment::ALL.include?(environment)
        raise ArgumentError, "environment must be #{Environment::PRODUCTION} or #{Environment::SANDBOX}"
      end

      Endpoint.respond(environment, request_json, @roots, ClockOnce.new(@clock_proc))
    end

    private

    # Runs `verify` with a fresh, lazily-read clock and turns whatever it
    # raises into a {VerificationResult}. `StandardError` and
    # `SystemStackError` map to MALFORMED, never INTERNAL_ERROR
    # (docs/design/0.7-hardening-parity.md, change 4): by construction every
    # checked failure inside {Receipt} and {Jws} already raises a
    # {VerificationError} with the right {Reason} at the right point, so
    # anything landing here uncaught is, at worst, a bug in input nobody has
    # vouched for yet — never grounds for the INTERNAL_ERROR alert.
    def contained
      clock = ClockOnce.new(@clock_proc)
      VerificationResult.ok(yield(clock))
    rescue VerificationError => e
      VerificationResult.error(Failure.new(reason: e.reason, message: e.message, cause: e.cause_error))
    rescue SystemStackError
      VerificationResult.error(
        Failure.new(reason: Reason::MALFORMED, message: "input nesting exhausted the stack", cause: nil)
      )
    rescue StandardError => e
      VerificationResult.error(
        Failure.new(reason: Reason::MALFORMED, message: "unexpected failure: #{e.class}", cause: nil)
      )
    end
  end
end
