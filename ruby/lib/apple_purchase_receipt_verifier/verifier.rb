# frozen_string_literal: true

require "json"

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
  # Nothing here decides anything. Each call reads the {Config} clock, hands
  # the input to `aprv.wasm` (the one module every implementation of this
  # repository runs) in an instance of its own, and turns the JSON the module
  # answers with into the types below. Parsing, certificate chains,
  # signatures and Apple's rules are the module's.
  #
  # The verify methods never raise for any input: every failure comes back as
  # a {VerificationResult} whose {VerificationResult#failure} carries a
  # {Failure}. A trap in the module, or an answer this wrapper cannot read, is
  # INTERNAL_ERROR (status 21009 at the endpoint) with the cause named in
  # {Failure#cause}; the instance that did it is discarded. Only
  # `SystemStackError` and a genuine VM-level exception (`NoMemoryError` and
  # friends) escape.
  class Verifier
    # `aprv.wasm`'s `env` parameter.
    ENV_CODES = { Environment::PRODUCTION => 0, Environment::SANDBOX => 1 }.freeze
    private_constant :ENV_CODES

    # The largest instant the module's `now-ms` takes.
    MAX_CLOCK_MILLIS = (2**63) - 1
    private_constant :MAX_CLOCK_MILLIS

    class << self
      # Compiles the wasm module on the first call in a process (about a
      # second; later calls reuse it), and makes one instance to prove the
      # module and the roots are usable.
      #
      # @param config [Config]
      # @return [Verifier]
      # @raise [ArgumentError] `config` is not a {Config}, its roots are an
      #   empty list (a verifier with no roots would answer UNTRUSTED_CHAIN to
      #   everything and nobody would notice until production), or the
      #   module refuses a root as a certificate
      # @raise [AbiMismatchError] the module does not speak the ABI this
      #   wrapper binds
      # @raise [ModuleIntegrityError] the module does not match its SHA-256
      # @raise [TrapError] the module failed while starting
      def create(config)
        raise ArgumentError, "config must be a Config" unless config.is_a?(Config)
        raise ArgumentError, "config.roots must not be empty" if config.custom_roots? && config.roots.empty?

        new(config)
      end
    end

    private_class_method :new

    # @param runtime [Runtime] the module to run; `aprv.wasm` unless a test
    #   supplies its own
    def initialize(config, runtime: Runtime.shared)
      @clock_proc = config.clock
      roots = config.roots.map { |der| [der].pack("m0") }
      @pool = InstancePool.new(runtime, JSON.generate("roots" => roots))
      freeze
    rescue RootsRejected => e
      raise ArgumentError, "the module refused config.roots: #{e.message}"
    end

    # Verifies a legacy PKCS#7 app receipt, given as the base64 string a
    # client sends, and decodes its payload.
    #
    # @param base64 [String]
    # @return [VerificationResult] of {ReceiptPayload}
    def verify_receipt(base64)
      verify("verify-receipt", base64) { |text| Wire.receipt_result(text) }
    end

    # Verifies any Apple-signed compact JWS (StoreKit 2 `jwsRepresentation`,
    # `signedTransactionInfo` / `signedRenewalInfo`, an app transaction, an
    # App Store Server Notifications V2 envelope or nested payload) and
    # returns it unchanged.
    #
    # @param jws [String]
    # @return [VerificationResult] of {JsonPayload}
    def verify_signed_data(jws)
      verify("verify-signed-data", jws) { |text| Wire.signed_data_result(text) }
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
      env = ENV_CODES.fetch(environment) do
        raise ArgumentError, "environment must be #{Environment::PRODUCTION} or #{Environment::SANDBOX}"
      end
      endpoint_answer(env, request_json)
    end

    private

    # The clock failed: it raised, or answered a value the module cannot
    # take. Not the input's fault.
    class ClockError < StandardError; end
    private_constant :ClockError

    # One receipt or JWS call: the clock first, whatever the input, then the
    # input.
    def verify(operation, input, &)
      now = read_clock
      unless input.is_a?(String)
        return VerificationResult.error(
          Failure.new(reason: Reason::MALFORMED, message: "input must be a String", cause: nil)
        )
      end

      call(operation, [now], input, &)
    rescue ClockError, TrapError => e
      internal_error(e)
    rescue StandardError => e
      internal_error(TrapError.new("#{e.class} in the wrapper"))
    end

    # The module's call in an instance of its own. The block decodes the
    # answer inside the same scope, so an answer that cannot be decoded
    # discards the instance too.
    def call(operation, scalars, input)
      @pool.with_guest { |guest| yield guest.call(operation, scalars, input) }
    end

    # The Config clock, read once for this call.
    def read_clock
      value = begin
        @clock_proc.call
      rescue SystemStackError, StandardError
        raise ClockError, "the configured clock raised"
      end
      unless value.is_a?(Integer) && value.between?(0, MAX_CLOCK_MILLIS)
        raise ClockError, "the configured clock did not return an Integer in 0..2**63-1"
      end

      value
    end

    # The endpoint's answer: the module's own bytes, or a status alone when
    # the input is no String or the call failed.
    def endpoint_answer(env, request_json)
      now = read_clock
      return status_only(Reason::MALFORMED) unless request_json.is_a?(String)

      call("verify-receipt-endpoint", [env, now], request_json) do |text|
        raise TrapError, "verify-receipt-endpoint: the answer is not UTF-8" unless text.valid_encoding?

        text
      end
    rescue StandardError
      status_only(Reason::INTERNAL_ERROR)
    end

    def internal_error(cause)
      VerificationResult.error(
        Failure.new(reason: Reason::INTERNAL_ERROR, message: cause.message, cause: cause)
      )
    end

    def status_only(reason)
      %({"status":#{AppleStatus.for_reason(reason)}})
    end
  end
end
