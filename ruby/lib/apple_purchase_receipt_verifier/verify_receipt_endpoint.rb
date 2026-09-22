# frozen_string_literal: true

require "json"

module ApplePurchaseReceiptVerifier
  # A drop-in local replacement for Apple's deprecated `verifyReceipt`
  # endpoint: the same request body, the same response body, the same status
  # codes — verified offline against pinned Apple roots instead of by calling
  # Apple. Field-by-field fidelity and the unavoidable gaps (everything that
  # only exists in Apple's subscription database, such as `latest_receipt_info`
  # and `pending_renewal_info`) are documented in COMPARISON.md.
  #
  # Like Apple's endpoint, it does **not** check the bundle id: the caller
  # compares `receipt["bundle_id"]`, exactly as with the real endpoint.
  #
  # In Rails, the whole migration is the controller body:
  #
  #   ENDPOINT = ApplePurchaseReceiptVerifier::VerifyReceiptEndpoint.new(
  #     trusted_roots: ApplePurchaseReceiptVerifier.apple_receipt_roots,
  #     environment: ApplePurchaseReceiptVerifier::Environment::PRODUCTION
  #   )
  #
  #   def create
  #     render json: ENDPOINT.verify_receipt_result(params.permit!.to_h).to_response
  #   end
  #
  # No method raises on any request input: every failure comes back as a
  # {VerifyReceiptResult} with a status and a
  # {VerifyReceiptResult#failure_reason}.
  class VerifyReceiptEndpoint
    # The Apple status codes this local implementation can produce. 21000,
    # 21004, 21005, 21006, 21010 and 21100-21199 are out of scope and are
    # never returned (COMPARISON.md).
    module Status
      OK                             = 0
      MALFORMED                      = 21_002
      NOT_AUTHENTICATED              = 21_003
      SANDBOX_RECEIPT_ON_PRODUCTION  = 21_007
      PRODUCTION_RECEIPT_ON_SANDBOX  = 21_008
      INTERNAL                       = 21_009
    end

    # Receipt types that count as production. Everything else —
    # "ProductionSandbox", "ProductionVPPSandbox", "Xcode", or a missing
    # attribute — routes as non-production. The routing fails closed: a
    # VPP-sandbox receipt misrouting to production is the finding that drove
    # PLAN.md D10.
    PRODUCTION_RECEIPT_TYPES = %w[Production ProductionVPP].freeze

    # Ceiling on a raw JSON request body, in bytes. A larger one fails with
    # {Reason::MALFORMED_REQUEST}, status 21002, before it is parsed: JSON
    # parsing allocates a multiple of the body, and that happens before any
    # verification. The number is the Java, PHP and Python ports'. It is
    # deliberately below {ReceiptVerifier::MAX_RECEIPT_BYTES}: the JSON entry
    # points parse the body as well as decoding the receipt. A request already
    # decoded to a Hash is not measured; its `receipt-data` still is. The
    # largest genuine receipt in the corpus is 106 KB of base64.
    MAX_REQUEST_BYTES = 1_048_576

    # @param trusted_roots [Array<OpenSSL::X509::Certificate, String>]
    # @param environment [String] which environment this instance emulates,
    #   {Environment::PRODUCTION} or {Environment::SANDBOX}. It drives
    #   21007/21008 routing. Typed rather than a boolean: `new(roots, false)`
    #   says nothing at a call site, and a boolean cannot grow a third mode
    #   without a breaking change.
    # @param clock [#call, nil] source of "now" for the `request_date` triple,
    #   which is the only wall-clock-dependent output here. It reaches no
    #   certificate-validity decision.
    def initialize(trusted_roots:, environment:, clock: nil)
      @roots = Chain.normalize_roots(trusted_roots)
      unless [Environment::PRODUCTION, Environment::SANDBOX].include?(environment)
        raise ArgumentError,
              "environment must be #{Environment::PRODUCTION} or #{Environment::SANDBOX}"
      end
      raise ArgumentError, "clock must respond to #call" if !clock.nil? && !clock.respond_to?(:call)

      @environment = environment.dup.freeze
      @clock = clock
      freeze
    end

    # Handles one verifyReceipt request: a request body already decoded to a
    # Hash, or the raw JSON text an HTTP framework hands over.
    #
    # A body that is not a JSON object (unparseable, `null`, an array, a
    # scalar), a raw body over {MAX_REQUEST_BYTES} or nested more than 64
    # levels deep, or a `receipt-data` that is missing, empty or not a String,
    # fails with {Reason::MALFORMED_REQUEST}, status 21002. A `receipt-data`
    # over {ReceiptVerifier::MAX_RECEIPT_BYTES} characters fails with
    # {Reason::INVALID_RECEIPT_FORMAT}, also 21002, before it is decoded.
    # Apple has no status
    # code for "that was not JSON"; 21002 ("the data in the receipt-data
    # property was malformed or missing") is the closest.
    #
    # @param request [Hash, String] `{"receipt-data" => base64}` or its JSON
    #   text. `password` and `exclude-old-transactions` are accepted for
    #   compatibility and never read (there is nothing local to validate them
    #   against).
    # @param now [Time, nil] the instant to render as `request_date` in place
    #   of the clock. It reaches `request_date` and nothing else: certificate
    #   validity never sees it.
    # @return [VerifyReceiptResult]
    # @raise [ArgumentError] if `now` is neither nil nor a Time
    def verify_receipt_result(request, now: nil)
      stamped(now) do |at|
        request.is_a?(String) ? from_json(request, at) : from_hash(request, at)
      end
    end

    # Verifies a bare base64 receipt, the value a request body carries as
    # `receipt-data`, with no envelope around it. nil, an empty String or a
    # non-String fails with {Reason::MALFORMED_REQUEST}, as a missing
    # `receipt-data` does.
    #
    # @param receipt_data [String, nil]
    # @param now [Time, nil] as for {#verify_receipt_result}
    # @return [VerifyReceiptResult]
    # @raise [ArgumentError] if `now` is neither nil nor a Time
    def verify_receipt_data(receipt_data, now: nil)
      stamped(now) { |at| verify(receipt_data, at) }
    end

    # The same decision in raw wire form: the JSON request body in, the JSON
    # response body out, so a framework's body can be piped straight through
    # without a DTO in between. The same as
    # `verify_receipt_result(body).to_json` for a String body; anything that
    # is not a String answers 21002.
    #
    # @param body [String]
    # @return [String]
    def verify_receipt_json(body)
      stamped(nil) { |at| from_json(body, at) }.to_json
    end

    private

    # Reads the time once per call, before anything else, so one result can
    # never carry two request dates. A clock that raises or returns something
    # other than a Time is contained like any other internal failure: the
    # result is {Reason::INTERNAL_ERROR} with the clock's error as its cause,
    # and its request_date (never rendered for a 21009) is the system time.
    def stamped(now)
      raise ArgumentError, "now must be a Time" unless now.nil? || now.is_a?(Time)

      begin
        at = now.nil? ? clock_time : now.getutc
      rescue SystemStackError, StandardError => e
        return internal_error(e, Time.now.utc)
      end
      yield at
    end

    def clock_time
      instant = @clock.nil? ? Time.now : @clock.call # steep:ignore NoMethod
      raise TypeError, "clock did not return a Time" unless instant.is_a?(Time)

      instant.getutc
    end

    def from_json(body, at)
      # Measured before the parser sees it. A non-String answers 21002 here
      # too, rather than reaching JSON.parse through an implicit #to_str that
      # would bypass the measurement.
      unless body.is_a?(String) && body.bytesize <= MAX_REQUEST_BYTES
        return failed(Reason::MALFORMED_REQUEST, at)
      end

      begin
        parsed = JsonLimits.parse(body)
      rescue JSON::ParserError, TypeError
        return failed(Reason::MALFORMED_REQUEST, at)
      end
      from_hash(parsed, at)
    end

    def from_hash(request, at)
      begin
        receipt_data = request.is_a?(Hash) ? request["receipt-data"] : nil
      rescue SystemStackError, StandardError => e
        return internal_error(e, at)
      end
      verify(receipt_data, at)
    end

    # The one verification path every entry point ends in. `at` only becomes
    # `request_date`: certificate validity is judged inside Receipt.verify,
    # which takes no time input.
    def verify(receipt_data, at)
      return failed(Reason::MALFORMED_REQUEST, at) unless receipt_data.is_a?(String) && !receipt_data.empty?

      # The primitive itself, not a ReceiptVerifier built around a wildcard
      # bundle id: like Apple's endpoint, no bundle-id claim is checked here
      # (callers compare receipt.bundle_id).
      receipt = Receipt.verify(Receipt.decode_base64(receipt_data), @roots)
      result(receipt, nil, nil, at)
    rescue VerificationError => e
      failed(e.reason, at)
    rescue SystemStackError, StandardError => e
      internal_error(e, at)
    end

    def failed(reason, at)
      result(nil, reason, nil, at)
    end

    def internal_error(cause, at)
      result(nil, Reason::INTERNAL_ERROR, cause, at)
    end

    def result(receipt, reason, cause, at)
      VerifyReceiptResult.__send__(:new, @environment, receipt, reason, cause, at)
    end
  end
end
