# frozen_string_literal: true

require "json"

module ApplePurchaseReceiptVerifier
  # The outcome of one {VerifyReceiptEndpoint} call: the Apple status, the
  # verified receipt or the reason there is none, and the Apple-shaped
  # response, rendered only when asked for.
  #
  # Exactly one of {#receipt} and {#failure_reason} is non-nil. The receipt is
  # kept whenever its bytes verified, including when the endpoint's own
  # environment answers 21007 or 21008, so a caller can re-render for the
  # other environment with {#to_json} without verifying twice. The status is
  # always recomputed from the receipt's own `receipt_type`, so no render
  # answers 0 for a receipt from the wrong environment.
  #
  # Frozen, and only the endpoint creates one: `VerifyReceiptResult.new` is
  # private, so a caller cannot build a result carrying status 0.
  class VerifyReceiptResult
    # @return [AppReceipt, nil] the verified receipt, or nil when
    #   verification failed. Present for 21007 and 21008 too: those say the
    #   receipt belongs to the other environment, not that it failed.
    attr_reader :receipt

    # @return [Symbol, nil] why there is no receipt, one of {Reason::ALL},
    #   {Reason::MALFORMED_REQUEST}, {Reason::REQUEST_TOO_LARGE} or
    #   {Reason::INTERNAL_ERROR}; nil exactly when {#receipt} is set
    attr_reader :failure_reason

    # @return [Exception, nil] the unexpected error behind
    #   {Reason::INTERNAL_ERROR}; nil for every other outcome
    attr_reader :failure_cause

    # @return [Time] the instant rendered as `request_date` (UTC), fixed when
    #   the call was made
    attr_reader :request_date

    private_class_method :new

    def initialize(environment, receipt, failure_reason, failure_cause, request_date)
      @environment = environment
      @receipt = receipt
      @failure_reason = failure_reason
      @failure_cause = failure_cause
      @request_date = request_date
      freeze
    end

    # Whether the receipt bytes verified: true exactly when {#receipt} is set.
    # That includes 21007 and 21008, where the receipt verified and only its
    # environment differs from the endpoint's, so this is not the same check
    # as `status.zero?`. `status.zero?` asks whether this endpoint's
    # environment accepts the receipt; `verified?` asks whether it verified
    # at all, which is what to check before reading {#receipt} or
    # re-rendering for the other environment.
    def verified?
      !@receipt.nil?
    end

    # @return [Integer] the Apple status for the endpoint's own environment
    def status
      status_for(@environment)
    end

    # The response body as a new Hash on each call, string-keyed. With no
    # argument, the endpoint's own environment; with {Environment::PRODUCTION}
    # or {Environment::SANDBOX}, what an endpoint of that environment would
    # answer for the same receipt at the same {#request_date}. A production
    # receipt answers 0 on Production and 21008 on Sandbox; any other receipt
    # answers 21007 on Production and 0 on Sandbox; a failed result answers
    # its own status on both.
    #
    # @param environment [String, nil]
    # @return [Hash{String => Object}]
    # @raise [ArgumentError] for any other environment, as the endpoint's
    #   constructor does
    def to_response(environment = nil)
      target = environment.nil? ? @environment : environment
      status = status_for(target)
      receipt = @receipt
      return { "status" => status } unless status == VerifyReceiptEndpoint::Status::OK && receipt

      {
        "status" => status,
        "environment" => target,
        "receipt" => receipt_json(receipt, @request_date)
      }
    end

    # {#to_response} serialized as the JSON response body, byte for byte what
    # {VerifyReceiptEndpoint#verify_receipt_json} answers.
    #
    # Defining `to_json` takes part in the json library's protocol, which
    # calls `to_json(state)` on a nested object, and Rails' `render json:`
    # calls `to_json(options)`. A JSON::State or a Hash in the first position
    # is that protocol, not an environment, and renders the endpoint's own
    # environment, so `JSON.generate([result])` and `render json: result`
    # both embed this response.
    #
    # @param environment [String, nil]
    # @return [String]
    # @raise [ArgumentError] for an environment other than
    #   {Environment::PRODUCTION} or {Environment::SANDBOX}
    def to_json(environment = nil, *_generator_arguments)
      environment = nil if environment.is_a?(Hash) || environment.is_a?(JSON::State)
      JSON.generate(to_response(environment))
    end

    private

    def status_for(environment)
      unless [Environment::PRODUCTION, Environment::SANDBOX].include?(environment)
        raise ArgumentError,
              "environment must be #{Environment::PRODUCTION} or #{Environment::SANDBOX}"
      end

      receipt = @receipt
      if receipt.nil?
        case @failure_reason
        when Reason::MALFORMED_REQUEST, Reason::REQUEST_TOO_LARGE, Reason::INVALID_RECEIPT_FORMAT
          return VerifyReceiptEndpoint::Status::MALFORMED
        when Reason::INTERNAL_ERROR
          return VerifyReceiptEndpoint::Status::INTERNAL
        else
          return VerifyReceiptEndpoint::Status::NOT_AUTHENTICATED
        end
      end

      # 21007/21008 routing from the receipt_type attribute; see
      # VerifyReceiptEndpoint::PRODUCTION_RECEIPT_TYPES. "Xcode" routes as
      # non-production for completeness only: an Xcode-generated receipt is
      # not Apple-signed, so it fails chain verification with 21003 and never
      # gets here.
      types = VerifyReceiptEndpoint::PRODUCTION_RECEIPT_TYPES
      production = types.include?(receipt.receipt_type) # steep:ignore
      if environment == Environment::PRODUCTION && !production
        VerifyReceiptEndpoint::Status::SANDBOX_RECEIPT_ON_PRODUCTION
      elsif environment == Environment::SANDBOX && production
        VerifyReceiptEndpoint::Status::PRODUCTION_RECEIPT_ON_SANDBOX
      else
        VerifyReceiptEndpoint::Status::OK
      end
    end

    def receipt_json(receipt, request_date)
      body = {} #: Hash[String, untyped]
      put(body, "receipt_type", receipt.receipt_type)
      # Apple echoes attribute 1 under both names (its response reference
      # defines adam_id as "See app_item_id"), and as JSON numbers, not as
      # the strings the in-app integers are rendered with.
      put(body, "adam_id", receipt.app_item_id)
      put(body, "app_item_id", receipt.app_item_id)
      put(body, "bundle_id", receipt.bundle_id)
      put(body, "application_version", receipt.app_version)
      put(body, "download_id", receipt.download_id)
      put(body, "version_external_identifier", receipt.version_external_identifier)
      put(body, "original_application_version", receipt.original_app_version)
      apple_dates(body, "receipt_creation_date", receipt.creation_date)
      apple_dates(body, "request_date", request_date)
      apple_dates(body, "original_purchase_date", receipt.original_purchase_date)
      apple_dates(body, "expiration_date", receipt.expiration_date)
      body["in_app"] = receipt.in_app_purchases.map { |purchase| in_app_json(purchase) }
      body
    end

    def in_app_json(purchase)
      entry = {} #: Hash[String, String]
      put(entry, "quantity", purchase.quantity&.to_s)
      put(entry, "product_id", purchase.product_id)
      put(entry, "transaction_id", purchase.transaction_id)
      put(entry, "original_transaction_id", purchase.original_transaction_id)
      apple_dates(entry, "purchase_date", purchase.purchase_date)
      apple_dates(entry, "original_purchase_date", purchase.original_purchase_date)
      apple_dates(entry, "expires_date", purchase.expires_date)
      apple_dates(entry, "cancellation_date", purchase.cancellation_date)
      put(entry, "web_order_line_item_id", purchase.web_order_line_item_id&.to_s)
      entry["is_trial_period"] = (purchase.is_trial_period == 1).to_s unless purchase.is_trial_period.nil?
      unless purchase.is_in_intro_offer_period.nil?
        entry["is_in_intro_offer_period"] = (purchase.is_in_intro_offer_period == 1).to_s
      end
      entry
    end

    def put(target, key, value)
      target[key] = value unless value.nil?
    end

    # Apple renders every date three ways: GMT wall-clock, epoch milliseconds
    # as a String, and US Pacific wall-clock.
    def apple_dates(target, prefix, date)
      return if date.nil?

      utc = date.utc? ? date : date.getutc
      target[prefix] = "#{utc.strftime("%Y-%m-%d %H:%M:%S")} Etc/GMT"
      target["#{prefix}_ms"] = (utc.to_r * 1000).to_i.to_s
      pacific = PacificTime.wall_clock(utc)
      target["#{prefix}_pst"] =
        "#{pacific.strftime("%Y-%m-%d %H:%M:%S")} #{PacificTime::ZONE_LABEL}"
    end
  end
end
