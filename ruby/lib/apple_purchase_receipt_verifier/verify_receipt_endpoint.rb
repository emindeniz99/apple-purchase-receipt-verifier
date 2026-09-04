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
  #     render json: ENDPOINT.verify_receipt(params.permit!.to_h)
  #   end
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

    MALFORMED_JSON = "{\"status\":#{Status::MALFORMED}}".freeze
    private_constant :MALFORMED_JSON

    # Receipt types that count as production. Everything else —
    # "ProductionSandbox", "ProductionVPPSandbox", "Xcode", or a missing
    # attribute — routes as non-production. The routing fails closed: a
    # VPP-sandbox receipt misrouting to production is the finding that drove
    # PLAN.md D10.
    PRODUCTION_RECEIPT_TYPES = %w[Production ProductionVPP].freeze

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

    # Handles one verifyReceipt request body. Never raises: like the real
    # endpoint, every failure is reported through `status`.
    #
    # @param request_body [Hash] `{"receipt-data" => base64}`. `password` and
    #   `exclude-old-transactions` are accepted for compatibility and never
    #   read (there is nothing local to validate them against).
    # @return [Hash] the response body, string-keyed
    def verify_receipt(request_body)
      receipt_data = request_body.is_a?(Hash) ? request_body["receipt-data"] : nil
      return { "status" => Status::MALFORMED } unless receipt_data.is_a?(String) && !receipt_data.empty?

      begin
        der = Receipt.decode_base64(receipt_data)
      rescue VerificationError
        return { "status" => Status::MALFORMED }
      end

      begin
        receipt = Receipt.verify(der, @roots)
        production = PRODUCTION_RECEIPT_TYPES.include?(receipt.receipt_type)
        if @environment == Environment::PRODUCTION && !production
          return { "status" => Status::SANDBOX_RECEIPT_ON_PRODUCTION }
        end
        if @environment == Environment::SANDBOX && production
          return { "status" => Status::PRODUCTION_RECEIPT_ON_SANDBOX }
        end

        {
          "status" => Status::OK,
          "environment" => @environment,
          "receipt" => receipt_json(receipt, now)
        }
      rescue VerificationError => e
        status = e.reason == Reason::INVALID_RECEIPT_FORMAT ? Status::MALFORMED : Status::NOT_AUTHENTICATED
        { "status" => status }
      rescue SystemStackError, StandardError
        { "status" => Status::INTERNAL }
      end
    end

    # The same decision in raw wire form: the JSON request body in, the JSON
    # response body out, so a framework's body can be piped straight through
    # without a DTO in between.
    #
    # A body that is not a JSON object answers 21002. Apple has no status code
    # for "that was not JSON"; 21002 ("the data in the receipt-data property
    # was malformed or missing") is the closest, and a JSON object without
    # usable receipt-data gets it anyway.
    #
    # @param body [String]
    # @return [String]
    def verify_receipt_json(body)
      parsed = parse_json_object(body)
      return MALFORMED_JSON if parsed.nil?

      JSON.generate(verify_receipt(parsed))
    end

    private

    def parse_json_object(body)
      parsed = JSON.parse(body)
      parsed.is_a?(Hash) ? parsed : nil
    rescue JSON::ParserError, TypeError
      nil
    end

    def now
      instant = @clock.nil? ? Time.now : @clock.call
      raise TypeError, "clock did not return a Time" unless instant.is_a?(Time)

      instant.utc
    end

    def receipt_json(receipt, request_date)
      body = {}
      put(body, "receipt_type", receipt.receipt_type)
      put(body, "bundle_id", receipt.bundle_id)
      put(body, "application_version", receipt.app_version)
      put(body, "original_application_version", receipt.original_app_version)
      apple_dates(body, "receipt_creation_date", receipt.creation_date)
      apple_dates(body, "request_date", request_date)
      apple_dates(body, "original_purchase_date", receipt.original_purchase_date)
      apple_dates(body, "expiration_date", receipt.expiration_date)
      body["in_app"] = receipt.in_app_purchases.map { |purchase| in_app_json(purchase) }
      body
    end

    def in_app_json(purchase)
      entry = {}
      put(entry, "quantity", purchase.quantity&.to_s)
      put(entry, "product_id", purchase.product_id)
      put(entry, "transaction_id", purchase.transaction_id)
      put(entry, "original_transaction_id", purchase.original_transaction_id)
      apple_dates(entry, "purchase_date", purchase.purchase_date)
      apple_dates(entry, "original_purchase_date", purchase.original_purchase_date)
      apple_dates(entry, "expires_date", purchase.expires_date)
      apple_dates(entry, "cancellation_date", purchase.cancellation_date)
      put(entry, "web_order_line_item_id", purchase.web_order_line_item_id&.to_s)
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
