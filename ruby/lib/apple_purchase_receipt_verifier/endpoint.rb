# frozen_string_literal: true

require "json"

module ApplePurchaseReceiptVerifier
  # @api private
  #
  # {Verifier#verify_receipt_endpoint}: a local stand-in for Apple's
  # deprecated `verifyReceipt` endpoint. Same request body, same response
  # body, same status codes, but verified offline against the pinned roots
  # instead of by calling Apple. Fields that exist only in Apple's
  # server-side database, such as `latest_receipt_info` and
  # `pending_renewal_info`, are not produced (COMPARISON.md). Like Apple's
  # endpoint, it checks no bundle id: the caller compares the verified
  # receipt's `bundle_id`.
  module Endpoint
    # The request body cap, in UTF-8 bytes: 3 MiB, Apple's own limit
    # (docs/design/0.7-api.md, Bounds). Both of Apple's endpoints answer a
    # 3,145,728-byte body and send HTTP 413 for 3,145,729; this answers
    # status 21002 instead, decided before any parsing.
    MAX_REQUEST_BYTES = 3_145_728

    class << self
      # @param environment [String] {Environment::PRODUCTION} or
      #   {Environment::SANDBOX}
      # @param request_json [String]
      # @param roots [Array<OpenSSL::X509::Certificate>]
      # @param clock [ClockOnce]
      # @return [String] the response body Apple's verifyReceipt would return
      def respond(environment, request_json, roots, clock)
        payload = receipt_data(request_json)
                  .then { |data| Receipt.verify(data, roots, clock) }
        production = Environment.from_receipt_type(payload.receipt_type) == Environment::PRODUCTION
        status =
          if environment == Environment::PRODUCTION && !production
            AppleStatus::SANDBOX_RECEIPT_ON_PRODUCTION
          elsif environment == Environment::SANDBOX && production
            AppleStatus::PRODUCTION_RECEIPT_ON_SANDBOX
          else
            AppleStatus::OK
          end
        return status_only(status) unless status == AppleStatus::OK

        render(environment, payload, clock.millis)
      rescue VerificationError => e
        status_only(AppleStatus.for_reason(e.reason))
      rescue SystemStackError, StandardError
        status_only(AppleStatus.for_reason(Reason::INTERNAL_ERROR))
      end

      private

      def status_only(status)
        %({"status":#{status}})
      end

      # The `receipt-data` string of a request body. A body over
      # {MAX_REQUEST_BYTES} is TOO_LARGE; a body that is not a JSON object
      # (unparseable, `null`, an array, a scalar) or nests deeper than 64,
      # and a `receipt-data` that is missing, empty or not a String, are
      # MALFORMED. The whole object is read, so a body that breaks after
      # `receipt-data` is still refused, and the last `receipt-data` wins,
      # as it would in a Hash. Anything after the object is not read.
      # `password` and `exclude-old-transactions` are read and ignored (as
      # in 0.6, COMPARISON.md): there is nothing local to validate them
      # against.
      def receipt_data(request_json)
        unless request_json.is_a?(String)
          raise VerificationError.new(Reason::MALFORMED, "request body must be a String")
        end
        if request_json.bytesize > MAX_REQUEST_BYTES
          raise VerificationError.new(Reason::TOO_LARGE,
                                      "request body exceeds the maximum of #{MAX_REQUEST_BYTES} bytes")
        end

        object = begin
          Json.parse_leading_object(request_json)
        rescue Json::Error => e
          raise VerificationError.new(Reason::MALFORMED, "request body is not a JSON object: #{e.message}")
        end

        value = object["receipt-data"]
        return value if value.is_a?(String) && !value.empty?

        raise VerificationError.new(Reason::MALFORMED, "receipt-data is missing, empty or not a String")
      end

      # The status-0 response. Keys and value types follow Apple's endpoint;
      # key order is deterministic but not part of the contract.
      def render(environment, receipt, request_date_millis)
        JSON.generate(
          "status" => AppleStatus::OK,
          "environment" => apple_environment_label(environment),
          "receipt" => receipt_json(receipt, request_date_millis)
        )
      end

      # {Environment::PRODUCTION} and {Environment::SANDBOX} are this
      # method's own parameter, spelled to match the endpoint config schema;
      # Apple's response body spells the same two environments the way its
      # receipt `receipt_type` and JWS `environment` claims do.
      def apple_environment_label(environment)
        environment == Environment::PRODUCTION ? "Production" : "Sandbox"
      end

      def receipt_json(receipt, request_date_millis)
        # @type var o: Hash[String, untyped]
        o = {}
        present(o, "receipt_type", receipt.receipt_type)
        # Apple echoes attribute 1 under both names (its response
        # reference defines adam_id as "See app_item_id"), and as JSON
        # numbers, not as the strings toJson's 64-bit ids are rendered
        # with.
        present(o, "adam_id", receipt.app_item_id)
        present(o, "app_item_id", receipt.app_item_id)
        present(o, "bundle_id", receipt.bundle_id)
        present(o, "application_version", receipt.application_version)
        present(o, "download_id", receipt.download_id)
        present(o, "version_external_identifier", receipt.version_external_identifier)
        present(o, "original_application_version", receipt.original_application_version)
        apple_dates(o, "receipt_creation_date", receipt.receipt_creation_date_ms)
        apple_dates(o, "request_date", request_date_millis)
        apple_dates(o, "original_purchase_date", receipt.original_purchase_date_ms)
        apple_dates(o, "expiration_date", receipt.expiration_date_ms)
        o["in_app"] = receipt.in_app.map { |purchase| purchase_json(purchase) }
        o
      end

      def purchase_json(purchase)
        # @type var o: Hash[String, untyped]
        o = {}
        present(o, "quantity", purchase.quantity&.to_s)
        present(o, "product_id", purchase.product_id)
        present(o, "transaction_id", purchase.transaction_id)
        present(o, "original_transaction_id", purchase.original_transaction_id)
        apple_dates(o, "purchase_date", purchase.purchase_date_ms)
        apple_dates(o, "original_purchase_date", purchase.original_purchase_date_ms)
        apple_dates(o, "expires_date", purchase.expires_date_ms)
        apple_dates(o, "cancellation_date", purchase.cancellation_date_ms)
        # Apple omits the key when attribute 1711 is 0, as it does for
        # consumables.
        unless purchase.web_order_line_item_id.nil? || purchase.web_order_line_item_id.zero?
          o["web_order_line_item_id"] = purchase.web_order_line_item_id.to_s
        end
        present(o, "is_trial_period", boolean_string(purchase.is_trial_period))
        present(o, "is_in_intro_offer_period", boolean_string(purchase.is_in_intro_offer_period))
        o
      end

      def boolean_string(value)
        return nil if value.nil?

        value.to_s
      end

      def present(json, key, value)
        json[key] = value unless value.nil?
      end

      # Apple renders every date three ways: GMT wall-clock, epoch
      # milliseconds as a String, and US Pacific wall-clock.
      def apple_dates(json, prefix, millis)
        return if millis.nil?

        utc = Time.at(Rational(millis, 1000)).utc
        json[prefix] = "#{utc.strftime("%Y-%m-%d %H:%M:%S")} Etc/GMT"
        json["#{prefix}_ms"] = millis.to_s
        pacific = PacificTime.wall_clock(utc)
        json["#{prefix}_pst"] = "#{pacific.strftime("%Y-%m-%d %H:%M:%S")} #{PacificTime::ZONE_LABEL}"
      end
    end
  end
end
