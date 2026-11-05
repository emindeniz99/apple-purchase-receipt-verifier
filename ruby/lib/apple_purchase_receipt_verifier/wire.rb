# frozen_string_literal: true

require "json"

module ApplePurchaseReceiptVerifier
  # Reads the JSON the module answers with (aprv-wire, the 0.7 "Our JSON")
  # into this gem's result types. Nothing here decides anything: the module
  # already did, and this is a typed copy of what it said. An answer that is
  # not shaped as the contract says is a {TrapError}, which the caller turns
  # into INTERNAL_ERROR and discards the instance for.
  #
  # @api private
  module Wire
    DECIMAL = /\A-?\d+\z/
    UNKNOWN_KEY = /\A\d+\z/
    REASON_TOKEN = /\A[A-Z_]{1,40}\z/
    # The top-level `environment` of a verified answer, to this gem's
    # {Environment} values.
    ENVIRONMENTS = {
      "Production" => Environment::PRODUCTION, "Sandbox" => Environment::SANDBOX, nil => nil
    }.freeze

    # What an accepting `init` answer states: the input length, and the
    # revocation state the module worked out for the configuration (the
    # list URLs it expects, and the earliest `nextUpdate` of the lists it
    # holds, epoch milliseconds, or nil).
    InitState = Data.define(:max_input_bytes, :revocation_urls, :revocation_valid_until_ms)

    class << self
      # `init`'s argument for a {Config}: `roots` (base64) only when the
      # caller chose them, then `revocation_lists` and `revocation_issuers`
      # (base64 of the bytes as given) and `distrust` (the two Strings as
      # given), each only when not empty. The default Config sends `{}`.
      # Nothing here reads a certificate or a list.
      #
      # @param config [Config]
      # @return [String]
      def init_config(config)
        init = {} #: Hash[String, untyped]
        init["roots"] = base64_all(config.roots) if config.custom_roots?
        lists = config.revocation_lists
        issuers = config.revocation_issuers
        distrust = config.distrust
        init["revocation_lists"] = base64_all(lists) unless lists.empty?
        init["revocation_issuers"] = base64_all(issuers) unless issuers.empty?
        unless distrust.empty?
          init["distrust"] = distrust.map { |entry| { "issuer" => entry.issuer, "serial" => entry.serial } }
        end
        JSON.generate(init)
      end

      # `init`'s answer: `{"ok":true,"max_input_bytes":N,
      # "revocation_urls":[...],"revocation_valid_until_ms":M|null}` or
      # `{"ok":false,"message":"..."}`. `N` is the most bytes of one input
      # the module needs (docs/rust-core/DECISIONS.md R42): a longer input is
      # cut to it, and the module answers TOO_LARGE for that. An accepting
      # answer without a positive integer there, or without the two
      # revocation members, comes from a module of another version, and is a
      # {TrapError} like any unusable answer.
      #
      # @param text [String]
      # @return [InitState]
      # @raise [RootsRejected] the module refused the configuration
      # @raise [TrapError] the answer is not an `init` answer
      def init_answer(text)
        answer = object(text, "init")
        case answer["ok"]
        when true
          InitState.new(max_input_bytes: max_input_bytes(answer), revocation_urls: revocation_urls(answer),
                        revocation_valid_until_ms: revocation_valid_until_ms(answer))
        when false
          raise RootsRejected, string(answer, "message") || "the configuration was refused"
        else
          raise TrapError, "init answered neither ok:true nor ok:false"
        end
      end

      # @param text [String] a `verify-receipt` answer
      # @return [VerificationResult] of {ReceiptPayload}
      def receipt_result(text)
        result(text, "verify-receipt") { |payload, environment| receipt_payload(payload, environment) }
      end

      # @param text [String] a `verify-signed-data` answer
      # @return [VerificationResult] of {JsonPayload}
      def signed_data_result(text)
        result(text, "verify-signed-data") do |payload, environment|
          raise TrapError, "verify-signed-data: the payload is not a string" unless payload.is_a?(String)

          JsonPayload.new(json: payload.freeze, environment: environment)
        end
      end

      private

      def base64_all(strings)
        strings.map { |bytes| [bytes].pack("m0") }
      end

      def max_input_bytes(answer)
        max = answer["max_input_bytes"]
        return max if max.is_a?(Integer) && max.positive?

        raise TrapError, "init accepted the configuration but states no max_input_bytes: " \
                         "the module is of another ABI version"
      end

      def revocation_urls(answer)
        urls = answer["revocation_urls"]
        return urls.map(&:freeze).freeze if urls.is_a?(Array) && urls.all?(String)

        raise TrapError, "init accepted the configuration but states no revocation_urls: " \
                         "the module is of another version"
      end

      def revocation_valid_until_ms(answer)
        value = answer["revocation_valid_until_ms"]
        return value if answer.key?("revocation_valid_until_ms") && (value.nil? || value.is_a?(Integer))

        raise TrapError, "init accepted the configuration but states no revocation_valid_until_ms: " \
                         "the module is of another version"
      end

      def result(text, operation)
        answer = object(text, operation)
        case answer["verified"]
        when true
          VerificationResult.ok(yield(answer["payload"], environment(answer, operation)))
        when false
          VerificationResult.error(failure(answer, operation))
        else
          raise TrapError, "#{operation}: the answer has no verified flag"
        end
      end

      def failure(answer, operation)
        token = answer["reason"]
        reason = token.is_a?(String) ? Reason::ALL.find { |r| r.to_s == token } : nil
        if reason.nil?
          shown = token.is_a?(String) && token.match?(REASON_TOKEN) ? token : "?"
          raise TrapError,
                "#{operation}: the module answered a reason this wrapper does not know (#{shown})"
        end

        Failure.new(reason: reason, message: required_string(answer, "message"), cause: nil)
      end

      # A verified answer's `environment`: "Production", "Sandbox" or null,
      # and present. Anything else is an answer this wrapper cannot read.
      def environment(answer, operation)
        raise TrapError, "#{operation}: the answer has no environment" unless answer.key?("environment")

        value = answer["environment"]
        return ENVIRONMENTS.fetch(value) if ENVIRONMENTS.key?(value)

        raise TrapError, "#{operation}: the answer states an environment this wrapper does not know"
      end

      def object(text, operation)
        parsed = JSON.parse(text)
        return parsed if parsed.is_a?(Hash)

        raise TrapError, "#{operation}: the answer is not a JSON object"
      rescue JSON::ParserError, EncodingError
        raise TrapError, "#{operation}: the answer is not JSON"
      end

      def receipt_payload(payload, environment)
        raise TrapError, "verify-receipt: the payload is not an object" unless payload.is_a?(Hash)

        ReceiptPayload.new(
          receipt_type: string(payload, "receipt_type"),
          app_item_id: id(payload, "app_item_id"),
          bundle_id: string(payload, "bundle_id"),
          bundle_id_bytes: bytes(payload, "bundle_id_bytes"),
          application_version: string(payload, "application_version"),
          opaque_value: bytes(payload, "opaque_value"),
          sha1_hash: bytes(payload, "sha1_hash"),
          receipt_creation_date_ms: integer(payload, "receipt_creation_date_ms"),
          download_id: id(payload, "download_id"),
          version_external_identifier: id(payload, "version_external_identifier"),
          in_app: list(payload, "in_app") { |purchase| in_app_purchase(purchase) }.freeze,
          original_purchase_date_ms: integer(payload, "original_purchase_date_ms"),
          preorder_date_ms: integer(payload, "preorder_date_ms"),
          original_application_version: string(payload, "original_application_version"),
          expiration_date_ms: integer(payload, "expiration_date_ms"),
          unknown_attributes: unknown_attributes(payload),
          environment: environment
        )
      end

      def in_app_purchase(purchase)
        raise TrapError, "verify-receipt: an in_app entry is not an object" unless purchase.is_a?(Hash)

        InAppPurchase.new(
          quantity: integer(purchase, "quantity"),
          product_id: string(purchase, "product_id"),
          transaction_id: string(purchase, "transaction_id"),
          purchase_date_ms: integer(purchase, "purchase_date_ms"),
          original_transaction_id: string(purchase, "original_transaction_id"),
          original_purchase_date_ms: integer(purchase, "original_purchase_date_ms"),
          expires_date_ms: integer(purchase, "expires_date_ms"),
          web_order_line_item_id: id(purchase, "web_order_line_item_id"),
          cancellation_date_ms: integer(purchase, "cancellation_date_ms"),
          cancellation_reason: integer(purchase, "cancellation_reason"),
          is_trial_period: boolean(purchase, "is_trial_period"),
          is_in_intro_offer_period: boolean(purchase, "is_in_intro_offer_period"),
          unknown_attributes: unknown_attributes(purchase)
        )
      end

      # `{"13": ["<base64>", ...]}` to `{13 => [bytes, ...]}`, in receipt
      # order.
      def unknown_attributes(container)
        raw = container["unknown_attributes"]
        raise TrapError, "unknown_attributes is not an object" unless raw.is_a?(Hash)

        raw.to_h do |type, values|
          unless type.match?(UNKNOWN_KEY)
            raise TrapError,
                  "unknown_attributes has a key that is not a type number"
          end
          raise TrapError, "unknown_attributes.#{type} is not a list" unless values.is_a?(Array)

          [Integer(type, 10), values.map do |value|
            decode_base64(value, "unknown_attributes.#{type}")
          end.freeze]
        end.freeze
      end

      def list(container, key, &)
        value = container[key]
        raise TrapError, "#{key} is not a list" unless value.is_a?(Array)

        value.map(&)
      end

      def string(container, key)
        value = container[key]
        return value.freeze if value.is_a?(String)
        return nil if value.nil?

        raise TrapError, "#{key} is not a string"
      end

      def required_string(container, key)
        string(container, key) || raise(TrapError, "#{key} is missing")
      end

      def integer(container, key)
        value = container[key]
        return value if value.nil? || value.is_a?(Integer)

        raise TrapError, "#{key} is not an integer"
      end

      def boolean(container, key)
        value = container[key]
        return value if value.nil? || value == true || value == false

        raise TrapError, "#{key} is not a boolean"
      end

      # 64-bit ids are JSON strings.
      def id(container, key)
        value = container[key]
        return nil if value.nil?
        return Integer(value, 10) if value.is_a?(String) && value.match?(DECIMAL)

        raise TrapError, "#{key} is not a decimal string"
      end

      def bytes(container, key)
        value = container[key]
        return nil if value.nil?

        decode_base64(value, key)
      end

      def decode_base64(value, where)
        raise TrapError, "#{where} is not a base64 string" unless value.is_a?(String)

        decoded = value.unpack1("m0") #: String
        decoded.freeze
      rescue ArgumentError
        raise TrapError, "#{where} is not base64"
      end
    end
  end
  private_constant :Wire
end
