# frozen_string_literal: true

require "json"

module ApplePurchaseReceiptVerifier
  # One in-app purchase decoded from a legacy app receipt (attribute 17).
  # Dates are epoch milliseconds, UTC, with an `_ms` suffix — the JWS half of
  # this API returns Apple's own claims the same way (docs/design/0.7-api.md).
  #
  # Public so callers can build one by hand in their own tests. Only a value
  # returned by {Verifier#verify_receipt} came from a receipt whose chain and
  # signature passed.
  InAppPurchase = Data.define(
    :quantity, :product_id, :transaction_id, :purchase_date_ms, :original_transaction_id,
    :original_purchase_date_ms, :expires_date_ms, :web_order_line_item_id, :cancellation_date_ms,
    :cancellation_reason, :is_trial_period, :is_in_intro_offer_period, :unknown_attributes
  ) do
    # @api private
    def json_value # steep:ignore UndeclaredMethodDefinition
      # @type self: InAppPurchase
      {
        "quantity" => quantity,
        "product_id" => product_id,
        "transaction_id" => transaction_id,
        "purchase_date_ms" => purchase_date_ms,
        "original_transaction_id" => original_transaction_id,
        "original_purchase_date_ms" => original_purchase_date_ms,
        "expires_date_ms" => expires_date_ms,
        "web_order_line_item_id" => web_order_line_item_id&.to_s,
        "cancellation_date_ms" => cancellation_date_ms,
        "cancellation_reason" => cancellation_reason,
        "is_trial_period" => is_trial_period,
        "is_in_intro_offer_period" => is_in_intro_offer_period,
        "unknown_attributes" => PayloadJson.unknown_attributes(unknown_attributes)
      }
    end
  end

  # A verified legacy app receipt — the payload of {Verifier#verify_receipt}.
  # Field names are Apple's own words from the verifyReceipt response
  # (docs/design/0.7-api.md): a caller reading {#to_json}, these readers and
  # Apple's documentation sees one vocabulary.
  #
  # {#environment} is the environment the module read from `receipt_type`
  # (docs/rust-core/DECISIONS.md R42): {Environment::PRODUCTION} for
  # `Production` and `ProductionVPP`, {Environment::SANDBOX} for
  # `ProductionSandbox` and `ProductionVPPSandbox`, `nil` otherwise. It is
  # not part of {#to_json}, which writes the receipt's own fields.
  #
  # Public so callers can build one by hand in their own tests. Only a value
  # returned by {Verifier#verify_receipt} came from a receipt whose chain and
  # signature passed.
  ReceiptPayload = Data.define(
    :receipt_type, :app_item_id, :bundle_id, :bundle_id_bytes, :application_version,
    :opaque_value, :sha1_hash, :receipt_creation_date_ms, :download_id,
    :version_external_identifier, :in_app, :original_purchase_date_ms, :preorder_date_ms,
    :original_application_version, :expiration_date_ms, :unknown_attributes, :environment
  ) do
    # This payload as JSON (docs/design/0.7-api.md, "Our JSON"). It holds the
    # full purchase data; the caller decides what to write where. Every port
    # writes the same value; the bytes may differ.
    # `null` for a missing field, 64-bit ids as JSON strings, bytes as padded
    # standard base64, `unknown_attributes` keyed by the decimal type with
    # each key's values in receipt order.
    #
    # @return [String]
    def to_json(*)
      # @type self: ReceiptPayload
      JSON.generate(
        "receipt_type" => receipt_type,
        "app_item_id" => app_item_id&.to_s,
        "bundle_id" => bundle_id,
        "bundle_id_bytes" => bundle_id_bytes && [bundle_id_bytes].pack("m0"),
        "application_version" => application_version,
        "opaque_value" => opaque_value && [opaque_value].pack("m0"),
        "sha1_hash" => sha1_hash && [sha1_hash].pack("m0"),
        "receipt_creation_date_ms" => receipt_creation_date_ms,
        "download_id" => download_id&.to_s,
        "version_external_identifier" => version_external_identifier&.to_s,
        "in_app" => in_app.map(&:json_value),
        "original_purchase_date_ms" => original_purchase_date_ms,
        "preorder_date_ms" => preorder_date_ms,
        "original_application_version" => original_application_version,
        "expiration_date_ms" => expiration_date_ms,
        "unknown_attributes" => PayloadJson.unknown_attributes(unknown_attributes)
      )
    end
  end

  # Writes the parts of {ReceiptPayload#to_json} that need more than a map.
  #
  # @api private
  module PayloadJson
    class << self
      # `unknown_attributes` as JSON: each type as a decimal key, its values
      # base64 in receipt order.
      def unknown_attributes(attributes)
        attributes.keys.sort.to_h do |type|
          [type.to_s, attributes[type].map { |value| [value].pack("m0") }]
        end
      end
    end
  end
  private_constant :PayloadJson
end
