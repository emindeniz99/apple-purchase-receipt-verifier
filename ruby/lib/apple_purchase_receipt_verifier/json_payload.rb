# frozen_string_literal: true

module ApplePurchaseReceiptVerifier
  # A verified JWS payload — the payload of {Verifier#verify_signed_data}:
  # the JSON object Apple signed, unchanged. One method covers every Apple
  # JWS (transactions, renewal info, app transactions, App Store Server
  # Notifications V2); the library ships no typed claim models, so callers
  # parse {#json} with the JSON library of their choice.
  #
  # Public so callers can build one by hand in their own tests.
  JsonPayload = Data.define(:json)
end
