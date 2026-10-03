# frozen_string_literal: true

module ApplePurchaseReceiptVerifier
  # A verified JWS payload — the payload of {Verifier#verify_signed_data}:
  # the JSON object Apple signed, unchanged. One method covers every Apple
  # JWS (transactions, renewal info, app transactions, App Store Server
  # Notifications V2); the library ships no typed claim models, so callers
  # parse {#json} with the JSON library of their choice.
  #
  # {#environment} is the environment the module read from the payload
  # (docs/rust-core/DECISIONS.md R42): {Environment::PRODUCTION},
  # {Environment::SANDBOX}, or `nil` when the payload names neither. It is
  # taken from the first of the top-level `environment`, `data.environment`
  # (App Store Server Notifications V2) and `summary.environment` (summary
  # notifications) that is present.
  #
  # Public so callers can build one by hand in their own tests; the
  # environment is then whatever the caller passes.
  JsonPayload = Data.define(:json, :environment)
end
