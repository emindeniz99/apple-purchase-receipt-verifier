# frozen_string_literal: true

# Offline verification of Apple App Store purchase receipts: StoreKit 2 / App
# Store Server JWS payloads and legacy PKCS#7 app receipts, against trust
# anchors the caller pins.
#
# Nothing here reaches the network and nothing reads the operating system's
# trust store. There is no OCSP, no CRL and no AIA fetch: revocation is
# disabled by design, which is the same trade-off Apple's own libraries make in
# offline mode (PLAN.md D12).
#
#   require "apple_purchase_receipt_verifier"
#
#   verifier = ApplePurchaseReceiptVerifier::ReceiptVerifier.new(
#     trusted_roots: ApplePurchaseReceiptVerifier.apple_receipt_roots,
#     bundle_id: "com.example.app"
#   )
#   receipt = verifier.verify_base64(receipt_data)
module ApplePurchaseReceiptVerifier
end

require_relative "apple_purchase_receipt_verifier/version"
require_relative "apple_purchase_receipt_verifier/errors"
require_relative "apple_purchase_receipt_verifier/asn1"
require_relative "apple_purchase_receipt_verifier/chain"
require_relative "apple_purchase_receipt_verifier/roots"
require_relative "apple_purchase_receipt_verifier/payloads"
require_relative "apple_purchase_receipt_verifier/jws"
require_relative "apple_purchase_receipt_verifier/receipt_payload"
require_relative "apple_purchase_receipt_verifier/cms"
require_relative "apple_purchase_receipt_verifier/receipt"
require_relative "apple_purchase_receipt_verifier/pacific_time"
require_relative "apple_purchase_receipt_verifier/verify_receipt_endpoint"
