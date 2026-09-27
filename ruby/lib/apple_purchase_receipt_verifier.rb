# frozen_string_literal: true

# Offline verification of Apple App Store purchase receipts: StoreKit 2 /
# App Store Server JWS payloads and legacy PKCS#7 app receipts, against
# trust anchors the caller pins.
#
# Nothing here reaches the network and nothing reads the operating system's
# trust store. There is no OCSP, no CRL and no AIA fetch: revocation is
# disabled by design, which is the same trade-off Apple's own libraries make
# in offline mode.
#
#   require "apple_purchase_receipt_verifier"
#
#   verifier = ApplePurchaseReceiptVerifier::Verifier.create(
#     ApplePurchaseReceiptVerifier::Config.defaults
#   )
#   result = verifier.verify_receipt(receipt_data)
module ApplePurchaseReceiptVerifier
end

require_relative "apple_purchase_receipt_verifier/version"
require_relative "apple_purchase_receipt_verifier/errors"
require_relative "apple_purchase_receipt_verifier/safe_text"
require_relative "apple_purchase_receipt_verifier/asn1"
require_relative "apple_purchase_receipt_verifier/json"
require_relative "apple_purchase_receipt_verifier/roots"
require_relative "apple_purchase_receipt_verifier/certificate_structure"
require_relative "apple_purchase_receipt_verifier/chain"
require_relative "apple_purchase_receipt_verifier/signature"
require_relative "apple_purchase_receipt_verifier/cms"
require_relative "apple_purchase_receipt_verifier/canonical_json"
require_relative "apple_purchase_receipt_verifier/receipt_payload"
require_relative "apple_purchase_receipt_verifier/clock"
require_relative "apple_purchase_receipt_verifier/receipt"
require_relative "apple_purchase_receipt_verifier/json_payload"
require_relative "apple_purchase_receipt_verifier/jws"
require_relative "apple_purchase_receipt_verifier/pacific_time"
require_relative "apple_purchase_receipt_verifier/endpoint"
require_relative "apple_purchase_receipt_verifier/config"
require_relative "apple_purchase_receipt_verifier/result"
require_relative "apple_purchase_receipt_verifier/verifier"
