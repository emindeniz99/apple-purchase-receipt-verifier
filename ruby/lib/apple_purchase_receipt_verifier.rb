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
# The verification itself is `aprv.wasm`, one WebAssembly module built from
# one Rust core and shared by every implementation of this repository. This
# gem loads it into the `wasmtime` gem's runtime and moves bytes in and JSON
# out; it parses no receipt, checks no signature and decides no trust.
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
require_relative "apple_purchase_receipt_verifier/result"
require_relative "apple_purchase_receipt_verifier/receipt_payload"
require_relative "apple_purchase_receipt_verifier/json_payload"
require_relative "apple_purchase_receipt_verifier/wire"
require_relative "apple_purchase_receipt_verifier/runtime"
require_relative "apple_purchase_receipt_verifier/guest"
require_relative "apple_purchase_receipt_verifier/pool"
require_relative "apple_purchase_receipt_verifier/config"
require_relative "apple_purchase_receipt_verifier/verifier"
