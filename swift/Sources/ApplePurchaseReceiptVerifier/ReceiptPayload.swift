import Foundation

/// One in-app purchase from a legacy app receipt (attribute 17).
public struct InAppPurchase: Sendable, Equatable {
    public var quantity: Int64?
    public var productId: String?
    public var transactionId: String?
    public var purchaseDateMs: Int64?
    public var originalTransactionId: String?
    public var originalPurchaseDateMs: Int64?
    public var expiresDateMs: Int64?
    public var webOrderLineItemId: Int64?
    public var cancellationDateMs: Int64?
    public var cancellationReason: Int64?
    /// 0 is `false`, any other value `true`.
    public var isTrialPeriod: Bool?
    /// 0 is `false`, any other value `true`.
    public var isInIntroOfferPeriod: Bool?
    /// Every attribute that did not end up in a field above, by attribute
    /// type, each type's raw value octets in receipt order.
    public var unknownAttributes: [Int: [[UInt8]]] = [:]

    public init() {}
}

/// A verified legacy app receipt. Only a value returned by
/// ``Verifier/verifyReceipt(base64:)`` came from a receipt whose chain and
/// signature passed: the verification module decoded it and this package
/// only reads the module's JSON. Public constructors let callers build one
/// by hand in their own tests.
///
/// Dates are epoch milliseconds, UTC. The 64-bit ids are `Int64`: an ASN.1
/// INTEGER can be negative, and the decoder reports what is there.
public struct ReceiptPayload: Sendable, Equatable {
    /// Attribute 0, e.g. `Production` or `ProductionSandbox`.
    public var receiptType: String?
    /// Attribute 1, the app's App Store item id. Zero in sandbox receipts.
    public var appItemId: Int64?
    /// Attribute 2, decoded.
    public var bundleId: String?
    /// Attribute 2, the value octets as they sit in the receipt: the input
    /// to Apple's device-hash formula.
    public var bundleIdBytes: [UInt8]?
    /// Attribute 3.
    public var applicationVersion: String?
    /// Attribute 4.
    public var opaqueValue: [UInt8]?
    /// Attribute 5, the SHA-1 device hash.
    public var sha1Hash: [UInt8]?
    /// Attribute 12.
    public var receiptCreationDateMs: Int64?
    /// Attribute 15. Genuine values run to eighteen digits.
    public var downloadId: Int64?
    /// Attribute 16.
    public var versionExternalIdentifier: Int64?
    /// Attribute 17, one entry per copy.
    public var inApp: [InAppPurchase] = []
    /// Attribute 18.
    public var originalPurchaseDateMs: Int64?
    /// Attribute 32, the pre-order date.
    public var preorderDateMs: Int64?
    /// Attribute 19.
    public var originalApplicationVersion: String?
    /// Attribute 21.
    public var expirationDateMs: Int64?
    /// Every attribute that did not end up in a field above, by attribute
    /// type, each type's raw value octets in receipt order.
    public var unknownAttributes: [Int: [[UInt8]]] = [:]
    /// The environment the verifier read from attribute 0
    /// (docs/rust-core/DECISIONS.md R42): ``Environment/production`` for
    /// `Production` and `ProductionVPP`, ``Environment/sandbox`` for
    /// `ProductionSandbox` and `ProductionVPPSandbox`, `nil` for anything
    /// else (`Xcode`, a missing value). Not part of ``toJson()``.
    public var environment: Environment?

    public init() {}
}

// MARK: - our JSON

extension ReceiptPayload {
    /// The payload as JSON, written by Foundation's `JSONSerialization`: the
    /// keys docs/design/0.7-api.md "Our JSON" lists, `null` for a missing
    /// field, 64-bit ids as strings, bytes as padded standard base64 and
    /// `unknown_attributes` keyed by decimal type. It holds the full purchase
    /// data; the caller decides what to write where. Ports agree on its
    /// value, not its bytes, so key order and escaping are Foundation's.
    public func toJson() -> String {
        jsonText([
            "receipt_type": nullable(receiptType),
            "app_item_id": nullable(appItemId.map(String.init)),
            "bundle_id": nullable(bundleId),
            "bundle_id_bytes": nullable(bundleIdBytes.map(base64)),
            "application_version": nullable(applicationVersion),
            "opaque_value": nullable(opaqueValue.map(base64)),
            "sha1_hash": nullable(sha1Hash.map(base64)),
            "receipt_creation_date_ms": nullable(receiptCreationDateMs),
            "download_id": nullable(downloadId.map(String.init)),
            "version_external_identifier": nullable(versionExternalIdentifier.map(String.init)),
            "in_app": inApp.map(\.jsonObject),
            "original_purchase_date_ms": nullable(originalPurchaseDateMs),
            "preorder_date_ms": nullable(preorderDateMs),
            "original_application_version": nullable(originalApplicationVersion),
            "expiration_date_ms": nullable(expirationDateMs),
            "unknown_attributes": attributesObject(unknownAttributes),
        ])
    }
}

extension InAppPurchase {
    fileprivate var jsonObject: [String: Any] {
        [
            "quantity": nullable(quantity),
            "product_id": nullable(productId),
            "transaction_id": nullable(transactionId),
            "purchase_date_ms": nullable(purchaseDateMs),
            "original_transaction_id": nullable(originalTransactionId),
            "original_purchase_date_ms": nullable(originalPurchaseDateMs),
            "expires_date_ms": nullable(expiresDateMs),
            // Always present here, null included — the omit-when-zero rule is
            // the endpoint's own (Apple's verifyReceipt), not this form's.
            "web_order_line_item_id": nullable(webOrderLineItemId.map(String.init)),
            "cancellation_date_ms": nullable(cancellationDateMs),
            "cancellation_reason": nullable(cancellationReason),
            "is_trial_period": nullable(isTrialPeriod),
            "is_in_intro_offer_period": nullable(isInIntroOfferPeriod),
            "unknown_attributes": attributesObject(unknownAttributes),
        ]
    }
}

/// A missing field is `null`, not omitted.
private func nullable<T>(_ value: T?) -> Any { value.map { $0 as Any } ?? NSNull() }

/// Keyed by decimal type, each value list base64 strings in receipt order.
private func attributesObject(_ attributes: [Int: [[UInt8]]]) -> [String: Any] {
    Dictionary(uniqueKeysWithValues: attributes.map { (String($0.key), $0.value.map(base64)) })
}

/// `object` as compact UTF-8 JSON. Sorted keys make the text the same on
/// every call for the same value; slashes stay unescaped, as the other ports
/// write them. The values are only strings, integers, booleans, `NSNull`,
/// arrays and objects, which `JSONSerialization` always accepts.
func jsonText(_ object: [String: Any]) -> String {
    guard
        let data = try? JSONSerialization.data(
            withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    else { preconditionFailure("JSONSerialization refused a JSON object built from strings and integers") }
    return String(decoding: data, as: UTF8.self)
}

/// Padded standard base64, the form "Our JSON" gives bytes.
private func base64(_ bytes: [UInt8]) -> String { Data(bytes).base64EncodedString() }
