import Foundation
import SwiftASN1

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
/// signature passed. Public constructors let callers build one by hand in
/// their own tests.
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
    /// Attribute 19.
    public var originalApplicationVersion: String?
    /// Attribute 21.
    public var expirationDateMs: Int64?
    /// Every attribute that did not end up in a field above, by attribute
    /// type, each type's raw value octets in receipt order.
    public var unknownAttributes: [Int: [[UInt8]]] = [:]

    public init() {}
}

// Attribute types. 1, 15, 16 and 1713 are on none of Apple's pages, not even
// the archived Receipt Fields chapter. They were established by decoding a
// genuine production receipt and lining its attributes up against the
// answer Apple's verifyReceipt endpoint gives for the same receipt (measured
// 2026-09-21): 1 app item id -> adam_id AND app_item_id; 15 download id ->
// download_id; 16 version external id -> version_external_identifier; 1713
// is trial period (in-app) -> is_trial_period.
private let attrReceiptType = 0
private let attrAppItemId = 1
private let attrBundleId = 2
private let attrAppVersion = 3
private let attrOpaqueValue = 4
private let attrSha1Hash = 5
private let attrCreationDate = 12
private let attrDownloadId = 15
private let attrVersionExternalIdentifier = 16
private let attrInApp = 17
private let attrOriginalPurchaseDate = 18
private let attrOriginalAppVersion = 19
private let attrExpirationDate = 21
private let knownTopLevel: Set<Int> = [
    attrReceiptType, attrAppItemId, attrBundleId, attrAppVersion, attrOpaqueValue, attrSha1Hash,
    attrCreationDate, attrDownloadId, attrVersionExternalIdentifier, attrOriginalPurchaseDate,
    attrOriginalAppVersion, attrExpirationDate,
]

private let iapQuantity = 1701
private let iapProductId = 1702
private let iapTransactionId = 1703
private let iapPurchaseDate = 1704
private let iapOriginalTransactionId = 1705
private let iapOriginalPurchaseDate = 1706
private let iapExpiresDate = 1708
private let iapWebOrderLineItemId = 1711
private let iapCancellationDate = 1712
private let iapIsTrialPeriod = 1713
private let iapIsInIntroOfferPeriod = 1719
private let knownInApp: Set<Int> = [
    iapQuantity, iapProductId, iapTransactionId, iapPurchaseDate, iapOriginalTransactionId,
    iapOriginalPurchaseDate, iapExpiresDate, iapWebOrderLineItemId, iapCancellationDate,
    iapIsTrialPeriod, iapIsInIntroOfferPeriod,
]

/// Why a payload could not be read at all — the `cause` behind
/// ``Reason/unreadablePayload``.
struct PayloadError: Error, Sendable, CustomStringConvertible {
    let detail: String
    init(_ detail: String) { self.detail = detail }
    var description: String { detail }
}

/// Decodes a date attribute and assigns it, returning whether it decoded.
///
/// `decodeDate` legitimately returns `nil` for an empty date string ("not
/// set", not kept raw) as well as throwing for one that does not parse (kept
/// raw). `try? decodeDate(value)` alone cannot tell the two apart: Swift
/// flattens the `Int64??` a `try?` around an already-`Int64?`-returning call
/// produces down to one level of `Optional` (SE-0230), so a legitimate
/// `nil` and a thrown error both read back as `nil` — which silently
/// mis-filed the G5 sandbox fixture's empty attribute 1712 as raw. This
/// keeps the assignment and the decoded/not-decoded verdict as two separate
/// answers instead of collapsing them into one `Optional`.
private func assignDate(_ value: [UInt8], _ assign: (Int64?) -> Void) -> Bool {
    do {
        assign(try decodeDate(value))
        return true
    } catch {
        return false
    }
}

private struct RawAttribute {
    let type: Int
    let value: [UInt8]
}

/// The receipt creation date (attribute 12), read the only way anything in a
/// payload is read before its signer is trusted: the top-level attribute SET
/// is walked shallowly, each entry's type is read, and only the value of the
/// FIRST type 12 is decoded. `nil` means "judge the chain at the clock": no
/// attribute 12, a first one that is empty or does not decode, or a walk
/// that fails anywhere. Never throws: nothing is trusted yet, so nothing
/// here can blame anyone.
func readCreationDate(_ content: [UInt8]) -> Int64? {
    guard let attributes = try? parseAttributeSet(content) else { return nil }
    guard let first = attributes.first(where: { $0.type == attrCreationDate }) else { return nil }
    return (try? decodeDate(first.value)) ?? nil
}

/// The full payload parse, run only after the chain and the signature have
/// passed. A trusted signer signed these bytes, so anything that stops the
/// parse (this library's grammar or a bound) is the library's failure or a
/// format Apple added, not the client's: the caller wraps this in
/// ``Reason/unreadablePayload``, never ``Reason/malformed``.
func parseReceiptPayload(_ content: [UInt8]) throws -> ReceiptPayload {
    let attributes = try parseAttributeSet(content)
    var receipt = ReceiptPayload()
    var seen: Set<Int> = []
    for attribute in attributes {
        if knownTopLevel.contains(attribute.type) {
            guard !seen.contains(attribute.type) else {
                receipt.unknownAttributes[attribute.type, default: []].append(attribute.value)
                continue
            }
            seen.insert(attribute.type)
        }
        let value = attribute.value
        var decoded = true
        switch attribute.type {
        case attrReceiptType:
            if let v = try? decodeString(value) { receipt.receiptType = v } else { decoded = false }
        case attrAppItemId:
            if let v = try? decodeInteger(value) { receipt.appItemId = v } else { decoded = false }
        case attrBundleId:
            // The octets are a field of their own, kept even when the
            // string does not decode, so they are never kept raw.
            receipt.bundleIdBytes = value
            receipt.bundleId = try? decodeString(value)
        case attrAppVersion:
            if let v = try? decodeString(value) { receipt.applicationVersion = v } else { decoded = false }
        case attrOpaqueValue:
            receipt.opaqueValue = value
        case attrSha1Hash:
            receipt.sha1Hash = value
        case attrCreationDate:
            decoded = assignDate(value) { receipt.receiptCreationDateMs = $0 }
        case attrDownloadId:
            if let v = try? decodeInteger(value) { receipt.downloadId = v } else { decoded = false }
        case attrVersionExternalIdentifier:
            if let v = try? decodeInteger(value) { receipt.versionExternalIdentifier = v } else { decoded = false }
        case attrInApp:
            if let v = try? parseInApp(value) { receipt.inApp.append(v) } else { decoded = false }
        case attrOriginalPurchaseDate:
            decoded = assignDate(value) { receipt.originalPurchaseDateMs = $0 }
        case attrOriginalAppVersion:
            if let v = try? decodeString(value) { receipt.originalApplicationVersion = v } else { decoded = false }
        case attrExpirationDate:
            decoded = assignDate(value) { receipt.expirationDateMs = $0 }
        default:
            decoded = false
        }
        if !decoded {
            receipt.unknownAttributes[attribute.type, default: []].append(value)
        }
    }
    return receipt
}

/// An in-app purchase. Anything that stops it from parsing — its attribute
/// SET or one of its attributes — makes the whole attribute 17 raw.
private func parseInApp(_ value: [UInt8]) throws -> InAppPurchase {
    let attributes = try parseAttributeSet(value)
    var purchase = InAppPurchase()
    var seen: Set<Int> = []
    for attribute in attributes {
        if knownInApp.contains(attribute.type) {
            guard !seen.contains(attribute.type) else {
                purchase.unknownAttributes[attribute.type, default: []].append(attribute.value)
                continue
            }
            seen.insert(attribute.type)
        }
        let value = attribute.value
        var decoded = true
        switch attribute.type {
        case iapQuantity:
            if let v = try? decodeInteger(value) { purchase.quantity = v } else { decoded = false }
        case iapProductId:
            if let v = try? decodeString(value) { purchase.productId = v } else { decoded = false }
        case iapTransactionId:
            if let v = try? decodeString(value) { purchase.transactionId = v } else { decoded = false }
        case iapPurchaseDate:
            decoded = assignDate(value) { purchase.purchaseDateMs = $0 }
        case iapOriginalTransactionId:
            if let v = try? decodeString(value) { purchase.originalTransactionId = v } else { decoded = false }
        case iapOriginalPurchaseDate:
            decoded = assignDate(value) { purchase.originalPurchaseDateMs = $0 }
        case iapExpiresDate:
            decoded = assignDate(value) { purchase.expiresDateMs = $0 }
        case iapWebOrderLineItemId:
            if let v = try? decodeInteger(value) { purchase.webOrderLineItemId = v } else { decoded = false }
        case iapCancellationDate:
            decoded = assignDate(value) { purchase.cancellationDateMs = $0 }
        case iapIsTrialPeriod:
            if let v = try? decodeInteger(value) { purchase.isTrialPeriod = v != 0 } else { decoded = false }
        case iapIsInIntroOfferPeriod:
            if let v = try? decodeInteger(value) { purchase.isInIntroOfferPeriod = v != 0 } else { decoded = false }
        default:
            decoded = false
        }
        if !decoded {
            purchase.unknownAttributes[attribute.type, default: []].append(value)
        }
    }
    return purchase
}

/// `SET OF ReceiptAttribute`, `ReceiptAttribute ::= SEQUENCE { type INTEGER,
/// version INTEGER, value OCTET STRING }` — fields after the third are
/// tolerated, so a field Apple appends later does not break parsing, and the
/// version is not read. Xcode receipts double-wrap the payload in an extra
/// OCTET STRING, unwrapped here.
private func parseAttributeSet(_ der: [UInt8]) throws -> [RawAttribute] {
    var root: ASN1Node
    do {
        root = try DER.parse(der)
    } catch {
        throw PayloadError("attribute set is not valid ASN.1")
    }
    if root.identifier == .octetString {
        do {
            root = try DER.parse(try payloadPrimitive(root))
        } catch {
            throw PayloadError("double-wrap is not valid ASN.1")
        }
    }
    guard root.identifier == .set else { throw PayloadError("attribute set is not an ASN.1 SET") }
    var attributes: [RawAttribute] = []
    for child in try payloadChildren(root) {
        let fields = try payloadChildren(child)
        guard child.identifier == .sequence, fields.count >= 3, fields[0].identifier == .integer,
            fields[2].identifier == .octetString
        else { throw PayloadError("malformed receipt attribute") }
        // The version is not read, but an INTEGER there must still be one.
        if fields[1].identifier == .integer, (try? attributeIntValue(fields[1])) == nil {
            throw PayloadError("malformed receipt attribute")
        }
        // The attribute TYPE is bounded at a 32-bit signed integer, the
        // width every port keys unknownAttributes by. Refused rather than
        // narrowed: narrowing would invent an attribute the receipt never
        // carried.
        guard let typeValue = try? attributeIntValue(fields[0]), typeValue >= 0,
            typeValue <= Int(Int32.max)
        else { throw PayloadError("receipt attribute type out of range") }
        attributes.append(RawAttribute(type: Int(typeValue), value: try payloadPrimitive(fields[2])))
    }
    return attributes
}

private func payloadChildren(_ node: ASN1Node) throws -> [ASN1Node] {
    guard case .constructed(let nodes) = node.content else {
        throw PayloadError("expected constructed ASN.1 node")
    }
    return Array(nodes)
}

private func payloadPrimitive(_ node: ASN1Node) throws -> [UInt8] {
    guard case .primitive(let bytes) = node.content else {
        throw PayloadError("expected primitive ASN.1 node")
    }
    return [UInt8](bytes)
}

/// A DER INTEGER's value: empty, or with a redundant leading octet, does not
/// parse (`nil` via `nil` return through `attributeIntValue`'s caller — this
/// throws, the caller decides null-and-kept-raw).
private func attributeIntValue(_ node: ASN1Node) throws -> Int64 {
    guard node.identifier == .integer else { throw PayloadError("not an ASN.1 integer") }
    let contents = try payloadPrimitive(node)
    guard let first = contents.first, contents.count <= 8 else {
        throw PayloadError("attribute integer out of range")
    }
    if contents.count > 1 {
        let second = contents[1]
        // X.690 8.3.2: the first nine bits are never all zero or all one.
        if (first == 0x00 && second & 0x80 == 0) || (first == 0xFF && second & 0x80 != 0) {
            throw PayloadError("attribute integer is not minimally encoded")
        }
    }
    var value: Int64 = first & 0x80 == 0 ? 0 : -1
    for byte in contents { value = (value << 8) | Int64(byte) }
    return value
}

private func decodeNested(_ der: [UInt8]) throws -> ASN1Node {
    do {
        return try DER.parse(der)
    } catch {
        throw PayloadError("attribute value is not valid ASN.1")
    }
}

/// A `UTF8String` or an `IA5String`, the two string types Apple's receipts
/// use. A `UTF8String` must be valid UTF-8; an `IA5String` must be ASCII —
/// IA5 is seven-bit, so a byte from 0x80 up does not decode, rather than
/// being read as Latin-1.
private func decodeString(_ der: [UInt8]) throws -> String {
    let node = try decodeNested(der)
    switch node.identifier {
    case .utf8String:
        guard let text = String(bytes: try payloadPrimitive(node), encoding: .utf8) else {
            throw PayloadError("not valid UTF-8")
        }
        return text
    case .ia5String:
        let bytes = try payloadPrimitive(node)
        guard bytes.allSatisfy({ $0 < 0x80 }) else { throw PayloadError("not seven-bit IA5") }
        return String(decoding: bytes, as: UTF8.self)
    default:
        throw PayloadError("attribute value is not an ASN.1 string")
    }
}

private func decodeInteger(_ der: [UInt8]) throws -> Int64 {
    let node = try decodeNested(der)
    return try attributeIntValue(node)
}

/// A date in an `IA5String` or `UTF8String`, as epoch milliseconds. An empty
/// string is `nil`: Apple writes an unset date that way, so it is not kept
/// raw (the caller decodes it successfully to "not set"). Anything else must
/// be exactly `YYYY-MM-DDTHH:MM:SSZ` (``parseReceiptDate(_:)``).
private func decodeDate(_ der: [UInt8]) throws -> Int64? {
    let text = try decodeString(der)
    if text.isEmpty { return nil }
    guard let millis = parseReceiptDate(text) else { throw PayloadError("unparseable receipt date") }
    return millis
}

// MARK: - canonical JSON

extension ReceiptPayload {
    /// The canonical JSON, fixed byte for byte: the keys below in this
    /// order, no whitespace, `null` for a missing field, 64-bit ids as
    /// strings, bytes as padded standard base64, `unknown_attributes` keys
    /// in ascending numeric order, and strings escaped exactly as
    /// ECMAScript `JSON.stringify` escapes them.
    public func toJson() -> String {
        var out = ""
        let json = JsonObjectWriter.open(into: { out += $0 })
        json.string("receipt_type", receiptType)
        json.id("app_item_id", appItemId)
        json.string("bundle_id", bundleId)
        json.bytes("bundle_id_bytes", bundleIdBytes)
        json.string("application_version", applicationVersion)
        json.bytes("opaque_value", opaqueValue)
        json.bytes("sha1_hash", sha1Hash)
        json.number("receipt_creation_date_ms", receiptCreationDateMs)
        json.id("download_id", downloadId)
        json.id("version_external_identifier", versionExternalIdentifier)
        json.key("in_app")
        json.raw("[")
        for (index, purchase) in inApp.enumerated() {
            if index > 0 { json.raw(",") }
            purchase.writeJson(into: json)
        }
        json.raw("]")
        json.number("original_purchase_date_ms", originalPurchaseDateMs)
        json.string("original_application_version", originalApplicationVersion)
        json.number("expiration_date_ms", expirationDateMs)
        json.attributes("unknown_attributes", unknownAttributes)
        json.close()
        return out
    }
}

extension InAppPurchase {
    fileprivate func writeJson(into parent: JsonObjectWriter) {
        var fragment = ""
        let json = JsonObjectWriter.open(into: { fragment += $0 })
        json.number("quantity", quantity)
        json.string("product_id", productId)
        json.string("transaction_id", transactionId)
        json.number("purchase_date_ms", purchaseDateMs)
        json.string("original_transaction_id", originalTransactionId)
        json.number("original_purchase_date_ms", originalPurchaseDateMs)
        json.number("expires_date_ms", expiresDateMs)
        // Always present here, null included — the omit-when-zero rule is
        // the endpoint's own (Apple's verifyReceipt), not this canonical
        // form's.
        json.id("web_order_line_item_id", webOrderLineItemId)
        json.number("cancellation_date_ms", cancellationDateMs)
        json.boolean("is_trial_period", isTrialPeriod)
        json.boolean("is_in_intro_offer_period", isInIntroOfferPeriod)
        json.attributes("unknown_attributes", unknownAttributes)
        json.close()
        parent.raw(fragment)
    }
}
