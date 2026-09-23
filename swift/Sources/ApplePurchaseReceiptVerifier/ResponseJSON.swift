import Foundation

// The verifyReceipt response body, written without `JSONSerialization` on the
// common path.
//
// swift-corelibs-foundation's `JSONSerialization` took about 56 ms to write
// the answer for a receipt with 187 purchases (22 ms of it without
// `.sortedKeys`; building the dictionary took 1.2 ms), measured on a release
// build with Swift 6.3.3 on Linux x86_64: about ten times the cost of
// verifying the receipt. The answer only ever holds strings, integers,
// arrays and dictionaries under a fixed set of keys, so this writer handles
// exactly those, and it borrows from `JSONSerialization` the two things that
// are platform-specific: the order `.sortedKeys` puts keys in (a locale
// collation, not byte order: it puts "_" before "a" and "a" before "A"), and
// the escaping of any string that is not plain printable ASCII. Anything
// else — a key outside the set, a value of another type — sends the whole
// response back to `JSONSerialization`, so no byte of the answer moves.
// ResponseJSONTests compares the two on every receipt fixture and on
// generated strings.

/// Every key a response can hold: `VerifyReceiptResult`'s render and the
/// `receiptJson` and `inAppJson` helpers, and the `_ms` and `_pst`
/// companions of each date.
private let responseKeys: [String] = {
    let plain = [
        "status", "environment", "receipt",
        "receipt_type", "adam_id", "app_item_id", "bundle_id", "application_version",
        "download_id", "version_external_identifier", "original_application_version", "in_app",
        "quantity", "product_id", "transaction_id", "original_transaction_id",
        "web_order_line_item_id", "is_trial_period", "is_in_intro_offer_period",
    ]
    let dates = [
        "receipt_creation_date", "request_date", "original_purchase_date", "expiration_date",
        "purchase_date", "expires_date", "cancellation_date",
    ]
    return plain + dates.flatMap { [$0, $0 + "_ms", $0 + "_pst"] }
}()

/// Each key's position in the order `JSONSerialization` writes them with
/// `.sortedKeys` on this platform, learned once by writing all of them and
/// reading the order back. Sorting a subset by the same comparator gives
/// the induced order, so ranks are all a response needs. nil when the order
/// could not be learned, in which case every response takes the Foundation
/// path.
private let responseKeyRank: [String: Int]? = {
    let object = Dictionary(uniqueKeysWithValues: responseKeys.map { ($0, 0) })
    guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) else {
        return nil
    }
    let text = String(decoding: data, as: UTF8.self)
    var rank: [String: Int] = [:]
    for key in responseKeys {
        // The closing quote and colon keep "purchase_date" from matching
        // "purchase_date_ms".
        guard let found = text.range(of: "\"\(key)\":") else { return nil }
        rank[key] = text.distance(from: text.startIndex, to: found.lowerBound)
    }
    return rank
}()

/// The response as `JSONSerialization.data(withJSONObject:options: [.sortedKeys])`
/// writes it, byte for byte; nil only when `JSONSerialization` itself fails.
func serializeResponse(_ response: [String: Any]) -> String? {
    serializeResponseWithWriter(response) ?? serializeResponseWithFoundation(response)
}

/// The writer alone; nil when it hands the response back to Foundation.
/// Internal so the differential test can tell which path answered.
func serializeResponseWithWriter(_ response: [String: Any]) -> String? {
    guard let rank = responseKeyRank else { return nil }
    var out: [UInt8] = []
    out.reserveCapacity(4096)
    guard writeJSON(response, rank: rank, into: &out) else { return nil }
    return String(decoding: out, as: UTF8.self)
}

/// The Foundation path, unchanged from before the writer existed. Internal
/// so the differential test can compare the two.
func serializeResponseWithFoundation(_ response: [String: Any]) -> String? {
    guard let encoded = try? JSONSerialization.data(withJSONObject: response, options: [.sortedKeys]) else {
        return nil
    }
    return String(data: encoded, encoding: .utf8)
}

/// Appends `value`; false when it holds anything this writer does not
/// handle, and then `out` is to be discarded.
private func writeJSON(_ value: Any, rank: [String: Int], into out: inout [UInt8]) -> Bool {
    switch value {
    case let string as String:
        return writeString(string, into: &out)
    case let number as Int64:
        out.append(contentsOf: String(number).utf8)
    case let number as Int:
        out.append(contentsOf: String(number).utf8)
    case let object as [String: Any]:
        var keys: [(rank: Int, key: String)] = []
        keys.reserveCapacity(object.count)
        for key in object.keys {
            guard let position = rank[key] else { return false }
            keys.append((position, key))
        }
        keys.sort { $0.rank < $1.rank }
        out.append(UInt8(ascii: "{"))
        for (index, entry) in keys.enumerated() {
            if index > 0 { out.append(UInt8(ascii: ",")) }
            guard writeString(entry.key, into: &out) else { return false }
            out.append(UInt8(ascii: ":"))
            guard writeJSON(object[entry.key]!, rank: rank, into: &out) else { return false }
        }
        out.append(UInt8(ascii: "}"))
    case let array as [Any]:
        out.append(UInt8(ascii: "["))
        for (index, element) in array.enumerated() {
            if index > 0 { out.append(UInt8(ascii: ",")) }
            guard writeJSON(element, rank: rank, into: &out) else { return false }
        }
        out.append(UInt8(ascii: "]"))
    default:
        return false
    }
    return true
}

/// Printable ASCII is written here, with `/` as `\/` as `JSONSerialization`
/// writes it (it escapes the solidus unless told `.withoutEscapingSlashes`).
/// A string holding anything else — a quote, a backslash, a control
/// character, DEL, any non-ASCII scalar — is escaped by `JSONSerialization`
/// itself, as a one-element array with the brackets taken off.
private func writeString(_ string: String, into out: inout [UInt8]) -> Bool {
    let plain = string.utf8.allSatisfy { $0 >= 0x20 && $0 < 0x7F && $0 != 0x22 && $0 != 0x5C }
    guard plain else {
        guard let data = try? JSONSerialization.data(withJSONObject: [string]),
            data.count >= 2, data.first == UInt8(ascii: "["), data.last == UInt8(ascii: "]")
        else { return false }
        out.append(contentsOf: data.dropFirst().dropLast())
        return true
    }
    out.append(UInt8(ascii: "\""))
    for byte in string.utf8 {
        if byte == UInt8(ascii: "/") { out.append(UInt8(ascii: "\\")) }
        out.append(byte)
    }
    out.append(UInt8(ascii: "\""))
    return true
}
