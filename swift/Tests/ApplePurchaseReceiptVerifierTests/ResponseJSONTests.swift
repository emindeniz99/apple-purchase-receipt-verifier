import Foundation
import XCTest

@testable import ApplePurchaseReceiptVerifier

/// `toJson()` has to produce the same bytes in nine ports, so its strings are
/// escaped exactly as ECMAScript `JSON.stringify` escapes them
/// (docs/design/0.7-api.md, "Canonical form"). Two shared vectors pin that
/// on fixed strings (`receipt/to-json-escapes`,
/// `receipt/to-json-escapes-html-and-separators`). The strings in a receipt
/// are signed but chosen by whoever built the app, so this runs the rule over
/// generated strings drawn from all of ASCII plus the non-ASCII scalars a
/// careless escaper gets wrong, in every string field, against an escaper
/// written here from the rule's own words.
final class ResponseJSONTests: XCTestCase {
    func testToJsonEscapesEveryStringFieldExactlyAsJSONStringify() throws {
        var random = SplitMix64(seed: 0x15_0E5C)
        let alphabet: [Unicode.Scalar] =
            (0...0x7F).map { Unicode.Scalar(UInt8($0)) }
            + ["é", "\u{00A0}", "\u{0085}", "\u{2028}", "\u{2029}", "\u{FEFF}", "😀", "漢"]
        for _ in 0..<1_000 {
            var fields: [String] = []
            for _ in 0..<7 {
                var text = String.UnicodeScalarView()
                for _ in 0..<Int.random(in: 0..<24, using: &random) {
                    text.append(alphabet.randomElement(using: &random)!)
                }
                fields.append(String(text))
            }
            var purchase = InAppPurchase()
            purchase.productId = fields[0]
            purchase.transactionId = fields[1]
            purchase.originalTransactionId = fields[2]
            var receipt = ReceiptPayload()
            receipt.receiptType = fields[3]
            receipt.bundleId = fields[4]
            receipt.applicationVersion = fields[5]
            receipt.originalApplicationVersion = fields[6]
            receipt.inApp = [purchase]
            let json = receipt.toJson()

            let pairs: [(String, String)] = [
                ("product_id", fields[0]), ("transaction_id", fields[1]), ("original_transaction_id", fields[2]),
                ("receipt_type", fields[3]), ("bundle_id", fields[4]), ("application_version", fields[5]),
                ("original_application_version", fields[6]),
            ]
            for (key, value) in pairs {
                // Compared as UTF-8 bytes: String.contains compares by
                // grapheme, which could match across an escaping difference.
                XCTAssertNotNil(
                    Data(json.utf8).range(of: Data(("\"\(key)\":" + Self.stringify(value)).utf8)),
                    "\(key) = \(value.debugDescription) is not escaped as JSON.stringify would: \(json)")
            }
            // And it is still JSON a strict reader takes back to the same
            // strings. JSONDecoder, not JSONSerialization: the latter drops a
            // leading U+FEFF from a string value on both platforms.
            let decoded = try JSONDecoder().decode(Shape.self, from: Data(json.utf8))
            XCTAssertEqual(
                [
                    decoded.in_app[0].product_id, decoded.in_app[0].transaction_id,
                    decoded.in_app[0].original_transaction_id, decoded.receipt_type, decoded.bundle_id,
                    decoded.application_version, decoded.original_application_version,
                ], fields)
        }
    }

    /// The rule, from its own words: `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`
    /// as short escapes, every other code point from U+0000 to U+001F as
    /// `\u00xx` in lowercase hex, and everything else raw.
    private static func stringify(_ value: String) -> String {
        let short: [UInt32: String] = [
            0x22: "\\\"", 0x5C: "\\\\", 0x08: "\\b", 0x0C: "\\f", 0x0A: "\\n", 0x0D: "\\r", 0x09: "\\t",
        ]
        let hex = Array("0123456789abcdef")
        var out = "\""
        for scalar in value.unicodeScalars {
            if let escape = short[scalar.value] {
                out += escape
            } else if scalar.value < 0x20 {
                out += "\\u00" + String(hex[Int(scalar.value >> 4)]) + String(hex[Int(scalar.value & 0xF)])
            } else {
                out.unicodeScalars.append(scalar)
            }
        }
        return out + "\""
    }

    private struct Shape: Decodable {
        struct Purchase: Decodable {
            let product_id: String
            let transaction_id: String
            let original_transaction_id: String
        }
        let receipt_type: String
        let bundle_id: String
        let application_version: String
        let original_application_version: String
        let in_app: [Purchase]
    }
}
