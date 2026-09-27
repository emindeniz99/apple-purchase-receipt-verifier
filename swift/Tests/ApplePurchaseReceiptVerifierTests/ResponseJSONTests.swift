import Foundation
import XCTest

@testable import ApplePurchaseReceiptVerifier

/// `toJson()` must parse back to the value it was written from
/// (docs/design/0.7-api.md "Our JSON"); its escaping is Foundation's. Two
/// shared vectors pin that on fixed strings (`receipt/to-json-escapes`,
/// `receipt/to-json-escapes-html-and-separators`). The strings in a receipt
/// are signed but chosen by whoever built the app, so this runs generated
/// strings drawn from all of ASCII plus the non-ASCII scalars a careless
/// escaper gets wrong through every string field and reads them back.
final class ResponseJSONTests: XCTestCase {
    func testToJsonRoundTripsEveryStringField() throws {
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

            // JSONDecoder, not JSONSerialization: the latter drops a leading
            // U+FEFF from a string value on both platforms.
            let decoded = try JSONDecoder().decode(Shape.self, from: Data(json.utf8))
            XCTAssertEqual(
                [
                    decoded.in_app[0].product_id, decoded.in_app[0].transaction_id,
                    decoded.in_app[0].original_transaction_id, decoded.receipt_type, decoded.bundle_id,
                    decoded.application_version, decoded.original_application_version,
                ], fields)
        }
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
