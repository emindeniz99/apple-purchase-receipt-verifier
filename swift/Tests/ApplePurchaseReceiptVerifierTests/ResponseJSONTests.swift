import Foundation
import XCTest

@testable import ApplePurchaseReceiptVerifier

/// The response body is written by `JSONEncoder` rather than by
/// `JSONSerialization` (`responseJSON` says why: on Linux,
/// `JSONSerialization` cost several times the verification for a large
/// receipt). That is only allowed because every byte matches, so it is
/// compared here with `JSONSerialization` on whichever Foundation the suite
/// is built against.
final class ResponseJSONTests: XCTestCase {
    /// Every answer every receipt fixture gives, on both environments.
    func testEncoderMatchesJSONSerializationOnEveryFixtureAnswer() async throws {
        let fixtures = VerifierTests.fixturesDir
        let generated = fixtures.appendingPathComponent("generated")
        let files = FileManager.default
        var roots: [Data] = appleReceiptRoots()
        var inputs: [String] = []
        for name in try files.contentsOfDirectory(atPath: generated.path).sorted()
        where name.hasPrefix("receipt") && name.hasSuffix(".der") {
            let data = try Data(contentsOf: generated.appendingPathComponent(name))
            if name.hasSuffix("-root.der") {
                roots.append(data)
            } else {
                inputs.append(data.base64EncodedString())
            }
        }
        let publicDir = fixtures.appendingPathComponent("public-receipts")
        for name in try files.contentsOfDirectory(atPath: publicDir.path).sorted() where name.hasSuffix(".b64") {
            inputs.append(try String(contentsOf: publicDir.appendingPathComponent(name), encoding: .utf8))
        }
        var purchases = 0
        for environment: AppleEnvironment in [.production, .sandbox] {
            let endpoint = try VerifyReceiptEndpoint(
                trustedRoots: roots, environment: environment,
                clock: { Date(timeIntervalSince1970: 1_735_689_600.25) })
            for receiptData in inputs {
                let result = await endpoint.verifyReceiptData(receiptData)
                for target: AppleEnvironment in [.production, .sandbox] {
                    assertMatchesJSONSerialization(try result.response(for: target))
                    XCTAssertEqual(try result.json(for: target), responseJSON(try result.response(for: target)))
                }
                purchases += result.receipt?.inAppPurchases.count ?? 0
            }
        }
        // The legacy receipt alone carries 187 purchases per environment.
        XCTAssertGreaterThan(purchases, 2 * 187)
    }

    /// No fixture sets every field, so a receipt that does is rendered here:
    /// every key the renderer can write is sorted by both writers. The
    /// strings in it are signed but chosen by whoever built the app, so
    /// every escaping rule is exercised: quotes, backslashes, the solidus,
    /// control characters, DEL, and non-ASCII scalars including U+2028 and
    /// one outside the BMP.
    func testEncoderMatchesJSONSerializationOnEveryFieldAndGeneratedStrings() throws {
        var random = SplitMix64(seed: 0x15_0E5C)
        let alphabet: [Unicode.Scalar] =
            (0...0x7F).map { Unicode.Scalar(UInt8($0)) }
            + ["é", "\u{00A0}", "\u{0085}", "\u{2028}", "\u{2029}", "\u{FEFF}", "😀", "漢"]
        for _ in 0..<1_000 {
            var text = String.UnicodeScalarView()
            for _ in 0..<Int.random(in: 0..<24, using: &random) {
                text.append(alphabet.randomElement(using: &random)!)
            }
            let string = String(text)
            let date = Date(timeIntervalSince1970: Double.random(in: 0...4e9, using: &random))
            let number = Int64.random(in: 0...Int64.max, using: &random)
            var purchase = InAppPurchase()
            purchase.quantity = number
            purchase.productId = string
            purchase.transactionId = string
            purchase.originalTransactionId = string
            purchase.purchaseDate = date
            purchase.originalPurchaseDate = date
            purchase.expiresDate = date
            purchase.cancellationDate = date
            purchase.webOrderLineItemId = number
            purchase.isTrialPeriod = 1
            purchase.isInIntroOfferPeriod = 0
            var receipt = AppReceipt()
            receipt.receiptType = string
            receipt.appItemId = number
            receipt.bundleId = string
            receipt.appVersion = string
            receipt.downloadId = number
            receipt.versionExternalIdentifier = number
            receipt.originalAppVersion = string
            receipt.creationDate = date
            receipt.originalPurchaseDate = date
            receipt.expirationDate = date
            receipt.inAppPurchases = [purchase, InAppPurchase()]
            let result = VerifyReceiptResult(
                environment: .sandbox, outcome: .verified(receipt), requestDate: date)
            assertMatchesJSONSerialization(try result.response(for: .sandbox))
        }
    }

    /// A key `JSONEncoder` would sort differently, or a value type
    /// ``ResponseValue`` does not hold, sends the whole response to
    /// `JSONSerialization`, so the answer still matches.
    func testOtherKeysAndValueTypesFallBack() {
        let responses: [[String: Any]] = [
            ["status": 0, "a_b": 1, "A": 1, "_": 2, "b": 3],
            ["status": 0, "a9": 1, "a_": 2],
            ["status": 0, "receipt": ["bundle_id": 1.5] as [String: Any]],
            ["status": 0, "receipt": ["bundle_id": true] as [String: Any]],
            ["status": 0, "receipt": ["in_app": [NSNull()]] as [String: Any]],
        ]
        for response in responses {
            XCTAssertNil(ResponseValue(response))
            XCTAssertEqual(responseJSON(response), foundationJSON(response))
        }
    }

    private func assertMatchesJSONSerialization(
        _ response: [String: Any], file: StaticString = #filePath, line: UInt = #line
    ) {
        XCTAssertNotNil(ResponseValue(response), "the answer fell back to JSONSerialization", file: file, line: line)
        XCTAssertEqual(responseJSON(response), foundationJSON(response), file: file, line: line)
    }

    private func foundationJSON(_ response: [String: Any]) -> String? {
        guard let data = try? JSONSerialization.data(withJSONObject: response, options: [.sortedKeys]) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }
}
