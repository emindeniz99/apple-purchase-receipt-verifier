import Foundation
import XCTest

@testable import ApplePurchaseReceiptVerifier

/// The response body is written by a small writer rather than by
/// `JSONSerialization` (ResponseJSON.swift says why: on Linux,
/// `JSONSerialization` cost ten times the verification for a large receipt).
/// The writer is only allowed because every byte matches, so it is compared
/// here with `JSONSerialization` on whichever Foundation the suite is built
/// against: CI proves it on Linux and on macOS separately.
final class ResponseJSONTests: XCTestCase {
    /// Every answer every receipt fixture gives, on both environments: the
    /// same inputs as `testBareReceiptDataAnswersLikeTheJsonBody`.
    func testWriterMatchesJSONSerializationOnEveryFixtureAnswer() async throws {
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
                    let response = try result.response(for: target)
                    XCTAssertNotNil(serializeResponseWithWriter(response), "the writer handed a fixture back")
                    XCTAssertEqual(serializeResponse(response), serializeResponseWithFoundation(response))
                }
                purchases += result.receipt?.inAppPurchases.count ?? 0
            }
        }
        // The legacy receipt alone carries 187 purchases per environment.
        XCTAssertGreaterThan(purchases, 2 * 187)
    }

    /// Strings the receipt carries (product ids, bundle ids, versions) are
    /// signed but chosen by whoever built the app, so every escaping rule is
    /// exercised: quotes, backslashes, the solidus, control characters, DEL,
    /// and non-ASCII scalars including U+2028 and one outside the BMP.
    func testWriterMatchesJSONSerializationOnGeneratedStrings() {
        var random = SplitMix64(seed: 0x15_0E5C)
        let alphabet: [Unicode.Scalar] =
            (0...0x7F).map { Unicode.Scalar(UInt8($0)) }
            + ["é", "\u{00A0}", "\u{0085}", "\u{2028}", "\u{2029}", "\u{FEFF}", "😀", "漢"]
        for _ in 0..<5_000 {
            var text = String.UnicodeScalarView()
            for _ in 0..<Int.random(in: 0..<24, using: &random) {
                // Mostly printable ASCII, so the writer's own path is taken.
                if Int.random(in: 0..<8, using: &random) == 0 {
                    text.append(alphabet.randomElement(using: &random)!)
                } else {
                    text.append(Unicode.Scalar(UInt8.random(in: 0x20...0x7E, using: &random)))
                }
            }
            let string = String(text)
            let response: [String: Any] = [
                "status": 0,
                "environment": string,
                "receipt": [
                    "bundle_id": string,
                    "download_id": Int64.random(in: Int64.min...Int64.max, using: &random),
                    "in_app": [["product_id": string, "quantity": "1"], [String: Any]()],
                ] as [String: Any],
            ]
            XCTAssertNotNil(serializeResponseWithWriter(response), string.debugDescription)
            XCTAssertEqual(
                serializeResponse(response), serializeResponseWithFoundation(response), string.debugDescription)
        }
    }

    /// A key or value the writer does not know sends the whole response to
    /// `JSONSerialization`, so the answer still matches.
    func testUnknownKeysAndValueTypesFallBack() {
        let responses: [[String: Any]] = [
            ["status": 0, "an_unknown_key": "x", "A": 1, "_": 2],
            ["status": 0, "receipt": ["bundle_id": 1.5] as [String: Any]],
            ["status": 0, "receipt": ["bundle_id": true] as [String: Any]],
            ["status": 0, "receipt": ["in_app": [NSNull()]] as [String: Any]],
        ]
        for response in responses {
            XCTAssertNil(serializeResponseWithWriter(response))
            XCTAssertEqual(serializeResponse(response), serializeResponseWithFoundation(response))
            XCTAssertNotNil(serializeResponse(response))
        }
    }
}
