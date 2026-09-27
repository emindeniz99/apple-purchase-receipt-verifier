import Foundation
import XCTest

@testable import ApplePurchaseReceiptVerifier

/// Base64 decoding and JSON parsing both allocate a multiple of their input
/// before any signature is checked, so an attacker who can send bytes can
/// make the verifier allocate in proportion to them. The shared cases in
/// fixtures/cases-0.7.json pin each cap's boundary through the public
/// methods (`receipt-base64/accept-at-the-size-cap`,
/// `endpoint/request-body-one-byte-over-the-size-cap-answers-21002`,
/// `raw/reject-jws-one-byte-over-the-size-cap`, the nesting cases and the
/// rest). What they cannot pin is the part of the contract that is Swift
/// API rather than behaviour, and one reader detail no vector exercises.
final class InputSizeBoundsTests: XCTestCase {
    /// The numbers are part of the public contract: a caller sizing an HTTP
    /// body limit in front of this library reads them from here. The request
    /// and receipt caps are Apple's 3 MiB (measured 2026-09-23: a
    /// 3,145,728-byte body is answered, a 3,145,729-byte one gets HTTP 413),
    /// and no receipt Apple accepts can be larger than the body that carries
    /// it. The design's bounds table fixes every one of these across ports.
    func testCapsAreTheCrossPortNumbers() {
        XCTAssertEqual(maxReceiptBytes, 3_145_728)
        XCTAssertEqual(maxEndpointRequestBytes, 3_145_728)
        XCTAssertEqual(maxJwsBytes, 262_144)
        XCTAssertEqual(maxJsonNestingDepth, 64)
        XCTAssertEqual(maxJsonNameLength, 50_000)
        XCTAssertEqual(maxJsonNumberLength, 1000)
        XCTAssertEqual(maxEmbeddedCertificates, 10)
        XCTAssertEqual(maxSignerInfos, 4)
        XCTAssertEqual(maxPathLength, 6)
    }

    /// Brackets inside a string are data. A depth count that saw them would
    /// refuse a legitimate body, and an escaped quote must not end the string
    /// early and expose the brackets after it. The body carries a genuine
    /// receipt, so status 0 proves the body was read to the end and the
    /// receipt verified; the nesting cases in the shared suite use bare
    /// brackets only.
    func testBracketsInsideStringsAreNotNesting() throws {
        let verifier = try TestFixtures.verifier(roots: [TestFixtures.receiptRoot])
        let receipt = standardBase64Encode(try TestFixtures.bytes(TestFixtures.receipt))
        let brackets = String(repeating: "[{", count: 100)
        for padding in [brackets, #"\"\\"# + brackets] {
            let body = #"{"x":""# + padding + #"","receipt-data":""# + receipt + #""}"#
            let response = verifier.verifyReceiptEndpoint(environment: .sandbox, requestJson: body)
            XCTAssertTrue(response.hasPrefix(#"{"status":0,"#), String(response.prefix(40)))
        }
    }
}
