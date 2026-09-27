import Foundation
import XCTest

@testable import ApplePurchaseReceiptVerifier

/// Base64 decoding and JSON parsing both allocate a multiple of their input
/// before any signature is checked, so an attacker who can send bytes can
/// make the verifier allocate in proportion to them. The shared cases in
/// fixtures/cases.json pin each cap's boundary through the public
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
        XCTAssertEqual(maxAsn1Depth, 32)
    }

    /// `depth` SEQUENCEs inside one another around one INTEGER, definite or
    /// BER-indefinite lengths.
    private func nestedSequences(_ depth: Int, indefinite: Bool = false) -> [UInt8] {
        var value: [UInt8] = [0x02, 0x01, 0x2A]
        for _ in 0..<depth {
            value = indefinite ? [0x30, 0x80] + value + [0x00, 0x00] : [0x30] + derLength(value.count) + value
        }
        return value
    }

    private func derLength(_ count: Int) -> [UInt8] {
        count < 0x80 ? [UInt8(count)] : [0x81, UInt8(count)]
    }

    /// The ASN.1 bound as the design counts it: 32 constructed values inside
    /// one another, the outermost included, pass; 33 do not; the primitive
    /// inside the innermost does not count; BER indefinite lengths, which
    /// receipt envelopes use, are followed. The shared cases pin 32 and 33
    /// through the envelope and the signed content; this pins the counting
    /// itself, and that the walk leaves an encoding it cannot follow to the
    /// parser rather than calling it too deep.
    func testTheAsn1DepthWalkCountsConstructedValuesOnly() {
        for indefinite in [false, true] {
            XCTAssertFalse(asn1DepthExceeded(nestedSequences(32, indefinite: indefinite)), "32, indefinite: \(indefinite)")
            XCTAssertTrue(asn1DepthExceeded(nestedSequences(33, indefinite: indefinite)), "33, indefinite: \(indefinite)")
        }
        // Siblings do not add depth.
        let wide: [UInt8] = [0x31, 0x0E] + nestedSequences(2) + nestedSequences(2)
        XCTAssertFalse(asn1DepthExceeded(wide))
        XCTAssertTrue(asn1DepthExceeded([0x31, 0x80] + nestedSequences(32) + [0x00, 0x00]), "33 with a sibling-free set on top")
        // Cut off after 20 of 40 levels: the lengths promise bytes that are
        // not there, so the walk cannot follow it and answers "not too
        // deep"; the parser that runs next refuses it.
        XCTAssertFalse(asn1DepthExceeded(Array(nestedSequences(40).prefix(40))))
        XCTAssertFalse(asn1DepthExceeded([]))
    }

    /// Past the bound, the signed content does not parse: the unverified
    /// creation-date read gives up (the clock stands in) and the full parse
    /// throws the error that becomes UNREADABLE_PAYLOAD's cause.
    func testSignedContentPastTheBoundDoesNotParse() {
        // SET { SEQUENCE { INTEGER 12, INTEGER 1, OCTET STRING } } inside
        // enough SETs to reach 33 levels.
        let attribute: [UInt8] = [0x30, 0x09, 0x02, 0x01, 0x0C, 0x02, 0x01, 0x01, 0x04, 0x01, 0x00]
        var content = attribute
        for _ in 0..<32 { content = [0x31] + derLength(content.count) + content }
        XCTAssertTrue(asn1DepthExceeded(content))
        XCTAssertNil(readCreationDate(content))
        XCTAssertThrowsError(try parseReceiptPayload(content)) { XCTAssertTrue($0 is PayloadError) }
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
            XCTAssertEqual(TestFixtures.status(response), 0, String(response.prefix(40)))
        }
    }
}
