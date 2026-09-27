import Foundation
import SwiftASN1
import XCTest
@testable import ApplePurchaseReceiptVerifier

// Places where this port and another had drifted apart. The nine
// implementations are one product, so each of these is a single answer all
// of them owe, and each test below is the pin that keeps this port on it
// where the shared cases in fixtures/cases-0.7.json do not reach.

// MARK: - receipt payload surgery

/// Splices a new payload into a genuine receipt. The fixtures are BER with
/// indefinite lengths from the CMS SEQUENCE down to the OCTET STRING that
/// holds the payload, so replacing that one primitive node needs no ancestor
/// length fixups. The CMS signature covers the payload, so a test about the
/// payload grammar re-signs the spliced payload under ``TestReceiptPki``,
/// since the full parse runs only after that check.
private enum ReceiptSurgery {
    static func children(_ node: ASN1Node) throws -> [ASN1Node] {
        guard case .constructed(let nodes) = node.content else { throw CocoaError(.formatting) }
        return Array(nodes)
    }

    static func primitive(_ node: ASN1Node) throws -> [UInt8] {
        guard case .primitive(let bytes) = node.content else { throw CocoaError(.formatting) }
        return [UInt8](bytes)
    }

    /// The attribute SET inside a receipt: contentInfo → [0] → SignedData →
    /// encapContentInfo → [0] → OCTET STRING (constructed in these BER
    /// fixtures, one primitive chunk inside).
    static func payload(of receipt: [UInt8]) throws -> [UInt8] {
        let contentInfo = try children(try BER.parse(receipt))
        let signedData = try children(try children(contentInfo[1])[0])
        let encap = try children(signedData[2])
        return try cmsOctetStringValue(try children(encap[1])[0])
    }

    /// The top-level attributes of an attribute SET, as encoded bytes.
    static func attributes(of set: [UInt8]) throws -> [[UInt8]] {
        try children(try DER.parse(set)).map { [UInt8]($0.encodedBytes) }
    }

    static func type(of attribute: [UInt8]) throws -> Int {
        try primitive(try children(try DER.parse(attribute))[0]).reduce(0) { $0 * 256 + Int($1) }
    }

    static func length(_ count: Int) -> [UInt8] {
        if count < 0x80 { return [UInt8(count)] }
        var bytes: [UInt8] = []
        var remaining = count
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }

    static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        [tag] + length(content.count) + content
    }

    static func set(_ attributes: [[UInt8]]) -> [UInt8] {
        tlv(0x31, attributes.flatMap { $0 })
    }

    /// One receipt attribute: SEQUENCE { INTEGER type, INTEGER 1, OCTET STRING }.
    /// The type is given as its raw INTEGER content bytes so a test can write
    /// a value no Int32 can hold.
    static func attribute(typeBytes: [UInt8], value: [UInt8]) -> [UInt8] {
        tlv(0x30, tlv(0x02, typeBytes) + tlv(0x02, [0x01]) + tlv(0x04, value))
    }

    /// The payload with one extra attribute inside its first in-app purchase
    /// (attribute 17), whose value is itself an attribute set.
    static func appendingInAppAttribute(_ attribute: [UInt8], to payload: [UInt8]) throws -> [UInt8] {
        var attributes = try attributes(of: payload)
        guard let index = try attributes.firstIndex(where: { try type(of: $0) == 17 }) else {
            throw CocoaError(.formatting)
        }
        let fields = try children(try DER.parse(attributes[index]))
        let inner = set(try Self.attributes(of: try primitive(fields[2])) + [attribute])
        attributes[index] = tlv(
            0x30, [UInt8](fields[0].encodedBytes) + [UInt8](fields[1].encodedBytes) + tlv(0x04, inner))
        return set(attributes)
    }
}

// MARK: - attribute types wider than a 32-bit signed integer

/// Java once mapped a receipt attribute type above 2^31-1 onto -1 and filed
/// the value under `unknownAttributes`; node rejected the receipt. The answer
/// is to refuse: `unknown_attributes` is keyed by a 32-bit type, and filing an
/// unrepresentable type under a representable one is how a parser starts
/// disagreeing with itself. The shared cases pin this for a top-level
/// attribute (`receipt/reject-attribute-type-above-int32-max`,
/// `receipt/attribute-type-int32-max-is-kept`); these pin it inside an in-app
/// purchase, where an attacker choosing where to hide the type must not find
/// a set that is parsed more leniently.
final class OversizedAttributeTypeTests: XCTestCase {
    static let outOfRange: [UInt8] = [0x00, 0x80, 0x00, 0x00, 0x00]  // 2^31
    static let largestInRange: [UInt8] = [0x7F, 0xFF, 0xFF, 0xFF]  // 2^31 - 1

    /// The genuine receipt's payload with `attribute` added to its first
    /// in-app purchase, signed under a test PKI, and the verdict of a
    /// verifier that trusts it.
    func verify(appendingInApp attribute: [UInt8]) throws -> VerificationResult<ReceiptPayload> {
        let payload = try ReceiptSurgery.appendingInAppAttribute(
            attribute, to: try ReceiptSurgery.payload(of: try TestFixtures.bytes(TestFixtures.receipt)))
        let pki = try TestReceiptPki()
        let receipt = try pki.sign(payload)
        let verifier = ApplePurchaseReceiptVerifier.Verifier(
            config: try Config.builder().roots([[UInt8](pki.rootDer)]).build())
        return verifier.verifyReceipt(base64: receipt.base64EncodedString())
    }

    /// 2^31 inside an in-app set: the in-app purchase does not parse, so the
    /// whole attribute 17 is kept raw and the receipt still verifies — the
    /// design's rule for an in-app purchase that does not parse
    /// (`receipt/unparseable-in-app-purchase-is-kept-raw`). 2^31-1 is
    /// representable: the purchase parses and keeps the attribute under its
    /// own type.
    func testAnOversizedTypeInsideAnInAppSetKeepsThePurchaseRaw() throws {
        let value = ReceiptSurgery.tlv(0x02, [0x2A])
        let oversized = try verify(
            appendingInApp: ReceiptSurgery.attribute(typeBytes: Self.outOfRange, value: value))
        let payload = try XCTUnwrap(oversized.payload, oversized.failure?.description ?? "")
        XCTAssertEqual(payload.inApp.count, 1, "the purchase carrying the oversized type is not typed")
        XCTAssertEqual(payload.unknownAttributes[17]?.count, 1, "and is kept raw instead")
        for purchase in payload.inApp {
            XCTAssertTrue(purchase.unknownAttributes.keys.allSatisfy { $0 >= 0 }, "no type was wrapped")
        }

        let representable = try verify(
            appendingInApp: ReceiptSurgery.attribute(typeBytes: Self.largestInRange, value: value))
        let kept = try XCTUnwrap(representable.payload, representable.failure?.description ?? "")
        XCTAssertEqual(kept.inApp.count, 2)
        XCTAssertNil(kept.unknownAttributes[17])
        XCTAssertEqual(kept.inApp.compactMap { $0.unknownAttributes[2_147_483_647] }.count, 1)
    }
}

// MARK: - no clock moves a verdict for a dated receipt

/// Certificate validity is judged at the receipt's own creation date when it
/// carries one; the clock stands in only when it does not
/// (`endpoint/clock-inside-the-window-verifies-a-dateless-receipt` pins that
/// side). A caller setting a clock to pin `request_date`, or to work around
/// skew, must not thereby move a verdict for a dated receipt. Both
/// expired-chain fixtures answer identically under every clock, including one
/// inside the certificates' 2020-2021 window.
final class CertificateValidityClockTests: XCTestCase {
    func testTheClockMovesNoVerdictForADatedReceipt() throws {
        let clocks: [Int64] = [
            0,  // 1970
            1_593_561_600_000,  // 2020-07-01, inside the expired chain's window
            1_735_689_600_000,  // 2025
            4_102_444_800_000,  // 2100
        ]
        for (fixture, expected) in [
            ("generated-0.7/receipt-expired-historical.der", 0),
            ("generated-0.7/receipt-expired-fresh.der", 21003),
        ] {
            let body = #"{"receipt-data":""# + standardBase64Encode(try TestFixtures.bytes(fixture)) + #""}"#
            for clock in clocks {
                let verifier = try TestFixtures.verifier(roots: ["generated-0.7/receipt-expired-root.der"], clock: clock)
                let response = verifier.verifyReceiptEndpoint(environment: .sandbox, requestJson: body)
                XCTAssertTrue(
                    response.hasPrefix(#"{"status":\#(expected)"#), "\(fixture) at clock \(clock): \(response.prefix(30))")
            }
        }
    }
}
