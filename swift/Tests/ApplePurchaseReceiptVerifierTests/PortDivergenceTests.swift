import Foundation
import SwiftASN1
import XCTest
@testable import ApplePurchaseReceiptVerifier

// Places where this port and one of java/, node/, python/ had drifted apart.
// The four implementations are one product, so each of these is a single
// answer all four owe, and each test below is the pin that keeps this port on
// it. A test here failing means the ports have started to disagree again, not
// that a payload changed its mind.

// MARK: - receipt payload surgery

/// Splices a new payload into a genuine receipt. The fixtures are BER with
/// indefinite lengths from the CMS SEQUENCE down to the OCTET STRING that
/// holds the payload, so replacing that one primitive node needs no ancestor
/// length fixups — the same property the certificate-bag surgery in
/// VerifierTests relies on. The CMS signature covers a messageDigest over the
/// payload, so a spliced receipt cannot pass signature verification: what these
/// tests read is the verdict the parser reaches BEFORE that check, which is
/// where receipt-format decisions are made.
private enum ReceiptSurgery {
    static func children(_ node: ASN1Node) throws -> [ASN1Node] {
        guard case .constructed(let nodes) = node.content else { throw CocoaError(.formatting) }
        return Array(nodes)
    }

    static func primitive(_ node: ASN1Node) throws -> [UInt8] {
        guard case .primitive(let bytes) = node.content else { throw CocoaError(.formatting) }
        return [UInt8](bytes)
    }

    /// The primitive OCTET STRING carrying the receipt's attribute set:
    /// contentInfo → [0] → SignedData → encapContentInfo → [0] → OCTET STRING.
    static func payloadNode(_ receipt: [UInt8]) throws -> ASN1Node {
        let contentInfo = try children(try BER.parse(receipt))
        let signedData = try children(try children(contentInfo[1])[0])
        let encap = try children(signedData[2])
        return try children(try children(encap[1])[0])[0]
    }

    static func payload(of receipt: Data) throws -> [UInt8] {
        try primitive(try payloadNode([UInt8](receipt)))
    }

    static func replacingPayload(of receipt: Data, with payload: [UInt8]) throws -> Data {
        let bytes = [UInt8](receipt)
        let range = try payloadNode(bytes).encodedBytes
        var serializer = DER.Serializer()
        try serializer.serialize(ASN1OctetString(contentBytes: payload[...]))
        // Explicit Arrays: Swift 6.1 (the CI container) cannot type
        // ArraySlice + [UInt8] + ArraySlice, 6.3 can.
        return Data(
            Array(bytes[..<range.startIndex]) + serializer.serializedBytes
                + Array(bytes[range.endIndex...]))
    }

    // MARK: attribute-set assembly

    /// The top-level attributes of an attribute SET, as encoded bytes.
    static func attributes(of set: [UInt8]) throws -> [[UInt8]] {
        try children(try DER.parse(set)).map { [UInt8]($0.encodedBytes) }
    }

    static func type(of attribute: [UInt8]) throws -> Int {
        try primitive(try children(try DER.parse(attribute))[0])
            .reduce(0) { $0 * 256 + Int($1) }
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

    /// The same receipt with one extra attribute in its top-level set.
    static func appendingAttribute(_ attribute: [UInt8], to receipt: Data) throws -> Data {
        let attributes = try attributes(of: try payload(of: receipt))
        return try replacingPayload(of: receipt, with: set(attributes + [attribute]))
    }

    /// The same receipt with one extra attribute inside its first in-app
    /// purchase (attribute 17), whose value is itself an attribute set.
    static func appendingInAppAttribute(_ attribute: [UInt8], to receipt: Data) throws -> Data {
        var attributes = try attributes(of: try payload(of: receipt))
        guard let index = try attributes.firstIndex(where: { try type(of: $0) == 17 }) else {
            throw CocoaError(.formatting)
        }
        let fields = try children(try DER.parse(attributes[index]))
        let inner = set(try Self.attributes(of: try primitive(fields[2])) + [attribute])
        attributes[index] = tlv(
            0x30,
            [UInt8](fields[0].encodedBytes)
                + [UInt8](fields[1].encodedBytes) + tlv(0x04, inner))
        return try replacingPayload(of: receipt, with: set(attributes))
    }

    /// The same receipt with attribute `type` dropped from its top-level set.
    static func removingAttribute(_ type: Int, from receipt: Data) throws -> Data {
        let attributes = try attributes(of: try payload(of: receipt))
        let kept = try attributes.filter { try Self.type(of: $0) != type }
        guard kept.count < attributes.count else { throw CocoaError(.formatting) }
        return try replacingPayload(of: receipt, with: set(kept))
    }
}

// MARK: - divergence 4: attribute types wider than a 32-bit signed integer

/// Java mapped a receipt attribute type above 2^31-1 onto -1 and filed the
/// value under `unknownAttributes`; node rejected the receipt. The answer is
/// to reject: -1 is not a valid attribute type, and filing an unrepresentable
/// type under a representable one is how a parser starts disagreeing with
/// itself. No fixture pins this, so the inputs are built here.
final class OversizedAttributeTypeTests: XCTestCase {
    static let outOfRange: [UInt8] = [0x00, 0x80, 0x00, 0x00, 0x00]  // 2^31
    static let largestInRange: [UInt8] = [0x7F, 0xFF, 0xFF, 0xFF]  // 2^31 - 1

    func fixture(_ name: String) throws -> Data {
        try Data(
            contentsOf: VerifierTests.fixturesDir
                .appendingPathComponent("generated").appendingPathComponent(name))
    }

    func verifier() throws -> ReceiptVerifier {
        try ReceiptVerifier(
            trustedRoots: [try fixture("receipt-root.der")],
            bundleId: VerifierTests.bundle)
    }

    func reason<T>(_ body: () async throws -> T) async -> VerificationError.Reason? {
        do {
            _ = try await body()
            return nil
        } catch let error as VerificationError {
            return error.reason
        } catch {
            XCTFail("expected a VerificationError, got \(error)")
            return nil
        }
    }

    /// 2^31 is rejected as a receipt-format error, and 2^31-1 — the largest
    /// type that IS representable — is not. The control is what makes this a
    /// test of the bound rather than of splicing: both receipts carry a
    /// payload the messageDigest no longer covers, so the in-range one still
    /// fails, but it fails LATER and for the signature, which it can only
    /// reach by getting through the parser first.
    func testRejectsAnAttributeTypeAboveTheSignedThirtyTwoBitRange() async throws {
        let genuine = try fixture("receipt.der")
        let oversized = try ReceiptSurgery.appendingAttribute(
            ReceiptSurgery.attribute(typeBytes: Self.outOfRange, value: [0x2A]), to: genuine)
        let representable = try ReceiptSurgery.appendingAttribute(
            ReceiptSurgery.attribute(typeBytes: Self.largestInRange, value: [0x2A]), to: genuine)

        let verifier = try verifier()
        let onOversized = await reason { try await verifier.verify(receipt: oversized) }
        let onRepresentable = await reason { try await verifier.verify(receipt: representable) }
        XCTAssertEqual(.invalidReceiptFormat, onOversized)
        XCTAssertEqual(
            .invalidSignature, onRepresentable,
            "2^31-1 is representable and must reach the signature check")
    }

    /// In-app attribute sets go through the same parser, so the same bound
    /// applies there — an attacker choosing where to hide the type must not
    /// find a set that is parsed more leniently.
    func testRejectsAnOversizedTypeInsideAnInAppAttributeSet() async throws {
        let genuine = try fixture("receipt.der")
        let oversized = try ReceiptSurgery.appendingInAppAttribute(
            ReceiptSurgery.attribute(typeBytes: Self.outOfRange, value: [0x2A]), to: genuine)
        let representable = try ReceiptSurgery.appendingInAppAttribute(
            ReceiptSurgery.attribute(typeBytes: Self.largestInRange, value: [0x2A]), to: genuine)

        let verifier = try verifier()
        let onOversized = await reason { try await verifier.verify(receipt: oversized) }
        let onRepresentable = await reason { try await verifier.verify(receipt: representable) }
        XCTAssertEqual(.invalidReceiptFormat, onOversized)
        XCTAssertEqual(.invalidSignature, onRepresentable)
    }

    /// The bound is on the attribute TYPE only. Values keep their full 8-byte
    /// range — real receipts carry 7-byte `web_order_line_item_id` integers,
    /// and Apple has no stated ceiling under 2^63 — so a value far above
    /// 2^31-1 must still parse. It reaches the signature check, which is as
    /// far as a spliced receipt can get.
    func testTheBoundDoesNotReachAttributeValues() async throws {
        // Attribute 1711 (web_order_line_item_id), value 2^63-1: the widest
        // integer the parser accepts, and 2^32 times over the type's bound.
        let huge = ReceiptSurgery.attribute(
            typeBytes: [0x06, 0xAF],
            value: ReceiptSurgery.tlv(0x02, [0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]))
        let spliced = try ReceiptSurgery.appendingInAppAttribute(
            huge, to: try fixture("receipt.der"))
        let verdict = await reason { try await self.verifier().verify(receipt: spliced) }
        XCTAssertEqual(
            .invalidSignature, verdict,
            "the type bound must not reach attribute values")
    }

    /// Through the endpoint the same input is a malformed-receipt answer
    /// (21002), not an authentication failure (21003).
    func testTheEndpointReportsAnOversizedTypeAs21002() async throws {
        let endpoint = try VerifyReceiptEndpoint(
            trustedRoots: [try fixture("receipt-root.der")], environment: .sandbox)
        let oversized = try ReceiptSurgery.appendingAttribute(
            ReceiptSurgery.attribute(typeBytes: Self.outOfRange, value: [0x2A]),
            to: try fixture("receipt.der"))
        let response = await endpoint.verifyReceipt(
            ["receipt-data": oversized.base64EncodedString()])
        XCTAssertEqual(21002, response["status"] as? Int)
    }
}

// MARK: - divergence 1: no clock may move a certificate-validity verdict

/// Certificate validity is judged at the payload's signedDate or the receipt's
/// creation date, and — when the payload carries neither — at the SYSTEM
/// clock, never at an injected one. A caller injecting a clock to test
/// staleness, or to work around skew, must not thereby accept a chain that is
/// expired. This port already routed both fallbacks to the system clock and
/// never offered a clock on the receipt verifier at all; these tests are what
/// keeps that true.
final class CertificateValidityClockTests: XCTestCase {
    /// Decades either side of every fixture's certificate window, plus "no
    /// clock at all". If a clock could reach a validity decision, these three
    /// would not agree.
    static let clocks: [(@Sendable () -> Date)?] = [
        nil,
        { Date(timeIntervalSince1970: 0) },  // 1970
        { Date(timeIntervalSince1970: 4_102_444_800) },  // 2100
    ]

    func fixture(_ name: String) throws -> Data {
        try Data(
            contentsOf: VerifierTests.fixturesDir
                .appendingPathComponent("generated").appendingPathComponent(name))
    }

    func text(_ name: String) throws -> String {
        String(data: try fixture(name), encoding: .utf8)!
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func reason<T>(_ body: () async throws -> T) async -> VerificationError.Reason? {
        do {
            _ = try await body()
            return nil
        } catch let error as VerificationError {
            return error.reason
        } catch {
            XCTFail("expected a VerificationError, got \(error)")
            return nil
        }
    }

    /// A JWS payload carrying NO signedDate — the case the fallback exists
    /// for. fixtures/generated/transaction.jws is signed by a chain valid
    /// 2024-01-01 to 2050-01-01, so at the system clock the chain validates
    /// and the (re-encoded, no longer signed) payload fails on its signature.
    /// Had the fallback been the injected clock, the 1970 and 2100 runs would
    /// report INVALID_CHAIN instead — which is exactly the verdict a clock
    /// must not be able to move.
    func testAPayloadWithNoSignedDateIsJudgedAtTheSystemClock() async throws {
        let segments = try text("transaction.jws").components(separatedBy: ".")
        var claims =
            try JSONSerialization.jsonObject(
                with: base64URLDecode(segments[1])!) as! [String: Any]
        claims.removeValue(forKey: "signedDate")
        XCTAssertNil(claims["signedDate"])
        let dateless = try JSONSerialization.data(withJSONObject: claims)
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let jws = "\(segments[0]).\(dateless).\(segments[2])"

        for clock in Self.clocks {
            let verifier = try JwsVerifier(
                trustedRoots: [try fixture("jws-root.der")], bundleId: VerifierTests.bundle,
                acceptedEnvironments: [.sandbox], maxSignedAgeMillis: nil, clock: clock)
            let verdict = await self.reason { try await verifier.verifyTransaction(jws) }
            XCTAssertEqual(
                .invalidSignature, verdict,
                "the certificate-validity verdict moved with the clock")
        }
    }

    /// The receipt equivalent: attribute 12 (the creation date) removed, so
    /// the chain is judged at the fallback. Two fixtures pin which fallback it
    /// is, in opposite directions — the genuine receipt's chain is valid today
    /// (2024-2050), the expired one's is not (2020-2021) — so a fallback that
    /// was anything but the system clock fails one of them.
    func testAReceiptWithNoCreationDateIsJudgedAtTheSystemClock() async throws {
        let genuine = try ReceiptSurgery.removingAttribute(
            12, from: try fixture("receipt.der"))
        let liveVerifier = try ReceiptVerifier(
            trustedRoots: [try fixture("receipt-root.der")], bundleId: VerifierTests.bundle)
        let onGenuine = await reason { try await liveVerifier.verifyCore(receipt: genuine) }
        XCTAssertEqual(
            .invalidSignature, onGenuine,
            "a chain valid today must validate for a receipt with no date")

        let expired = try ReceiptSurgery.removingAttribute(
            12, from: try fixture("receipt-expired-historical.der"))
        let expiredVerifier = try ReceiptVerifier(
            trustedRoots: [try fixture("receipt-expired-root.der")],
            bundleId: VerifierTests.bundle)
        let onExpired = await reason { try await expiredVerifier.verifyCore(receipt: expired) }
        XCTAssertEqual(
            .invalidChain, onExpired,
            "a chain expired today must not validate for a receipt with no date")
    }

    /// The endpoint is the one receipt-path API that takes a clock (it stamps
    /// `request_date`). Both expired-chain fixtures answer identically under
    /// every clock, including one sitting inside the certificate's 2020-2021
    /// window — the clock reaches the response's timestamps and nothing else.
    func testTheEndpointClockMovesNoCertificateValidityVerdict() async throws {
        let insideTheWindow: @Sendable () -> Date = {
            Date(timeIntervalSince1970: 1_593_561_600)  // 2020-07-01
        }
        for (fixture, expected) in [
            ("receipt-expired-historical.der", 0),
            ("receipt-expired-fresh.der", 21003),
        ] {
            let request = ["receipt-data": try self.fixture(fixture).base64EncodedString()]
            for clock in Self.clocks + [insideTheWindow] {
                let endpoint = try VerifyReceiptEndpoint(
                    trustedRoots: [try self.fixture("receipt-expired-root.der")],
                    environment: .sandbox, clock: clock)
                let response = await endpoint.verifyReceipt(request)
                XCTAssertEqual(
                    expected, response["status"] as? Int,
                    "\(fixture): the status moved with the clock")
            }
        }
    }
}
