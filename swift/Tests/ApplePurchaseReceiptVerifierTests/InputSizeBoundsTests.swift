import Foundation
import XCTest

@testable import ApplePurchaseReceiptVerifier

/// Base64 decoding and JSON parsing both allocate a multiple of their input
/// before any signature is checked, so an attacker who can send bytes can
/// make the verifier allocate in proportion to them. Each cap below is
/// pinned three ways: one unit over is refused, and refused before the
/// expensive step (the test says how it knows); exactly at the cap the cap
/// does not fire; and the exact answer a caller sees. The numbers are the
/// Java, PHP and Python ports', so a caller moving between ports sees the
/// same boundary.
final class InputSizeBoundsTests: XCTestCase {
    static let receiptCap = 2_097_152
    static let requestCap = 1_048_576
    static let jwsCap = 262_144
    static let receiptCapMessage = "receipt exceeds the maximum accepted size of 2097152 bytes"
    static let jwsCapMessage = "jws exceeds the maximum accepted size of 262144 bytes"
    static let depthMessage = "header/payload nests more than 64 levels deep"

    /// The numbers are part of the public contract: a caller sizing an HTTP
    /// body limit in front of this library reads them from here.
    func testCapsAreTheCrossPortNumbers() {
        XCTAssertEqual(ReceiptVerifier.maxReceiptBytes, Self.receiptCap)
        XCTAssertEqual(VerifyReceiptEndpoint.maxRequestBytes, Self.requestCap)
        XCTAssertEqual(JwsVerifier.maxJwsBytes, Self.jwsCap)
        XCTAssertEqual(VerifyReceiptEndpoint.maxJsonNestingDepth, 64)
        XCTAssertEqual(JwsVerifier.maxJsonNestingDepth, 64)
    }

    // MARK: - helpers

    func receiptVerifier() throws -> ReceiptVerifier {
        try ReceiptVerifier(
            trustedRoots: [try VerifyReceiptResultTests.generated("receipt-root.der")],
            bundleId: VerifierTests.bundle)
    }

    /// An endpoint whose verification primitive answers INVALID_SIGNATURE
    /// (21003) for anything it is handed. A 21003 therefore proves the input
    /// got past every cap and was decoded; any other answer proves it did
    /// not reach the primitive.
    func spyEndpoint() throws -> VerifyReceiptEndpoint {
        VerifyReceiptEndpoint(try VerifyReceiptResultTests.endpoint(.sandbox)) { _, _ in
            throw VerificationError(.invalidSignature, "reached the verification primitive")
        }
    }

    func thrown(_ body: () async throws -> Void) async -> VerificationError? {
        do {
            try await body()
            return nil
        } catch {
            return error as? VerificationError
        }
    }

    /// Valid base64 of `count` characters: all 'A', which decodes to zeros.
    /// Only the size decides whether it is refused before decoding.
    func base64(count: Int) -> String {
        precondition(count % 4 == 0)
        return String(repeating: "A", count: count)
    }

    /// A JSON request body of exactly `bytes` UTF-8 bytes whose receipt-data
    /// is valid base64, padded with whitespace, which JSON ignores.
    func body(bytes: Int) -> String {
        let head = #"{"receipt-data":"AAAA"}"#
        return head + String(repeating: " ", count: bytes - head.utf8.count)
    }

    func jwsVerifier() throws -> JwsVerifier {
        try JwsVerifier(
            trustedRoots: [try VerifyReceiptResultTests.generated("jws-root.der")],
            bundleId: VerifierTests.bundle, acceptedEnvironments: [.sandbox])
    }

    func nested(_ depth: Int) -> String {
        String(repeating: "[", count: depth) + String(repeating: "]", count: depth)
    }

    func base64URL(_ text: String) -> String {
        Data(text.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    // MARK: - receipt base64 string

    /// Over the cap the decode never runs: the answer is the cap's own
    /// message, where the same string decoded would have failed in the CMS
    /// parse with another one. Exactly at the cap it is decoded and reaches
    /// that parse.
    func testReceiptBase64OverTheCapIsRefusedBeforeDecoding() async throws {
        let verifier = try receiptVerifier()
        let over = await thrown { _ = try await verifier.verify(base64Receipt: self.base64(count: Self.receiptCap + 4)) }
        XCTAssertEqual(over?.reason, .invalidReceiptFormat)
        XCTAssertEqual(over?.message, Self.receiptCapMessage)

        let at = await thrown { _ = try await verifier.verify(base64Receipt: self.base64(count: Self.receiptCap)) }
        XCTAssertEqual(at?.reason, .invalidReceiptFormat, "zeros are not a CMS structure")
        XCTAssertNotEqual(at?.message, Self.receiptCapMessage, "the cap must not fire at the cap")
    }

    /// The unit is UTF-8 bytes, not characters: a string of fewer characters
    /// than the cap whose UTF-8 is longer is refused. No such string is
    /// base64, so this moves no verdict; it pins what is measured.
    func testReceiptBase64IsMeasuredInUTF8Bytes() async throws {
        let text = String(repeating: "é", count: Self.receiptCap / 2 + 1)
        XCTAssertLessThan(text.count, Self.receiptCap)
        let verifier = try receiptVerifier()
        let error = await thrown { _ = try await verifier.verify(base64Receipt: text) }
        XCTAssertEqual(error?.message, Self.receiptCapMessage)
    }

    /// At the endpoint the receipt-data is capped before decoding, on both
    /// entry points that carry it: over the cap the spy primitive is never
    /// reached (21002, not its 21003); at the cap it is.
    func testEndpointReceiptDataOverTheCapIsRefusedBeforeDecoding() async throws {
        let endpoint = try spyEndpoint()
        let over = base64(count: Self.receiptCap + 4)
        for result in [
            await endpoint.verifyReceiptData(over),
            await endpoint.verifyReceiptResult(["receipt-data": over]),
        ] {
            XCTAssertEqual(result.failureReason, .invalidReceiptFormat)
            XCTAssertEqual(result.status, 21002)
            XCTAssertEqual(result.json(), #"{"status":21002}"#)
        }

        let at = base64(count: Self.receiptCap)
        for result in [
            await endpoint.verifyReceiptData(at),
            await endpoint.verifyReceiptResult(["receipt-data": at]),
        ] {
            XCTAssertEqual(result.failureReason, .invalidSignature, "at the cap the receipt is decoded and verified")
            XCTAssertEqual(result.status, 21003)
        }
    }

    // MARK: - receipt DER

    /// Every DER entry point shares the cap, and over it the CMS parse never
    /// runs: the cap's message, where the same zeros parsed would have
    /// failed with another one.
    func testReceiptDEROverTheCapIsRefusedBeforeParsing() async throws {
        let verifier = try receiptVerifier()
        let roots = [try VerifyReceiptResultTests.generated("receipt-root.der")]
        let over = Data(count: Self.receiptCap + 1)
        let at = Data(count: Self.receiptCap)
        // Void closures: none of them hands an AppReceipt back by copy.
        let entryPoints: [(String, (Data) async throws -> Void)] = [
            ("verify(receipt:)", { _ = try await verifier.verify(receipt: $0) }),
            ("verifyCore(receipt:)", { _ = try await verifier.verifyCore(receipt: $0) }),
            ("static verifyCore", { _ = try await ReceiptVerifier.verifyCore(receipt: $0, trustedRoots: roots) }),
        ]
        for (label, entryPoint) in entryPoints {
            let overError = await thrown { try await entryPoint(over) }
            XCTAssertEqual(overError?.reason, .invalidReceiptFormat, label)
            XCTAssertEqual(overError?.message, Self.receiptCapMessage, label)

            let atError = await thrown { try await entryPoint(at) }
            XCTAssertEqual(atError?.reason, .invalidReceiptFormat, label)
            XCTAssertNotEqual(atError?.message, Self.receiptCapMessage, "\(label): the cap must not fire at the cap")
        }
    }

    // MARK: - request body

    /// Over the cap the body is never parsed: 21002 MALFORMED_REQUEST, where
    /// the same body parsed would have reached the spy primitive (21003).
    /// Exactly at the cap it is parsed and does reach it.
    func testRequestBodyOverTheCapIsRefusedBeforeParsing() async throws {
        let endpoint = try spyEndpoint()
        let over = await endpoint.verifyReceiptResult(body(bytes: Self.requestCap + 1))
        XCTAssertEqual(over.failureReason, .malformedRequest)
        XCTAssertEqual(over.status, 21002)
        XCTAssertEqual(over.json(), #"{"status":21002}"#)
        let wire = await endpoint.verifyReceiptJSON(body(bytes: Self.requestCap + 1))
        XCTAssertEqual(wire, #"{"status":21002}"#)

        let at = await endpoint.verifyReceiptResult(body(bytes: Self.requestCap))
        XCTAssertEqual(at.failureReason, .invalidSignature, "at the cap the body is parsed")
    }

    /// The body is measured in UTF-8 bytes: a body of fewer characters than
    /// the cap whose UTF-8 is longer is refused. Java and Python measure
    /// UTF-16 units or characters today and would parse this body; the unit
    /// is to be unified across ports later.
    func testRequestBodyIsMeasuredInUTF8Bytes() async throws {
        let text = #"{"receipt-data":"AAAA","pad":""# + String(repeating: "é", count: Self.requestCap / 2) + #""}"#
        XCTAssertLessThan(text.count, Self.requestCap)
        XCTAssertGreaterThan(text.utf8.count, Self.requestCap)
        let endpoint = try spyEndpoint()
        let result = await endpoint.verifyReceiptResult(text)
        XCTAssertEqual(result.failureReason, .malformedRequest)
    }

    // MARK: - request nesting depth

    /// 64 open containers (the object plus 63 arrays) are parsed and reach
    /// the spy primitive; 65 answer 21002 MALFORMED_REQUEST, which they
    /// could not if the parser had run, since the body is otherwise valid.
    func testRequestNestingPastSixtyFourIsRefusedBeforeParsing() async throws {
        let endpoint = try spyEndpoint()
        let at = await endpoint.verifyReceiptResult(#"{"receipt-data":"AAAA","x":"# + nested(63) + "}")
        XCTAssertEqual(at.failureReason, .invalidSignature, "depth 64 is parsed")

        let over = await endpoint.verifyReceiptResult(#"{"receipt-data":"AAAA","x":"# + nested(64) + "}")
        XCTAssertEqual(over.failureReason, .malformedRequest)
        XCTAssertEqual(over.status, 21002)
        XCTAssertEqual(over.json(), #"{"status":21002}"#)
    }

    /// Brackets inside a string are data. Counting them would refuse a
    /// legitimate body; an escaped quote must not end the string early and
    /// expose the brackets after it.
    func testBracketsInsideStringsAreNotNesting() async throws {
        let endpoint = try spyEndpoint()
        let brackets = String(repeating: "[{", count: 100)
        let plain = await endpoint.verifyReceiptResult(#"{"receipt-data":"AAAA","x":""# + brackets + #""}"#)
        XCTAssertEqual(plain.failureReason, .invalidSignature)
        let escaped = await endpoint.verifyReceiptResult(#"{"receipt-data":"AAAA","x":"\"\\"# + brackets + #""}"#)
        XCTAssertEqual(escaped.failureReason, .invalidSignature)
    }

    // MARK: - byte-floor receipt

    /// fixtures/cases.json requires every port to accept this 1 MiB-class
    /// receipt, so the receipt cap must sit above it on every verifier entry
    /// point. Its JSON body (about 1.38 MB of base64) is over the request
    /// cap, so the endpoint's JSON path answers 21002: that is the request
    /// cap working, and Java, PHP and Python answer the same.
    func testByteFloorReceiptVerifiesAndItsJSONBodyIsOverTheRequestCap() async throws {
        let der = try VerifyReceiptResultTests.generated("receipt-byte-floor.der")
        let root = try VerifyReceiptResultTests.generated("large-receipt-root.der")
        let base64 = der.base64EncodedString()
        XCTAssertLessThan(base64.utf8.count, Self.receiptCap)

        let verifier = try ReceiptVerifier(trustedRoots: [root], bundleId: VerifierTests.bundle)
        let fromDER = try await verifier.verify(receipt: der)
        let fromBase64 = try await verifier.verify(base64Receipt: base64)
        XCTAssertEqual(fromDER.inAppPurchases.count, 2300)
        XCTAssertEqual(fromBase64.inAppPurchases.count, 2300)

        let endpoint = try VerifyReceiptEndpoint(trustedRoots: [root], environment: .sandbox)
        let bare = await endpoint.verifyReceiptData(base64)
        let decoded = await endpoint.verifyReceiptResult(["receipt-data": base64])
        XCTAssertTrue(bare.isVerified)
        XCTAssertTrue(decoded.isVerified)

        let body = #"{"receipt-data":""# + base64 + #""}"#
        XCTAssertGreaterThan(body.utf8.count, Self.requestCap)
        let wire = await endpoint.verifyReceiptResult(body)
        XCTAssertEqual(wire.failureReason, .malformedRequest)
        XCTAssertEqual(wire.json(), #"{"status":21002}"#)
    }

    // MARK: - JWS

    /// Over the cap the input is never split: the cap's message, where the
    /// same dotless string split would have been refused for its segment
    /// count. Exactly at the cap it is split and refused for that. All three
    /// entry points share the check.
    func testJwsOverTheCapIsRefusedBeforeSplitting() async throws {
        let verifier = try jwsVerifier()
        let over = String(repeating: "A", count: Self.jwsCap + 1)
        let at = String(repeating: "A", count: Self.jwsCap)
        let entryPoints: [(String, (String) async throws -> Void)] = [
            ("verifyTransaction", { _ = try await verifier.verifyTransaction($0) }),
            ("verifyAppTransaction", { _ = try await verifier.verifyAppTransaction($0) }),
            ("verifyRaw", { _ = try await verifier.verifyRaw($0) }),
        ]
        for (label, entryPoint) in entryPoints {
            let overError = await thrown { try await entryPoint(over) }
            XCTAssertEqual(overError?.reason, .invalidJwsFormat, label)
            XCTAssertEqual(overError?.message, Self.jwsCapMessage, label)

            let atError = await thrown { try await entryPoint(at) }
            XCTAssertEqual(atError?.reason, .invalidJwsFormat, label)
            XCTAssertEqual(atError?.message, "expected 3 dot-separated segments, got 1", label)
        }
    }

    /// Depth 64 in the header is parsed (the answer is about its missing
    /// `alg`); depth 65 is refused before parsing. The payload is checked
    /// at the same point, before the header is even read: a deep payload is
    /// refused even behind a header that would have failed on its own.
    func testJwsJsonNestingPastSixtyFourIsRefusedBeforeParsing() async throws {
        let verifier = try jwsVerifier()
        func jws(header: String, payload: String) -> String {
            "\(base64URL(header)).\(base64URL(payload))."
        }
        let cases: [(String, String, String, String)] = [
            ("header at 64", #"{"x":"# + nested(63) + "}", "{}", "alg must be ES256"),
            ("header at 65", #"{"x":"# + nested(64) + "}", "{}", Self.depthMessage),
            ("payload at 64", "{}", #"{"x":"# + nested(63) + "}", "alg must be ES256"),
            ("payload at 65", "{}", #"{"x":"# + nested(64) + "}", Self.depthMessage),
        ]
        for (label, header, payload, message) in cases {
            let error = await thrown { _ = try await verifier.verifyRaw(jws(header: header, payload: payload)) }
            XCTAssertEqual(error?.reason, .invalidJwsFormat, label)
            XCTAssertEqual(error?.message, message, label)
        }
    }
}
