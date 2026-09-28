import Foundation
import XCTest

@testable import ApplePurchaseReceiptVerifier

/// 0.6's `VerifyReceiptResult` is gone: the endpoint now returns Apple's
/// response string, and `VerificationResult` carries exactly one of a
/// payload and a failure by construction. What that type promised a caller
/// still has to hold, and these pin the parts the shared cases cannot see:
/// the cause behind an unreadable payload, when the clock is read, and that
/// the endpoint is `verifyReceipt` plus a rendering and nothing else.
final class VerifyReceiptResultTests: XCTestCase {
    static let now: Int64 = 1_735_689_600_000  // 2025-01-01T00:00:00Z

    /// Apple signed content the library cannot read: UNREADABLE_PAYLOAD, and
    /// the parser's own error is the cause, so an operator can see why
    /// (docs/design/0.7-api.md, "`cause` carries the parser or provider
    /// exception"). The shared case `receipt/unreadable-payload-under-a-valid-signature`
    /// pins the reason; a vector cannot pin a cause.
    func testUnreadableSignedContentCarriesTheParsersErrorAsItsCause() throws {
        let verifier = try TestFixtures.verifier(roots: ["generated-0.7/api-receipt-root.der"], clock: Self.now)
        let result = verifier.verifyReceipt(
            base64: standardBase64Encode(try TestFixtures.bytes("generated-0.7/receipt-content-not-asn1.der")))
        let failure = try XCTUnwrap(result.failure)
        XCTAssertEqual(failure.reason, .unreadablePayload)
        XCTAssertTrue(failure.cause is PayloadError, "cause: \(String(describing: failure.cause))")
    }

    /// The clock answers "what time is it now?" in two places only: the
    /// chain check when the receipt or JWS carries no signing date, and
    /// `request_date` in the endpoint response (docs/design/0.7-api.md,
    /// "Clock"). A clock read anywhere else could move a verdict for a
    /// receipt that states its own date.
    func testTheClockIsReadOnlyForAMissingDateAndForRequestDate() throws {
        let clock = CountingClock(Self.now)
        func verifier(_ root: String) throws -> ApplePurchaseReceiptVerifier.Verifier {
            ApplePurchaseReceiptVerifier.Verifier(
                config: try Config.builder().roots([try TestFixtures.bytes(root)]).clock(clock.read).build())
        }
        let dated = standardBase64Encode(try TestFixtures.bytes(TestFixtures.receipt))
        let receipts = try verifier(TestFixtures.receiptRoot)

        XCTAssertTrue(receipts.verifyReceipt(base64: dated).verified)
        XCTAssertEqual(clock.reads, 0, "a dated receipt is judged at its own date")

        let response = receipts.verifyReceiptEndpoint(environment: .sandbox, requestJson: #"{"receipt-data":"\#(dated)"}"#)
        XCTAssertTrue(response.contains(#""request_date_ms":"1735689600000""#), response)
        XCTAssertEqual(clock.reads, 1, "request_date is read once")

        _ = receipts.verifyReceiptEndpoint(environment: .production, requestJson: #"{"receipt-data":"\#(dated)"}"#)
        XCTAssertEqual(clock.reads, 1, "a 21007 has no request_date to stamp")

        let dateless = standardBase64Encode(try TestFixtures.bytes("generated-0.7/receipt-no-creation-date.der"))
        XCTAssertTrue(try verifier("generated-0.7/divergence-receipt-root.der").verifyReceipt(base64: dateless).verified)
        XCTAssertEqual(clock.reads, 2, "a dateless receipt is judged at the clock")

        let jwsVerifier = try verifier(TestFixtures.jwsRoot)
        XCTAssertTrue(jwsVerifier.verifySignedData(jws: try TestFixtures.text(TestFixtures.jws)).verified)
        XCTAssertEqual(clock.reads, 2, "a JWS with a signedDate is judged at it")
    }

    /// The endpoint is `verifyReceipt` plus Apple's rendering: over every
    /// receipt in the repository — the generated 0.7 set, the genuine public
    /// receipts and the receipt-data encodings in generated/receipt-b64 —
    /// the status it answers is the one the design's table gives for what
    /// `verifyReceipt` decided on the same string, in both environments. A
    /// second path through the endpoint (a lenient decoder, a cap of its
    /// own) would show up here as a disagreement on some fixture.
    func testTheEndpointAnswersWhatVerifyReceiptDecided() throws {
        let files = FileManager.default
        let generated = TestFixtures.directory.appendingPathComponent("generated-0.7")
        var roots: [[UInt8]] = try ["AppleIncRootCertificate.cer", "AppleRootCA-G2.cer", "AppleRootCA-G3.cer"].map {
            try TestFixtures.bytes("../certs/\($0)")
        }
        var inputs: [(String, String)] = []
        for name in try files.contentsOfDirectory(atPath: generated.path).sorted() where name.hasSuffix(".der") {
            let bytes = try TestFixtures.bytes("generated-0.7/\(name)")
            if name.hasSuffix("-root.der") {
                // A root fixture that is deliberately not a certificate is
                // refused at startup, which is not what this test is about.
                if (try? Config.builder().roots([bytes])) != nil { roots.append(bytes) }
            } else {
                inputs.append((name, standardBase64Encode(bytes)))
            }
        }
        for directory in ["generated/receipt-b64", "public-receipts"] {
            for name in try files.contentsOfDirectory(
                atPath: TestFixtures.directory.appendingPathComponent(directory).path
            ).sorted() where name.hasSuffix(".txt") || name.hasSuffix(".b64") {
                inputs.append(
                    (
                        name,
                        try String(
                            contentsOf: TestFixtures.directory.appendingPathComponent("\(directory)/\(name)"), encoding: .utf8)
                    ))
            }
        }
        // Every source must contribute, or a moved directory would make this
        // test pass over nothing.
        for source in [".der", ".txt", ".b64"] {
            XCTAssertTrue(inputs.contains { $0.0.hasSuffix(source) }, "no \(source) receipt fixtures found")
        }

        let verifier = ApplePurchaseReceiptVerifier.Verifier(
            config: try Config.builder().roots(roots).clock { Self.now }.build())
        var statuses: Set<Int> = []
        for (name, receiptData) in inputs {
            let result = verifier.verifyReceipt(base64: receiptData)
            let body = jsonText(["receipt-data": receiptData])
            for environment in [Environment.production, .sandbox] {
                let want = Self.status(result, environment)
                let response = verifier.verifyReceiptEndpoint(environment: environment, requestJson: body)
                let got = (try JSONSerialization.jsonObject(with: Data(response.utf8)) as? [String: Any])?["status"]
                XCTAssertEqual(got as? Int, want, "\(name) on \(environment)")
                statuses.insert(want)
            }
        }
        // The comparison covers every answer the fixtures can give, not only
        // the easy one.
        XCTAssertEqual(statuses, [0, 21002, 21003, 21007, 21008, 21009])
    }

    /// The design's status table, written out here rather than borrowed from
    /// the endpoint it checks.
    private static func status(_ result: VerificationResult<ReceiptPayload>, _ environment: Environment) -> Int {
        if let payload = result.payload {
            let production = ["Production", "ProductionVPP"].contains(payload.receiptType ?? "")
            switch (environment, production) {
            case (.production, false): return 21007
            case (.sandbox, true): return 21008
            default: return 0
            }
        }
        switch result.failure!.reason {
        case .malformed, .tooLarge: return 21002
        case .invalidSignature, .untrustedChain, .invalidCertificate, .invalidCertificatePurpose: return 21003
        case .unreadablePayload, .internalError: return 21009
        }
    }
}

/// A clock that counts its reads.
private final class CountingClock: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    private let now: Int64

    init(_ now: Int64) { self.now = now }

    var reads: Int {
        lock.lock()
        defer { lock.unlock() }
        return count
    }

    var read: @Sendable () -> Int64 {
        { [self] in
            lock.lock()
            defer { lock.unlock() }
            count += 1
            return now
        }
    }
}
