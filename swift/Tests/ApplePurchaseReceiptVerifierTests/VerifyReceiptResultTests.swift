import Foundation
import XCTest

@testable import ApplePurchaseReceiptVerifier

/// `VerifyReceiptResult` is what a caller decides on: whether to trust the
/// receipt, why it failed, and what to answer. Each test below pins one
/// promise the type makes to that caller, and says what goes wrong for them
/// if it breaks.
final class VerifyReceiptResultTests: XCTestCase {
    static let now = Date(timeIntervalSince1970: 1_735_689_600)  // 2025-01-01T00:00:00Z

    static func generated(_ name: String) throws -> Data {
        try Data(
            contentsOf: VerifierTests.fixturesDir.appendingPathComponent("generated")
                .appendingPathComponent(name))
    }

    static func endpoint(
        _ environment: AppleEnvironment, clock: (@Sendable () -> Date)? = nil
    ) throws -> VerifyReceiptEndpoint {
        try VerifyReceiptEndpoint(
            trustedRoots: [try generated("receipt-root.der")], environment: environment, clock: clock)
    }

    static func base64(_ name: String) throws -> String {
        try generated(name).base64EncodedString()
    }

    // MARK: - the outcome invariant

    /// A caller reads `receipt` when it is there and `failureReason` when it
    /// is not. If both could be set, or neither, a caller would either trust
    /// a receipt that failed or have no reason to log. `isVerified` must
    /// follow the receipt, not the status: 21007 and 21008 are verified
    /// receipts in the wrong environment, and a caller that retried only on
    /// `status == 0` would drop them.
    func testExactlyOneOfReceiptAndReasonForEveryStatus() async throws {
        let production = try Self.endpoint(.production)
        let sandbox = try Self.endpoint(.sandbox)
        let broken = VerifyReceiptEndpoint(sandbox) { _, _ in throw UnexpectedFailure() }
        let rows: [(String, VerifyReceiptResult, Int, Bool)] = [
            ("0", await sandbox.verifyReceiptData(try Self.base64("receipt.der")), 0, true),
            ("21007", await production.verifyReceiptData(try Self.base64("receipt.der")), 21007, true),
            ("21008", await sandbox.verifyReceiptData(try Self.base64("receipt-type-production.der")), 21008, true),
            ("21002 envelope", await sandbox.verifyReceiptResult("not json"), 21002, false),
            ("21002 base64", await sandbox.verifyReceiptData("not base64!"), 21002, false),
            ("21002 cms", await sandbox.verifyReceiptData(try Self.base64("receipt-empty-content.der")), 21002, false),
            ("21003", await sandbox.verifyReceiptData(try Self.base64("receipt-foreign.der")), 21003, false),
            ("21009", await broken.verifyReceiptData(try Self.base64("receipt.der")), 21009, false),
        ]
        for (label, result, status, verified) in rows {
            XCTAssertEqual(status, result.status, label)
            XCTAssertEqual(verified, result.isVerified, label)
            XCTAssertNotEqual(result.receipt == nil, result.failureReason == nil, "\(label): exactly one must be set")
            XCTAssertEqual(verified, result.receipt != nil, label)
            switch result.outcome {
            case .verified:
                XCTAssertTrue(verified, label)
            case .failed(let reason, let cause):
                XCTAssertFalse(verified, label)
                XCTAssertEqual(reason == .internalError, cause != nil, "\(label): a cause only for INTERNAL_ERROR")
            }
        }
    }

    /// The two new reasons name where the failure sits, so a caller can tell
    /// a broken client (envelope) from a broken receipt (base64 or CMS) from
    /// a library fault, even though the first two share status 21002.
    func testFailureReasonsNameWhereTheRequestFailed() async throws {
        let endpoint = try Self.endpoint(.sandbox)
        let cases: [(String, VerifyReceiptResult, VerificationError.Reason)] = [
            ("not json", await endpoint.verifyReceiptResult("not json"), .malformedRequest),
            ("array body", await endpoint.verifyReceiptResult("[]"), .malformedRequest),
            ("nil body", await endpoint.verifyReceiptResult(nil), .malformedRequest),
            ("no receipt-data", await endpoint.verifyReceiptResult([:]), .malformedRequest),
            ("number receipt-data", await endpoint.verifyReceiptResult(["receipt-data": 3]), .malformedRequest),
            ("empty receipt-data", await endpoint.verifyReceiptResult(["receipt-data": ""]), .malformedRequest),
            ("nil data", await endpoint.verifyReceiptData(nil), .malformedRequest),
            ("empty data", await endpoint.verifyReceiptData(""), .malformedRequest),
            ("whitespace data", await endpoint.verifyReceiptData(" \r\n"), .invalidReceiptFormat),
            ("bad base64", await endpoint.verifyReceiptData("AA==AA=="), .invalidReceiptFormat),
            ("not a receipt", await endpoint.verifyReceiptData("AQIDBA=="), .invalidReceiptFormat),
            ("foreign root", await endpoint.verifyReceiptData(try Self.base64("receipt-foreign.der")), .invalidChain),
        ]
        for (label, result, reason) in cases {
            XCTAssertEqual(reason, result.failureReason, label)
            XCTAssertNil(result.failureCause, label)
        }
    }

    /// An error the library did not anticipate must still produce an Apple
    /// answer, 21009, with the error kept for the caller's logs. A throw here
    /// would turn one bad receipt into a failed HTTP request. No input
    /// reaches this today, so the test swaps in a failing primitive.
    func testAnUnexpectedErrorBecomesInternalError() async throws {
        let broken = VerifyReceiptEndpoint(try Self.endpoint(.sandbox)) { _, _ in throw UnexpectedFailure() }
        let request = "{\"receipt-data\":\"\(try Self.base64("receipt.der"))\"}"
        let result = await broken.verifyReceiptResult(request)
        XCTAssertEqual(.internalError, result.failureReason)
        XCTAssertTrue(result.failureCause is UnexpectedFailure)
        XCTAssertEqual(21009, result.status)
        XCTAssertEqual("{\"status\":21009}", result.json())
        XCTAssertEqual("{\"status\":21009}", try result.json(for: .production))
        let json = await broken.verifyReceiptJSON(request)
        XCTAssertEqual("{\"status\":21009}", json)

        // A VerificationError from the same place is a verdict, not a fault.
        let rejecting = VerifyReceiptEndpoint(try Self.endpoint(.sandbox)) { _, _ in
            throw VerificationError(.invalidSignature, "test")
        }
        let rejected = await rejecting.verifyReceiptResult(request)
        XCTAssertEqual(.invalidSignature, rejected.failureReason)
        XCTAssertNil(rejected.failureCause)
        XCTAssertEqual(21003, rejected.status)
    }

    // MARK: - rendering for either environment

    /// The point of keeping the receipt on a 21007: the caller answers the
    /// sandbox retry from the same result instead of verifying twice. The
    /// status is recomputed from the receipt's own type every time, so a
    /// sandbox receipt can never be rendered as a production 0, whichever
    /// endpoint verified it.
    func testRendersForEitherEnvironmentFromTheReceiptsOwnType() async throws {
        let table: [(String, AppleEnvironment, [AppleEnvironment: Int])] = [
            ("receipt.der", .production, [.production: 21007, .sandbox: 0]),
            ("receipt.der", .sandbox, [.production: 21007, .sandbox: 0]),
            ("receipt-type-vpp-sandbox.der", .production, [.production: 21007, .sandbox: 0]),
            ("receipt-no-type.der", .sandbox, [.production: 21007, .sandbox: 0]),
            ("receipt-type-production.der", .production, [.production: 0, .sandbox: 21008]),
            ("receipt-type-production.der", .sandbox, [.production: 0, .sandbox: 21008]),
            ("receipt-type-vpp.der", .sandbox, [.production: 0, .sandbox: 21008]),
            ("receipt-foreign.der", .production, [.production: 21003, .sandbox: 21003]),
        ]
        for (fixture, verifiedOn, expected) in table {
            let endpoint = try Self.endpoint(verifiedOn)
            let result = await endpoint.verifyReceiptData(try Self.base64(fixture), now: Self.now)
            XCTAssertEqual(expected[verifiedOn], result.status, "\(fixture) on \(verifiedOn)")
            for (target, status) in expected {
                let label = "\(fixture) verified on \(verifiedOn), rendered for \(target)"
                let response = try result.response(for: target)
                XCTAssertEqual(status, response["status"] as? Int, label)
                if status == 0 {
                    XCTAssertEqual(target.rawValue, response["environment"] as? String, label)
                    XCTAssertNotNil(response["receipt"], label)
                } else {
                    XCTAssertEqual(["status"], Array(response.keys), label)
                }
                // What an endpoint of that environment answers for the same
                // request, byte for byte.
                let direct = await (try Self.endpoint(target)).verifyReceiptData(
                    try Self.base64(fixture), now: Self.now)
                XCTAssertEqual(direct.json(), try result.json(for: target), label)
            }
            XCTAssertEqual(result.json(), try result.json(for: verifiedOn), fixture)
        }
    }

    /// Apple's endpoint has two environments; asking for a third is refused
    /// the way the initializer refuses it, not silently folded into one.
    func testRefusesToRenderForAnEnvironmentItCannotEmulate() async throws {
        let result = await (try Self.endpoint(.sandbox)).verifyReceiptData(try Self.base64("receipt.der"))
        for environment: AppleEnvironment in [.xcode, .localTesting] {
            XCTAssertThrowsError(try result.response(for: environment)) {
                XCTAssertEqual(.wrongEnvironment, ($0 as? VerificationError)?.reason)
            }
            XCTAssertThrowsError(try result.json(for: environment)) {
                XCTAssertEqual(.wrongEnvironment, ($0 as? VerificationError)?.reason)
            }
        }
    }

    // MARK: - request_date

    /// An explicit time becomes request_date and the clock is not read at
    /// all. It must not reach anything else: the verified fields and the
    /// status are what the endpoint's own clock gives.
    func testAnExplicitTimeSetsRequestDateOnly() async throws {
        let clock = CountingClock()
        let endpoint = try Self.endpoint(.sandbox, clock: clock.read)
        let base64 = try Self.base64("receipt.der")
        let pinned = await endpoint.verifyReceiptData(base64, now: Self.now)
        XCTAssertEqual(0, clock.reads, "an explicit time must replace the clock, not add to it")
        XCTAssertEqual(Self.now, pinned.requestDate)
        let receipt = try XCTUnwrap(pinned.response()["receipt"] as? [String: Any])
        XCTAssertEqual("1735689600000", receipt["request_date_ms"] as? String)
        XCTAssertEqual("2025-01-01 00:00:00 Etc/GMT", receipt["request_date"] as? String)
        XCTAssertEqual("2024-12-31 16:00:00 America/Los_Angeles", receipt["request_date_pst"] as? String)

        let live = await endpoint.verifyReceiptData(base64)
        XCTAssertEqual(pinned.status, live.status)
        XCTAssertEqual(
            try withoutRequestDate(pinned.json()), try withoutRequestDate(live.json()),
            "a verified field moved with the request time")
    }

    /// Without an explicit time the clock is read exactly once per call, at
    /// the start, and every later render reuses that instant. A second read
    /// would let two renders of one result disagree about when the request
    /// was answered.
    func testTheClockIsReadOncePerCall() async throws {
        let base64 = try Self.base64("receipt.der")
        let calls: [(String, (VerifyReceiptEndpoint) async -> VerifyReceiptResult)] = [
            ("dictionary", { await $0.verifyReceiptResult(["receipt-data": base64]) }),
            ("json", { await $0.verifyReceiptResult("{\"receipt-data\":\"\(base64)\"}") }),
            ("data", { await $0.verifyReceiptData(base64) }),
            ("malformed json", { await $0.verifyReceiptResult("[]") }),
        ]
        for (label, call) in calls {
            let clock = CountingClock()
            let result = await call(try Self.endpoint(.sandbox, clock: clock.read))
            XCTAssertEqual(1, clock.reads, label)
            XCTAssertEqual(clock.first, result.requestDate, label)
            let first = result.json()
            XCTAssertEqual(first, result.json(), label)
            _ = try result.json(for: .production)
            XCTAssertEqual(1, clock.reads, "\(label): rendering read the clock")
        }
    }

    // MARK: - one path

    /// A bare receipt and the same receipt inside a request body are one
    /// request, so they must give one answer, byte for byte, over every
    /// receipt fixture in the repository: generated DER, the genuine public
    /// receipts, and the receipt-data encodings in generated/receipt-b64.
    func testBareReceiptDataAnswersLikeTheJsonBody() async throws {
        let fixtures = VerifierTests.fixturesDir
        let generated = fixtures.appendingPathComponent("generated")
        let files = FileManager.default
        var roots: [Data] = appleReceiptRoots()
        var inputs: [(String, String)] = []
        for name in try files.contentsOfDirectory(atPath: generated.path).sorted()
        where name.hasPrefix("receipt") && name.hasSuffix(".der") {
            let data = try Data(contentsOf: generated.appendingPathComponent(name))
            if name.hasSuffix("-root.der") {
                roots.append(data)
            } else if name.hasSuffix(".der") {
                inputs.append((name, data.base64EncodedString()))
            }
        }
        let b64Dir = generated.appendingPathComponent("receipt-b64")
        for name in try files.contentsOfDirectory(atPath: b64Dir.path).sorted() {
            let text = try String(contentsOf: b64Dir.appendingPathComponent(name), encoding: .utf8)
            inputs.append((name, text))
        }
        let publicDir = fixtures.appendingPathComponent("public-receipts")
        for name in try files.contentsOfDirectory(atPath: publicDir.path).sorted() where name.hasSuffix(".b64") {
            let text = try String(contentsOf: publicDir.appendingPathComponent(name), encoding: .utf8)
            inputs.append((name, text))
        }
        // Every source must contribute, or a moved directory would make this
        // test pass over nothing.
        for source in [".der", ".txt", ".b64"] {
            XCTAssertTrue(inputs.contains { $0.0.hasSuffix(source) }, "no \(source) receipt fixtures found")
        }

        var statuses: Set<Int> = []
        for environment: AppleEnvironment in [.production, .sandbox] {
            let endpoint = try VerifyReceiptEndpoint(
                trustedRoots: roots, environment: environment, clock: { Self.now })
            for (name, receiptData) in inputs {
                let body = String(
                    decoding: try JSONSerialization.data(withJSONObject: ["receipt-data": receiptData]),
                    as: UTF8.self)
                let bare = await endpoint.verifyReceiptData(receiptData).json()
                let viaBody = await endpoint.verifyReceiptJSON(body)
                if body.utf8.count > VerifyReceiptEndpoint.maxRequestBytes {
                    // The byte-floor receipt: its body is over the request
                    // cap, so the body is refused unparsed while the bare
                    // string is still verified. InputSizeBoundsTests pins it.
                    XCTAssertEqual(viaBody, #"{"status":21002}"#, "\(name) on \(environment)")
                    continue
                }
                XCTAssertEqual(viaBody, bare, "\(name) on \(environment)")
                let result = await endpoint.verifyReceiptResult(body)
                XCTAssertEqual(viaBody, result.json(), "\(name) on \(environment)")
                statuses.insert(result.status)
            }
        }
        // The comparison covers every answer the fixtures can give, not only
        // the easy one.
        XCTAssertEqual([0, 21002, 21003, 21007, 21008], statuses)
    }

    private func withoutRequestDate(_ json: String) throws -> String {
        var response = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        if var receipt = response["receipt"] as? [String: Any] {
            for key in ["request_date", "request_date_ms", "request_date_pst"] {
                receipt.removeValue(forKey: key)
            }
            response["receipt"] = receipt
        }
        return String(
            decoding: try JSONSerialization.data(withJSONObject: response, options: [.sortedKeys]),
            as: UTF8.self)
    }
}

private struct UnexpectedFailure: Error {}

/// A clock that counts its reads and moves one second per read, so a second
/// read would show up as a different `request_date`.
private final class CountingClock: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    let first = VerifyReceiptResultTests.now

    var reads: Int {
        lock.lock()
        defer { lock.unlock() }
        return count
    }

    var read: @Sendable () -> Date {
        { [self] in
            lock.lock()
            defer { lock.unlock() }
            count += 1
            return first.addingTimeInterval(Double(count - 1))
        }
    }
}
