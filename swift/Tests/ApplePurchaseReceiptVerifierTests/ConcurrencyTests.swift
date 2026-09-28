import Crypto
import Foundation
import XCTest

@testable import ApplePurchaseReceiptVerifier

/// The README tells integrators to build one `Verifier` and share it across
/// every request. `Verifier`, `Config`, `VerificationResult`, `ReceiptPayload`
/// and `JsonPayload` are all `Sendable`, so Swift 6 language mode already
/// turns a data race on a shared value into a compile error; this is the
/// runtime half of that claim.
///
/// Sixteen child tasks run fifty iterations each through every entry point a
/// shared `Verifier` would serve, and every answer has to equal the answer a
/// single sequential call gets. What this is written to catch is not a
/// missing lock but state that is shared after all: a cached parser, a
/// reused buffer, or a result that one task's verification writes into while
/// another reads it.
final class ConcurrencyTests: XCTestCase {
    static let tasks = 16
    static let iterations = 50

    private static func fixtureURL(_ path: String) -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("fixtures")
            .appendingPathComponent(path)
    }

    private static func der(_ path: String) throws -> [UInt8] {
        [UInt8](try Data(contentsOf: fixtureURL(path)))
    }

    private static func trimmedText(_ path: String) throws -> String {
        String(decoding: try Data(contentsOf: fixtureURL(path)), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func testOneSharedVerifierServesManyTasksIdentically() async throws {
        let receiptRoot = try Self.der("generated-0.7/receipt-root.der")
        let jwsRoot = try Self.der("generated/jws-root.der")
        // A fixed clock so the response is comparable: request_date is "now"
        // by design, and two calls a millisecond apart legitimately differ
        // on it. Nothing else in the response moves with time.
        let fixedNow: Int64 = 1_735_689_600_000  // 2025-01-01T00:00:00Z
        let receiptConfig = try Config.builder().roots([receiptRoot]).clock { fixedNow }.build()
        let jwsConfig = try Config.builder().roots([jwsRoot]).clock { fixedNow }.build()
        let receiptVerifier = Verifier(config: receiptConfig)
        let endpointVerifier = Verifier(config: receiptConfig)
        let jwsVerifier = Verifier(config: jwsConfig)

        let receiptBase64 = standardBase64Encode(try Self.der("generated-0.7/receipt.der"))
        let requestJSON = #"{"receipt-data":""# + receiptBase64 + #""}"#
        let jws = try Self.trimmedText("generated/transaction.jws")

        // The sequential answers, taken first: the tasks are compared with
        // what the library says when nothing is racing, not merely with
        // each other.
        let expectedReceipt = Self.describe(receiptVerifier.verifyReceipt(base64: receiptBase64))
        let expectedResponse = endpointVerifier.verifyReceiptEndpoint(environment: .sandbox, requestJson: requestJSON)
        let expectedTransaction = Self.describe(jwsVerifier.verifySignedData(jws: jws))
        XCTAssertTrue(expectedResponse.contains(#""status":0"#), "the sequential request did not verify")

        let mismatches = try await withThrowingTaskGroup(of: [String].self) { group in
            for task in 0..<Self.tasks {
                group.addTask {
                    var found: [String] = []
                    for n in 0..<Self.iterations {
                        let at = "task \(task), iteration \(n)"
                        if Self.describe(receiptVerifier.verifyReceipt(base64: receiptBase64)) != expectedReceipt {
                            found.append("\(at): verifyReceipt")
                        }
                        if endpointVerifier.verifyReceiptEndpoint(environment: .sandbox, requestJson: requestJSON)
                            != expectedResponse
                        {
                            found.append("\(at): verifyReceiptEndpoint")
                        }
                        if Self.describe(jwsVerifier.verifySignedData(jws: jws)) != expectedTransaction {
                            found.append("\(at): verifySignedData")
                        }
                    }
                    return found
                }
            }
            return try await group.reduce(into: []) { $0 += $1 }
        }
        XCTAssertEqual(mismatches, [], "concurrent answers differ from the sequential ones")
    }

    /// Enough of a verified receipt to notice a claim read from another
    /// task's parse.
    static func describe(_ result: VerificationResult<ReceiptPayload>) -> String {
        guard let receipt = result.payload else { return "FAILED:\(result.failure?.reason.rawValue ?? "?")" }
        return receipt.toJson()
    }

    static func describe(_ result: VerificationResult<JsonPayload>) -> String {
        guard let payload = result.payload else { return "FAILED:\(result.failure?.reason.rawValue ?? "?")" }
        return payload.json
    }
}
