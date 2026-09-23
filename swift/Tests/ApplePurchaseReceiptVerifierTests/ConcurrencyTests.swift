import Foundation
import XCTest

@testable import ApplePurchaseReceiptVerifier

/// The README tells integrators to build one verifier of each kind and share
/// it across every request. Swift 6 language mode already turns a data race
/// on a shared value into a compile error, since every public type is
/// `Sendable`; this is the runtime half of that claim.
///
/// Sixteen child tasks run fifty iterations each through every entry point a
/// shared instance would serve, and every answer has to equal the answer a
/// single sequential call gets. What this is written to catch is not a
/// missing lock but state that is shared after all: a cached parser, a
/// reused buffer, an `@unchecked Sendable` that is not, or a result that one
/// task's verification writes into while another reads it.
final class ConcurrencyTests: XCTestCase {
    static let tasks = 16
    static let iterations = 50

    func testOneSharedInstanceOfEachVerifierServesManyTasksIdentically() async throws {
        let receiptRoot = try VerifyReceiptResultTests.generated("receipt-root.der")
        let receipts = try ReceiptVerifier(trustedRoots: [receiptRoot], bundleId: VerifierTests.bundle)
        // A fixed clock so the response is comparable: request_date is "now"
        // by design, and two calls a millisecond apart legitimately differ on
        // it. Nothing else in the response moves with time.
        let endpoint = try VerifyReceiptEndpoint(
            trustedRoots: [receiptRoot], environment: .sandbox, clock: { VerifyReceiptResultTests.now })
        let transactions = try JwsVerifier(
            trustedRoots: [try VerifyReceiptResultTests.generated("jws-root.der")],
            bundleId: VerifierTests.bundle, acceptedEnvironments: [.sandbox])

        let receiptBase64 = try VerifyReceiptResultTests.base64("receipt.der")
        let requestJSON = #"{"receipt-data":""# + receiptBase64 + #""}"#
        let jws = String(decoding: try VerifyReceiptResultTests.generated("transaction.jws"), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)

        // The sequential answers, taken first: the tasks are compared with
        // what the library says when nothing is racing, not merely with each
        // other.
        let expectedReceipt = Self.describe(try await receipts.verify(base64Receipt: receiptBase64))
        let expectedResponse = await endpoint.verifyReceiptResult(["receipt-data": receiptBase64]).json()
        let expectedJSON = await endpoint.verifyReceiptJSON(requestJSON)
        let expectedTransaction = try Self.describe(try await transactions.verifyTransaction(jws))
        XCTAssertTrue(expectedResponse.contains(#""status":0"#), "the sequential request did not verify")
        XCTAssertEqual(expectedJSON, expectedResponse, "the JSON body and the dictionary are one request")

        let mismatches = try await withThrowingTaskGroup(of: [String].self) { group in
            for task in 0..<Self.tasks {
                group.addTask {
                    var found: [String] = []
                    for n in 0..<Self.iterations {
                        let at = "task \(task), iteration \(n)"
                        if Self.describe(try await receipts.verify(base64Receipt: receiptBase64)) != expectedReceipt {
                            found.append("\(at): verify(base64Receipt:)")
                        }
                        if await endpoint.verifyReceiptResult(["receipt-data": receiptBase64]).json() != expectedResponse {
                            found.append("\(at): verifyReceiptResult(_: [String: Any])")
                        }
                        if await endpoint.verifyReceiptJSON(requestJSON) != expectedJSON {
                            found.append("\(at): verifyReceiptJSON")
                        }
                        if try Self.describe(try await transactions.verifyTransaction(jws)) != expectedTransaction {
                            found.append("\(at): verifyTransaction")
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
    /// task's parse. Dictionary keys are sorted so the text does not depend
    /// on hash order.
    static func describe(_ receipt: AppReceipt) -> String {
        let purchases = receipt.inAppPurchases.map {
            "\($0.productId ?? "-")/\($0.transactionId ?? "-")/\($0.purchaseDate?.timeIntervalSince1970 ?? -1)"
        }
        return [
            receipt.bundleId ?? "-", receipt.receiptType ?? "-", receipt.appVersion ?? "-",
            "\(receipt.creationDate?.timeIntervalSince1970 ?? -1)",
            receipt.sha1Hash?.base64EncodedString() ?? "-", receipt.opaqueValue?.base64EncodedString() ?? "-",
            receipt.unknownAttributes.keys.sorted().map(String.init).joined(separator: ","),
            purchases.joined(separator: ","),
        ].joined(separator: "|")
    }

    /// Every claim, encoded with sorted keys, so a field left unwritten by a
    /// racing decode shows up.
    static func describe(_ payload: TransactionPayload) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return String(decoding: try encoder.encode(payload), as: UTF8.self)
    }
}
