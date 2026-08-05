import Foundation
import XCTest
@testable import ApplePurchaseVerifier

/// Mirrors the Java/Node/Python test matrices over the shared fixture sets:
/// fixtures/generated/ (cross-language parity) and fixtures/apple-official/
/// (Apple's own library fixtures).
final class VerifierTests: XCTestCase {
    static let bundle = "com.example.app"
    static let appleBundle = "com.example"
    static let xcodeBundle = "com.example.naturelab.backyardbirds.example"

    static var fixturesDir: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // ApplePurchaseVerifierTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // swift
            .deletingLastPathComponent()  // apple-purchase-verification
            .appendingPathComponent("fixtures")
    }

    func fixture(_ segments: String...) throws -> Data {
        try Data(contentsOf: segments.reduce(Self.fixturesDir) {
            $0.appendingPathComponent($1)
        })
    }

    func text(_ segments: String...) throws -> String {
        String(data: try Data(contentsOf: segments.reduce(Self.fixturesDir) {
            $0.appendingPathComponent($1)
        }), encoding: .utf8)!.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func jwsVerifier(root: String = "jws-root.der",
                     bundleId: String = VerifierTests.bundle,
                     environments: Set<AppleEnvironment> = [.sandbox],
                     appAppleId: Int64? = nil,
                     maxSignedAgeMillis: Int64? = nil) throws -> JwsVerifier {
        try JwsVerifier(trustedRoots: [try fixture("generated", root)], bundleId: bundleId,
                        acceptedEnvironments: environments, appAppleId: appAppleId,
                        maxSignedAgeMillis: maxSignedAgeMillis)
    }

    func assertReason<T>(_ reason: VerificationError.Reason,
                         _ body: () async throws -> T) async {
        do {
            _ = try await body()
            XCTFail("expected \(reason.rawValue) but no error was thrown")
        } catch let error as VerificationError {
            XCTAssertEqual(error.reason, reason, error.description)
        } catch {
            XCTFail("expected VerificationError, got \(error)")
        }
    }

    // MARK: shared fixtures

    func testVerifiesSharedTransactionFixture() async throws {
        let payload = try await jwsVerifier().verifyTransaction(try text("generated", "transaction.jws"))
        XCTAssertEqual(payload.productId, "\(Self.bundle).pro")
        XCTAssertEqual(payload.transactionId, "2000000000000001")
        XCTAssertEqual(payload.signedDate, 1_722_945_600_000)
        XCTAssertTrue(payload.isActive(at: Date()))
    }

    func testVerifiesSharedAppTransactionFixture() async throws {
        let payload = try await jwsVerifier(appAppleId: 123_456_789)
            .verifyAppTransaction(try text("generated", "app-transaction.jws"))
        XCTAssertEqual(payload.appAppleId, 123_456_789)
        XCTAssertEqual(payload.applicationVersion, "1.2.3")
    }

    func testExpiredChainFixturesBehaveAsManifested() async throws {
        let verifier = try jwsVerifier(root: "jws-expired-root.der")
        let historical = try await verifier.verifyTransaction(
            try text("generated", "expired-cert-historical.jws"))
        XCTAssertEqual(historical.signedDate, 1_590_969_600_000)
        await assertReason(.invalidChain) {
            try await verifier.verifyTransaction(try self.text("generated", "expired-cert-fresh.jws"))
        }
    }

    func testVerifiesSharedReceiptFixtureWithDeviceHash() async throws {
        let verifier = try ReceiptVerifier(
            trustedRoots: [try fixture("generated", "receipt-root.der")], bundleId: Self.bundle)
        let guid = Data(hex: try text("generated", "device-guid.hex"))
        let receipt = try await verifier.verify(
            receipt: try fixture("generated", "receipt.der"), deviceGuid: guid)
        XCTAssertEqual(receipt.appVersion, "1.2.3")
        XCTAssertEqual(receipt.inAppPurchases.count, 2)
        let vip = receipt.inAppPurchases.first { $0.productId == "\(Self.bundle).vip" }
        XCTAssertEqual(vip?.webOrderLineItemId, 42)
        XCTAssertNotNil(vip?.expiresDate)
    }

    func testRejectsSharedForeignRootReceipt() async throws {
        let verifier = try ReceiptVerifier(
            trustedRoots: [try fixture("generated", "receipt-root.der")], bundleId: Self.bundle)
        await assertReason(.invalidChain) {
            try await verifier.verify(receipt: try self.fixture("generated", "receipt-foreign.der"))
        }
    }

    // MARK: Apple official fixtures

    func appleVerifier() throws -> JwsVerifier {
        try JwsVerifier(trustedRoots: [try fixture("apple-official", "certs", "testCA.der")],
                        bundleId: Self.appleBundle, acceptedEnvironments: [.sandbox])
    }

    func testVerifiesAppleTransactionInfoFixture() async throws {
        let payload = try await appleVerifier().verifyTransaction(
            try text("apple-official", "mock_signed_data", "transactionInfo"))
        XCTAssertEqual(payload.bundleId, Self.appleBundle)
        XCTAssertEqual(payload.environment, "Sandbox")
        XCTAssertEqual(payload.signedDate, 1_672_956_154_000)
    }

    func testVerifiesAppleRenewalInfoAndNotificationFixtures() async throws {
        let verifier = try appleVerifier()
        let renewal = try await verifier.verifyRaw(
            try text("apple-official", "mock_signed_data", "renewalInfo"))
        XCTAssertEqual(renewal["environment"] as? String, "Sandbox")
        let notification = try await verifier.verifyRaw(
            try text("apple-official", "mock_signed_data", "testNotification"))
        XCTAssertEqual(notification["notificationType"] as? String, "TEST")
    }

    func testRejectsAppleNegativeFixtures() async throws {
        let verifier = try appleVerifier()
        await assertReason(.wrongBundleId) {
            try await verifier.verifyTransaction(
                try self.text("apple-official", "mock_signed_data", "wrongBundleId"))
        }
        await assertReason(.invalidJwsFormat) {
            try await verifier.verifyTransaction(
                try self.text("apple-official", "mock_signed_data", "missingX5CHeaderClaim"))
        }
        await assertReason(.invalidJwsFormat) {
            try await verifier.verifyTransaction(
                try self.text("apple-official", "xcode", "xcode-signed-transaction"))
        }
    }

    func testRejectsXcodeReceiptAgainstRealAppleRoots() async throws {
        let verifier = try ReceiptVerifier(trustedRoots: appleReceiptRoots(),
                                           bundleId: Self.xcodeBundle)
        await assertReason(.invalidChain) {
            try await verifier.verify(
                base64Receipt: try self.text("apple-official", "xcode", "xcode-app-receipt-empty"))
        }
    }

    // MARK: negatives

    func testRejectsTamperedPayload() async throws {
        let segments = try text("generated", "transaction.jws").components(separatedBy: ".")
        var claims = try JSONSerialization.jsonObject(
            with: base64URLDecode(segments[1])!) as! [String: Any]
        claims["productId"] = "\(Self.bundle).premium_forever"
        let forged = try JSONSerialization.data(withJSONObject: claims)
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        await assertReason(.invalidSignature) {
            try await self.jwsVerifier().verifyTransaction(
                "\(segments[0]).\(forged).\(segments[2])")
        }
    }

    func testRejectsWrongBundleEnvironmentStalenessAndGarbage() async throws {
        let jws = try text("generated", "transaction.jws")
        await assertReason(.wrongBundleId) {
            try await self.jwsVerifier(bundleId: "com.other.app").verifyTransaction(jws)
        }
        await assertReason(.wrongEnvironment) {
            try await self.jwsVerifier(environments: [.production]).verifyTransaction(jws)
        }
        await assertReason(.stalePayload) {
            try await self.jwsVerifier(maxSignedAgeMillis: 60_000).verifyTransaction(jws)
        }
        await assertReason(.invalidJwsFormat) {
            try await self.jwsVerifier().verifyTransaction("not-a-jws")
        }
    }

    func testRejectsChainFromForeignRootAgainstRealAppleRoot() async throws {
        let pinned = try JwsVerifier(trustedRoots: appleJwsRoots(), bundleId: Self.bundle,
                                     acceptedEnvironments: [.sandbox])
        await assertReason(.invalidChain) {
            try await pinned.verifyTransaction(try self.text("generated", "transaction.jws"))
        }
    }

    func testVerifyRawSkipsClaimChecksButNotSignature() async throws {
        let claims = try await jwsVerifier(bundleId: "com.whatever.else")
            .verifyRaw(try text("generated", "transaction.jws"))
        XCTAssertEqual(claims["bundleId"] as? String, Self.bundle)
    }

    func testRejectsTamperedReceiptWrongGuidAndGarbage() async throws {
        let verifier = try ReceiptVerifier(
            trustedRoots: [try fixture("generated", "receipt-root.der")], bundleId: Self.bundle)
        var tampered = try fixture("generated", "receipt.der")
        let needle = Data(Self.bundle.utf8)
        let range = tampered.range(of: needle)!
        tampered[range.lowerBound] ^= 0x01
        await assertReason(.invalidSignature) {
            try await verifier.verify(receipt: tampered)
        }

        var guid = Data(hex: try text("generated", "device-guid.hex"))
        guid[0] ^= 0x01
        await assertReason(.deviceHashMismatch) {
            try await verifier.verify(receipt: try self.fixture("generated", "receipt.der"),
                                      deviceGuid: guid)
        }

        await assertReason(.invalidReceiptFormat) {
            try await verifier.verify(receipt: Data([1, 2, 3, 4]))
        }
    }

    func testBundledAppleRootsLoad() {
        XCTAssertFalse(appleJwsRoots()[0].isEmpty)
        XCTAssertFalse(appleReceiptRoots()[0].isEmpty)
    }
}

extension Data {
    init(hex: String) {
        var bytes: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            bytes.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        self.init(bytes)
    }
}

/// verifyReceipt-compat semantics over the shared receipt fixture.
final class VerifyReceiptEndpointTests: XCTestCase {
    func fixture(_ segments: String...) throws -> Data {
        try Data(contentsOf: segments.reduce(VerifierTests.fixturesDir) {
            $0.appendingPathComponent($1)
        })
    }

    func endpoint(production: Bool) throws -> VerifyReceiptEndpoint {
        try VerifyReceiptEndpoint(
            trustedRoots: [try fixture("generated", "receipt-root.der")],
            production: production)
    }

    func request() throws -> [String: Any] {
        ["receipt-data": try fixture("generated", "receipt.der").base64EncodedString()]
    }

    func testAnswersLikeVerifyReceiptForValidSandboxReceipt() async throws {
        let response = await (try endpoint(production: false)).verifyReceipt(try request())
        XCTAssertEqual(response["status"] as? Int, 0)
        XCTAssertEqual(response["environment"] as? String, "Sandbox")
        let receipt = response["receipt"] as! [String: Any]
        XCTAssertEqual(receipt["receipt_type"] as? String, "ProductionSandbox")
        XCTAssertEqual(receipt["bundle_id"] as? String, "com.example.app")
        XCTAssertEqual(receipt["receipt_creation_date"] as? String,
                       "2024-08-06 12:00:00 Etc/GMT")
        XCTAssertEqual(receipt["receipt_creation_date_ms"] as? String, "1722945600000")
        XCTAssertEqual(receipt["receipt_creation_date_pst"] as? String,
                       "2024-08-06 05:00:00 America/Los_Angeles")
        let inApp = receipt["in_app"] as! [[String: Any]]
        XCTAssertEqual(inApp.count, 2)
        XCTAssertEqual(inApp[0]["quantity"] as? String, "1")
        XCTAssertEqual(inApp[0]["web_order_line_item_id"] as? String, "42")
    }

    func testRoutesSandboxReceiptOnProductionTo21007() async throws {
        let response = await (try endpoint(production: true)).verifyReceipt(try request())
        XCTAssertEqual(response["status"] as? Int, 21007)
    }

    func testReportsMalformedRequestsAs21002() async throws {
        let endpoint = try endpoint(production: false)
        let empty = await endpoint.verifyReceipt([:])
        XCTAssertEqual(empty["status"] as? Int, 21002)
        let garbage = await endpoint.verifyReceipt(["receipt-data": "AQIDBA=="])
        XCTAssertEqual(garbage["status"] as? Int, 21002)
    }

    func testReportsUnauthenticReceiptsAs21003() async throws {
        let foreign = try self.fixture("generated", "receipt-foreign.der")
        let response = await (try endpoint(production: false))
            .verifyReceipt(["receipt-data": foreign.base64EncodedString()])
        XCTAssertEqual(response["status"] as? Int, 21003)
    }
}
