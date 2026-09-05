import Foundation
import XCTest
// Deliberately NOT `@testable`: this file compiles against the module's
// PUBLIC surface only, so it is the pin on what the library exports. A
// declaration that loses `public` fails this file at compile time, before any
// assertion runs — which is the only way visibility can be pinned in Swift.
import ApplePurchaseReceiptVerifier

/// The parts of the public surface the four ports agreed on, exercised the way
/// a package consumer would reach them.
final class PublicApiTests: XCTestCase {
    static var generated: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // ApplePurchaseReceiptVerifierTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // swift
            .deletingLastPathComponent()  // project root
            .appendingPathComponent("fixtures")
            .appendingPathComponent("generated")
    }

    func fixture(_ name: String) throws -> Data {
        try Data(contentsOf: Self.generated.appendingPathComponent(name))
    }

    /// `verifyCore` is public, in both spellings, and both skip the bundle-id
    /// claim check — node and python export the same primitive as
    /// `verifyReceiptCore`, and the endpoint is built on it rather than on a
    /// ReceiptVerifier carrying a wildcard bundle id that nothing compares.
    func testVerifyCoreIsPublicAndSkipsTheBundleIdCheck() async throws {
        let roots = [try fixture("receipt-root.der")]
        let receipt = try fixture("receipt.der")

        // The static spelling: no bundle id anywhere in the call.
        let fromStatic = try await ReceiptVerifier.verifyCore(
            receipt: receipt,
            trustedRoots: roots)
        XCTAssertEqual("com.example.app", fromStatic.bundleId)

        // The instance spelling: the verifier's bundle id is deliberately one
        // the receipt does NOT carry, and verifyCore still returns the
        // receipt — the claim check belongs to verify(receipt:), not here.
        let verifier = try ReceiptVerifier(trustedRoots: roots, bundleId: "com.example.other")
        let fromInstance = try await verifier.verifyCore(receipt: receipt)
        XCTAssertEqual("com.example.app", fromInstance.bundleId)

        // Same receipt through verify(receipt:): now the claim check runs.
        do {
            _ = try await verifier.verify(receipt: receipt)
            XCTFail("expected WRONG_BUNDLE_ID")
        } catch let error as VerificationError {
            XCTAssertEqual(.wrongBundleId, error.reason, error.description)
        }
    }

    /// The endpoint takes the same typed `environment` node, python and
    /// fixtures/cases.json use.
    func testEndpointTakesATypedEnvironment() async throws {
        let roots = [try fixture("receipt-root.der")]
        let request = ["receipt-data": try fixture("receipt.der").base64EncodedString()]

        let sandbox = try VerifyReceiptEndpoint(trustedRoots: roots, environment: .sandbox)
        let onSandbox = await sandbox.verifyReceipt(request)
        XCTAssertEqual(0, onSandbox["status"] as? Int)
        XCTAssertEqual("Sandbox", onSandbox["environment"] as? String)

        let production = try VerifyReceiptEndpoint(trustedRoots: roots, environment: .production)
        let onProduction = await production.verifyReceipt(request)
        XCTAssertEqual(21007, onProduction["status"] as? Int)
    }

    /// Apple's verifyReceipt endpoint has only two environments to emulate.
    /// The other two ``AppleEnvironment`` cases are rejected rather than
    /// silently folded into one of them.
    func testEndpointRejectsAnEnvironmentItCannotEmulate() throws {
        let roots = [try fixture("receipt-root.der")]
        for environment: AppleEnvironment in [.xcode, .localTesting] {
            do {
                _ = try VerifyReceiptEndpoint(trustedRoots: roots, environment: environment)
                XCTFail("expected WRONG_ENVIRONMENT for \(environment.rawValue)")
            } catch let error as VerificationError {
                XCTAssertEqual(.wrongEnvironment, error.reason, error.description)
            }
        }
    }

    /// The boolean spelling still works and still means the same thing — the
    /// typed initializer was added beside it, not in place of it. Marked
    /// deprecated so calling the deprecated overload raises no warning here.
    @available(*, deprecated)
    func testDeprecatedBooleanEnvironmentStillDelegates() async throws {
        let roots = [try fixture("receipt-root.der")]
        let request = ["receipt-data": try fixture("receipt.der").base64EncodedString()]
        let now = Date(timeIntervalSince1970: 1_735_689_600)
        for production in [true, false] {
            let old = try VerifyReceiptEndpoint(
                trustedRoots: roots, production: production,
                clock: { now })
            let new = try VerifyReceiptEndpoint(
                trustedRoots: roots, environment: production ? .production : .sandbox,
                clock: { now })
            let fromOld = await old.verifyReceipt(request)
            let fromNew = await new.verifyReceipt(request)
            XCTAssertEqual(
                try json(fromOld), try json(fromNew),
                "production: \(production)")
        }
    }

    private func json(_ value: [String: Any]) throws -> String {
        String(
            decoding: try JSONSerialization.data(
                withJSONObject: value,
                options: [.sortedKeys]),
            as: UTF8.self)
    }
}
