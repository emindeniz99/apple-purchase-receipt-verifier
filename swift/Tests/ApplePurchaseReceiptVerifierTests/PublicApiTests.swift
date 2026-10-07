import Foundation
import XCTest
// Deliberately NOT `@testable`: this file compiles against the module's
// PUBLIC surface only, so it is the pin on what the library exports. A
// declaration that loses `public` fails this file at compile time, before any
// assertion runs — which is the only way visibility can be pinned in Swift.
import ApplePurchaseReceiptVerifier

/// The 0.7 surface every port shares (docs/design/0.7-api.md), reached the
/// way a package consumer reaches it. The shared cases exercise the three
/// verify methods through a harness; what they cannot see is whether a
/// consumer outside the module can name each type, build a `Config`, build
/// payloads by hand for their own tests, and read the helpers.
final class PublicApiTests: XCTestCase {
    static var fixtures: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // ApplePurchaseReceiptVerifierTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // swift
            .deletingLastPathComponent()  // project root
            .appendingPathComponent("fixtures")
    }

    func fixture(_ path: String) throws -> [UInt8] {
        [UInt8](try Data(contentsOf: Self.fixtures.appendingPathComponent(path)))
    }

    /// Setup, the three methods and the result shape, from outside the
    /// module: a `Config` from its initializer with the caller's own roots
    /// and clock, one `Verifier`, and a result that carries exactly one of a
    /// payload and a failure.
    func testTheThreeMethodsAndTheirResultsFromOutsideTheModule() throws {
        let config = Config(roots: [try fixture("generated-0.7/receipt-root.der")], clock: { 1_735_689_600_000 })
        XCTAssertEqual(config.roots?.count, 1)
        let verifier = try Verifier(config: config)
        let base64 = Data(try fixture("generated-0.7/receipt.der")).base64EncodedString()

        let receipt: VerificationResult<ReceiptPayload> = verifier.verifyReceipt(base64: base64)
        XCTAssertTrue(receipt.verified)
        XCTAssertNil(receipt.failure)
        XCTAssertEqual(receipt.payload?.bundleId, "com.example.app")
        XCTAssertEqual(receipt.payload?.bundleIdBytes.map { Array($0.dropFirst(2)) }, Array("com.example.app".utf8))

        let signed: VerificationResult<JsonPayload> = verifier.verifySignedData(jws: "a.b")
        XCTAssertFalse(signed.verified)
        XCTAssertNil(signed.payload)
        let failure: Failure = try XCTUnwrap(signed.failure)
        XCTAssertEqual(failure.reason, .malformed)
        XCTAssertFalse(failure.message.isEmpty)
        let asError: any Error = failure
        XCTAssertTrue(asError is Failure, "Failure conforms to Error")

        let response: String = verifier.verifyReceiptEndpoint(
            environment: .production, requestJson: #"{"receipt-data":"\#(base64)"}"#)
        XCTAssertEqual(response, #"{"status":\#(AppleStatus.sandboxReceiptOnProduction)}"#)
    }

    /// A verifier with no roots would answer UNTRUSTED_CHAIN to everything
    /// and nobody would notice until production, so it is refused once, at
    /// startup, and a certificate the verification module does not accept is
    /// refused the same way. `Config` stores what it is given and the
    /// `Verifier` refuses it; the defaults never throw, and their roots are
    /// the module's built-in Apple roots, which `nil` names.
    func testVerifierRefusesMisconfigurationAtStartup() {
        XCTAssertThrowsError(try Verifier(config: Config(roots: []))) { XCTAssertTrue($0 is ConfigError) }
        XCTAssertThrowsError(try Verifier(config: Config(roots: [[0x30, 0x00]]))) { XCTAssertTrue($0 is ConfigError) }
        XCTAssertNoThrow(try Verifier(config: Config()))
        XCTAssertNil(Config().roots)
        XCTAssertNil(Config(roots: nil, clock: nil).roots)
        XCTAssertEqual(Config(roots: []).roots?.count, 0)
    }

    /// The closed set of reasons, in the design's spelling. Adding a value
    /// is a breaking change in all nine ports.
    func testReasonIsTheClosedSetOfEight() {
        XCTAssertEqual(
            Reason.allCases.map(\.rawValue),
            [
                "MALFORMED", "TOO_LARGE", "INVALID_SIGNATURE", "UNTRUSTED_CHAIN", "INVALID_CERTIFICATE",
                "INVALID_CERTIFICATE_PURPOSE", "UNREADABLE_PAYLOAD", "INTERNAL_ERROR",
            ])
    }

    /// The environment is the verifier's answer, on each payload
    /// (docs/rust-core/DECISIONS.md R42): `Environment` keeps Apple's two
    /// spellings and no helper repeating the rule. The 0.7 helpers
    /// `fromReceiptType` and `fromJwsEnvironment` are gone; a call to either
    /// no longer compiles.
    func testEnvironmentIsApplesTwoSpellingsAndThePayloadsCarryIt() {
        XCTAssertEqual(Environment.production.rawValue, "Production")
        XCTAssertEqual(Environment.sandbox.rawValue, "Sandbox")
        XCTAssertNil(Environment(rawValue: "Xcode"))
        XCTAssertNil(ReceiptPayload().environment)
        XCTAssertEqual(JsonPayload(json: "{}", environment: .sandbox).environment, .sandbox)
        XCTAssertNil(JsonPayload(json: "{}", environment: nil).environment)
    }

    /// Named constants for every status Apple documents, so a caller never
    /// writes 21007 by hand.
    func testAppleStatusNamesEveryDocumentedCode() {
        XCTAssertEqual(
            [
                AppleStatus.ok, AppleStatus.requestNotPost, AppleStatus.noLongerSent,
                AppleStatus.malformedReceiptData, AppleStatus.receiptNotAuthenticated,
                AppleStatus.sharedSecretMismatch, AppleStatus.serverUnavailable, AppleStatus.subscriptionExpired,
                AppleStatus.sandboxReceiptOnProduction, AppleStatus.productionReceiptOnSandbox,
                AppleStatus.internalDataAccessError, AppleStatus.accountNotFound,
                AppleStatus.internalDataAccessErrorRangeFirst, AppleStatus.internalDataAccessErrorRangeLast,
            ],
            [0, 21000, 21001, 21002, 21003, 21004, 21005, 21006, 21007, 21008, 21009, 21010, 21100, 21199])
    }

    /// release-please bumps `version.txt` and `Version.current` together;
    /// a startup log that reports a version other than the tag is worse than
    /// none.
    func testVersionIsTheRepositoryVersion() throws {
        let file = Self.fixtures.deletingLastPathComponent().appendingPathComponent("version.txt")
        let version = try String(contentsOf: file, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        XCTAssertEqual(Version.current, version)
    }

    /// Callers build payloads by hand to test their own logic, so every
    /// field is settable from outside and `toJson()` writes what was set.
    func testPayloadsCanBeBuiltByHand() throws {
        var purchase = InAppPurchase()
        purchase.quantity = 1
        purchase.productId = "p"
        purchase.transactionId = "t"
        purchase.purchaseDateMs = 1_000
        purchase.originalTransactionId = "o"
        purchase.originalPurchaseDateMs = 2_000
        purchase.expiresDateMs = 3_000
        purchase.webOrderLineItemId = 4
        purchase.cancellationDateMs = nil
        purchase.isTrialPeriod = false
        purchase.isInIntroOfferPeriod = true
        purchase.unknownAttributes = [1720: [[0x01]]]
        var receipt = ReceiptPayload()
        receipt.receiptType = "ProductionSandbox"
        receipt.appItemId = 5
        receipt.bundleId = "b"
        receipt.bundleIdBytes = [0x0C, 0x01, 0x62]
        receipt.applicationVersion = "1"
        receipt.opaqueValue = [0x01]
        receipt.sha1Hash = [0x02]
        receipt.receiptCreationDateMs = 6_000
        receipt.downloadId = 7
        receipt.versionExternalIdentifier = 8
        receipt.inApp = [purchase]
        receipt.originalPurchaseDateMs = 9_000
        receipt.preorderDateMs = 9_500
        receipt.originalApplicationVersion = "0"
        receipt.expirationDateMs = nil
        receipt.unknownAttributes = [13: [[0x03]]]
        // Not part of toJson(): the payload's own fields only.
        receipt.environment = .sandbox
        let want =
            #"{"receipt_type":"ProductionSandbox","app_item_id":"5","bundle_id":"b","bundle_id_bytes":"DAFi","#
            + #""application_version":"1","opaque_value":"AQ==","sha1_hash":"Ag==","receipt_creation_date_ms":6000,"#
            + #""download_id":"7","version_external_identifier":"8","in_app":[{"quantity":1,"product_id":"p","#
            + #""transaction_id":"t","purchase_date_ms":1000,"original_transaction_id":"o","#
            + #""original_purchase_date_ms":2000,"expires_date_ms":3000,"web_order_line_item_id":"4","#
            + #""cancellation_date_ms":null,"is_trial_period":false,"is_in_intro_offer_period":true,"#
            + #""unknown_attributes":{"1720":["AQ=="]}}],"original_purchase_date_ms":9000,"#
            + #""preorder_date_ms":9500,"original_application_version":"0","expiration_date_ms":null,"#
            + #""unknown_attributes":{"13":["Aw=="]}}"#
        // The same value, not the same bytes (docs/design/0.7-api.md "Our JSON").
        XCTAssertTrue(
            sameJsonValue(
                try JSONSerialization.jsonObject(with: Data(receipt.toJson().utf8)),
                try JSONSerialization.jsonObject(with: Data(want.utf8))),
            receipt.toJson())
        XCTAssertEqual(JsonPayload(json: "{}", environment: .production).json, "{}")
    }
}
