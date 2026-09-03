import Crypto
import Foundation
import SwiftASN1
import X509
import XCTest
@testable import ApplePurchaseReceiptVerifier

/// Behaviour over the shared fixture sets that fixtures/cases.json does not
/// pin: the tampering negatives, the clock seam itself, and the bundled Apple
/// roots.
final class VerifierTests: XCTestCase {
    static let bundle = "com.example.app"

    static var fixturesDir: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // ApplePurchaseReceiptVerifierTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // swift
            .deletingLastPathComponent()  // project root
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
                     maxSignedAgeMillis: Int64? = nil,
                     clock: (@Sendable () -> Date)? = nil) throws -> JwsVerifier {
        try JwsVerifier(trustedRoots: [try fixture("generated", root)], bundleId: bundleId,
                        acceptedEnvironments: environments, appAppleId: appAppleId,
                        maxSignedAgeMillis: maxSignedAgeMillis,
                        clock: clock)
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
        XCTAssertTrue(payload.isActive(at: Date()))
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

    func testRejectsStalePayloadAndGarbage() async throws {
        let jws = try text("generated", "transaction.jws")
        await assertReason(.stalePayload) {
            try await self.jwsVerifier(maxSignedAgeMillis: 60_000).verifyTransaction(jws)
        }
        await assertReason(.invalidJwsFormat) {
            try await self.jwsVerifier().verifyTransaction("not-a-jws")
        }
    }

    func testRejectsTamperedReceiptAndGarbage() async throws {
        let verifier = try ReceiptVerifier(
            trustedRoots: [try fixture("generated", "receipt-root.der")], bundleId: Self.bundle)
        var tampered = try fixture("generated", "receipt.der")
        let needle = Data(Self.bundle.utf8)
        let range = tampered.range(of: needle)!
        tampered[range.lowerBound] ^= 0x01
        await assertReason(.invalidSignature) {
            try await verifier.verify(receipt: tampered)
        }

        await assertReason(.invalidReceiptFormat) {
            try await verifier.verify(receipt: Data([1, 2, 3, 4]))
        }
    }

    // MARK: the clock seam

    /// fixtures/generated/transaction.jws is signed at this instant, and both
    /// expired-chain fixtures below sign at a fixed instant too — every
    /// expectation in this section is arithmetic on those, not on "now".
    static let transactionSignedAt = Date(timeIntervalSince1970: 1_722_945_600)

    func testOmittedClockReadsTheSystemClock() async throws {
        let jws = try text("generated", "transaction.jws")
        // No clock supplied: the age is measured against the real now, so a
        // max age well under the fixture's real age rejects and one well over
        // it accepts. Both bounds are derived from the system clock at run
        // time — an implementation that had quietly frozen "now" would fail
        // one of them.
        let realAgeMillis = Int64(Date().timeIntervalSince(Self.transactionSignedAt) * 1000)
        XCTAssertGreaterThan(realAgeMillis, 0, "the fixture is signed in the past")
        await assertReason(.stalePayload) {
            try await self.jwsVerifier(maxSignedAgeMillis: realAgeMillis / 2)
                .verifyTransaction(jws)
        }
        _ = try await jwsVerifier(maxSignedAgeMillis: realAgeMillis * 2).verifyTransaction(jws)
    }

    func testInjectedClockMovesTheStalenessVerdictDeterministically() async throws {
        let jws = try text("generated", "transaction.jws")
        let signedAt = Self.transactionSignedAt
        // 30 s after signing, under a 60 s max age: accepted.
        let fresh = try await jwsVerifier(
            maxSignedAgeMillis: 60_000,
            clock: { signedAt.addingTimeInterval(30) }).verifyTransaction(jws)
        XCTAssertEqual(Self.bundle, fresh.bundleId)
        // 61 s after signing, same policy: stale. Nothing but the clock moved.
        await assertReason(.stalePayload) {
            try await self.jwsVerifier(
                maxSignedAgeMillis: 60_000,
                clock: { signedAt.addingTimeInterval(61) }).verifyTransaction(jws)
        }
        // The instant fixtures/cases.json pins for transaction/reject-stale-payload.
        await assertReason(.stalePayload) {
            try await self.jwsVerifier(
                maxSignedAgeMillis: 60_000,
                clock: { Date(timeIntervalSince1970: 1_735_689_600) }).verifyTransaction(jws)
        }
    }

    func testInjectedClockDoesNotMoveCertificateValidityVerdicts() async throws {
        // Chain validity is judged at the payload's signedDate (PLAN.md 2.1
        // step 4). Both verdicts must therefore be identical under a clock
        // decades before and decades after the certificate's window, and
        // identical again with no clock at all.
        let historical = try text("generated", "expired-cert-historical.jws")
        let freshPayload = try text("generated", "expired-cert-fresh.jws")
        let clocks: [(@Sendable () -> Date)?] = [
            nil,
            { Date(timeIntervalSince1970: 0) },              // 1970
            { Date(timeIntervalSince1970: 4_102_444_800) },  // 2100
        ]
        for clock in clocks {
            let payload = try await jwsVerifier(root: "jws-expired-root.der", clock: clock)
                .verifyTransaction(historical)
            XCTAssertEqual(1_590_969_600_000, payload.signedDate)
            await assertReason(.invalidChain) {
                try await self.jwsVerifier(root: "jws-expired-root.der", clock: clock)
                    .verifyTransaction(freshPayload)
            }
        }
    }

    func testBundledAppleRootsAreAllThreePublishedRoots() {
        // Both sets carry all three published Apple roots (PLAN D15).
        for roots in [appleJwsRoots(), appleReceiptRoots()] {
            XCTAssertEqual(3, roots.count)
            for root in roots {
                XCTAssertFalse(root.isEmpty)
            }
        }
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
        let receipt = response["receipt"] as! [String: Any]
        let inApp = receipt["in_app"] as! [[String: Any]]
        XCTAssertEqual(inApp[0]["quantity"] as? String, "1")
        XCTAssertEqual(inApp[0]["web_order_line_item_id"] as? String, "42")
        XCTAssertNotNil(receipt["request_date"])
        XCTAssertNotNil(receipt["request_date_ms"])
        XCTAssertNotNil(receipt["request_date_pst"])
        let coins = inApp.first { ($0["product_id"] as? String) == "com.example.app.coins100" }!
        XCTAssertNotNil(coins["purchase_date"])
        XCTAssertNotNil(coins["purchase_date_ms"])
        XCTAssertNotNil(coins["purchase_date_pst"])
        let vip = inApp.first { ($0["product_id"] as? String) == "com.example.app.vip" }!
        XCTAssertNotNil(vip["expires_date_ms"])
        XCTAssertNotNil(vip["expires_date_pst"])
    }

    /// `request_date` is the response's one wall-clock field — Apple stamps
    /// it with the time the request was served — so the clock drives it too,
    /// for the same reason it drives staleness. It moves no verdict.
    func testInjectedClockStampsRequestDateAndMovesNoVerdict() async throws {
        let now = Date(timeIntervalSince1970: 1_735_689_600)  // 2025-01-01T00:00:00Z
        let pinned = try VerifyReceiptEndpoint(
            trustedRoots: [try fixture("generated", "receipt-root.der")],
            production: false,
            clock: { now })
        let response = await pinned.verifyReceipt(try request())
        let receipt = response["receipt"] as! [String: Any]
        XCTAssertEqual(receipt["request_date_ms"] as? String, "1735689600000")
        XCTAssertEqual(receipt["request_date"] as? String, "2025-01-01 00:00:00 Etc/GMT")

        // Same request through the default (system-clock) endpoint: identical
        // status and identical verified fields, only request_date differs.
        let live = await (try endpoint(production: false)).verifyReceipt(try request())
        XCTAssertEqual(response["status"] as? Int, live["status"] as? Int)
        let liveReceipt = live["receipt"] as! [String: Any]
        XCTAssertNotEqual(liveReceipt["request_date_ms"] as? String,
                          receipt["request_date_ms"] as? String)
        // Compared as sorted-key JSON: Swift dictionaries have no order, so
        // describing them would compare orderings rather than content.
        func withoutRequestDate(_ json: [String: Any]) throws -> String {
            let kept = json.filter { !$0.key.hasPrefix("request_date") }
            return String(decoding: try JSONSerialization.data(withJSONObject: kept,
                                                               options: [.sortedKeys]),
                          as: UTF8.self)
        }
        XCTAssertEqual(try withoutRequestDate(liveReceipt), try withoutRequestDate(receipt),
                       "a verified field moved with the clock")
    }

    func testReportsMalformedRequestsAs21002() async throws {
        let endpoint = try endpoint(production: false)
        let empty = await endpoint.verifyReceipt([:])
        XCTAssertEqual(empty["status"] as? Int, 21002)
        let missing = await endpoint.verifyReceipt(nil)
        XCTAssertEqual(missing["status"] as? Int, 21002)
        let garbage = await endpoint.verifyReceipt(["receipt-data": "AQIDBA=="])
        XCTAssertEqual(garbage["status"] as? Int, 21002)
    }

    func requestJSON() throws -> String {
        let base64 = try fixture("generated", "receipt.der").base64EncodedString()
        return "{\"receipt-data\":\"\(base64)\"}"
    }

    /// request_date is "now": two calls legitimately disagree on it.
    func withoutRequestDate(_ response: [String: Any]) -> [String: Any] {
        var copy = response
        if var receipt = copy["receipt"] as? [String: Any] {
            for key in ["request_date", "request_date_ms", "request_date_pst"] {
                receipt.removeValue(forKey: key)
            }
            copy["receipt"] = receipt
        }
        return copy
    }

    func testVerifyReceiptJSONPinsTheWireTypes() async throws {
        let body = await (try endpoint(production: false)).verifyReceiptJSON(try requestJSON())
        // Raw bytes, not just the parse: status is a JSON number and every
        // number-shaped receipt field is a JSON string, as Apple sends them.
        XCTAssertTrue(body.contains("\"status\":0"), body)
        XCTAssertTrue(body.contains("\"quantity\":\"1\""), body)
        XCTAssertTrue(body.contains("\"web_order_line_item_id\":\"42\""), body)
        let parsed = try XCTUnwrap(try JSONSerialization.jsonObject(
            with: XCTUnwrap(body.data(using: .utf8))) as? [String: Any])
        XCTAssertTrue(parsed["status"] is NSNumber)
        XCTAssertEqual(parsed["environment"] as? String, "Sandbox")
        let receipt = try XCTUnwrap(parsed["receipt"] as? [String: Any])
        XCTAssertTrue(receipt["receipt_creation_date_ms"] is String)
        XCTAssertTrue(receipt["request_date_ms"] is String)
        for purchase in try XCTUnwrap(receipt["in_app"] as? [[String: Any]]) {
            XCTAssertTrue(purchase["quantity"] is String)
            XCTAssertTrue(purchase["web_order_line_item_id"] is String)
            XCTAssertTrue(purchase["purchase_date_ms"] is String)
        }
    }

    func testVerifyReceiptJSONRendersIsInIntroOfferPeriodAsAString() async throws {
        let receiptData = try String(
            contentsOf: VerifierTests.fixturesDir
                .appendingPathComponent("public-receipts")
                .appendingPathComponent("receipt-sandbox-g5.b64"),
            encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        let endpoint = try VerifyReceiptEndpoint(
            trustedRoots: appleReceiptRoots(), production: false)
        let body = await endpoint.verifyReceiptJSON("{\"receipt-data\":\"\(receiptData)\"}")
        XCTAssertTrue(body.contains("\"is_in_intro_offer_period\":\"false\""), body)
        let parsed = try XCTUnwrap(try JSONSerialization.jsonObject(
            with: XCTUnwrap(body.data(using: .utf8))) as? [String: Any])
        let receipt = try XCTUnwrap(parsed["receipt"] as? [String: Any])
        let purchases = try XCTUnwrap(receipt["in_app"] as? [[String: Any]])
        XCTAssertFalse(purchases.isEmpty)
        for purchase in purchases {
            XCTAssertTrue(purchase["is_in_intro_offer_period"] is String)
        }
    }

    func testVerifyReceiptJSONOmitsReceiptAndEnvironmentOnNonZeroStatus() async throws {
        let body = await (try endpoint(production: true)).verifyReceiptJSON(try requestJSON())
        XCTAssertEqual(body, "{\"status\":21007}")
    }

    func testVerifyReceiptJSONAnswers21002ForABodyThatIsNotAnObject() async throws {
        let endpoint = try endpoint(production: false)
        for body in ["", "not json", "{", "[]", "[{\"receipt-data\":\"x\"}]",
                     "null", "3", "\"receipt\"", "true"] {
            let response = await endpoint.verifyReceiptJSON(body)
            XCTAssertEqual(response, "{\"status\":21002}", body)
        }
    }

    func testVerifyReceiptJSONMatchesTheDictionaryApi() async throws {
        let endpoint = try endpoint(production: false)
        let viaDictionary = await endpoint.verifyReceipt(try request())
        let body = await endpoint.verifyReceiptJSON(try requestJSON())
        let viaJSON = try XCTUnwrap(try JSONSerialization.jsonObject(
            with: XCTUnwrap(body.data(using: .utf8))) as? [String: Any])
        XCTAssertEqual(withoutRequestDate(viaJSON) as NSDictionary,
                       withoutRequestDate(viaDictionary) as NSDictionary)
    }
}

/// Regression tests for the adversarial-review findings + PLAN D10.
final class ReviewFixesTests: XCTestCase {
    func fixture(_ segments: String...) throws -> Data {
        try Data(contentsOf: segments.reduce(VerifierTests.fixturesDir) {
            $0.appendingPathComponent($1)
        })
    }

    func testRejectsTrailingBytesAfterCms() async throws {
        let verifier = try ReceiptVerifier(
            trustedRoots: [try fixture("generated", "receipt-root.der")],
            bundleId: "com.example.app")
        var padded = try fixture("generated", "receipt.der")
        padded.append(contentsOf: [0x00, 0xde, 0xad, 0xbe])
        do {
            _ = try await verifier.verify(receipt: padded)
            XCTFail("expected INVALID_RECEIPT_FORMAT")
        } catch let error as VerificationError {
            XCTAssertEqual(error.reason, .invalidReceiptFormat)
        }
    }

    func testRejectsAReceiptDateOutsideTheRepresentableRange() async throws {
        let verifier = try ReceiptVerifier(
            trustedRoots: [try fixture("generated", "receipt-root.der")],
            bundleId: "com.example.app")
        do {
            _ = try await verifier.verify(receipt: Self.outOfRangeDateReceipt)
            XCTFail("expected INVALID_RECEIPT_FORMAT")
        } catch let error as VerificationError {
            XCTAssertEqual(error.reason, .invalidReceiptFormat)
        }
    }

    func testRejectsAnEmbeddedCertificateWhoseRsaKeyIsUnparseable() async throws {
        // One byte of the signer certificate's modulus, made even. The DER
        // stays well formed so swift-asn1 passes it through to BoringSSL,
        // which rejects it — and swift-crypto before 4.5.1 freed the EVP_PKEY
        // in its catch block and again in deinit, corrupting the heap and
        // aborting the process before any chain or signature check. This test
        // crashes the whole runner rather than failing if that floor is ever
        // lowered, which is the loudest signal available for a double free.
        let verifier = try ReceiptVerifier(
            trustedRoots: [try fixture("generated", "receipt-root.der")],
            bundleId: "com.example.app")
        var mutated = try fixture("generated", "receipt.der")
        XCTAssertEqual(mutated[1121], 0x35, "fixture layout changed; re-locate the modulus byte")
        mutated[1121] = 0x00
        // Repeated because a double free does not abort every time: a single
        // call returns cleanly often enough that a one-shot test reports
        // success against a vulnerable dependency. Verified: with the floor
        // lowered to swift-crypto 3.15.1 the one-shot version passed and this
        // one kills the runner with signal 5.
        for _ in 0..<200 {
            do {
                _ = try await verifier.verify(receipt: mutated)
                XCTFail("expected a verification failure")
            } catch is VerificationError {
                // Throwing is the whole assertion.
            }
        }
    }

    /// A receipt whose creation date is `999999-12-31T23:59:59Z`, carrying the
    /// shared fixture's own signer certificate so the parse reaches the policy.
    /// `ISO8601DateFormatter` accepts a six-digit year; GeneralizedTime holds
    /// only four, and X509's `Time` converts with `try!`, so before the range
    /// check this aborted the process instead of throwing. Rebuilt from
    /// fixtures/generated/receipt.der with the payload replaced; the signature
    /// no longer matches, which is the point — the crash came first.
    static let outOfRangeDateReceipt = Data(base64Encoded:
        "MIIFGQYJKoZIhvcNAQcCoIIFCjCCBQYCAQExDTALBglghkgBZQMEAgEwMwYJKoZIhvcNAQcBoCYEJDEiMCACAQwC" +
        "AQEEGBYWOTk5OTk5LTEyLTMxVDIzOjU5OjU5WqCCAtkwggLVMIIBvaADAgECAgEPMA0GCSqGSIb3DQEBCwUAMBcx" +
        "FTATBgNVBAMMDEZha2UgV1dEUiBDQTAgFw0yNDAxMDEwMDAwMDBaGA8yMDUwMDEwMTAwMDAwMFowHzEdMBsGA1UE" +
        "AwwURmFrZSBSZWNlaXB0IFNpZ25pbmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDayocrktbzriQR" +
        "/EwHhZzvxW48pcwOXjx2nCj0zviFJ2xdfzMb8ODpl6LXXn8BZ5j2JKWC4/92Xfq9nu2yZLDptV6Nx+m2P1hk/Vib" +
        "zHQJ5qQ3uaU354/aH/TPA/w6B7ogeAuXSDDytaV/Z/uhuX61KKpsBg6YtxwoHU1hHMaLDgZLR3m0hUAUO10NVR+r" +
        "1mirmldsLjzvSVq69fWAZdl5uQV2SUXz5Hk8oRmFjxNEv6Xmg/uDVhHz/bGP2DtMVRVNjVNPvRfeSBfw3QsFaprV" +
        "jSCWroAzbOvM7r7JvMapZae8f7FCOBb6ru/9LN5ezyogkT4LYngNiNMPCFWZt881AgMBAAGjIjAgMAwGA1UdEwEB" +
        "/wQCMAAwEAYKKoZIhvdjZAYLAQQCBQAwDQYJKoZIhvcNAQELBQADggEBADTcnfH4cgNVcLPXFZatM5kYitrSKpS8" +
        "x/+6osJ2RetV+NbElY2lGzKORIoXLiPIPG9qO+WmP5VahwWI9ejG7jprXUsFzSvNCMvLGQEGLMQSeKaBp3c99s1W" +
        "ackBfq8+zYinv4zGAnvGKMrpBex3Oi5yHHQojwT1qvnVRuLtgPAQohaZiFighN8xHmytRWskWL1x2fo4h59c7S2W" +
        "cSZcrqauQEp8DlkYQqbEhm1MMGXI2rTpOQQCkmnKgyWEDTCdAXtjiYsqCLJ24BMDvjrbeerrRBo0nPBat08QT4a4" +
        "DRAaTz1mA279uU2eV6+RdPhEA1/pF0rD80yQrzLcnwvpzhwxggHeMIIB2gIBATAcMBcxFTATBgNVBAMMDEZha2Ug" +
        "V1dEUiBDQQIBDzALBglghkgBZQMEAgGggZYwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUx" +
        "DxcNMjQwODA2MTIwMDAwWjArBgkqhkiG9w0BCTQxHjAcMAsGCWCGSAFlAwQCAaENBgkqhkiG9w0BAQsFADAvBgkq" +
        "hkiG9w0BCQQxIgQgOCEqyt40p6ah5MLX+ax9VU9h268QnUyap2QqkBSOKDAwDQYJKoZIhvcNAQELBQAEggEApVar" +
        "k1HGF6nVTye/RnLd7LPCIZgS5Nc8fe+y19KFuRNDIZxe1rcy0En38maFSZODlHLlfwpoIGlsQ6EDfakf49+2miip" +
        "IKgl3gjNYvgQ2m4y4YSReQ1SRURS5R2etwjaK3G3Vcnl7tJKYbXFKMtDyQusulapF6jr/M4sfqgY/Kmuler+X5Dj" +
        "xTZfkS4i4o0KMl4phduGec0yS8GNQUob0J4BfukJdZhgqtnbaiaOeUy0JBHqqtmWgxkYUV8qHqoC4R7tXO5HOCuc" +
        "5gdP4u4lW+vYNoFuTHgwsKz0NVqb5y4HDPL1ApFKQU70Inrd1ia53sdtPhfDuOyCYNuYUfU8yw==")!
}

/// Anti-forgery controls, signing-time behaviour, and malformed-input safety.
final class ParityTests: XCTestCase {
    static let bundle = "com.example.app"
    func fx(_ n: String) throws -> Data {
        try Data(contentsOf: VerifierTests.fixturesDir.appendingPathComponent("generated").appendingPathComponent(n))
    }
    func expect(_ reason: VerificationError.Reason, _ body: () async throws -> Void) async {
        do { try await body(); XCTFail("expected \(reason.rawValue)") }
        catch let e as VerificationError { XCTAssertEqual(e.reason, reason, e.description) }
        catch { XCTFail("unexpected \(error)") }
    }

    func testMalformedReceiptThrowsInsteadOfCrashing() async throws {
        // SEQUENCE containing only the CMS OID — previously an uncatchable trap.
        let malformed = Data([0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02])
        let v = try ReceiptVerifier(trustedRoots: [try fx("receipt-root.der")], bundleId: Self.bundle)
        await expect(.invalidReceiptFormat) { _ = try await v.verify(receipt: malformed) }
        let ep = try VerifyReceiptEndpoint(trustedRoots: [try fx("receipt-root.der")], production: false)
        let resp = await ep.verifyReceipt(["receipt-data": malformed.base64EncodedString()])
        XCTAssertEqual(resp["status"] as? Int, 21002)
    }
}

// MARK: - chain-building bound

/// The bound on chain building. A receipt's embedded certificates are
/// attacker-supplied and reach chain building before any signature is checked,
/// and swift-certificates' Verifier searches whatever candidate pool it is
/// handed, so both what goes into that pool and how much of it there can be
/// are load-bearing. Every receipt here is the genuine
/// fixtures/generated/receipt.der with a different certificate bag spliced in:
/// the file is BER with indefinite lengths, so the splice needs no ancestor
/// length fixups, and the CMS signature covers the signed attributes rather
/// than the bag.
final class ChainBuildingBoundTests: XCTestCase {
    static let notValidBefore = Date(timeIntervalSince1970: 1_577_836_800) // 2020-01-01
    static let notValidAfter = Date(timeIntervalSince1970: 2_051_222_400)  // 2035-01-01

    func verifier() throws -> ReceiptVerifier {
        try ReceiptVerifier(
            trustedRoots: [try Data(contentsOf: VerifierTests.fixturesDir
                .appendingPathComponent("generated")
                .appendingPathComponent("receipt-root.der"))],
            bundleId: VerifierTests.bundle)
    }

    func genuineReceipt() throws -> Data {
        try Data(contentsOf: VerifierTests.fixturesDir
            .appendingPathComponent("generated").appendingPathComponent("receipt.der"))
    }

    // MARK: certificate bag surgery

    private static let contextZero = ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)

    /// The SignedData `certificates [0]` node of a receipt.
    private static func certificatesNode(_ receipt: [UInt8]) throws -> ASN1Node {
        func children(_ node: ASN1Node) throws -> [ASN1Node] {
            guard case .constructed(let nodes) = node.content else {
                throw CocoaError(.formatting)
            }
            return Array(nodes)
        }
        let contentInfo = try children(try BER.parse(receipt))
        let signedData = try children(try children(contentInfo[1])[0])
        guard let node = signedData.dropFirst(3).first(where: {
            $0.identifier.tagClass == .contextSpecific && $0.identifier.tagNumber == 0
        }) else { throw CocoaError(.formatting) }
        return node
    }

    static func embeddedCertificates(of receipt: Data) throws -> [Certificate] {
        guard case .constructed(let nodes) = try certificatesNode([UInt8](receipt)).content else {
            throw CocoaError(.formatting)
        }
        return try nodes.map { try Certificate(derEncoded: [UInt8]($0.encodedBytes)) }
    }

    static func replacingCertificates(of receipt: Data,
                                      with certificates: [Certificate]) throws -> Data {
        let bytes = [UInt8](receipt)
        let range = try certificatesNode(bytes).encodedBytes
        var serializer = DER.Serializer()
        try serializer.appendConstructedNode(identifier: contextZero) { certs in
            for certificate in certificates {
                try certs.serialize(certificate)
            }
        }
        // Explicit Arrays: Swift 6.1 (the CI container) cannot type
        // ArraySlice + [UInt8] + ArraySlice, 6.3 can.
        return Data(Array(bytes[..<range.startIndex]) + serializer.serializedBytes
            + Array(bytes[range.endIndex...]))
    }

    static func certificate(subject: DistinguishedName, issuer: DistinguishedName,
                            serial: Certificate.SerialNumber,
                            key: Certificate.PrivateKey,
                            signedBy issuerKey: Certificate.PrivateKey,
                            dnsName: String? = nil) throws -> Certificate {
        try Certificate(
            version: .v3, serialNumber: serial, publicKey: key.publicKey,
            notValidBefore: notValidBefore, notValidAfter: notValidAfter,
            issuer: issuer, subject: subject,
            extensions: try Certificate.Extensions {
                if let dnsName {
                    SubjectAlternativeNames([.dnsName(dnsName)])
                }
            },
            issuerPrivateKey: issuerKey)
    }

    static func name(_ commonName: String) throws -> DistinguishedName {
        try DistinguishedName { CommonName(commonName) }
    }

    /// A bag whose certificates all claim to be issued by `issuer` and all
    /// share one key, so each is a signature-valid parent of every other, told
    /// apart only by a SubjectAlternativeName — which is the one field
    /// swift-certificates' loop detection compares beyond subject and key.
    /// The leaf keeps the genuine signer's issuer and serial so the CMS signer
    /// id still resolves to it.
    static func fanout(count: Int, signerOf genuine: [Certificate]) throws -> [Certificate] {
        let shared = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let leaf = try certificate(
            subject: try name("Fanout Leaf"), issuer: genuine[0].issuer,
            serial: genuine[0].serialNumber,
            key: Certificate.PrivateKey(P256.Signing.PrivateKey()), signedBy: shared)
        return [leaf] + (0..<count).map { index in
            try! certificate(subject: genuine[0].issuer, issuer: genuine[0].issuer,
                             serial: .init(bytes: [0x10, UInt8(index)]),
                             key: shared, signedBy: shared,
                             dnsName: "ca\(index).example")
        }
    }

    // MARK: the bounds

    /// The certificate count bound, from every side: eleven certificates are
    /// rejected before any of them is walked, with a message naming the bound,
    /// the genuine three-certificate receipt still verifies, and so does a bag
    /// of exactly ten. Red if the bound stops firing (raise it and the first
    /// part fails), red if it is tightened below a genuine chain (lower it to
    /// 2 and the second fails), and red if the comparison tightens by one
    /// (`<` for `<=` fails the third).
    ///
    /// The bound is not what makes the walk cheap — the walk costs at most one
    /// signature check per embedded certificate with or without it, measured
    /// under `maximumEmbeddedCertificates`. It is what stops an unauthenticated
    /// caller choosing how much of that work happens at all, at the same 10 as
    /// node, python and java.
    func testTheCertificateCountBoundFiresAndStillClearsAGenuineReceipt() async throws {
        let genuine = try genuineReceipt()
        let flooded = try Self.replacingCertificates(
            of: genuine,
            with: try Self.fanout(count: 10,
                                  signerOf: try Self.embeddedCertificates(of: genuine)))
        do {
            _ = try await verifier().verify(receipt: flooded)
            XCTFail("expected INVALID_CHAIN")
        } catch let error as VerificationError {
            XCTAssertEqual(error.reason, .invalidChain)
            XCTAssertTrue(error.message.contains("11 certificates"), error.message)
            XCTAssertTrue(
                error.message.contains("maximum of \(ReceiptVerifier.maximumEmbeddedCertificates)"),
                error.message)
        }

        _ = try await verifier().verify(receipt: genuine)

        // Exactly the bound: seven self-signed certificates the walk never
        // takes, ahead of the genuine three.
        let genuineCertificates = try Self.embeddedCertificates(of: genuine)
        let padding = try (0..<(ReceiptVerifier.maximumEmbeddedCertificates
                                - genuineCertificates.count)).map { index -> Certificate in
            let key = Certificate.PrivateKey(P256.Signing.PrivateKey())
            return try Self.certificate(
                subject: try Self.name("Padding \(index)"), issuer: try Self.name("Padding \(index)"),
                serial: .init(bytes: [0x9A, UInt8(index)]), key: key, signedBy: key)
        }
        let exactly = padding + genuineCertificates
        XCTAssertEqual(exactly.count, ReceiptVerifier.maximumEmbeddedCertificates)
        _ = try await verifier().verify(
            receipt: try Self.replacingCertificates(of: genuine, with: exactly))
    }

    /// A receipt whose bag stops at the intermediate, with the root coming
    /// from the pinned store, verifies. Node, Python and Java all accept this
    /// shape — their path builders stop as soon as the current certificate is
    /// issued by a pinned anchor — and so did this library before the walk
    /// existed. Red if the walk ever grows a fixed chain length again.
    func testAcceptsAReceiptWhoseEmbeddedBagStopsAtTheIntermediate() async throws {
        let genuine = try genuineReceipt()
        let certificates = try Self.embeddedCertificates(of: genuine)
        XCTAssertEqual(certificates.count, 3)
        let receipt = try Self.replacingCertificates(of: genuine,
                                                     with: Array(certificates.prefix(2)))
        _ = try await verifier().verify(receipt: receipt)
    }

    /// A self-signed certificate that merely borrows the intermediate's
    /// subject name must not displace the real intermediate, at any position
    /// in the bag. This is what forces the walk to select by signature: a
    /// name-only match takes whichever collides first, and this VALID receipt
    /// is then rejected from bag index 0 and 1 (measured: accepted at 2 and 3,
    /// rejected at 0 and 1, when the walk matched on the name alone).
    func testAcceptsAGenuineReceiptCarryingAnIssuerNameCollisionAtAnyIndex() async throws {
        let genuine = try genuineReceipt()
        let certificates = try Self.embeddedCertificates(of: genuine)
        let key = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let decoy = try Self.certificate(
            subject: certificates[0].issuer, issuer: certificates[0].issuer,
            serial: .init(bytes: [0xDE, 0xC0]), key: key, signedBy: key)
        for index in 0...certificates.count {
            var bag = certificates
            bag.insert(decoy, at: index)
            let receipt = try Self.replacingCertificates(of: genuine, with: bag)
            do {
                _ = try await verifier().verify(receipt: receipt)
            } catch {
                XCTFail("decoy at index \(index) flipped a valid receipt: \(error)")
            }
        }
    }

    /// The other half of the walk's predicate. A decoy that borrows the real
    /// intermediate's public KEY under a different name did, as far as a
    /// signature check can tell, sign the leaf — so a walk that selected by
    /// signature alone would take it from ahead of the real intermediate,
    /// hand the Verifier a path whose names do not chain, and reject this
    /// VALID receipt from bag index 0 and 1. The `$0.subject == tip.issuer`
    /// clause is what skips it; delete the clause and this goes red there.
    func testAcceptsAGenuineReceiptCarryingAKeyOnlyCloneAtAnyIndex() async throws {
        let genuine = try genuineReceipt()
        let certificates = try Self.embeddedCertificates(of: genuine)
        let attacker = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let clone = try Certificate(
            version: .v3, serialNumber: .init(bytes: [0xC1, 0x0F]),
            publicKey: certificates[1].publicKey,
            notValidBefore: Self.notValidBefore, notValidAfter: Self.notValidAfter,
            issuer: try Self.name("Attacker Root"), subject: try Self.name("Key Clone"),
            extensions: try Certificate.Extensions {
                BasicConstraints.isCertificateAuthority(maxPathLength: nil)
            },
            issuerPrivateKey: attacker)
        for index in 0...certificates.count {
            var bag = certificates
            bag.insert(clone, at: index)
            let receipt = try Self.replacingCertificates(of: genuine, with: bag)
            do {
                _ = try await verifier().verify(receipt: receipt)
            } catch {
                XCTFail("key clone at index \(index) flipped a valid receipt: \(error)")
            }
        }
    }

    /// The attack the certificate count cannot bound: ten certificates, inside
    /// the count bound, and at about 4,300 bytes smaller than the genuine
    /// 79,104-byte legacy fixture, so no caller-side size limit reaches it
    /// either. Handing that bag to swift-certificates as intermediates cost
    /// 148.8 s through this same entry point on a release build, against
    /// 4.0 ms with the walk in place.
    ///
    /// What this pins is that the walk takes each subject at most ONCE.
    /// Deduplicating by certificate instead — the obvious simplification —
    /// puts all nine of these self-issued certificates in the store, where
    /// they are once again each other's parents: measured under that mutation
    /// this test takes 268.4 s on the debug build CI runs and 147.4 s on a
    /// release build, against 0.009 s debug / 0.004 s release as written. That
    /// puts the 2 s budget 222x above the working debug cost — a CI runner two
    /// orders of magnitude slower than this laptop still passes — and 134x
    /// below the broken one, which no runner is fast enough to sneak under.
    ///
    /// A sibling test ran the same fanout hidden behind a decoy chain. It went
    /// red under this mutation and no other, and its own 2 s budget did not
    /// survive it: measured just before it was removed, it PASSED in 1.855 s
    /// under the mutation on a release build (3.08 s debug, a 1.5x margin) — a
    /// green test over broken code. Deleted rather than re-budgeted, because
    /// this test covers that mutation with the margins above and
    /// `testAcceptsAGenuineReceiptCarryingAnIssuerNameCollisionAtAnyIndex`
    /// already covers the walk stepping past a name-matching non-signer.
    func testRejectsAFanoutOfSelfIssuedCertificatesWithoutSearchingIt() async throws {
        let genuine = try genuineReceipt()
        let receipt = try Self.replacingCertificates(
            of: genuine,
            with: try Self.fanout(count: 9,
                                  signerOf: try Self.embeddedCertificates(of: genuine)))
        let started = Date()
        do {
            _ = try await verifier().verify(receipt: receipt)
            XCTFail("expected INVALID_CHAIN")
        } catch let error as VerificationError {
            XCTAssertEqual(error.reason, .invalidChain)
        }
        XCTAssertLessThan(-started.timeIntervalSinceNow, 2.0)
    }

    /// The count guard runs before anything else touches the bag. Moving it
    /// down to just before the `Verifier` is built still rejects a flooded
    /// receipt, and left every other test in this file green (measured), so
    /// nothing else pins the position. This bag separates the two: it is over
    /// the bound AND omits the signer certificate, so the guard where it is
    /// reports the bound, while a guard that runs after `signerCertificate()`
    /// tells the caller the receipt is malformed instead.
    func testTheCountGuardRunsBeforeTheSignerIsResolved() async throws {
        let genuine = try genuineReceipt()
        let certificates = try Self.embeddedCertificates(of: genuine)
        let key = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let bag = try (0...ReceiptVerifier.maximumEmbeddedCertificates).map { index in
            try Self.certificate(
                subject: certificates[0].issuer, issuer: certificates[0].issuer,
                serial: .init(bytes: [0x70, UInt8(index)]), key: key, signedBy: key)
        }
        let receipt = try Self.replacingCertificates(of: genuine, with: bag)
        do {
            _ = try await verifier().verify(receipt: receipt)
            XCTFail("expected INVALID_CHAIN")
        } catch let error as VerificationError {
            XCTAssertEqual(error.reason, .invalidChain)
            XCTAssertTrue(
                error.message.contains("maximum of \(ReceiptVerifier.maximumEmbeddedCertificates)"),
                error.message)
        }
    }

    /// The one verdict the walk moved. A decoy that borrows the real
    /// intermediate's DN *and* its public key satisfies the walk's predicate —
    /// the key it carries really did sign the leaf — so the walk takes it and
    /// stops instead of backtracking to the real intermediate. Measured on a
    /// release build: with the whole certificate bag handed to the Verifier
    /// this receipt was accepted at all four positions; it is now rejected
    /// from the two ahead of the real intermediate and still accepted from the
    /// two behind it. That is position for position what node and python
    /// answer on the same four receipts (measured); java accepts all four, a
    /// java-vs-node/python split that predates this walk. Only a receipt whose
    /// signer the attacker controls has this shape, so no genuine receipt pays
    /// for it — but the record should not claim the walk moves nothing.
    func testAKeyCloningDecoyDisplacesTheIntermediateOnlyFromAheadOfIt() async throws {
        let genuine = try genuineReceipt()
        let certificates = try Self.embeddedCertificates(of: genuine)
        XCTAssertEqual(certificates[0].issuer, certificates[1].subject)
        let attacker = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let clone = try Certificate(
            version: .v3, serialNumber: .init(bytes: [0xC1, 0x0E]),
            publicKey: certificates[1].publicKey,
            notValidBefore: Self.notValidBefore, notValidAfter: Self.notValidAfter,
            issuer: try Self.name("Attacker Root"), subject: certificates[1].subject,
            extensions: try Certificate.Extensions {
                BasicConstraints.isCertificateAuthority(maxPathLength: nil)
            },
            issuerPrivateKey: attacker)

        for index in 0...certificates.count {
            var bag = certificates
            bag.insert(clone, at: index)
            let receipt = try Self.replacingCertificates(of: genuine, with: bag)
            do {
                _ = try await verifier().verify(receipt: receipt)
                XCTAssertGreaterThan(index, 1, "clone at index \(index) was not taken")
            } catch let error as VerificationError {
                XCTAssertLessThan(index, 2, "clone at index \(index) was taken: \(error)")
                XCTAssertEqual(error.reason, .invalidChain)
            }
        }
    }

    /// A signature cycle among the embedded certificates is rejected, in both
    /// shapes it comes in: leaf signed by A, A signed by B, B signed by A. With
    /// the issuer names chaining inside the bag, `subjectsTaken` stops the walk
    /// at B, whose issuer names a subject already taken. With the issuer names
    /// pointing outside the bag, no subject the walk records is ever an issuer
    /// it tests, that guard never fires, and the count clause stops the walk at
    /// the size of the bag instead. Before the count clause existed, deleting
    /// the `$0.subject == tip.issuer` clause made the second shape loop forever
    /// (measured: the run was killed at 120 s, against 0.004 s as shipped), so
    /// the mutation surfaced as a hang rather than a red test — and a test
    /// that fails by hanging takes the machine down with it. Neither shape can
    /// loop past the bag now; what the two pin is the verdict.
    func testRejectsASignatureCycleAmongTheEmbeddedCertificates() async throws {
        let genuine = try genuineReceipt()
        let certificates = try Self.embeddedCertificates(of: genuine)
        let keyA = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let keyB = Certificate.PrivateKey(P256.Signing.PrivateKey())
        // The leaf keeps the genuine signer's issuer and serial so the CMS
        // signer id still resolves to it, and A carries that same issuer name
        // as its subject so the walk takes one real step before the cycle.
        let leaf = try Self.certificate(
            subject: try Self.name("Cycle Leaf"), issuer: certificates[0].issuer,
            serial: certificates[0].serialNumber,
            key: Certificate.PrivateKey(P256.Signing.PrivateKey()), signedBy: keyA)
        let insideTheBag = [
            leaf,
            try Self.certificate(
                subject: certificates[0].issuer, issuer: try Self.name("Cycle B"),
                serial: .init(bytes: [0x41]), key: keyA, signedBy: keyB),
            try Self.certificate(
                subject: try Self.name("Cycle B"), issuer: certificates[0].issuer,
                serial: .init(bytes: [0x42]), key: keyB, signedBy: keyA),
        ]
        let outsideTheBag = [
            leaf,
            try Self.certificate(
                subject: certificates[0].issuer, issuer: try Self.name("Cycle A Issuer"),
                serial: .init(bytes: [0x43]), key: keyA, signedBy: keyB),
            try Self.certificate(
                subject: try Self.name("Cycle B"), issuer: try Self.name("Cycle B Issuer"),
                serial: .init(bytes: [0x44]), key: keyB, signedBy: keyA),
        ]

        for (shape, bag) in [("inside", insideTheBag), ("outside", outsideTheBag)] {
            let receipt = try Self.replacingCertificates(of: genuine, with: bag)
            do {
                _ = try await verifier().verify(receipt: receipt)
                XCTFail("expected INVALID_CHAIN for the cycle chaining \(shape) the bag")
            } catch let error as VerificationError {
                XCTAssertEqual(error.reason, .invalidChain, shape)
            }
        }
    }
}
