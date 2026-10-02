import Foundation
import XCTest

@testable import ApplePurchaseReceiptVerifier

/// Behaviour the shared cases in fixtures/cases.json do not pin, kept from
/// the 0.7 Swift suite where it can still be reached through the public
/// API. Since 0.8 the verification module decides all of it, so these are
/// tests of the module through this host; MIGRATION.md Phase 7 step 1 moves
/// them into fixtures/cases.json, and the tests that needed swift-crypto to
/// forge receipts went with that dependency.
final class PortBehaviourTests: XCTestCase {
    /// An x5c entry starting with U+FEFF is outside the base64 alphabet and
    /// must be INVALID_CERTIFICATE, like any other character there. A header
    /// reader that dropped a leading mark would decode the genuine leaf
    /// behind it and answer INVALID_SIGNATURE (the header is not re-signed),
    /// so only the reason tells the two apart.
    func testRejectsAnX5cEntryStartingWithAByteOrderMark() throws {
        let segments = try TestFixtures.text(TestFixtures.jws).components(separatedBy: ".")
        var header = String(decoding: try XCTUnwrap(base64URLDecode(segments[0])), as: UTF8.self)
        let x5c = try XCTUnwrap(header.range(of: "\"x5c\""))
        let firstEntry = try XCTUnwrap(header.range(of: "\"", range: x5c.upperBound..<header.endIndex))
        header.insert("\u{FEFF}", at: firstEntry.upperBound)
        let jws = "\(base64URL(Array(header.utf8))).\(segments[1]).\(segments[2])"
        let result = try TestFixtures.verifier(roots: [TestFixtures.jwsRoot]).verifySignedData(jws: jws)
        XCTAssertEqual(result.failure?.reason, .invalidCertificate, result.failure?.message ?? "verified")
    }

    /// One byte of the signer certificate's modulus, made even. A verdict,
    /// never a crash (0.7 pinned a swift-crypto double free here). The
    /// verdict is UNTRUSTED_CHAIN, the shared case
    /// `receipt/reject-signer-with-an-even-rsa-modulus`'s answer, which the
    /// Java implementation gives too: the changed byte breaks the
    /// intermediate's signature over the leaf, so the chain fails before the
    /// key is used. 0.7 Swift answered INVALID_CERTIFICATE only because
    /// swift-crypto refused the key while decoding it.
    func testASignerWhoseRsaKeyIsRefusedIsAVerdict() throws {
        var mutated = try TestFixtures.bytes(TestFixtures.receipt)
        XCTAssertEqual(mutated[1121], 0x89, "fixture layout changed; re-locate the signer's last modulus byte")
        XCTAssertEqual(Array(mutated[1122..<1127]), [0x02, 0x03, 0x01, 0x00, 0x01], "the exponent follows it")
        mutated[1121] = 0x00
        let base64 = standardBase64Encode(mutated)
        let verifier = try TestFixtures.verifier(roots: [TestFixtures.receiptRoot])
        for _ in 0..<3 {
            XCTAssertEqual(verifier.verifyReceipt(base64: base64).failure?.reason, .untrustedChain)
        }
    }

    /// A SEQUENCE holding only the SignedData OID: MALFORMED, and 21002 at
    /// the endpoint.
    func testATruncatedContentInfoIsMalformed() throws {
        let truncated: [UInt8] = [0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02]
        let verifier = try TestFixtures.verifier(roots: [TestFixtures.receiptRoot])
        let base64 = standardBase64Encode(truncated)
        XCTAssertEqual(verifier.verifyReceipt(base64: base64).failure?.reason, .malformed)
        XCTAssertEqual(
            verifier.verifyReceiptEndpoint(environment: .sandbox, requestJson: #"{"receipt-data":"\#(base64)"}"#),
            #"{"status":21002}"#)
    }

    /// Apple sends `is_in_intro_offer_period` as the string "true" or
    /// "false", not a JSON boolean.
    func testRendersIsInIntroOfferPeriodAsAString() throws {
        let receiptData = try TestFixtures.text(TestFixtures.g5)
        let body = Verifier(config: .defaults()).verifyReceiptEndpoint(
            environment: .sandbox, requestJson: #"{"receipt-data":"\#(receiptData)"}"#)
        let parsed = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(body.utf8)) as? [String: Any])
        let receipt = try XCTUnwrap(parsed["receipt"] as? [String: Any], String(body.prefix(200)))
        let purchases = try XCTUnwrap(receipt["in_app"] as? [[String: Any]])
        XCTAssertFalse(purchases.isEmpty)
        for purchase in purchases {
            XCTAssertTrue(purchase["is_in_intro_offer_period"] is String, purchase.description)
        }
    }

    /// Bodies that are not a JSON object at all: each is a client error,
    /// 21002, and never an answer about a receipt.
    func testAnswers21002ForABodyThatIsNotAnObject() throws {
        let verifier = try TestFixtures.verifier(roots: [TestFixtures.receiptRoot])
        for body in ["", "not json", "{", "[{\"receipt-data\":\"x\"}]", "\"receipt\"", "true"] {
            XCTAssertEqual(
                verifier.verifyReceiptEndpoint(environment: .sandbox, requestJson: body), #"{"status":21002}"#, body)
        }
    }

    /// Apple answers 21002 to a receipt-data string that starts with a
    /// byte-order mark; a JSON escape is the same string once parsed, so both
    /// escaped spellings get the same answer.
    func testRefusesReceiptDataStartingWithAnEscapedByteOrderMark() throws {
        let verifier = try TestFixtures.verifier(roots: [TestFixtures.receiptRoot])
        let base64 = standardBase64Encode(try TestFixtures.bytes(TestFixtures.receipt))
        XCTAssertEqual(
            TestFixtures.status(
                verifier.verifyReceiptEndpoint(environment: .sandbox, requestJson: #"{"receipt-data":"\#(base64)"}"#)),
            0, "the control must verify")
        for mark in ["\u{FEFF}", "\\ufeff", "\\uFEFF"] {
            XCTAssertEqual(
                verifier.verifyReceiptEndpoint(environment: .sandbox, requestJson: "{\"receipt-data\":\"\(mark)\(base64)\"}"),
                #"{"status":21002}"#, mark)
        }
    }

    /// The same bytes are accepted under the anchor that signed them and
    /// refused under every other, Apple's own roots included: the anchor set
    /// is exactly the configured one.
    func testAVerdictFollowsTheConfiguredRootsAndNothingElse() throws {
        let receipt = standardBase64Encode(try TestFixtures.bytes(TestFixtures.receipt))
        let accepted = try TestFixtures.verifier(roots: [TestFixtures.receiptRoot]).verifyReceipt(base64: receipt)
        XCTAssertEqual(accepted.payload?.bundleId, "com.example.app")
        for verifier in [try TestFixtures.verifier(roots: [TestFixtures.jwsRoot]), Verifier(config: .defaults())] {
            XCTAssertEqual(verifier.verifyReceipt(base64: receipt).failure?.reason, .untrustedChain)
        }
        let jws = try TestFixtures.text(TestFixtures.jws)
        XCTAssertTrue(try TestFixtures.verifier(roots: [TestFixtures.jwsRoot]).verifySignedData(jws: jws).verified)
        for verifier in [try TestFixtures.verifier(roots: [TestFixtures.receiptRoot]), Verifier(config: .defaults())] {
            XCTAssertEqual(verifier.verifySignedData(jws: jws).failure?.reason, .untrustedChain)
        }
    }

    /// Certificate validity is judged at the receipt's own creation date
    /// when it carries one; no clock moves the verdict for a dated receipt.
    func testTheClockMovesNoVerdictForADatedReceipt() throws {
        let clocks: [Int64] = [0, 1_593_561_600_000, 1_735_689_600_000, 4_102_444_800_000]
        for (fixture, expected) in [
            ("generated-0.7/receipt-expired-historical.der", 0),
            ("generated-0.7/receipt-expired-fresh.der", 21003),
        ] {
            let body = #"{"receipt-data":""# + standardBase64Encode(try TestFixtures.bytes(fixture)) + #""}"#
            for clock in clocks {
                let verifier = try TestFixtures.verifier(roots: ["generated-0.7/receipt-expired-root.der"], clock: clock)
                let response = verifier.verifyReceiptEndpoint(environment: .sandbox, requestJson: body)
                XCTAssertEqual(TestFixtures.status(response), expected, "\(fixture) at clock \(clock): \(response.prefix(30))")
            }
        }
    }

    /// The endpoint is `verifyReceipt` plus Apple's rendering: over every
    /// receipt in the repository, the status it answers is the one the
    /// design's table gives for what `verifyReceipt` decided on the same
    /// string, in both environments.
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
                inputs.append((name, try TestFixtures.text("\(directory)/\(name)")))
            }
        }
        for source in [".der", ".txt", ".b64"] {
            XCTAssertTrue(inputs.contains { $0.0.hasSuffix(source) }, "no \(source) receipt fixtures found")
        }
        let verifier = Verifier(config: try Config.builder().roots(roots).clock { 1_735_689_600_000 }.build())
        var statuses: Set<Int> = []
        for (name, receiptData) in inputs {
            let result = verifier.verifyReceipt(base64: receiptData)
            let body = jsonText(["receipt-data": receiptData])
            for environment in [Environment.production, .sandbox] {
                let want = Self.status(result, environment)
                let got = TestFixtures.status(verifier.verifyReceiptEndpoint(environment: environment, requestJson: body))
                XCTAssertEqual(got, want, "\(name) on \(environment)")
                statuses.insert(want)
            }
        }
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

/// Anchors come from the caller's Config and bytes from the caller, never
/// from the platform. The crypto, X.509 and ASN.1 modules and the Security
/// framework's trust and certificate API are banned for every wrapper in one
/// place, the one-implementation gate (tools/check-one-implementation.mjs).
final class SourceIsolationTests: XCTestCase {
    static var sources: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/ApplePurchaseReceiptVerifier")
    }

    static let forbidden = [
        "URLSession", "URLRequest", "NWConnection", "SSL_CERT_FILE", "SSL_CERT_DIR", "/etc/ssl",
    ]

    func testNoSourceFileReachesATrustStoreOrTheNetwork() throws {
        let files = try XCTUnwrap(FileManager.default.enumerator(at: Self.sources, includingPropertiesForKeys: nil))
            .compactMap { $0 as? URL }.filter { $0.pathExtension == "swift" }
        XCTAssertGreaterThanOrEqual(files.count, 10, "the scan found \(files.count) files, so it found the wrong tree")
        for file in files {
            let code = try String(contentsOf: file, encoding: .utf8).split(separator: "\n")
                .filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }.joined(separator: "\n")
            for needle in Self.forbidden {
                XCTAssertFalse(code.contains(needle), "\(file.lastPathComponent) names \"\(needle)\"")
            }
        }
    }

    /// WasmKit is the one direct dependency: a new one is a supply-chain
    /// decision, not a side effect.
    func testWasmKitIsTheOnlyDependency() throws {
        let manifest = try String(
            contentsOf: Self.sources.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
                .appendingPathComponent("Package.swift"), encoding: .utf8)
        let urls = manifest.split(separator: "\n").filter { $0.contains(".package(url:") }
            .compactMap { $0.split(separator: "\"").dropFirst().first.map(String.init) }
        XCTAssertEqual(urls, ["https://github.com/swiftwasm/WasmKit.git"])
    }
}
