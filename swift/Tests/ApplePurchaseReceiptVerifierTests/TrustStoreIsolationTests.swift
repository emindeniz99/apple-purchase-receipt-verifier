import Foundation
import SwiftASN1
import X509
import XCTest
@testable import ApplePurchaseReceiptVerifier

/// Trust reaches this library through exactly one door: the roots of the
/// `Config` a `Verifier` is built from. Not through Security.framework, not
/// through swift-certificates' `CertificateStore.systemTrustRoots`, not
/// through a CA bundle on disk, not through the network.
///
/// Every other port pins this — go's `systemtrust_test.go`, rust's
/// `trust_pinning.rs`, php's `PinnedAnchorsTest.php`, ruby's
/// `hostile_input_test.rb` — and swift is where it is easiest to lose. On
/// Linux `CertificateStore.systemTrustRoots` is one word away from a
/// `CertificateStore(roots)`, and on Darwin `SecTrustEvaluateWithError` is
/// the answer every Apple-platform tutorial gives. So the rule is asserted
/// three ways: structurally over the sources and the dependency set (the half
/// that holds on Darwin, where the tests cannot install anything);
/// behaviourally, on chains that are well-formed in every respect except
/// their anchor; and against this machine's real trust store, which is
/// loaded, effective in this very process, and still moves no verdict.
///
/// No shared case can say any of this: a vector names its anchors, so it
/// cannot test what happens with anchors nobody named.
final class TrustStoreIsolationTests: XCTestCase {
    // MARK: - the structural half

    /// Every spelling by which a Swift file could reach a trust store this
    /// library was not handed, or reach the network. Comments legitimately
    /// name some of these — `Roots.swift` cites Apple's `https://` CA page,
    /// and this file's own prose names all of them — so the ban is on code.
    private static let forbidden = [
        "Security", "SecTrust", "SecCertificate", "SecKey", "SecPolicy",
        "systemTrustRoots", "URLSession", "URLRequest", "URLProtocol",
        "NWConnection", "NIOSSL", "Socket", "URL(string:",
        "SSL_CERT_FILE", "SSL_CERT_DIR", "/etc/ssl", "ca-certificates",
        "http://", "https://",
    ]

    /// The mechanised form of the whole rule, and the only half that runs
    /// unchanged on Darwin: a `SecTrust` call cannot appear without failing
    /// here first.
    func testNoSourceFileNamesAPlatformTrustStoreOrANetworkClient() throws {
        let files = Self.sourceFiles()
        XCTAssertGreaterThanOrEqual(
            files.count, 5, "the source scan found \(files.count) files, so it found the wrong tree")
        for file in files {
            let code = Self.codeStrippedOfComments(try String(contentsOf: file, encoding: .utf8))
            for needle in Self.forbidden {
                XCTAssertFalse(
                    code.contains(needle),
                    "\(file.lastPathComponent) names \"\(needle)\": anchors come from the "
                        + "caller's Config and bytes come from the caller, never from the platform")
            }
        }
    }

    /// The other way a platform verifier arrives: not written, but linked. A
    /// new direct dependency is a supply-chain decision, and swift-nio-ssl or
    /// any Security.framework shim would bring an ambient trust store with it.
    func testTheDependencySetCannotQuietlyGrowAPlatformVerifier() throws {
        let manifest = try String(contentsOf: Self.packageManifest, encoding: .utf8)
        var urls: [String] = []
        for line in manifest.split(separator: "\n") where line.contains(".package(url:") {
            let quoted = line.split(separator: "\"")
            if quoted.count > 1 { urls.append(String(quoted[1])) }
        }
        XCTAssertEqual(
            urls.sorted(),
            [
                "https://github.com/apple/swift-asn1.git",
                "https://github.com/apple/swift-certificates.git",
                "https://github.com/apple/swift-crypto.git",
            ],
            "the direct dependency set changed")
    }

    // MARK: - the behavioural half

    /// The positive proof that the anchor set is exactly the configured one:
    /// the same bytes are accepted under the anchor that signed them and
    /// refused under every other, Apple's own roots included. Nothing about
    /// the material changes between the two halves — only the configuration.
    func testAVerdictFollowsTheConfiguredRootsAndNothingElse() throws {
        let receipt = standardBase64Encode(try TestFixtures.bytes(TestFixtures.receipt))
        let accepted = try TestFixtures.verifier(roots: [TestFixtures.receiptRoot]).verifyReceipt(base64: receipt)
        XCTAssertEqual(accepted.payload?.bundleId, "com.example.app")

        let wrongAnchors: [ApplePurchaseReceiptVerifier.Verifier] = [
            try TestFixtures.verifier(roots: [TestFixtures.jwsRoot]),
            ApplePurchaseReceiptVerifier.Verifier(config: .defaults()),
        ]
        for verifier in wrongAnchors {
            XCTAssertEqual(verifier.verifyReceipt(base64: receipt).failure?.reason, .untrustedChain)
        }

        // The same on the JWS path, down to the pair check itself.
        let jws = try TestFixtures.text(TestFixtures.jws)
        XCTAssertTrue(try TestFixtures.verifier(roots: [TestFixtures.jwsRoot]).verifySignedData(jws: jws).verified)
        let (leaf, intermediate) = try Self.chainOf(jws)
        let signedAt: Int64 = 1_722_945_600_000  // generated/manifest.json
        let jwsRoot = try Certificate(derEncoded: try TestFixtures.bytes(TestFixtures.jwsRoot))
        XCTAssertNoThrow(try validatePair(leaf: leaf, intermediate: intermediate, anchors: [jwsRoot], atMillis: signedAt))
        let receiptRoot = try Certificate(derEncoded: try TestFixtures.bytes(TestFixtures.receiptRoot))
        for anchors in [Config.defaults().roots, [receiptRoot]] {
            XCTAssertThrowsError(
                try validatePair(leaf: leaf, intermediate: intermediate, anchors: anchors, atMillis: signedAt)
            ) { XCTAssertEqual(($0 as? Failure)?.reason, .untrustedChain) }
        }
    }

    /// This machine's entire trust store, handed to the library as its roots:
    /// 100-odd certificate authorities that every TLS client on the host
    /// accepts, and they verify nothing here, because they issued nothing
    /// here. The complement of the pinning test — and the assertion that would
    /// start failing the day the bundled Apple roots were sourced from the
    /// host rather than from `Sources/.../certs`.
    func testThisMachinesOwnTrustRootsConferNoStanding() throws {
        let hostRoots = Self.systemTrustRootDERs()
        try XCTSkipIf(hostRoots.isEmpty, "no CA bundle on this host to read real public roots from")
        XCTAssertGreaterThan(hostRoots.count, 1)

        let bundled = Config.defaults().roots
        for root in hostRoots {
            XCTAssertFalse(
                bundled.contains(try Certificate(derEncoded: root)),
                "a root from this host's trust store is among the bundled Apple anchors")
        }

        // The premise: genuinely Apple-signed material that this library does
        // accept, so the refusals below are about the anchors and not about
        // the receipt.
        let genuine = try TestFixtures.text("public-receipts/receipt-sandbox-g5.b64")
        XCTAssertTrue(ApplePurchaseReceiptVerifier.Verifier(config: .defaults()).verifyReceipt(base64: genuine).verified)

        // And the conclusion, on genuine and on fixture material alike.
        let hostVerifier = ApplePurchaseReceiptVerifier.Verifier(
            config: try Config.builder().roots(hostRoots).build())
        for receipt in [genuine, standardBase64Encode(try TestFixtures.bytes(TestFixtures.receipt))] {
            XCTAssertEqual(hostVerifier.verifyReceipt(base64: receipt).failure?.reason, .untrustedChain)
        }
    }

    /// The strongest form available without root on this machine, and the one
    /// aimed squarely at the swift-specific mistake: prove that
    /// swift-certificates' system trust store is loaded and *effective in this
    /// very process* — a certificate validates through it — and then show that
    /// with no pinned roots at all this library trusts nothing. A library that
    /// had folded the system store in, by using
    /// `CertificateStore.systemTrustRoots` or by appending to it, would accept
    /// something here; there is no ambient set to fall back on.
    ///
    /// `ConfigBuilder.build()` refuses an empty root set, so the empty set is
    /// handed to the internal verify functions the `Verifier` wraps.
    func testTheSystemTrustStoreIsLiveInThisProcessAndStillUnreachable() async throws {
        let hostRoots = Self.systemTrustRootDERs()
        try XCTSkipIf(hostRoots.isEmpty, "no CA bundle on this host")

        var systemVerifier = X509.Verifier(rootCertificates: CertificateStore.systemTrustRoots) {
            RFC5280Policy()
        }
        var reachedThroughTheSystemStore = false
        for der in hostRoots {
            guard let root = try? Certificate(derEncoded: der) else { continue }
            let result = await systemVerifier.validate(leaf: root, intermediates: CertificateStore())
            if case .validCertificate = result {
                reachedThroughTheSystemStore = true
                break
            }
        }
        try XCTSkipIf(
            !reachedThroughTheSystemStore,
            "swift-certificates found no usable system trust roots here — it looks for them "
                + "only on Linux, and only at its two hard-coded paths — so the premise that "
                + "the system store is live cannot be established on this host")

        // The system store is live, populated and accepting chains. None of
        // that reaches these calls.
        XCTAssertThrowsError(try Config.builder().roots([]).build(), "an empty root set is a startup error")
        let receipt = standardBase64Encode(try TestFixtures.bytes(TestFixtures.receipt))
        let genuine = try TestFixtures.text("public-receipts/receipt-sandbox-g5.b64")
        for base64 in [receipt, genuine] {
            XCTAssertEqual(
                verifyReceipt(base64: base64, roots: [], clock: { 0 }).failure?.reason, .untrustedChain)
        }
        let (leaf, intermediate) = try Self.chainOf(try TestFixtures.text(TestFixtures.jws))
        XCTAssertThrowsError(
            try validatePair(leaf: leaf, intermediate: intermediate, anchors: [], atMillis: 1_722_945_600_000)
        ) { XCTAssertEqual(($0 as? Failure)?.reason, .untrustedChain) }
    }

    // MARK: - helpers

    /// The leaf and intermediate out of a compact JWS's `x5c` header — the two
    /// certificates `validatePair` judges.
    private static func chainOf(_ jws: String) throws -> (Certificate, Certificate) {
        let segments = jws.components(separatedBy: ".")
        let header = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(XCTUnwrap(decodeBase64URLStrict(segments[0]))))
                as? [String: Any])
        let x5c = try XCTUnwrap(header["x5c"] as? [String])
        return (try parseX5cCertificate(x5c[0]), try parseX5cCertificate(x5c[1]))
    }

    /// The two paths swift-certificates itself reads for
    /// `CertificateStore.systemTrustRoots`, plus the one a Darwin or BSD host
    /// keeps a bundle at — so the "hand the host's roots to the library" test
    /// has something to read there too.
    private static let systemTrustBundlePaths = [
        "/etc/ssl/certs/ca-certificates.crt",  // Debian, Ubuntu, Arch, Alpine
        "/etc/pki/tls/certs/ca-bundle.crt",  // Fedora
        "/etc/ssl/cert.pem",  // FreeBSD, Homebrew OpenSSL on macOS
    ]

    /// Every root in this host's trust store as DER, or an empty list where no
    /// bundle exists. Entries this X.509 parser cannot read are dropped rather
    /// than failing the test: the point is the anchors, not the bundle.
    private static func systemTrustRootDERs() -> [[UInt8]] {
        for path in systemTrustBundlePaths {
            guard let bundle = try? String(contentsOfFile: path, encoding: .utf8),
                let documents = try? PEMDocument.parseMultiple(pemString: bundle)
            else { continue }
            var roots: [[UInt8]] = []
            for document in documents where document.discriminator == "CERTIFICATE" {
                if (try? Certificate(derEncoded: document.derBytes)) != nil {
                    roots.append(document.derBytes)
                }
            }
            if !roots.isEmpty { return roots }
        }
        return []
    }

    private static var sourcesDir: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // ApplePurchaseReceiptVerifierTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // swift
            .appendingPathComponent("Sources")
            .appendingPathComponent("ApplePurchaseReceiptVerifier")
    }

    private static var packageManifest: URL {
        TestFixtures.directory.deletingLastPathComponent().appendingPathComponent("Package.swift")
    }

    private static func sourceFiles() -> [URL] {
        let enumerator = FileManager.default.enumerator(at: sourcesDir, includingPropertiesForKeys: nil)
        var files: [URL] = []
        while let url = enumerator?.nextObject() as? URL {
            if url.pathExtension == "swift" { files.append(url) }
        }
        return files.sorted { $0.path < $1.path }
    }

    /// A Swift source with its comments removed, so the ban above lands on
    /// code and not on prose that legitimately names what the code avoids.
    /// String literals are tracked (a `//` inside one is not a comment) and
    /// block comments nest, as they do in Swift.
    private static func codeStrippedOfComments(_ source: String) -> String {
        let characters = Array(source)
        var out = ""
        var index = 0
        var blockDepth = 0
        var inStringLiteral = false
        while index < characters.count {
            let character = characters[index]
            let next = index + 1 < characters.count ? characters[index + 1] : "\0"
            if blockDepth > 0 {
                if character == "/" && next == "*" {
                    blockDepth += 1
                    index += 2
                } else if character == "*" && next == "/" {
                    blockDepth -= 1
                    index += 2
                } else {
                    index += 1
                }
                continue
            }
            if inStringLiteral {
                if character == "\\" {
                    index += 2
                    continue
                }
                if character == "\"" { inStringLiteral = false }
                out.append(character)
                index += 1
                continue
            }
            if character == "/" && next == "/" {
                while index < characters.count && characters[index] != "\n" { index += 1 }
                continue
            }
            if character == "/" && next == "*" {
                blockDepth = 1
                index += 2
                continue
            }
            if character == "\"" { inStringLiteral = true }
            out.append(character)
            index += 1
        }
        return out
    }
}
