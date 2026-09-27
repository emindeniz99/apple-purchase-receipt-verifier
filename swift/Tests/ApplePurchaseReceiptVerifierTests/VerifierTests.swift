import Crypto
import Foundation
import SwiftASN1
import X509
import XCTest
@testable import ApplePurchaseReceiptVerifier

/// The fixture tree and the verifiers the tests below build from it.
enum TestFixtures {
    static var directory: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()  // ApplePurchaseReceiptVerifierTests
            .deletingLastPathComponent()  // Tests
            .deletingLastPathComponent()  // swift
            .deletingLastPathComponent()  // project root
            .appendingPathComponent("fixtures")
    }

    static func bytes(_ path: String) throws -> [UInt8] {
        [UInt8](try Data(contentsOf: directory.appendingPathComponent(path)))
    }

    /// A text fixture without its trailing newline.
    static func text(_ path: String) throws -> String {
        String(decoding: try Data(contentsOf: directory.appendingPathComponent(path)), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// A verifier anchored on the DER fixtures at `roots`, reading a fixed
    /// clock when one is given.
    static func verifier(roots: [String], clock: Int64? = nil) throws -> ApplePurchaseReceiptVerifier.Verifier {
        var builder = try Config.builder().roots(roots.map { try bytes($0) })
        if let clock { builder = builder.clock { clock } }
        return ApplePurchaseReceiptVerifier.Verifier(config: try builder.build())
    }

    /// The generated 0.7 receipt and the root that anchors it. Its bag holds
    /// signer, WWDR intermediate and root, in that order.
    static let receipt = "generated-0.7/receipt.der"
    static let receiptRoot = "generated-0.7/receipt-root.der"
    static let jws = "generated/transaction.jws"
    static let jwsRoot = "generated/jws-root.der"
}

func base64URL(_ bytes: [UInt8]) -> String {
    Data(bytes).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

/// What the shared cases in fixtures/cases-0.7.json do not pin: reader
/// details a vector file cannot express, the bundled roots, and dependency
/// regressions that need more than one call to show.
final class VerifierTests: XCTestCase {
    /// An x5c entry starting with U+FEFF is outside the base64 alphabet and
    /// must be INVALID_CERTIFICATE, like any other character there. A header
    /// parsed by a reader that drops a leading mark from a string value
    /// (Foundation's `JSONSerialization` does, always on Darwin) decodes the
    /// genuine leaf behind it, and the answer becomes whatever the signature
    /// check says; for a header signed in its mutated state, that would be a
    /// verified JWS. Here the header is not re-signed, so such a reader
    /// answers INVALID_SIGNATURE and only the reason tells the two apart.
    func testRejectsAnX5cEntryStartingWithAByteOrderMark() throws {
        let segments = try TestFixtures.text(TestFixtures.jws).components(separatedBy: ".")
        var header = String(decoding: try XCTUnwrap(decodeBase64URLStrict(segments[0])), as: UTF8.self)
        let x5c = try XCTUnwrap(header.range(of: "\"x5c\""))
        let firstEntry = try XCTUnwrap(header.range(of: "\"", range: x5c.upperBound..<header.endIndex))
        header.insert("\u{FEFF}", at: firstEntry.upperBound)
        let jws = "\(base64URL(Array(header.utf8))).\(segments[1]).\(segments[2])"
        let result = try TestFixtures.verifier(roots: [TestFixtures.jwsRoot]).verifySignedData(jws: jws)
        XCTAssertEqual(result.failure?.reason, .invalidCertificate, result.failure?.message ?? "verified")
    }

    /// An `x5c[1]` whose 262,144-bit RSA key BoringSSL refuses, under a root
    /// nobody pinned (docs/design/0.7-hardening-parity.md, change 1). The
    /// shared case `signed-data/reject-untrusted-oversized-x5c` pins the
    /// verdict, UNTRUSTED_CHAIN; this pins why it is that verdict. Building
    /// the certificate decodes its key and fails, so the answer could only
    /// have been INVALID_CERTIFICATE had the key been decoded: its slices are
    /// all the chain check read, and no pinned root verified them.
    func testAnUntrustedX5cIntermediateIsNeverBuilt() throws {
        let jws = try TestFixtures.text("generated-0.7/jws-untrusted-oversized-x5c.jws")
        let header = try XCTUnwrap(
            try JSONSerialization.jsonObject(
                with: Data(XCTUnwrap(decodeBase64URLStrict(jws.components(separatedBy: ".")[0])))) as? [String: Any])
        let x5c = try XCTUnwrap(header["x5c"] as? [String])
        let intermediate = try sliceX5cCertificate(x5c[1])
        XCTAssertNil(try? Certificate(derEncoded: intermediate.der), "the premise: building it decodes a refused key")
        let roots = try Config.builder().roots([try TestFixtures.bytes("generated-0.7/hardening-jws-root.der")]).build()
        XCTAssertFalse(roots.roots.contains { signatureVerifies(intermediate, by: $0) })
        let result = ApplePurchaseReceiptVerifier.Verifier(config: roots).verifySignedData(jws: jws)
        XCTAssertEqual(result.failure?.reason, .untrustedChain)
    }

    /// `Config.defaults()` carries all three published Apple roots (PLAN
    /// D15): Apple's guidance is to trust every root on its PKI page, and a
    /// chain re-anchored on the one a trimmed set left out would fail closed,
    /// silently, in production.
    func testTheDefaultsCarryAllThreePublishedAppleRoots() throws {
        let roots = Config.defaults().roots
        XCTAssertEqual(roots.count, 3)
        let fromCerts = try ["AppleIncRootCertificate.cer", "AppleRootCA-G2.cer", "AppleRootCA-G3.cer"].map {
            try Certificate(derEncoded: [UInt8](Data(contentsOf: TestFixtures.directory
                .deletingLastPathComponent().appendingPathComponent("certs").appendingPathComponent($0))))
        }
        XCTAssertEqual(Set(roots.map(\.subject.description)), Set(fromCerts.map(\.subject.description)))
        for root in fromCerts {
            XCTAssertTrue(roots.contains(root), "\(root.subject) is not among the defaults")
        }
    }

    /// One byte of the signer certificate's modulus, made even. The DER stays
    /// well formed so swift-asn1 passes it through to BoringSSL, which
    /// rejects the key — and swift-crypto before 4.5.1 freed the EVP_PKEY in
    /// its catch block and again in deinit, corrupting the heap and aborting
    /// the process before any chain or signature check. This test crashes the
    /// whole runner rather than failing if that floor is ever lowered, which
    /// is the loudest signal available for a double free.
    ///
    /// Repeated because a double free does not abort every time: a single
    /// call returns cleanly often enough that a one-shot test reports success
    /// against a vulnerable dependency (0.6 measured it: with the floor
    /// lowered to swift-crypto 3.15.1 the one-shot version passed and this
    /// one killed the runner with signal 5). The shared case
    /// `receipt/reject-signer-on-an-unimplemented-curve` pins the verdict for
    /// an unusable signer key once; this pins the absence of the double free.
    func testASignerWhoseRsaKeyBoringSSLRefusesIsAVerdictNotACrash() throws {
        var mutated = try TestFixtures.bytes(TestFixtures.receipt)
        XCTAssertEqual(mutated[1121], 0x89, "fixture layout changed; re-locate the signer's last modulus byte")
        XCTAssertEqual(Array(mutated[1122..<1127]), [0x02, 0x03, 0x01, 0x00, 0x01], "the exponent follows it")
        mutated[1121] = 0x00
        let base64 = standardBase64Encode(mutated)
        let verifier = try TestFixtures.verifier(roots: [TestFixtures.receiptRoot])
        for _ in 0..<200 {
            let result = verifier.verifyReceipt(base64: base64)
            XCTAssertEqual(result.failure?.reason, .invalidCertificate)
        }
    }

    /// A SEQUENCE holding only the SignedData OID, the input that used to be
    /// an uncatchable out-of-range trap in the CMS walk: MALFORMED, and 21002
    /// at the endpoint.
    func testATruncatedContentInfoIsMalformedNotATrap() throws {
        let truncated: [UInt8] = [0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02]
        let verifier = try TestFixtures.verifier(roots: [TestFixtures.receiptRoot])
        let base64 = standardBase64Encode(truncated)
        XCTAssertEqual(verifier.verifyReceipt(base64: base64).failure?.reason, .malformed)
        XCTAssertEqual(
            verifier.verifyReceiptEndpoint(environment: .sandbox, requestJson: #"{"receipt-data":"\#(base64)"}"#),
            #"{"status":21002}"#)
    }
}

/// verifyReceipt-compatible answers the shared endpoint cases do not spell
/// out.
final class VerifyReceiptEndpointTests: XCTestCase {
    func verifier() throws -> ApplePurchaseReceiptVerifier.Verifier {
        try TestFixtures.verifier(roots: [TestFixtures.receiptRoot])
    }

    func receiptBase64() throws -> String {
        standardBase64Encode(try TestFixtures.bytes(TestFixtures.receipt))
    }

    /// Apple sends `is_in_intro_offer_period` as the string "true" or
    /// "false", not a JSON boolean; a client decoding Apple's response type
    /// breaks on a boolean. The shared endpoint cases pin `is_trial_period`
    /// this way but not this key.
    func testRendersIsInIntroOfferPeriodAsAString() throws {
        let receiptData = try TestFixtures.text("public-receipts/receipt-sandbox-g5.b64")
        let verifier = ApplePurchaseReceiptVerifier.Verifier(config: .defaults())
        let body = verifier.verifyReceiptEndpoint(
            environment: .sandbox, requestJson: #"{"receipt-data":"\#(receiptData)"}"#)
        XCTAssertTrue(body.contains(#""is_in_intro_offer_period":"false""#), body)
        let parsed = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(body.utf8)) as? [String: Any])
        let receipt = try XCTUnwrap(parsed["receipt"] as? [String: Any])
        let purchases = try XCTUnwrap(receipt["in_app"] as? [[String: Any]])
        XCTAssertFalse(purchases.isEmpty)
        for purchase in purchases {
            XCTAssertTrue(purchase["is_in_intro_offer_period"] is String, purchase.description)
        }
    }

    /// Bodies that are not a JSON object at all, beyond the array, null and
    /// scalar the shared cases carry: empty, not JSON, truncated, and an
    /// object wrapped in an array. Each is a client error, 21002, and never
    /// an answer about a receipt.
    func testAnswers21002ForABodyThatIsNotAnObject() throws {
        let verifier = try verifier()
        for body in ["", "not json", "{", "[{\"receipt-data\":\"x\"}]", "\"receipt\"", "true"] {
            XCTAssertEqual(
                verifier.verifyReceiptEndpoint(environment: .sandbox, requestJson: body), #"{"status":21002}"#, body)
        }
    }

    /// Apple answers 21002 to a receipt-data string that starts with a
    /// byte-order mark (docs/evidence/2026-09-23-verifyreceipt-base64.md).
    /// The shared case writes the mark as raw UTF-8; a JSON escape is the same
    /// string once parsed, so both escaped spellings must get the same
    /// answer. A reader that drops the mark (Foundation's does) lets the
    /// genuine base64 behind it verify.
    func testRefusesReceiptDataStartingWithAnEscapedByteOrderMark() throws {
        let verifier = try verifier()
        let base64 = try receiptBase64()
        XCTAssertEqual(
            verifier.verifyReceiptEndpoint(environment: .sandbox, requestJson: #"{"receipt-data":"\#(base64)"}"#)
                .hasPrefix(#"{"status":0,"#), true, "the control must verify")
        for mark in ["\u{FEFF}", "\\ufeff", "\\uFEFF"] {
            XCTAssertEqual(
                verifier.verifyReceiptEndpoint(
                    environment: .sandbox, requestJson: "{\"receipt-data\":\"\(mark)\(base64)\"}"),
                #"{"status":21002}"#, mark)
        }
    }
}

// MARK: - the top-down walk over the certificate bag

/// The certificate bag is unsigned and reaches the chain walk before any
/// signature is checked, so what the walk takes from it, and how much of it
/// it looks at, is load-bearing. Every receipt here is the genuine
/// fixtures/generated-0.7/receipt.der with a different certificate bag
/// spliced in: the file is BER with indefinite lengths, so the splice needs
/// no ancestor length fixups, and the CMS signature covers the content rather
/// than the bag.
final class ChainBuildingBoundTests: XCTestCase {
    static let notValidBefore = Date(timeIntervalSince1970: 1_577_836_800)  // 2020-01-01
    static let notValidAfter = Date(timeIntervalSince1970: 2_051_222_400)  // 2035-01-01

    func verify(_ receipt: [UInt8]) throws -> ApplePurchaseReceiptVerifier.VerificationResult<ReceiptPayload> {
        try TestFixtures.verifier(roots: [TestFixtures.receiptRoot]).verifyReceipt(base64: standardBase64Encode(receipt))
    }

    func genuineReceipt() throws -> [UInt8] { try TestFixtures.bytes(TestFixtures.receipt) }

    // MARK: certificate bag surgery

    private static let contextZero = ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)

    private static func children(_ node: ASN1Node) throws -> [ASN1Node] {
        guard case .constructed(let nodes) = node.content else { throw CocoaError(.formatting) }
        return Array(nodes)
    }

    /// The SignedData `certificates [0]` node of a receipt.
    private static func certificatesNode(_ receipt: [UInt8]) throws -> ASN1Node {
        let contentInfo = try children(try BER.parse(receipt))
        let signedData = try children(try children(contentInfo[1])[0])
        guard
            let node = signedData.dropFirst(3).first(where: {
                $0.identifier.tagClass == .contextSpecific && $0.identifier.tagNumber == 0
            })
        else { throw CocoaError(.formatting) }
        return node
    }

    static func embeddedCertificates(of receipt: [UInt8]) throws -> [Certificate] {
        try children(try certificatesNode(receipt)).map { try Certificate(derEncoded: [UInt8]($0.encodedBytes)) }
    }

    /// - Parameter appendingRawDER: extra elements written into the
    ///   `certificates [0]` node verbatim, after the encoded certificates.
    ///   Well-formed ASN.1 that is not a certificate goes in this way — a
    ///   `Certificate` value cannot express it.
    static func replacingCertificates(
        of receipt: [UInt8], with certificates: [Certificate], appendingRawDER rawDER: [[UInt8]] = []
    ) throws -> [UInt8] {
        let range = try certificatesNode(receipt).encodedBytes
        var serializer = DER.Serializer()
        try serializer.appendConstructedNode(identifier: contextZero) { certs in
            for certificate in certificates {
                try certs.serialize(certificate)
            }
            for der in rawDER {
                certs.serializeRawBytes(der)
            }
        }
        // Explicit Arrays: Swift 6.1 (the CI floor) cannot type
        // ArraySlice + [UInt8] + ArraySlice, 6.3 can.
        return Array(receipt[..<range.startIndex]) + serializer.serializedBytes + Array(receipt[range.endIndex...])
    }

    static func certificate(
        subject: DistinguishedName, issuer: DistinguishedName, serial: Certificate.SerialNumber,
        key: Certificate.PrivateKey, signedBy issuerKey: Certificate.PrivateKey, dnsName: String? = nil
    ) throws -> Certificate {
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

    /// Self-signed padding no anchor vouches for.
    static func padding(_ count: Int, serialPrefix: UInt8) throws -> [Certificate] {
        try (0..<count).map { index in
            let key = Certificate.PrivateKey(P256.Signing.PrivateKey())
            return try certificate(
                subject: try name("Padding \(index)"), issuer: try name("Padding \(index)"),
                serial: .init(bytes: [serialPrefix, UInt8(index)]), key: key, signedBy: key)
        }
    }

    /// A leaf carrying the genuine signer's issuer and serial, so the CMS
    /// signer id resolves to it, followed by `count` certificates that all
    /// claim that issuer's name and share one key, so each is a
    /// signature-valid parent of every other.
    static func fanout(count: Int, signerOf genuine: [Certificate]) throws -> [Certificate] {
        let shared = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let leaf = try certificate(
            subject: try name("Fanout Leaf"), issuer: genuine[0].issuer, serial: genuine[0].serialNumber,
            key: Certificate.PrivateKey(P256.Signing.PrivateKey()), signedBy: shared)
        return [leaf]
            + (try (0..<count).map { index in
                try certificate(
                    subject: genuine[0].issuer, issuer: genuine[0].issuer,
                    serial: .init(bytes: [0x10, UInt8(index)]), key: shared, signedBy: shared,
                    dnsName: "ca\(index).example")
            })
    }

    // MARK: the bounds

    /// The certificate count is judged before any entry is decoded: ten
    /// genuine-shaped certificates and an eleventh that is well-formed ASN.1
    /// and not a certificate answer with the bound's message, not the
    /// unreadable-entry one. Both are MALFORMED, so only the message tells
    /// which check ran first; a decode-first order would spend decoding work
    /// on a bag that is refused anyway.
    func testTheCountBoundIsAppliedBeforeAnyCertificateIsDecoded() throws {
        let genuine = try genuineReceipt()
        let certificates = try Self.embeddedCertificates(of: genuine)
        let ten = try Self.padding(maxEmbeddedCertificates - certificates.count, serialPrefix: 0x9B) + certificates
        XCTAssertEqual(ten.count, maxEmbeddedCertificates)
        XCTAssertTrue(try verify(Self.replacingCertificates(of: genuine, with: ten)).verified, "ten must verify")
        // SEQUENCE { OCTET STRING } — parses as ASN.1, decodes as nothing.
        let garbage: [UInt8] = [0x30, 0x06, 0x04, 0x04, 0xDE, 0xAD, 0xBE, 0xEF]
        let failure = try verify(Self.replacingCertificates(of: genuine, with: ten, appendingRawDER: [garbage])).failure
        XCTAssertEqual(failure?.reason, .malformed)
        XCTAssertTrue(failure?.message.contains("embeds 11 certificates") == true, failure?.message ?? "")
    }

    /// The same order, seen from the other side: a bag over the bound that
    /// also omits the signer answers with the bound, not with "signer
    /// certificate not embedded".
    func testTheCountGuardRunsBeforeTheSignerIsResolved() throws {
        let genuine = try genuineReceipt()
        let failure = try verify(
            Self.replacingCertificates(of: genuine, with: Self.padding(maxEmbeddedCertificates + 1, serialPrefix: 0x70))
        ).failure
        XCTAssertEqual(failure?.reason, .malformed)
        XCTAssertTrue(
            failure?.message.contains("maximum of \(maxEmbeddedCertificates)") == true, failure?.message ?? "")
    }

    /// An embedded entry that is an empty or childless SEQUENCE: the
    /// identity read that lets an unreadable signer be named used to index
    /// `[0]` into it and trap (found by the `receipt-der` fuzz target). It is
    /// an unreadable stranger the SignerInfo does not name: MALFORMED.
    func testAnEmptySequenceInTheCertificateBagIsAMalformedReceiptNotATrap() throws {
        let genuine = try genuineReceipt()
        let certificates = try Self.embeddedCertificates(of: genuine)
        for entry: [UInt8] in [[0x30, 0x00], [0x30, 0x02, 0x30, 0x00], [0x30, 0x02, 0x05, 0x00]] {
            let receipt = try Self.replacingCertificates(of: genuine, with: certificates, appendingRawDER: [entry])
            XCTAssertEqual(try verify(receipt).failure?.reason, .malformed, "entry \(entry)")
        }
    }

    /// A bag that stops at the intermediate, with the root coming from the
    /// pinned set, verifies: the path ends as soon as the current
    /// certificate is issued by a pinned anchor, as in every other port.
    func testAcceptsAReceiptWhoseEmbeddedBagStopsAtTheIntermediate() throws {
        let genuine = try genuineReceipt()
        let certificates = try Self.embeddedCertificates(of: genuine)
        XCTAssertEqual(certificates.count, 3)
        let result = try verify(Self.replacingCertificates(of: genuine, with: Array(certificates.prefix(2))))
        XCTAssertTrue(result.verified, result.failure?.description ?? "")
    }

    /// A self-signed certificate that merely borrows the intermediate's
    /// subject name must not displace the real intermediate, at any position
    /// in the bag: the walk selects by signature, not by name.
    func testAcceptsAGenuineReceiptCarryingAnIssuerNameCollisionAtAnyIndex() throws {
        let genuine = try genuineReceipt()
        let certificates = try Self.embeddedCertificates(of: genuine)
        let key = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let decoy = try Self.certificate(
            subject: certificates[0].issuer, issuer: certificates[0].issuer,
            serial: .init(bytes: [0xDE, 0xC0]), key: key, signedBy: key)
        for index in 0...certificates.count {
            var bag = certificates
            bag.insert(decoy, at: index)
            let result = try verify(Self.replacingCertificates(of: genuine, with: bag))
            XCTAssertTrue(result.verified, "decoy at index \(index): \(result.failure?.description ?? "")")
        }
    }

    /// Decoys that carry the real intermediate's public KEY, under another
    /// name or under its very name, issued by an attacker's root. Each did,
    /// as far as a signature check can tell, sign the leaf. 0.6 walked up
    /// from the leaf and took the name-and-key clone when it sat ahead of the
    /// real intermediate, rejecting this valid receipt from bag positions 0
    /// and 1. The top-down walk admits a certificate only once a pinned root
    /// has vouched for it, and no pinned root vouches for either clone, so
    /// the genuine receipt verifies at every position — the answer Java
    /// always gave.
    func testAcceptsAGenuineReceiptCarryingAKeyCloneAtAnyIndex() throws {
        let genuine = try genuineReceipt()
        let certificates = try Self.embeddedCertificates(of: genuine)
        XCTAssertEqual(certificates[0].issuer, certificates[1].subject)
        let attacker = Certificate.PrivateKey(P256.Signing.PrivateKey())
        for (label, subject) in [("key only", try Self.name("Key Clone")), ("name and key", certificates[1].subject)] {
            let clone = try Certificate(
                version: .v3, serialNumber: .init(bytes: [0xC1, 0x0F]), publicKey: certificates[1].publicKey,
                notValidBefore: Self.notValidBefore, notValidAfter: Self.notValidAfter,
                issuer: try Self.name("Attacker Root"), subject: subject,
                extensions: try Certificate.Extensions { BasicConstraints.isCertificateAuthority(maxPathLength: nil) },
                issuerPrivateKey: attacker)
            for index in 0...certificates.count {
                var bag = certificates
                bag.insert(clone, at: index)
                let result = try verify(Self.replacingCertificates(of: genuine, with: bag))
                XCTAssertTrue(result.verified, "\(label) clone at index \(index): \(result.failure?.description ?? "")")
            }
        }
    }

    /// Nine self-issued certificates sharing one key, each a signature-valid
    /// parent of every other, under a leaf that claims the genuine signer's
    /// identity. Handed to a bottom-up path search as intermediates, a bag
    /// like this cost 148.8 s through 0.6's entry point before its walk was
    /// bounded. No pinned root vouches for any of them, so the top-down walk
    /// admits none and the answer is UNTRUSTED_CHAIN without a search.
    func testRejectsAFanoutOfSelfIssuedCertificatesWithoutSearchingIt() throws {
        let genuine = try genuineReceipt()
        let receipt = try Self.replacingCertificates(
            of: genuine, with: Self.fanout(count: 9, signerOf: Self.embeddedCertificates(of: genuine)))
        let started = Date()
        XCTAssertEqual(try verify(receipt).failure?.reason, .untrustedChain)
        XCTAssertLessThan(-started.timeIntervalSinceNow, 2.0)
    }

    /// A signature cycle among the embedded certificates, in both shapes it
    /// comes in: leaf signed by A, A signed by B, B signed by A, with the
    /// issuer names chaining inside the bag or pointing outside it. Neither
    /// reaches a pinned root, so neither can loop and both are refused.
    func testRejectsASignatureCycleAmongTheEmbeddedCertificates() throws {
        let genuine = try genuineReceipt()
        let certificates = try Self.embeddedCertificates(of: genuine)
        let keyA = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let keyB = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let leaf = try Self.certificate(
            subject: try Self.name("Cycle Leaf"), issuer: certificates[0].issuer, serial: certificates[0].serialNumber,
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
            XCTAssertEqual(
                try verify(Self.replacingCertificates(of: genuine, with: bag)).failure?.reason, .untrustedChain, shape)
        }
    }
}
