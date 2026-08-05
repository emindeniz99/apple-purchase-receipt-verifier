import Crypto
import _CryptoExtras
import Foundation
import SwiftASN1
import X509

/// One in-app purchase from a legacy app receipt (attribute 17).
public struct InAppPurchase: Sendable {
    public var quantity: Int64?
    public var productId: String?
    public var transactionId: String?
    public var originalTransactionId: String?
    public var purchaseDate: Date?
    public var originalPurchaseDate: Date?
    public var expiresDate: Date?
    public var cancellationDate: Date?
    public var webOrderLineItemId: Int64?
    public var isInIntroOfferPeriod: Int64?
}

/// A verified legacy app receipt. Only receipts returned by
/// ``ReceiptVerifier`` should be trusted.
public struct AppReceipt: Sendable {
    public var bundleId: String?
    public var bundleIdBytes: Data?
    public var appVersion: String?
    public var opaqueValue: Data?
    public var sha1Hash: Data?
    public var creationDate: Date?
    public var originalAppVersion: String?
    public var expirationDate: Date?
    public var inAppPurchases: [InAppPurchase] = []
}

/// Verifies legacy PKCS#7 app receipts completely offline against the
/// pinned Apple Inc. Root CA — the server-side port of Apple's "Validating
/// receipts on the device" procedure (PLAN.md §2.2), mirroring the Java
/// implementation. CMS parsing accepts BER (genuine Apple/Xcode receipts
/// use indefinite lengths).
public struct ReceiptVerifier: Sendable {
    private let roots: [Certificate]
    private let bundleId: String

    /// - Parameters:
    ///   - trustedRoots: pinned DER roots (production: ``appleReceiptRoots()``)
    ///   - bundleId: bundle id the receipt must carry
    public init(trustedRoots: [Data], bundleId: String) throws {
        guard !trustedRoots.isEmpty, !bundleId.isEmpty else {
            throw VerificationError(.invalidCertificate, "trustedRoots and bundleId are required")
        }
        self.roots = try trustedRoots.map { try Certificate(derEncoded: [UInt8]($0)) }
        self.bundleId = bundleId
    }

    /// Verifies a base64 receipt (the usual client transport form).
    public func verify(base64Receipt: String, deviceGuid: Data? = nil) async throws -> AppReceipt {
        guard let der = Data(base64Encoded: base64Receipt,
                             options: [.ignoreUnknownCharacters]) else {
            throw VerificationError(.invalidReceiptFormat, "receipt is not valid base64")
        }
        return try await verify(receipt: der, deviceGuid: deviceGuid)
    }

    /// Verifies a DER/BER receipt. Passing `deviceGuid` additionally
    /// enforces the device-hash binding: SHA1(guid ‖ opaqueValue ‖
    /// bundleIdBytes) must equal attribute 5 (optional — PLAN.md D4).
    public func verify(receipt: Data, deviceGuid: Data? = nil) async throws -> AppReceipt {
        let cms = try CMSReceipt(parsing: [UInt8](receipt))

        // Parsed before signature verification only to learn the creation
        // date (chain validity anchors at signing time); nothing from it is
        // trusted until the chain + signature checks pass.
        let fields = try parsePayload(cms.content)
        let at = fields.creationDate ?? Date()

        let signerCert = try cms.signerCertificate()
        var verifier = Verifier(rootCertificates: CertificateStore(roots)) {
            RFC5280Policy(validationTime: at)
        }
        let result = await verifier.validate(
            leafCertificate: signerCert,
            intermediates: CertificateStore(cms.certificates))
        if case .couldNotValidate = result {
            throw VerificationError(.invalidChain,
                "signer chain does not validate to a pinned root")
        }
        try cms.verifySignature(signerCert: signerCert)

        guard fields.bundleId == bundleId else {
            throw VerificationError(.wrongBundleId,
                "expected \(bundleId) but receipt has \(fields.bundleId ?? "nil")")
        }
        if let deviceGuid {
            try verifyDeviceHash(fields, deviceGuid: deviceGuid)
        }
        return fields
    }

    private func verifyDeviceHash(_ fields: AppReceipt, deviceGuid: Data) throws {
        guard let opaque = fields.opaqueValue, let expected = fields.sha1Hash,
              let bundleBytes = fields.bundleIdBytes else {
            throw VerificationError(.deviceHashMismatch,
                "receipt lacks the attributes needed for the device-hash check")
        }
        var input = Data()
        input.append(deviceGuid)
        input.append(opaque)
        input.append(bundleBytes)
        let computed = Data(Insecure.SHA1.hash(data: input))
        // Constant-time comparison.
        guard computed.count == expected.count,
              zip(computed, expected).reduce(0, { $0 | ($1.0 ^ $1.1) }) == 0 else {
            throw VerificationError(.deviceHashMismatch,
                "computed device hash does not match attribute 5")
        }
    }
}

// MARK: - CMS SignedData (BER-tolerant)

private struct CMSReceipt {
    let content: [UInt8]
    let certificates: [Certificate]
    let certificateNodes: [(serial: [UInt8], issuer: [UInt8])]
    let signerIssuer: [UInt8]
    let signerSerial: [UInt8]
    let digestName: String
    let signedAttrsBytes: [UInt8]?
    let messageDigest: [UInt8]?
    let signature: [UInt8]

    init(parsing bytes: [UInt8]) throws {
        let root: ASN1Node
        do {
            root = try BER.parse(bytes)
        } catch {
            throw VerificationError(.invalidReceiptFormat, "not parseable ASN.1")
        }
        do {
            let contentInfo = try Self.children(root)
            let contentType = try ASN1ObjectIdentifier(derEncoded: contentInfo[0])
            guard contentType == [1, 2, 840, 113549, 1, 7, 2] else {
                throw VerificationError(.invalidReceiptFormat, "not CMS SignedData")
            }
            let signedData = try Self.children(try Self.explicit(contentInfo[1]))

            // encapContentInfo: SEQ { OID, [0] EXPLICIT OCTET STRING }
            let encap = try Self.children(signedData[2])
            guard encap.count >= 2 else {
                throw VerificationError(.invalidReceiptFormat, "no encapsulated payload")
            }
            self.content = try Self.octetStringValue(try Self.explicit(encap[1]))

            var certificates: [Certificate] = []
            var certificateNodes: [(serial: [UInt8], issuer: [UInt8])] = []
            for node in signedData.dropFirst(3) where node.identifier.tagClass == .contextSpecific
                && node.identifier.tagNumber == 0 {
                for certNode in try Self.children(node) {
                    let der = [UInt8](certNode.encodedBytes)
                    certificates.append(try Certificate(derEncoded: der))
                    let tbs = try Self.children(try Self.children(DER.parse(der))[0])
                    var index = 0
                    if tbs[0].identifier.tagClass == .contextSpecific { index = 1 }
                    certificateNodes.append((serial: try Self.primitive(tbs[index]),
                                             issuer: [UInt8](tbs[index + 2].encodedBytes)))
                }
            }
            self.certificates = certificates
            self.certificateNodes = certificateNodes

            guard let signerInfos = signedData.last,
                  signerInfos.identifier == .set,
                  let signerInfo = try Self.children(signerInfos).first else {
                throw VerificationError(.invalidReceiptFormat, "no signer info")
            }
            let signerFields = try Self.children(signerInfo)
            let sid = try Self.children(signerFields[1])
            self.signerIssuer = [UInt8](sid[0].encodedBytes)
            self.signerSerial = try Self.primitive(sid[1])

            let digestAlgOid = try ASN1ObjectIdentifier(
                derEncoded: try Self.children(signerFields[2])[0])
            switch digestAlgOid {
            case [1, 3, 14, 3, 2, 26]: self.digestName = "sha1"
            case [2, 16, 840, 1, 101, 3, 4, 2, 1]: self.digestName = "sha256"
            default:
                throw VerificationError(.invalidReceiptFormat, "unsupported digest algorithm")
            }

            var index = 3
            if signerFields[index].identifier.tagClass == .contextSpecific
                && signerFields[index].identifier.tagNumber == 0 {
                let attrsNode = signerFields[index]
                // Signature covers the signedAttrs re-encoded as an explicit
                // SET (RFC 5652 §5.4): swap the IMPLICIT [0] tag for SET.
                var reencoded = [UInt8](attrsNode.encodedBytes)
                reencoded[0] = 0x31
                self.signedAttrsBytes = reencoded
                var digest: [UInt8]? = nil
                for attr in try Self.children(attrsNode) {
                    let parts = try Self.children(attr)
                    if try ASN1ObjectIdentifier(derEncoded: parts[0])
                        == [1, 2, 840, 113549, 1, 9, 4] {
                        digest = try Self.primitive(try Self.children(parts[1])[0])
                    }
                }
                self.messageDigest = digest
                index += 1
            } else {
                self.signedAttrsBytes = nil
                self.messageDigest = nil
            }
            index += 1 // signatureAlgorithm — RSA PKCS#1 v1.5, digest drives the hash
            self.signature = try Self.primitive(signerFields[index])
        } catch let error as VerificationError {
            throw error
        } catch {
            throw VerificationError(.invalidReceiptFormat, "malformed CMS structure")
        }
    }

    func signerCertificate() throws -> Certificate {
        for (offset, node) in certificateNodes.enumerated()
        where node.serial == signerSerial && node.issuer == signerIssuer {
            return certificates[offset]
        }
        throw VerificationError(.invalidReceiptFormat, "signer certificate not embedded")
    }

    func verifySignature(signerCert: Certificate) throws {
        guard let publicKey = _RSA.Signing.PublicKey(signerCert.publicKey) else {
            throw VerificationError(.invalidSignature, "signer key is not RSA")
        }
        let signedBytes: [UInt8]
        if let signedAttrsBytes {
            let contentDigest: [UInt8] = digestName == "sha1"
                ? [UInt8](Insecure.SHA1.hash(data: Data(content)))
                : [UInt8](SHA256.hash(data: Data(content)))
            guard let messageDigest, messageDigest == contentDigest else {
                throw VerificationError(.invalidSignature,
                    "messageDigest attribute does not match content")
            }
            signedBytes = signedAttrsBytes
        } else {
            signedBytes = content
        }
        let rsaSignature = _RSA.Signing.RSASignature(rawRepresentation: Data(signature))
        let valid: Bool
        if digestName == "sha1" {
            valid = publicKey.isValidSignature(rsaSignature,
                for: Insecure.SHA1.hash(data: Data(signedBytes)), padding: .insecurePKCS1v1_5)
        } else {
            valid = publicKey.isValidSignature(rsaSignature,
                for: SHA256.hash(data: Data(signedBytes)), padding: .insecurePKCS1v1_5)
        }
        guard valid else {
            throw VerificationError(.invalidSignature, "CMS signature check failed")
        }
    }

    static func children(_ node: ASN1Node) throws -> [ASN1Node] {
        guard case .constructed(let nodes) = node.content else {
            throw VerificationError(.invalidReceiptFormat, "expected constructed ASN.1 node")
        }
        return Array(nodes)
    }

    /// Unwraps an EXPLICIT context tag ([0] { inner }) to its inner node.
    static func explicit(_ node: ASN1Node) throws -> ASN1Node {
        let inner = try children(node)
        guard inner.count == 1 else {
            throw VerificationError(.invalidReceiptFormat, "expected single explicit content")
        }
        return inner[0]
    }

    static func primitive(_ node: ASN1Node) throws -> [UInt8] {
        guard case .primitive(let bytes) = node.content else {
            throw VerificationError(.invalidReceiptFormat, "expected primitive ASN.1 node")
        }
        return [UInt8](bytes)
    }

    /// Value bytes of an OCTET STRING, joining BER constructed chunks.
    static func octetStringValue(_ node: ASN1Node) throws -> [UInt8] {
        switch node.content {
        case .primitive(let bytes):
            return [UInt8](bytes)
        case .constructed(let chunks):
            var out: [UInt8] = []
            for chunk in chunks {
                out.append(contentsOf: try octetStringValue(chunk))
            }
            return out
        }
    }
}

// MARK: - Receipt payload (strict DER)

private let attrBundleId = 2
private let attrAppVersion = 3
private let attrOpaqueValue = 4
private let attrSha1Hash = 5
private let attrCreationDate = 12
private let attrInApp = 17
private let attrOriginalAppVersion = 19
private let attrExpirationDate = 21

private func parsePayload(_ content: [UInt8]) throws -> AppReceipt {
    var receipt = AppReceipt()
    for (type, value) in try parseAttributeSet(content) {
        switch type {
        case attrBundleId:
            receipt.bundleId = try decodeString(value)
            receipt.bundleIdBytes = Data(value)
        case attrAppVersion: receipt.appVersion = try decodeString(value)
        case attrOpaqueValue: receipt.opaqueValue = Data(value)
        case attrSha1Hash: receipt.sha1Hash = Data(value)
        case attrCreationDate: receipt.creationDate = try decodeDate(value)
        case attrInApp: receipt.inAppPurchases.append(try parseInApp(value))
        case attrOriginalAppVersion: receipt.originalAppVersion = try decodeString(value)
        case attrExpirationDate: receipt.expirationDate = try decodeDate(value)
        default: break // receipts carry undocumented attribute types
        }
    }
    return receipt
}

private func parseInApp(_ value: [UInt8]) throws -> InAppPurchase {
    var purchase = InAppPurchase()
    for (type, v) in try parseAttributeSet(value) {
        switch type {
        case 1701: purchase.quantity = try decodeInteger(v)
        case 1702: purchase.productId = try decodeString(v)
        case 1703: purchase.transactionId = try decodeString(v)
        case 1704: purchase.purchaseDate = try decodeDate(v)
        case 1705: purchase.originalTransactionId = try decodeString(v)
        case 1706: purchase.originalPurchaseDate = try decodeDate(v)
        case 1708: purchase.expiresDate = try decodeDate(v)
        case 1711: purchase.webOrderLineItemId = try decodeInteger(v)
        case 1712: purchase.cancellationDate = try decodeDate(v)
        case 1719: purchase.isInIntroOfferPeriod = try decodeInteger(v)
        default: break
        }
    }
    return purchase
}

private func parseAttributeSet(_ der: [UInt8]) throws -> [(Int, [UInt8])] {
    let root: ASN1Node
    do {
        root = try DER.parse(der)
    } catch {
        throw VerificationError(.invalidReceiptFormat, "attribute set is not valid ASN.1")
    }
    guard root.identifier == .set else {
        throw VerificationError(.invalidReceiptFormat, "attribute set is not an ASN.1 SET")
    }
    var attributes: [(Int, [UInt8])] = []
    for child in try CMSReceipt.children(root) {
        let fields = try CMSReceipt.children(child)
        guard child.identifier == .sequence, fields.count >= 3,
              fields[0].identifier == .integer, fields[2].identifier == .octetString else {
            throw VerificationError(.invalidReceiptFormat, "malformed receipt attribute")
        }
        attributes.append((try intValue(try CMSReceipt.primitive(fields[0])),
                           try CMSReceipt.primitive(fields[2])))
    }
    return attributes
}

private func intValue(_ contents: [UInt8]) throws -> Int {
    guard contents.count <= 6 else {
        throw VerificationError(.invalidReceiptFormat, "attribute integer out of range")
    }
    if let first = contents.first, first >= 0x80 {
        throw VerificationError(.invalidReceiptFormat, "negative receipt integer")
    }
    return contents.reduce(0) { $0 * 256 + Int($1) }
}

private func parseNested(_ der: [UInt8]) throws -> ASN1Node {
    do {
        return try DER.parse(der)
    } catch {
        throw VerificationError(.invalidReceiptFormat, "attribute value is not valid ASN.1")
    }
}

private func decodeString(_ der: [UInt8]) throws -> String {
    let node = try parseNested(der)
    guard node.identifier == .utf8String || node.identifier == .ia5String,
          let text = String(bytes: try CMSReceipt.primitive(node), encoding: .utf8) else {
        throw VerificationError(.invalidReceiptFormat, "attribute value is not an ASN.1 string")
    }
    return text
}

private func decodeInteger(_ der: [UInt8]) throws -> Int64 {
    let node = try parseNested(der)
    guard node.identifier == .integer else {
        throw VerificationError(.invalidReceiptFormat, "attribute value is not an ASN.1 integer")
    }
    return Int64(try intValue(try CMSReceipt.primitive(node)))
}

/// RFC 3339 date in an IA5String; empty means absent (real receipts do this).
private func decodeDate(_ der: [UInt8]) throws -> Date? {
    let text = try decodeString(der)
    if text.isEmpty { return nil }
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    if let date = formatter.date(from: text) { return date }
    formatter.formatOptions = [.withInternetDateTime]
    guard let date = formatter.date(from: text) else {
        throw VerificationError(.invalidReceiptFormat, "unparseable receipt date: \(text)")
    }
    return date
}
