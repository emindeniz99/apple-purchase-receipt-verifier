import Crypto
import Foundation
import SwiftASN1
@_spi(CMS) import X509
import _CryptoExtras

/// A receipt PKI minted at test time, for tests whose subject is the payload
/// grammar. The full payload parse runs only after the chain and the CMS
/// signature have passed, so a payload spliced into a genuine receipt stops at
/// INVALID_SIGNATURE (or INVALID_CHAIN, when the splice makes the creation
/// date unusable) and never reaches the parser. Signing it here, under a chain
/// the test then trusts, is what lets such a test keep reaching it.
///
/// Valid 2024-01-01 to 2050-01-01, the window the shared generated fixtures
/// use, so "now" and every creation date the tests write fall inside it.
struct TestReceiptPki {
    let root: Certificate
    let intermediate: Certificate
    let leaf: Certificate
    private let leafKey: Certificate.PrivateKey

    static let notValidBefore = Date(timeIntervalSince1970: 1_704_067_200)  // 2024-01-01
    static let notValidAfter = Date(timeIntervalSince1970: 2_524_608_000)  // 2050-01-01

    init() throws {
        let rootKey = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let intermediateKey = Certificate.PrivateKey(P256.Signing.PrivateKey())
        leafKey = Certificate.PrivateKey(try _RSA.Signing.PrivateKey(keySize: .bits2048))
        let rootName = try DistinguishedName { CommonName("Test Receipt Root") }
        let intermediateName = try DistinguishedName { CommonName("Test Receipt CA") }
        root = try Self.certificate(
            subject: rootName, issuer: rootName, serial: 1, key: rootKey, signedBy: rootKey,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
            })
        intermediate = try Self.certificate(
            subject: intermediateName, issuer: rootName, serial: 2, key: intermediateKey, signedBy: rootKey,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
            })
        // 1.2.840.113635.100.6.11.1, the Apple receipt-signing marker.
        var leafExtensions = Certificate.Extensions()
        try leafExtensions.append(
            Certificate.Extension(oid: [1, 2, 840, 113635, 100, 6, 11, 1], critical: false, value: [0x05, 0x00]))
        leaf = try Self.certificate(
            subject: try DistinguishedName { CommonName("Test Receipt Signing") }, issuer: intermediateName,
            serial: 3, key: leafKey, signedBy: intermediateKey, extensions: leafExtensions)
    }

    /// The anchor to trust, as the DER a verifier takes.
    var rootDer: Data {
        var serializer = DER.Serializer()
        try! serializer.serialize(root)
        return Data(serializer.serializedBytes)
    }

    /// A CMS SignedData the leaf really signed over `payload`, with the
    /// payload attached and the intermediate embedded.
    func sign(_ payload: [UInt8]) throws -> Data {
        Data(
            try CMS.sign(
                payload, additionalIntermediateCertificates: [intermediate], certificate: leaf,
                privateKey: leafKey, detached: false))
    }

    private static func certificate(
        subject: DistinguishedName, issuer: DistinguishedName, serial: Int,
        key: Certificate.PrivateKey, signedBy issuerKey: Certificate.PrivateKey,
        extensions: Certificate.Extensions
    ) throws -> Certificate {
        try Certificate(
            version: .v3, serialNumber: .init(bytes: [UInt8(serial)]), publicKey: key.publicKey,
            notValidBefore: notValidBefore, notValidAfter: notValidAfter,
            issuer: issuer, subject: subject, extensions: extensions, issuerPrivateKey: issuerKey)
    }
}
