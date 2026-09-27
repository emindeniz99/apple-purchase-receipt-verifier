import Crypto
import _CryptoExtras
import Foundation
import SwiftASN1
import X509

/// Verifying a CMS `SignerInfo` signature against a receipt signer's public
/// key: any digest and signature algorithm this library's crypto
/// dependencies (swift-crypto, `_CryptoExtras`) implement, never a
/// hand-written primitive (#160: "any receipt signer algorithm",
/// docs/design/0.7-api.md). The signer is already
/// pinned to an Apple root and carries Apple's receipt-signing marker before
/// this runs, so a change of algorithm on Apple's side does not reject
/// genuine receipts.
///
/// Digests: MD5 (Q15 — RSA binds the digest inside the signature, so a
/// relabelling attack still needs a genuine Apple signature plus a
/// collision), SHA-1, SHA-256, SHA-384, SHA-512. SHA-224 is not implemented:
/// swift-crypto exposes no SHA-224 hash function, so a signer that used it
/// fails as an unsupported digest, exactly as an algorithm this crate's
/// crypto dependencies do not implement.
///
/// Signature schemes: RSASSA-PKCS1-v1_5, RSASSA-PSS (`_CryptoExtras`), ECDSA
/// on P-256 and P-384 (Ed25519 is not a receipt-signing algorithm Apple
/// uses, so it is not wired in here, though the underlying certificate
/// parser accepts it for the certificate chain itself).
enum ReceiptDigest {
    case md5, sha1, sha256, sha384, sha512

    func hash(_ bytes: [UInt8]) -> [UInt8] {
        switch self {
        case .md5: return Array(Insecure.MD5.hash(data: bytes))
        case .sha1: return Array(Insecure.SHA1.hash(data: bytes))
        case .sha256: return Array(SHA256.hash(data: bytes))
        case .sha384: return Array(SHA384.hash(data: bytes))
        case .sha512: return Array(SHA512.hash(data: bytes))
        }
    }
}

/// The digest OIDs this library implements, dotted string to ``ReceiptDigest``.
func digestAlgorithm(oid: String) -> ReceiptDigest? {
    switch oid {
    case "1.2.840.113549.2.5": return .md5
    case "1.3.14.3.2.26": return .sha1
    case "2.16.840.1.101.3.4.2.1": return .sha256
    case "2.16.840.1.101.3.4.2.2": return .sha384
    case "2.16.840.1.101.3.4.2.3": return .sha512
    default: return nil  // includes SHA-224 (2.16.840.1.101.3.4.2.4): unimplemented
    }
}

let oidRSAEncryption = "1.2.840.113549.1.1.1"
let oidRSASSAPSS = "1.2.840.113549.1.1.10"
let oidECPublicKey = "1.2.840.10045.2.1"

/// A signature algorithm OID that NAMES a specific digest (rather than
/// leaving it to the CMS `digestAlgorithm` field), and the digest it names.
/// Used to refuse a signer whose `signatureAlgorithm` and `digestAlgorithm`
/// disagree — the relabelling defence both the Java and Rust reviews landed
/// on (docs/evidence review, "Disagreements" item 6): `rsaEncryption` and
/// `id-ecPublicKey` are generic and take whatever `digestAlgorithm` states;
/// every other OID here must match it exactly.
func namedDigest(signatureAlgorithmOID oid: String) -> ReceiptDigest? {
    switch oid {
    case "1.2.840.113549.1.1.4": return .md5
    case "1.2.840.113549.1.1.5": return .sha1
    case "1.2.840.113549.1.1.11": return .sha256
    case "1.2.840.113549.1.1.12": return .sha384
    case "1.2.840.113549.1.1.13": return .sha512
    case "1.2.840.10045.4.1": return .sha1
    case "1.2.840.10045.4.3.2": return .sha256
    case "1.2.840.10045.4.3.3": return .sha384
    case "1.2.840.10045.4.3.4": return .sha512
    default: return nil
    }
}

/// Verifies a CMS `SignerInfo` signature over `signedBytes` (the content
/// itself, or the re-encoded signed attributes), using `signer`'s public
/// key, `digestAlgorithmOID` (the CMS `digestAlgorithm` field) and
/// `signatureAlgorithmOID` (the CMS `signatureAlgorithm` field).
///
/// Returns `false` for a digest or a key/algorithm pairing this library does
/// not implement — never a crash — which the caller reports as
/// ``Reason/invalidSignature``.
func verifySignerSignature(
    signer: Certificate, digestAlgorithmOID: String, signatureAlgorithmOID: String,
    signature: [UInt8], signedBytes: [UInt8]
) -> Bool {
    guard let digest = digestAlgorithm(oid: digestAlgorithmOID) else { return false }
    // A signature algorithm that names its own hash must agree with
    // digestAlgorithm — RFC 5652 does not allow the two to disagree, and
    // silently preferring one would let an attacker relabel a signature onto
    // a different digest's algorithm identifier.
    if let named = namedDigest(signatureAlgorithmOID: signatureAlgorithmOID), named != digest {
        return false
    }
    switch signatureAlgorithmOID {
    case oidRSAEncryption, "1.2.840.113549.1.1.4", "1.2.840.113549.1.1.5", "1.2.840.113549.1.1.11",
        "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13":
        return verifyRSAPKCS1(signer: signer, digest: digest, signature: signature, signedBytes: signedBytes)
    case oidRSASSAPSS:
        return verifyRSAPSS(signer: signer, digest: digest, signature: signature, signedBytes: signedBytes)
    case oidECPublicKey, "1.2.840.10045.4.1", "1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3",
        "1.2.840.10045.4.3.4":
        return verifyECDSA(signer: signer, digest: digest, signature: signature, signedBytes: signedBytes)
    default:
        return false
    }
}

private func verifyRSAPKCS1(
    signer: Certificate, digest: ReceiptDigest, signature: [UInt8], signedBytes: [UInt8]
) -> Bool {
    guard let publicKey = _RSA.Signing.PublicKey(signer.publicKey) else { return false }
    let rsaSignature = _RSA.Signing.RSASignature(rawRepresentation: signature)
    return verifyRSA(publicKey, rsaSignature, digest, signedBytes, padding: .insecurePKCS1v1_5)
}

private func verifyRSAPSS(
    signer: Certificate, digest: ReceiptDigest, signature: [UInt8], signedBytes: [UInt8]
) -> Bool {
    guard let publicKey = _RSA.Signing.PublicKey(signer.publicKey) else { return false }
    let rsaSignature = _RSA.Signing.RSASignature(rawRepresentation: signature)
    return verifyRSA(publicKey, rsaSignature, digest, signedBytes, padding: .PSS)
}

/// Generic over `_RSA.Signing.Padding` so the digest switch (which must pick
/// a concrete `Digest`-conforming hash type per branch) is written once for
/// both PKCS#1 v1.5 and PSS.
private func verifyRSA(
    _ publicKey: _RSA.Signing.PublicKey, _ signature: _RSA.Signing.RSASignature, _ digest: ReceiptDigest,
    _ content: [UInt8], padding: _RSA.Signing.Padding
) -> Bool {
    switch digest {
    case .md5: return publicKey.isValidSignature(signature, for: Insecure.MD5.hash(data: content), padding: padding)
    case .sha1: return publicKey.isValidSignature(signature, for: Insecure.SHA1.hash(data: content), padding: padding)
    case .sha256: return publicKey.isValidSignature(signature, for: SHA256.hash(data: content), padding: padding)
    case .sha384: return publicKey.isValidSignature(signature, for: SHA384.hash(data: content), padding: padding)
    case .sha512: return publicKey.isValidSignature(signature, for: SHA512.hash(data: content), padding: padding)
    }
}

private func verifyECDSA(
    signer: Certificate, digest: ReceiptDigest, signature: [UInt8], signedBytes: [UInt8]
) -> Bool {
    // ASN.1 DER `ECDSA-Sig-Value`, as CMS carries it (unlike a JWS ES256
    // signature, which is raw r‖s).
    if let key = P256.Signing.PublicKey(signer.publicKey),
        let ecdsaSignature = try? P256.Signing.ECDSASignature(derRepresentation: signature)
    {
        switch digest {
        case .sha256: return key.isValidSignature(ecdsaSignature, for: SHA256.hash(data: signedBytes))
        case .sha384: return key.isValidSignature(ecdsaSignature, for: SHA384.hash(data: signedBytes))
        case .sha512: return key.isValidSignature(ecdsaSignature, for: SHA512.hash(data: signedBytes))
        case .sha1: return key.isValidSignature(ecdsaSignature, for: Insecure.SHA1.hash(data: signedBytes))
        case .md5: return key.isValidSignature(ecdsaSignature, for: Insecure.MD5.hash(data: signedBytes))
        }
    }
    if let key = P384.Signing.PublicKey(signer.publicKey),
        let ecdsaSignature = try? P384.Signing.ECDSASignature(derRepresentation: signature)
    {
        switch digest {
        case .sha256: return key.isValidSignature(ecdsaSignature, for: SHA256.hash(data: signedBytes))
        case .sha384: return key.isValidSignature(ecdsaSignature, for: SHA384.hash(data: signedBytes))
        case .sha512: return key.isValidSignature(ecdsaSignature, for: SHA512.hash(data: signedBytes))
        case .sha1: return key.isValidSignature(ecdsaSignature, for: Insecure.SHA1.hash(data: signedBytes))
        case .md5: return key.isValidSignature(ecdsaSignature, for: Insecure.MD5.hash(data: signedBytes))
        }
    }
    return false
}

// MARK: - JWS ES256

/// Verifies a raw (r‖s, 64-byte) ES256 signature under `leaf`'s P-256 key —
/// the JWS signing-input form (RFC 7518 §3.4), unlike CMS's DER form above.
func verifyES256(leaf: Certificate, signature: [UInt8], signingInput: [UInt8]) -> Bool {
    guard signature.count == 64, let key = P256.Signing.PublicKey(leaf.publicKey),
        let ecdsaSignature = try? P256.Signing.ECDSASignature(rawRepresentation: signature)
    else { return false }
    return key.isValidSignature(ecdsaSignature, for: SHA256.hash(data: signingInput))
}
