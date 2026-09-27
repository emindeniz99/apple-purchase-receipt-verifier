import SwiftASN1
import X509

/// CMS / PKCS#7 `SignedData` structure walking for legacy app receipts.
///
/// Bytes in, bytes out: this file decides what a receipt *says*; the crypto
/// lives in ``SignatureCrypto``. Both definite and indefinite (BER) lengths
/// occur in genuine receipts — Apple's own Xcode receipts use indefinite
/// lengths — so the reader accepts both.
///
/// Depth: the envelope is walked by ``asn1DepthExceeded(_:)`` before
/// `SwiftASN1` parses it, so one nested past ``maxAsn1Depth`` is
/// ``Reason/malformed`` whatever `SwiftASN1`'s own, looser bound would say.

/// One `SignerInfo` of a receipt.
struct CmsSignerInfo {
    /// The issuer Name TLV, encoded, named by `issuerAndSerialNumber`.
    let issuerRaw: [UInt8]
    /// The serial number content octets named by `issuerAndSerialNumber`.
    let serialContents: [UInt8]
    let digestAlgorithmOID: String
    let signatureAlgorithmOID: String
    /// The `signedAttrs [0]` bytes, re-tagged as an explicit SET (RFC 5652
    /// §5.4 — the bytes the signature actually covers when present).
    let signedAttrsBytes: [UInt8]?
    let signature: [UInt8]
}

struct ParsedCms {
    /// The encapsulated content — the receipt payload.
    let content: [UInt8]
    /// The embedded certificates that decoded, in bag order.
    let certificates: [Certificate]
    /// Each decoded certificate's (serial, issuer) identity, same order and
    /// index as `certificates`.
    let certificateIdentities: [(serial: [UInt8], issuer: [UInt8])]
    /// The identity of every embedded entry that did NOT decode as a
    /// certificate, read as generic ASN.1 so it is nameable even though it
    /// is not a certificate at all.
    let unreadableIdentities: [(serial: [UInt8], issuer: [UInt8])]
    /// Whether at least one embedded entry did not decode.
    let hasUnreadable: Bool
    /// Every SignerInfo, in order. Never empty.
    let signerInfos: [CmsSignerInfo]
    /// The `eContentType` OID's content octets.
    let contentTypeOctets: [UInt8]
}

let maxEmbeddedCertificates = 10
let maxSignerInfos = 4

func malformedReceipt(_ detail: String) -> Failure { Failure(.malformed, detail) }

/// Parses a CMS `SignedData` blob (the whole receipt DER), enforcing the
/// embedded-certificate and SignerInfo counts before a single certificate is
/// decoded or a single signature checked.
func parseCms(_ der: [UInt8]) throws -> ParsedCms {
    guard !asn1DepthExceeded(der) else {
        throw malformedReceipt("receipt nests ASN.1 deeper than \(maxAsn1Depth) values")
    }
    let root: ASN1Node
    do {
        root = try BER.parse(der)
    } catch {
        throw malformedReceipt("not parseable ASN.1")
    }
    do {
        let contentInfo = try cmsChildren(root)
        let contentType = try ASN1ObjectIdentifier(derEncoded: contentInfo.at(0))
        guard contentType == [1, 2, 840, 113549, 1, 7, 2] else {
            throw malformedReceipt("not CMS SignedData")
        }
        let signedData = try cmsChildren(try cmsExplicit(contentInfo.at(1)))
        let encap = try cmsChildren(signedData.at(2))
        guard encap.count >= 2 else { throw malformedReceipt("no encapsulated payload") }
        let content = try cmsOctetStringValue(try cmsExplicit(encap[1]))
        let contentTypeOctets = [UInt8]((try cmsPrimitive(encap.at(0))))

        var certificateDER: [[UInt8]] = []
        for node in signedData.dropFirst(3)
        where node.identifier.tagClass == .contextSpecific && node.identifier.tagNumber == 0 {
            for certNode in try cmsChildren(node) {
                certificateDER.append([UInt8](certNode.encodedBytes))
            }
        }
        guard certificateDER.count <= maxEmbeddedCertificates else {
            throw malformedReceipt(
                "receipt embeds \(certificateDER.count) certificates, more than the maximum of \(maxEmbeddedCertificates)"
            )
        }

        var certificates: [Certificate] = []
        var certificateIdentities: [(serial: [UInt8], issuer: [UInt8])] = []
        var unreadableIdentities: [(serial: [UInt8], issuer: [UInt8])] = []
        var hasUnreadable = false
        for entryDER in certificateDER {
            let identity = certificateIdentity(entryDER)
            guard certificateSignatureBitStringIsAligned(entryDER) else {
                // A certificate whose own outer signature BIT STRING is not
                // byte-aligned does not decode all the way down, whether or
                // not swift-certificates' own (more lenient) reader would
                // accept it — an embedded entry that is not the signer and
                // does not decode is a defect of the receipt, MALFORMED,
                // whatever it is a defect IN (docs review: a genuine receipt
                // padded with such a stranger is not a positive case).
                hasUnreadable = true
                if let identity { unreadableIdentities.append(identity) }
                continue
            }
            if let certificate = try? Certificate(derEncoded: entryDER), let identity {
                certificates.append(certificate)
                certificateIdentities.append(identity)
            } else if let identity {
                // A readable identity (the TBSCertificate shape parses), but
                // the certificate itself does not construct — in practice
                // this crate's crypto dependencies (BoringSSL) refusing an
                // oversized or unimplemented key eagerly, where the
                // reference ports' own ASN.1 readers store the key as
                // opaque bytes and only refuse it lazily, when it is used.
                // Q16 (docs/design/0.7-hardening-parity.md): a certificate
                // no pinned root vouches for is ignored rather than fatal,
                // so this is excluded from the trust pool without being
                // "unreadable" for the whole-receipt MALFORMED verdict.
                // Still recorded so the SIGNER itself, if this is it,
                // answers invalidCertificate (change 5).
                unreadableIdentities.append(identity)
            } else {
                hasUnreadable = true
            }
        }

        guard let signerInfosNode = signedData.last, signerInfosNode.identifier == .set else {
            throw malformedReceipt("no signer info")
        }
        let signerInfoNodes = try cmsChildren(signerInfosNode)
        guard !signerInfoNodes.isEmpty else { throw malformedReceipt("no signer info") }
        guard signerInfoNodes.count <= maxSignerInfos else {
            throw malformedReceipt(
                "receipt carries \(signerInfoNodes.count) SignerInfos, more than the maximum of \(maxSignerInfos)"
            )
        }
        let signerInfos = try signerInfoNodes.map(parseSignerInfo)

        return ParsedCms(
            content: content, certificates: certificates, certificateIdentities: certificateIdentities,
            unreadableIdentities: unreadableIdentities, hasUnreadable: hasUnreadable,
            signerInfos: signerInfos, contentTypeOctets: contentTypeOctets)
    } catch let failure as Failure {
        throw failure
    } catch {
        throw malformedReceipt("malformed CMS structure")
    }
}

private func parseSignerInfo(_ node: ASN1Node) throws -> CmsSignerInfo {
    let fields = try cmsChildren(node)
    let sid = try cmsChildren(fields.at(1))
    let issuerRaw = [UInt8]((try sid.at(0)).encodedBytes)
    let serialContents = try cmsPrimitive(sid.at(1))
    let digestAlgOID = try ASN1ObjectIdentifier(derEncoded: try cmsChildren(fields.at(2)).at(0))

    var index = 3
    var signedAttrsBytes: [UInt8]?
    if index < fields.count, fields[index].identifier.tagClass == .contextSpecific,
        fields[index].identifier.tagNumber == 0
    {
        var reencoded = [UInt8](fields[index].encodedBytes)
        guard !reencoded.isEmpty else { throw malformedReceipt("empty signed attributes") }
        reencoded[0] = 0x31  // SET
        // The SYNTAX of every SignerInfo's signedAttrs is judged here, before
        // any key is used, so a broken one is MALFORMED whichever position
        // it holds among several SignerInfos (docs/design review J4 / R1
        // disagreement 4). A well-formed set that merely lacks a mandatory
        // attribute, or carries one twice, is left to the signature check
        // (INVALID_SIGNATURE for that signer) — `signedAttributeValues`
        // reports both kinds as a non-throwing outcome, and only a broken
        // structure throws here.
        _ = try signedAttributeValues(reencoded)
        signedAttrsBytes = reencoded
        index += 1
    }
    let signatureAlgorithm = try cmsChildren(fields.at(index))
    let signatureAlgorithmOID = try ASN1ObjectIdentifier(derEncoded: signatureAlgorithm.at(0))
    index += 1
    let signature = try cmsPrimitive(fields.at(index))
    return CmsSignerInfo(
        issuerRaw: issuerRaw, serialContents: serialContents,
        digestAlgorithmOID: digestAlgOID.description, signatureAlgorithmOID: signatureAlgorithmOID.description,
        signedAttrsBytes: signedAttrsBytes, signature: signature)
}

/// Whether `certificateDER`'s OWN outer `signatureValue BIT STRING` (the
/// third field of `Certificate ::= SEQUENCE { tbsCertificate,
/// signatureAlgorithm, signatureValue BIT STRING }`) declares zero unused
/// bits, as any byte-oriented signature does. swift-certificates' own
/// reader does not check this, so it accepts a certificate a stricter X.509
/// reader (Java's, Rust's own ASN.1 walk) refuses — a divergence this
/// library closes by hand rather than by hand-writing signature
/// cryptography: this is a structural ASN.1 read, not a crypto primitive.
/// Fails OPEN (`true`) for anything that does not have the expected shape,
/// so a genuinely malformed entry is still caught by the certificate parse
/// itself rather than by this narrower check.
func certificateSignatureBitStringIsAligned(_ certificateDER: [UInt8]) -> Bool {
    guard let root = try? DER.parse(certificateDER), root.identifier == .sequence,
        case .constructed(let topLevel) = root.content
    else { return true }
    let fields = Array(topLevel)
    guard fields.count >= 3, fields[2].identifier == .bitString,
        case .primitive(let bytes) = fields[2].content, let unusedBits = bytes.first
    else { return true }
    return unusedBits == 0
}

/// The identity (serial, issuer) of one embedded entry, read as generic
/// ASN.1 rather than as an X.509 certificate — available even for an entry
/// no certificate decoder accepts, which is what lets an unreadable SIGNER
/// be told apart from an unreadable stranger.
///
/// `TBSCertificate ::= SEQUENCE { [0] version DEFAULT v1, serialNumber
/// INTEGER, signature AlgorithmIdentifier, issuer Name, ... }`.
private func certificateIdentity(_ der: [UInt8]) -> (serial: [UInt8], issuer: [UInt8])? {
    guard let tbs = try? cmsChildren(try cmsChildren(DER.parse(der)).at(0)) else { return nil }
    var index = 0
    if let first = tbs.first, first.identifier.tagClass == .contextSpecific { index = 1 }
    guard let serialNode = tbs[safe: index], serialNode.identifier == .integer,
        let issuerNode = tbs[safe: index + 2], issuerNode.identifier == .sequence,
        let serial = try? cmsPrimitive(serialNode)
    else { return nil }
    return (serial: serial, issuer: [UInt8](issuerNode.encodedBytes))
}

// MARK: - signed attributes

/// The `messageDigest` and `contentType` signed attributes, or why the set
/// (well-formed as an RFC 5652 §5.3 attribute set) cannot be checked as a
/// signature. RFC 5652 §5.3 makes both mandatory whenever signedAttrs are
/// present.
///
/// Requiring both here, rather than only reading `messageDigest`, is a real
/// control and not an accident of Apple's grammar: genuine receipts carry NO
/// signedAttrs, so their RSA signature is taken directly over `cms.content`,
/// a DER SET beginning `0x31`. A forger who sets `signedAttrs = 0xA0 ||
/// <genuine payload SET>[1..]` reproduces, byte for byte, the bytes Apple
/// signed (the tag-swap in ``ParsedCms``/``CmsSignerInfo/signedAttrsBytes``
/// turns `0xA0` back into `0x31`) and could reuse a genuine Apple signature
/// while `cms.content` becomes entirely theirs — unless this function
/// insists the reused bytes also parse as `SEQUENCE { OID, SET OF value }`
/// carrying both mandatory attributes, which a genuine payload's attributes
/// do not.
enum SignedAttributesOutcome {
    case ok(messageDigest: [UInt8], contentType: [UInt8])
    case missingContentType
    case missingMessageDigest
    case duplicateAttribute
}

private let oidMessageDigest: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 9, 4]
private let oidContentType: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 9, 3]

/// - Throws: `Failure(.malformed, …)` when the bytes are not `SET OF
///   Attribute` at all, or an attribute is not `SEQUENCE { OID, SET OF
///   value }`. Never throws for a well-formed set that merely lacks
///   `contentType`/`messageDigest` or carries one twice — those come back as
///   a non-`.ok` case.
func signedAttributeValues(_ signedAttrs: [UInt8]) throws -> SignedAttributesOutcome {
    let root: ASN1Node
    do {
        root = try DER.parse(signedAttrs)
    } catch {
        throw malformedReceipt("malformed signedAttrs")
    }
    var messageDigest: [UInt8]?
    var contentType: [UInt8]?
    var duplicate = false
    for attribute in try cmsChildren(root) {
        let parts = try cmsChildren(attribute)
        guard let typeNode = parts[safe: 0], typeNode.identifier == .objectIdentifier,
            let valuesNode = parts[safe: 1], valuesNode.identifier == .set
        else { throw malformedReceipt("malformed signed attribute") }
        let values = try cmsChildren(valuesNode)
        guard let value = values.first else { throw malformedReceipt("malformed signed attribute") }
        guard let attributeOID = try? ASN1ObjectIdentifier(derEncoded: typeNode) else {
            throw malformedReceipt("malformed signed attribute")
        }
        if attributeOID == oidContentType {
            // A contentType value that is not an OID reads as empty octets,
            // which no eContentType matches.
            let oidValue = (value.identifier == .objectIdentifier ? try? cmsPrimitive(value) : nil) ?? []
            if contentType != nil { duplicate = true }
            contentType = oidValue
        }
        if attributeOID == oidMessageDigest {
            if messageDigest != nil { duplicate = true }
            messageDigest = (try? cmsPrimitive(value)) ?? []
        }
    }
    guard let contentType else { return .missingContentType }
    guard let messageDigest else { return .missingMessageDigest }
    if duplicate { return .duplicateAttribute }
    return .ok(messageDigest: messageDigest, contentType: contentType)
}

// MARK: - low-level ASN.1 helpers, throwing `Failure(.malformed, …)`

func cmsChildren(_ node: ASN1Node) throws -> [ASN1Node] {
    guard case .constructed(let nodes) = node.content else {
        throw malformedReceipt("expected constructed ASN.1 node")
    }
    return Array(nodes)
}

/// Unwraps an EXPLICIT context tag (`[0] { inner }`) to its inner node.
func cmsExplicit(_ node: ASN1Node) throws -> ASN1Node {
    let inner = try cmsChildren(node)
    guard inner.count == 1 else { throw malformedReceipt("expected single explicit content") }
    return inner[0]
}

func cmsPrimitive(_ node: ASN1Node) throws -> [UInt8] {
    guard case .primitive(let bytes) = node.content else {
        throw malformedReceipt("expected primitive ASN.1 node")
    }
    return [UInt8](bytes)
}

/// Value bytes of an OCTET STRING, joining BER constructed chunks.
func cmsOctetStringValue(_ node: ASN1Node) throws -> [UInt8] {
    switch node.content {
    case .primitive(let bytes): return [UInt8](bytes)
    case .constructed(let chunks):
        var out: [UInt8] = []
        for chunk in chunks { out.append(contentsOf: try cmsOctetStringValue(chunk)) }
        return out
    }
}

/// Bounds-checked element access that throws instead of trapping on
/// attacker-controlled ASN.1 structures — nothing in this file may crash on
/// unauthenticated input.
extension Array where Element == ASN1Node {
    func at(_ index: Int) throws -> ASN1Node {
        guard index >= 0, index < count else { throw malformedReceipt("truncated ASN.1 structure") }
        return self[index]
    }
}

extension Array {
    subscript(safe index: Int) -> Element? {
        indices.contains(index) ? self[index] : nil
    }
}
