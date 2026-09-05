import Crypto
import _CryptoExtras
import Foundation
import SwiftASN1
import X509

/// One in-app purchase from a legacy app receipt (attribute 17).
public struct InAppPurchase: Sendable {
    /// Raw unmodeled attributes by type — forward compatibility (PLAN D10).
    public var unknownAttributes: [Int: [Data]] = [:]
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
    /// Raw values of attribute types this library does not model, keyed by
    /// type — forward compatibility for fields Apple may add (PLAN D10).
    /// Values are the raw octet-string contents, verified but undecoded.
    public var unknownAttributes: [Int: [Data]] = [:]
    /// Attribute 0, e.g. "Production" / "ProductionSandbox" (undocumented).
    public var receiptType: String?
    /// Attribute 18 (undocumented; community-established).
    public var originalPurchaseDate: Date?
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
    /// Upper bound on a receipt's embedded certificates, applied while the CMS
    /// is parsed — on the number of elements in the certificate set, before
    /// any of them is decoded and long before the path walk in
    /// ``verifyCore(receipt:)`` reaches them. Genuine receipts
    /// embed 1 to 3 (fixtures/public-receipts: xcode-with-purchases 1,
    /// sandbox-g5 3, sandbox-legacy 3), and Java, Node and Python bound the
    /// same input at the same 10: the value is that parity plus headroom over
    /// a genuine chain, not a complexity budget. The walk does not grow with
    /// the square of it. `&&` short-circuits, so a certificate's signature is
    /// checked only in the step whose `tip.issuer` is that certificate's
    /// subject, and no two steps test the same issuer — the walk therefore
    /// costs at most one signature check per embedded certificate, and only
    /// the subject comparisons are quadratic. Measured on a release build with
    /// this bound lifted, over the walk's worst case (a bag that is one
    /// genuine n-long chain, so every step advances): 29.1 ms at 101
    /// certificates, 136.3 ms at 401, 1,037.7 ms at 1,601 — x4.7 then x7.6 per
    /// x4, against the x16 per x4 a quadratic cost would show.
    static let maximumEmbeddedCertificates = 10

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
        guard let der = decodeReceiptBase64(base64Receipt) else {
            throw VerificationError(.invalidReceiptFormat, "receipt is not valid base64")
        }
        return try await verify(receipt: der, deviceGuid: deviceGuid)
    }

    /// Verifies a DER/BER receipt. Passing `deviceGuid` additionally
    /// enforces the device-hash binding: SHA1(guid ‖ opaqueValue ‖
    /// bundleIdBytes) must equal attribute 5 (optional — PLAN.md D4).
    public func verify(receipt: Data, deviceGuid: Data? = nil) async throws -> AppReceipt {
        let fields = try await verifyCore(receipt: receipt)
        guard fields.bundleId == bundleId else {
            throw VerificationError(
                .wrongBundleId,
                "expected \(bundleId) but receipt has \(fields.bundleId ?? "nil")")
        }
        if let deviceGuid {
            try verifyDeviceHash(fields, deviceGuid: deviceGuid)
        }
        return fields
    }

    /// Chain + signature verification WITHOUT the bundle-id claim check —
    /// the primitive under both ``verify(receipt:deviceGuid:)`` and the
    /// verifyReceipt-compat endpoint (which, like Apple's endpoint, accepts
    /// any bundle). Public because node and python export the same primitive
    /// as `verifyReceiptCore`; a caller that unlocks products must compare
    /// ``AppReceipt/bundleId`` itself or use ``verify(receipt:deviceGuid:)``.
    public func verifyCore(receipt: Data) async throws -> AppReceipt {
        try await Self.verifyCore(receipt: receipt, roots: roots)
    }

    /// ``verifyCore(receipt:)`` for a caller that has no single bundle id to
    /// check — the verifyReceipt-compat endpoint, which accepts any bundle.
    /// Same primitive, pinned roots supplied per call.
    public static func verifyCore(
        receipt: Data,
        trustedRoots: [Data]
    ) async throws -> AppReceipt {
        guard !trustedRoots.isEmpty else {
            throw VerificationError(.invalidCertificate, "trustedRoots is required")
        }
        return try await verifyCore(
            receipt: receipt,
            roots: try trustedRoots.map { try Certificate(derEncoded: [UInt8]($0)) })
    }

    static func verifyCore(receipt: Data, roots: [Certificate]) async throws -> AppReceipt {
        // `maximumEmbeddedCertificates` is applied inside this parse, on the
        // element count, so an oversized bag is refused before any of it is
        // decoded and nothing below ever sees more than the bound.
        let cms = try CMSReceipt(parsing: [UInt8](receipt))

        // Parsed before signature verification only to learn the creation
        // date (chain validity anchors at signing time); nothing from it is
        // trusted until the chain + signature checks pass.
        let fields = try parsePayload(cms.content)
        // Wall-clock only as the stand-in for a missing creation date: chain
        // validity is judged at the receipt's signing time (PLAN.md 2.2 step
        // 2), so this is deliberately not routed through any injected clock.
        let at = fields.creationDate ?? Date()

        let signerCert = try cms.signerCertificate()
        try requireDecodableExtensions(signerCert, what: "receipt signer certificate")
        // Hand chain building a single path instead of the whole certificate
        // bag. swift-certificates' Verifier is a backtracking DFS whose
        // candidate pool IS the intermediate store: every pop pushes one
        // partial chain per store entry whose subject equals the current tip's
        // issuer, and it recognises a repeat only by (subject, public key,
        // SAN). k certificates sharing one subject and one key but carrying
        // distinct SANs are therefore each a signature-valid parent of every
        // other, and the search walks the sum over j of k!/(k-j)! paths before
        // giving up: measured through this entry point on a release build, the
        // k=9 receipt the chain-building tests below build cost 148.8 s handed
        // to the Verifier whole, against 4.0 ms with the walk below in place.
        // At about 4,300 bytes it is smaller than the genuine 79,104-byte
        // legacy receipt, and its ten certificates are inside the count bound
        // above, so neither a caller-side size limit nor that bound reaches it.
        //
        // Two properties of the walk below do the work:
        //
        //  - A step takes the certificate that actually SIGNED the tip, not
        //    merely one carrying the issuer's name. Apple's own port of this
        //    procedure matches on the name alone (app-store-server-library-swift
        //    AppReceiptVerifier.verifyChain) and can afford to, because it also
        //    demands the WWDR marker OID on the intermediate it picked. This
        //    library does not require that OID — node, python and java do not —
        //    so a name-only match here lets any self-signed certificate that
        //    borrows the intermediate's subject displace the real one and turn
        //    a VALID receipt into a rejected one. Selecting by signature is
        //    also what node (chain.ts issuedBy) and python (_chain.py
        //    _issued_by) do, so it is the cross-language shape as well.
        //  - A subject is taken at most once. `subjectsTaken` holds the
        //    subjects the walk has taken, and the candidate's subject IS
        //    `tip.issuer`, so the guard and the insert name the same value and
        //    the walk cannot revisit a subject — which is why it stops at the
        //    first revisit on a signature cycle and why no two steps test the
        //    same issuer. Downstream, the store is
        //    `Dictionary(grouping:by: \.subject)`, so one entry per subject
        //    means the Verifier's lookup returns at most one candidate: each
        //    pop pushes at most one partial chain, the stack never grows past
        //    one entry, and the whole search is at most as long as the path.
        //    Without this the fanout above simply rebuilds itself inside the
        //    store, because each of those k certificates signs the next.
        //  - The walk is never longer than the bag. Every step appends one
        //    certificate out of `cms.certificates`, so a walk that has
        //    appended as many as the bag holds has revisited one, and the
        //    count clause stops it there whatever the two clauses below do.
        //    Without it, a 2-cycle whose issuer names point outside the bag
        //    never trips the subject guard, and removing the `$0.subject ==
        //    tip.issuer` clause made that bag loop forever (measured: the run
        //    was killed at 120 s) — a bug that surfaced as a hang, not a red
        //    test, and took the machine running the suite down with it.
        //
        // The walk only chooses the pool. Everything a chain must satisfy —
        // validity at signing time, basic constraints, reaching a pinned root —
        // stays with RFC5280Policy and the Verifier: a receipt whose embedded
        // bag stops at the intermediate still validates against the pinned
        // root, as it does in node, python and java. One verdict does move.
        // A decoy that borrows the real intermediate's DN *and* its public key
        // satisfies the predicate below, so the walk takes it and stops rather
        // than backtracking to the real intermediate. Measured on a release
        // build: with the whole bag handed to the Verifier that receipt was
        // accepted at all four bag positions; it is now rejected when the
        // decoy sits ahead of the real intermediate (positions 0 and 1) and
        // still accepted behind it (2 and 3) — position for position what node
        // and python do, while java accepts all four, a split that predates
        // this walk. Only a receipt the attacker signed themselves has that
        // shape, so the move costs no genuine receipt.
        var intermediates: [Certificate] = []
        var subjectsTaken: Set<DistinguishedName> = []
        var tip = signerCert
        while intermediates.count < cms.embeddedCount,
            !subjectsTaken.contains(tip.issuer),
            let issuer = cms.certificates.first(where: {
                $0.subject == tip.issuer
                    && $0.publicKey.isValidSignature(tip.signature, for: tip)
            })
        {
            intermediates.append(issuer)
            subjectsTaken.insert(issuer.subject)
            tip = issuer
        }

        var verifier = Verifier(rootCertificates: CertificateStore(roots)) {
            RFC5280Policy(validationTime: at)
        }
        let result = await verifier.validate(
            leafCertificate: signerCert,
            intermediates: CertificateStore(intermediates))
        if case .couldNotValidate = result {
            throw VerificationError(
                .invalidChain,
                "signer chain does not validate to a pinned root")
        }
        // Apple marker OID on the receipt-signing leaf, checked after chain
        // validation (parity with the other three: a foreign chain reports
        // INVALID_CHAIN first). The chain check alone does not distinguish
        // signer purpose — developer certs chain through the same WWDR
        // intermediate to the same pinned root.
        let receiptSignerOID: ASN1ObjectIdentifier = [1, 2, 840, 113635, 100, 6, 11, 1]
        guard signerCert.extensions.contains(where: { $0.oid == receiptSignerOID }) else {
            throw VerificationError(
                .invalidCertificatePurpose,
                "receipt signer certificate lacks Apple receipt-signing marker OID")
        }
        try cms.verifySignature(signerCert: signerCert)
        return fields
    }

    private func verifyDeviceHash(_ fields: AppReceipt, deviceGuid: Data) throws {
        guard let opaque = fields.opaqueValue, let expected = fields.sha1Hash,
            let bundleBytes = fields.bundleIdBytes
        else {
            throw VerificationError(
                .deviceHashMismatch,
                "receipt lacks the attributes needed for the device-hash check")
        }
        var input = Data()
        input.append(deviceGuid)
        input.append(opaque)
        input.append(bundleBytes)
        let computed = Data(Insecure.SHA1.hash(data: input))
        // Constant-time comparison.
        guard computed.count == expected.count,
            zip(computed, expected).reduce(0, { $0 | ($1.0 ^ $1.1) }) == 0
        else {
            throw VerificationError(
                .deviceHashMismatch,
                "computed device hash does not match attribute 5")
        }
    }
}

// MARK: - receipt-data base64

/// Decodes a `receipt-data` string exactly as a client transports one,
/// shared by ``ReceiptVerifier/verify(base64Receipt:deviceGuid:)`` and
/// ``VerifyReceiptEndpoint/verifyReceipt(_:)``. Apple's rule: `receipt-data`
/// is Base64 as defined in RFC 4648, and Foundation's
/// `base64EncodedString(options:)` can emit the standard (`+/`) or the
/// base64url (`-_`) alphabet, with or without padding, with CR/LF line
/// endings at 64 or 76 columns — so every one of those is accepted, with
/// whitespace (CR, LF, space, tab) tolerated anywhere. Rejected (`nil`):
/// a character outside both alphabets, both alphabets in one string,
/// anything but whitespace after the padding, a stripped length congruent
/// to 1 mod 4, and an empty or whitespace-only string. No canonical-
/// trailing-bits check — that discipline is left to `Data(base64Encoded:)`.
///
/// Whitespace is stripped and the alphabet normalized to standard by
/// walking UTF-8 bytes rather than `Character`s: Swift's `String` groups a
/// `"\r\n"` pair into a single extended grapheme cluster, so comparing
/// `Character`s against `"\r"` and `"\n"` individually never matches a
/// PEM-wrapped receipt's line endings and rejects every 76-column input.
/// Padding is validated in place rather than discarded and recomputed: `pad`
/// counts the trailing `=` characters and `data` is the stripped length
/// without them. The input is accepted only when `pad == 0` (no padding
/// supplied) or `pad` equals the canonical amount for `data`'s length mod 4
/// (`(4 - data % 4) % 4`) — any other count is rejected, including both
/// over- and under-padded input. `data % 4 == 1` is rejected below and stays
/// rejected regardless of padding.
func decodeReceiptBase64(_ text: String) -> Data? {
    var body: [UInt8] = []
    var sawPadding = false
    var padCount = 0
    var standardAlphabet = false
    var urlsafeAlphabet = false

    for byte in text.utf8 {
        switch byte {
        case 0x0D, 0x0A, 0x20, 0x09:  // \r \n space \t
            continue
        default:
            break
        }
        if sawPadding {
            guard byte == 0x3D else { return nil }  // only '=' may follow padding
            padCount += 1
            continue
        }
        switch byte {
        case 0x3D:  // '='
            sawPadding = true
            padCount = 1
        case 0x2B:  // '+'
            standardAlphabet = true
            body.append(0x2B)
        case 0x2F:  // '/'
            standardAlphabet = true
            body.append(0x2F)
        case 0x2D:  // '-'
            urlsafeAlphabet = true
            body.append(0x2B)
        case 0x5F:  // '_'
            urlsafeAlphabet = true
            body.append(0x2F)
        case 0x30...0x39, 0x41...0x5A, 0x61...0x7A:  // 0-9 A-Z a-z
            body.append(byte)
        default:
            return nil
        }
    }

    guard !(standardAlphabet && urlsafeAlphabet) else { return nil }
    guard !body.isEmpty else { return nil }
    // The impossible-length test is on the DATA, not the padded string:
    // "A===" is a multiple of four in total and still encodes no whole byte.
    guard body.count % 4 != 1 else { return nil }

    let remainder = body.count % 4
    guard padCount == 0 || padCount == (4 - remainder) % 4 else { return nil }
    if remainder != 0 {
        body.append(contentsOf: repeatElement(UInt8(ascii: "="), count: 4 - remainder))
    }
    return Data(base64Encoded: Data(body), options: [])
}

// MARK: - CMS SignedData (BER-tolerant)

private struct CMSReceipt {
    let content: [UInt8]
    /// The embedded certificates this build could read, and their identities
    /// in the same order. An entry that would not decode is NOT here — see
    /// `unreadableNodes`.
    let certificates: [Certificate]
    let certificateNodes: [(serial: [UInt8], issuer: [UInt8])]
    /// The identities of the entries that would not decode, and the first
    /// error. Held rather than thrown, because WHICH entry it is changes the
    /// verdict: a stranger the receipt merely carries is a defect of the
    /// receipt, while the SIGNER being unreadable is a defect of a
    /// certificate and gets the verdict an unreadable x5c entry gets on the
    /// JWS path (receipt/reject-signer-*).
    let unreadableNodes: [(serial: [UInt8], issuer: [UInt8])]
    let unreadable: Error?
    /// Every entry, readable or not — what the count bound is measured in.
    let embeddedCount: Int
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
            let contentType = try ASN1ObjectIdentifier(derEncoded: contentInfo.at(0))
            guard contentType == [1, 2, 840, 113549, 1, 7, 2] else {
                throw VerificationError(.invalidReceiptFormat, "not CMS SignedData")
            }
            let signedData = try Self.children(try Self.explicit(contentInfo.at(1)))

            // encapContentInfo: SEQ { OID, [0] EXPLICIT OCTET STRING }
            let encap = try Self.children(signedData.at(2))
            guard encap.count >= 2 else {
                throw VerificationError(.invalidReceiptFormat, "no encapsulated payload")
            }
            self.content = try Self.octetStringValue(try Self.explicit(encap[1]))

            // The embedded certificates are attacker-supplied and every one of
            // them is a walk candidate in `verifyCore`, before anything about
            // the receipt has been verified, so a flood is refused on the
            // element count — before a single element is decoded. Decoding
            // first would spend exactly the work the bound exists to refuse,
            // and would let a malformed entry anywhere in an oversized bag
            // answer "malformed receipt" where the bound answers "too many".
            var certificateDER: [[UInt8]] = []
            for node in signedData.dropFirst(3)
            where node.identifier.tagClass == .contextSpecific
                && node.identifier.tagNumber == 0
            {
                for certNode in try Self.children(node) {
                    certificateDER.append([UInt8](certNode.encodedBytes))
                }
            }
            guard certificateDER.count <= ReceiptVerifier.maximumEmbeddedCertificates else {
                throw VerificationError(
                    .invalidChain,
                    "receipt embeds \(certificateDER.count) certificates, "
                        + "more than the maximum of \(ReceiptVerifier.maximumEmbeddedCertificates)")
            }
            var certificates: [Certificate] = []
            var certificateNodes: [(serial: [UInt8], issuer: [UInt8])] = []
            var unreadableNodes: [(serial: [UInt8], issuer: [UInt8])] = []
            var unreadable: Error?
            for der in certificateDER {
                // The identity is read as generic ASN.1, so it is
                // available even for an entry no X.509 decoder accepts —
                // which is what lets the signer be NAMED before it is
                // known to be readable.
                let identity: (serial: [UInt8], issuer: [UInt8])?
                do {
                    let tbs = try Self.children(try Self.children(DER.parse(der))[0])
                    var index = 0
                    if let first = tbs.first, first.identifier.tagClass == .contextSpecific { index = 1 }
                    identity = (
                        serial: try Self.primitive(tbs.at(index)),
                        issuer: [UInt8]((try tbs.at(index + 2)).encodedBytes)
                    )
                } catch {
                    identity = nil
                }
                do {
                    let certificate = try Certificate(derEncoded: der)
                    guard let identity else { throw VerificationError(.invalidReceiptFormat, "unreadable") }
                    certificates.append(certificate)
                    certificateNodes.append(identity)
                } catch {
                    if unreadable == nil { unreadable = error }
                    if let identity { unreadableNodes.append(identity) }
                }
            }
            self.certificates = certificates
            self.certificateNodes = certificateNodes
            self.unreadableNodes = unreadableNodes
            self.unreadable = unreadable
            self.embeddedCount = certificateDER.count

            guard let signerInfos = signedData.last,
                signerInfos.identifier == .set,
                let signerInfo = try Self.children(signerInfos).first
            else {
                throw VerificationError(.invalidReceiptFormat, "no signer info")
            }
            let signerFields = try Self.children(signerInfo)
            let sid = try Self.children(signerFields.at(1))
            self.signerIssuer = [UInt8]((try sid.at(0)).encodedBytes)
            self.signerSerial = try Self.primitive(sid.at(1))

            let digestAlgOid = try ASN1ObjectIdentifier(
                derEncoded: try Self.children(signerFields.at(2)).at(0))
            switch digestAlgOid {
            case [1, 3, 14, 3, 2, 26]: self.digestName = "sha1"
            case [2, 16, 840, 1, 101, 3, 4, 2, 1]: self.digestName = "sha256"
            default:
                throw VerificationError(.invalidReceiptFormat, "unsupported digest algorithm")
            }

            var index = 3
            if index < signerFields.count,
                signerFields[index].identifier.tagClass == .contextSpecific,
                signerFields[index].identifier.tagNumber == 0
            {
                let attrsNode = signerFields[index]
                // Signature covers the signedAttrs re-encoded as an explicit
                // SET (RFC 5652 §5.4): swap the IMPLICIT [0] tag for SET.
                var reencoded = [UInt8](attrsNode.encodedBytes)
                guard !reencoded.isEmpty else {
                    throw VerificationError(.invalidReceiptFormat, "empty signed attributes")
                }
                reencoded[0] = 0x31
                self.signedAttrsBytes = reencoded
                var digest: [UInt8]? = nil
                for attr in try Self.children(attrsNode) {
                    let parts = try Self.children(attr)
                    if try ASN1ObjectIdentifier(derEncoded: parts.at(0))
                        == [1, 2, 840, 113549, 1, 9, 4]
                    {
                        digest = try Self.primitive(try Self.children(parts.at(1)).at(0))
                    }
                }
                self.messageDigest = digest
                index += 1
            } else {
                self.signedAttrsBytes = nil
                self.messageDigest = nil
            }
            index += 1  // signatureAlgorithm — RSA PKCS#1 v1.5, digest drives the hash
            self.signature = try Self.primitive(signerFields.at(index))
        } catch let error as VerificationError {
            throw error
        } catch {
            throw VerificationError(.invalidReceiptFormat, "malformed CMS structure")
        }
    }

    func signerCertificate() throws -> Certificate {
        if unreadableNodes.contains(where: { $0.serial == signerSerial && $0.issuer == signerIssuer }) {
            throw VerificationError(
                .invalidCertificate, "receipt signer certificate is not a valid certificate")
        }
        for (offset, node) in certificateNodes.enumerated()
        where node.serial == signerSerial && node.issuer == signerIssuer {
            // A stranger in the bag that would not decode is still fatal —
            // the bag is unsigned, so bytes that cannot be read are the
            // receipt's problem.
            if unreadable != nil {
                throw VerificationError(
                    .invalidReceiptFormat, "an embedded certificate is not a valid certificate")
            }
            return certificates[offset]
        }
        if unreadable != nil {
            throw VerificationError(
                .invalidReceiptFormat, "an embedded certificate is not a valid certificate")
        }
        throw VerificationError(.invalidReceiptFormat, "signer certificate not embedded")
    }

    func verifySignature(signerCert: Certificate) throws {
        guard let publicKey = _RSA.Signing.PublicKey(signerCert.publicKey) else {
            throw VerificationError(.invalidSignature, "signer key is not RSA")
        }
        let signedBytes: [UInt8]
        if let signedAttrsBytes {
            let contentDigest: [UInt8] =
                digestName == "sha1"
                ? [UInt8](Insecure.SHA1.hash(data: Data(content)))
                : [UInt8](SHA256.hash(data: Data(content)))
            guard let messageDigest, messageDigest == contentDigest else {
                throw VerificationError(
                    .invalidSignature,
                    "messageDigest attribute does not match content")
            }
            signedBytes = signedAttrsBytes
        } else {
            signedBytes = content
        }
        let rsaSignature = _RSA.Signing.RSASignature(rawRepresentation: Data(signature))
        let valid: Bool
        if digestName == "sha1" {
            valid = publicKey.isValidSignature(
                rsaSignature,
                for: Insecure.SHA1.hash(data: Data(signedBytes)), padding: .insecurePKCS1v1_5)
        } else {
            valid = publicKey.isValidSignature(
                rsaSignature,
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

/// Bounds-checked element access that throws a VerificationError instead of
/// triggering Swift's fatal (uncatchable) out-of-bounds trap on attacker-
/// controlled ASN.1 structures.
private extension Array {
    func at(_ index: Int) throws -> Element {
        guard index >= 0, index < count else {
            throw VerificationError(.invalidReceiptFormat, "truncated ASN.1 structure")
        }
        return self[index]
    }
}

// MARK: - Receipt payload (strict DER)

private let attrReceiptType = 0
private let attrOriginalPurchaseDate = 18
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
        case attrReceiptType: receipt.receiptType = try decodeString(value)
        case attrOriginalPurchaseDate: receipt.originalPurchaseDate = try decodeDate(value)
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
        default: receipt.unknownAttributes[type, default: []].append(Data(value))
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
        default: purchase.unknownAttributes[type, default: []].append(Data(v))
        }
    }
    return purchase
}

private func parseAttributeSet(_ der: [UInt8]) throws -> [(Int, [UInt8])] {
    var root: ASN1Node
    do {
        root = try DER.parse(der)
    } catch {
        throw VerificationError(.invalidReceiptFormat, "attribute set is not valid ASN.1")
    }
    if root.identifier == .octetString {
        // Xcode receipts double-wrap the payload in an extra OCTET STRING.
        do {
            root = try DER.parse(try CMSReceipt.primitive(root))
        } catch {
            throw VerificationError(.invalidReceiptFormat, "double-wrap is not valid ASN.1")
        }
    }
    guard root.identifier == .set else {
        throw VerificationError(.invalidReceiptFormat, "attribute set is not an ASN.1 SET")
    }
    var attributes: [(Int, [UInt8])] = []
    for child in try CMSReceipt.children(root) {
        let fields = try CMSReceipt.children(child)
        guard child.identifier == .sequence, fields.count >= 3,
            fields[0].identifier == .integer, fields[2].identifier == .octetString
        else {
            throw VerificationError(.invalidReceiptFormat, "malformed receipt attribute")
        }
        // The attribute TYPE is bounded at a 32-bit signed integer, the width
        // every port keys `unknownAttributes` by. A larger type is rejected
        // rather than mapped onto some in-range stand-in: -1 (or any clamp) is
        // not a valid attribute type, and filing an unrepresentable type under
        // a representable one is how a parser starts disagreeing with itself
        // and with the other ports. The attribute VALUE keeps its full 8-byte
        // range — real receipts carry 7-byte integers (web_order_line_item_id)
        // — so this bound is on the type alone.
        let type = try intValue(try CMSReceipt.primitive(fields[0]))
        guard type <= Int(Int32.max) else {
            throw VerificationError(
                .invalidReceiptFormat,
                "receipt attribute type \(type) exceeds the 32-bit signed range")
        }
        attributes.append((type, try CMSReceipt.primitive(fields[2])))
    }
    return attributes
}

private func intValue(_ contents: [UInt8]) throws -> Int {
    // 8-byte cap: real receipts carry 7-byte integers (web_order_line_item_id).
    guard contents.count <= 8 else {
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
        let text = String(bytes: try CMSReceipt.primitive(node), encoding: .utf8)
    else {
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

/// Whether swift-certificates can express this instant as a policy's
/// validation time.
///
/// GeneralizedTime holds only years 0...9999, and building one outside that
/// range hits a `try!` inside X509's `Time` that traps the process instead of
/// throwing. `ISO8601DateFormatter` accepts a six-digit year, and the dates it
/// parses here come out of an unverified payload and reach the policy before
/// any chain or signature check — so without this bound a receipt carrying
/// "999999-12-31T23:59:59Z" aborts the caller's process.
///
/// The bounds are compared as `TimeInterval`s, not as `Date`s, and that is
/// the whole of what makes a NaN instant fail closed. `Date` is `Comparable`,
/// so `>=` and `<=` come from the protocol as the negation of `<`: for a NaN
/// every `<` is false, so both negations are TRUE and `date >= lower &&
/// date <= upper` answers `true` — the opposite of what a range check means
/// and the opposite of what this guard is for. IEEE comparison on the
/// intervals answers false on either side instead, which is the fail-closed
/// answer. The infinities are outside the bounds either way.
func isRepresentableAsCertificateValidationTime(_ date: Date) -> Bool {
    // 0001-01-01T00:00:00Z ... 9999-12-31T23:59:59Z
    let seconds = date.timeIntervalSince1970
    return seconds >= -62_135_596_800 && seconds <= 253_402_300_799
}

/// RFC 3339 date in an IA5String; empty means absent (real receipts do this).
private func decodeDate(_ der: [UInt8]) throws -> Date? {
    let text = try decodeString(der)
    if text.isEmpty { return nil }
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    var parsed = formatter.date(from: text)
    if parsed == nil {
        formatter.formatOptions = [.withInternetDateTime]
        parsed = formatter.date(from: text)
    }
    guard let date = parsed else {
        throw VerificationError(.invalidReceiptFormat, "unparseable receipt date: \(text)")
    }
    guard isRepresentableAsCertificateValidationTime(date) else {
        throw VerificationError(
            .invalidReceiptFormat,
            "receipt date out of representable range: \(text)")
    }
    return date
}
