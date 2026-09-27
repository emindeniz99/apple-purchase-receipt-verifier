import SwiftASN1
import X509

/// Certificate path validation.
///
/// A path is found first and judged second, as a PKIX walk does: a chain
/// that reaches no pinned root is ``Reason/untrustedChain`` whatever its
/// dates say, and only a path that does reach one has its certificates'
/// validity windows checked, where a certificate outside its window at the
/// chain instant is ``Reason/invalidCertificate``.
///
/// Walking down from the roots (rather than up from the leaf) means no key a
/// pinned anchor did not vouch for, directly or through a certificate it
/// vouched for, is ever used to check a signature: a receipt padded with
/// certificates carrying an attacker's own key (their choice of size and
/// exponent) costs one name comparison per issuer for each of them, and they
/// are simply left out.

/// The longest path the builder will walk, anchor excluded.
let maxPathLength = 6

/// The extensions a certificate on the path may mark critical: the ones a
/// PKIX validator processes (RFC 5280 6.1), and for the leaf also
/// `cRLDistributionPoints` and `extKeyUsage`. Any other extension marked
/// critical makes the certificate unusable, so the path fails, as a PKIX
/// validator fails it. Verbatim from the Rust port's `chain.rs`.
let processedExtensions: Set<String> = [
    "2.5.29.15",  // keyUsage
    "2.5.29.32",  // certificatePolicies
    "2.5.29.33",  // policyMappings
    "2.5.29.54",  // inhibitAnyPolicy
    "2.5.29.28",  // issuingDistributionPoint
    "2.5.29.27",  // deltaCRLIndicator
    "2.5.29.36",  // policyConstraints
    "2.5.29.19",  // basicConstraints
    "2.5.29.17",  // subjectAltName
    "2.5.29.30",  // nameConstraints
]
let processedLeafExtensions: Set<String> = [
    "2.5.29.31",  // cRLDistributionPoints
    "2.5.29.37",  // extKeyUsage
]

func untrusted(_ detail: String) -> Failure { Failure(.untrustedChain, detail) }

func outsideValidity() -> Failure {
    Failure(.invalidCertificate, "certificate is outside its validity window at the chain instant")
}

func unprocessedCriticalExtension() -> Failure {
    untrusted("a certificate on the path has an unsupported critical extension")
}

/// Whether `certificate` marks critical an extension no step here processes.
func hasUnprocessedCriticalExtension(_ certificate: Certificate, leaf: Bool) -> Bool {
    for ext in certificate.extensions where ext.critical {
        let oid = ext.oid.description
        let processed = processedExtensions.contains(oid) || (leaf && processedLeafExtensions.contains(oid))
        if !processed { return true }
    }
    return false
}

/// What X509_check_issued accepts, minus the parts that need a name
/// canonicaliser: the names chain by structural equality, the authority key
/// identifier agrees with the issuer's subject key identifier and serial
/// where it names them, and the issuer's keyUsage, if it decodes, permits
/// keyCertSign. A keyUsage extension present but not decodable fails closed
/// (untrusted), rather than being read as "no restriction".
func checkIssued(_ certificate: Certificate, issuedBy issuer: Certificate) -> Bool {
    guard certificate.issuer == issuer.subject else { return false }
    let akid = try? certificate.extensions.authorityKeyIdentifier
    let skid = try? issuer.extensions.subjectKeyIdentifier
    if let keyId = akid?.keyIdentifier, let issuerKeyId = skid?.keyIdentifier, keyId != issuerKeyId {
        return false
    }
    if let serial = akid?.authorityCertSerialNumber, serial != issuer.serialNumber {
        return false
    }
    if let keyUsageExtension = issuer.extensions[oid: .X509ExtensionID.keyUsage] {
        guard let keyUsage = try? KeyUsage(keyUsageExtension), keyUsage.keyCertSign else { return false }
    }
    return true
}

/// `checkIssued` plus the signature itself, checked with `issuer`'s key —
/// the key an anchor has already vouched for by the time this is called.
func issuedBy(_ certificate: Certificate, _ issuer: Certificate) -> Bool {
    checkIssued(certificate, issuedBy: issuer) && issuer.publicKey.isValidSignature(certificate.signature, for: certificate)
}

func issuedByAnyAnchor(_ certificate: Certificate, _ anchors: [Certificate]) -> Bool {
    anchors.contains { issuedBy(certificate, $0) }
}

/// A certificate cut into the three parts of `Certificate ::= SEQUENCE {
/// tbsCertificate, signatureAlgorithm, signatureValue }` with swift-asn1, the
/// way ``parseCms(_:)`` reads a receipt: enough to check the signature over
/// the TBS with a key that is already trusted, and nothing that decodes the
/// certificate's own key. swift-certificates builds a `Certificate`'s public
/// key while it parses it — BoringSSL refusing an oversized RSA key, say —
/// so a `Certificate` is built from these bytes only after a pinned root has
/// vouched for them.
struct CertificateSlices {
    /// The whole certificate, for building it once it is vouched for.
    let der: [UInt8]
    /// The encoded `tbsCertificate`, the bytes the issuer signed.
    let tbs: [UInt8]
    /// The outer `signatureAlgorithm`, when it is one swift-certificates
    /// verifies certificate signatures with; `nil` for any other, which no
    /// key then verifies.
    let signatureAlgorithm: Certificate.SignatureAlgorithm?
    /// The `signatureValue` BIT STRING's bytes, without its unused-bits octet.
    let signature: [UInt8]
}

/// The certificate signature algorithms swift-certificates implements
/// (`Certificate.Signature(signatureAlgorithm:signatureBytes:)`), by OID. No
/// allowlist beyond what the library verifies (Q14); a built certificate's
/// own `signatureAlgorithm`, parameters included, must still equal the one
/// matched here (``buildVouched(_:)``).
private let certificateSignatureAlgorithms: [ASN1ObjectIdentifier: Certificate.SignatureAlgorithm] = [
    [1, 2, 840, 10045, 4, 3, 2]: .ecdsaWithSHA256,
    [1, 2, 840, 10045, 4, 3, 3]: .ecdsaWithSHA384,
    [1, 2, 840, 10045, 4, 3, 4]: .ecdsaWithSHA512,
    [1, 2, 840, 113549, 1, 1, 5]: .sha1WithRSAEncryption,
    [1, 2, 840, 113549, 1, 1, 11]: .sha256WithRSAEncryption,
    [1, 2, 840, 113549, 1, 1, 12]: .sha384WithRSAEncryption,
    [1, 2, 840, 113549, 1, 1, 13]: .sha512WithRSAEncryption,
    [1, 3, 101, 112]: .ed25519,
]

/// `der` sliced as a certificate, or `nil` when it does not have the shape
/// of one: not DER, not a SEQUENCE of exactly a SEQUENCE, an
/// AlgorithmIdentifier and a byte-aligned BIT STRING.
func sliceCertificate(_ der: [UInt8]) -> CertificateSlices? {
    guard let root = try? DER.parse(der), root.identifier == .sequence,
        case .constructed(let topLevel) = root.content
    else { return nil }
    let fields = Array(topLevel)
    guard fields.count == 3, fields[0].identifier == .sequence, fields[1].identifier == .sequence,
        fields[2].identifier == .bitString, case .primitive(let bits) = fields[2].content, bits.first == 0,
        case .constructed(let algorithm) = fields[1].content, let oidNode = Array(algorithm).first,
        let oid = try? ASN1ObjectIdentifier(derEncoded: oidNode)
    else { return nil }
    return CertificateSlices(
        der: der, tbs: [UInt8](fields[0].encodedBytes), signatureAlgorithm: certificateSignatureAlgorithms[oid],
        signature: [UInt8](bits.dropFirst()))
}

/// Whether `issuer`'s key — one a pinned root has already vouched for, or
/// the root's own — verifies `slices`' signature over its TBS. The
/// verification is swift-crypto's, through swift-certificates' public
/// byte-level API; nothing about the certificate under test is decoded.
func signatureVerifies(_ slices: CertificateSlices, by issuer: Certificate) -> Bool {
    guard let algorithm = slices.signatureAlgorithm else { return false }
    return issuer.publicKey.isValidSignature(slices.signature, for: slices.tbs, signatureAlgorithm: algorithm)
}

/// The certificate behind `slices`, built now that its signature has
/// verified under a vouched key: ``Reason/invalidCertificate`` when
/// swift-certificates refuses it (a key it cannot use, a malformed field) or
/// one of its extensions does not decode. The built certificate must carry
/// the signature algorithm the check used, parameters included, so the
/// check covered exactly what swift-certificates would have verified.
func buildVouched(_ slices: CertificateSlices) throws -> Certificate {
    guard let certificate = try? Certificate(derEncoded: slices.der), hasOnlyDecodableExtensions(certificate)
    else {
        throw Failure(.invalidCertificate, "x5c entry is not a valid certificate")
    }
    guard certificate.signatureAlgorithm == slices.signatureAlgorithm else {
        throw untrusted("certificate signature algorithm parameters do not match")
    }
    return certificate
}

/// Validates the fixed JWS path leaf, intermediate, pinned anchor, and
/// returns the two certificates.
///
/// Walked from the anchor down, and lazily: the intermediate's signature is
/// checked with the pinned anchors' keys on its sliced bytes, and only then
/// is it built (which decodes its key); the leaf is checked with that key
/// and only then built. So no key an anchor did not vouch for is decoded or
/// used — an `x5c[1]` carrying an attacker's oversized key under a foreign
/// root is ``Reason/untrustedChain``, never a verdict about that key. Then
/// the names, key identifiers and keyUsage of each link, the intermediate's
/// window, its CA flag and the leaf's window, at `atMillis`.
func validatePair(
    leaf: CertificateSlices, intermediate: CertificateSlices, anchors: [Certificate], atMillis: Int64
) throws -> (leaf: Certificate, intermediate: Certificate) {
    let vouching = anchors.filter { signatureVerifies(intermediate, by: $0) }
    guard !vouching.isEmpty else {
        throw untrusted("intermediate is not issued by a pinned root")
    }
    let intermediateCertificate = try buildVouched(intermediate)
    guard vouching.contains(where: { checkIssued(intermediateCertificate, issuedBy: $0) }) else {
        throw untrusted("intermediate is not issued by a pinned root")
    }
    guard signatureVerifies(leaf, by: intermediateCertificate) else {
        throw untrusted("leaf is not issued by the intermediate")
    }
    let leafCertificate = try buildVouched(leaf)
    guard checkIssued(leafCertificate, issuedBy: intermediateCertificate) else {
        throw untrusted("leaf is not issued by the intermediate")
    }
    guard certificateValid(intermediateCertificate, atMillis: atMillis) else { throw outsideValidity() }
    guard isCA(intermediateCertificate) else { throw untrusted("intermediate is not a CA") }
    guard !hasUnprocessedCriticalExtension(intermediateCertificate, leaf: false) else {
        throw unprocessedCriticalExtension()
    }
    guard certificateValid(leafCertificate, atMillis: atMillis) else { throw outsideValidity() }
    guard !hasUnprocessedCriticalExtension(leafCertificate, leaf: true) else {
        throw unprocessedCriticalExtension()
    }
    return (leafCertificate, intermediateCertificate)
}

/// Whether every one of `certificate`'s extensions decodes all the way
/// down. swift-certificates keeps an extension's value as opaque bytes, so
/// a value that stops decoding partway through (a re-encoded length lie
/// inside, say, a `BasicConstraints`) is invisible until something asks for
/// that extension — this walks all of them up front, so a certificate
/// "that is not a certificate all the way down" (a corrupted extension) is
/// caught once, as ``Reason/invalidCertificate``, rather than surfacing
/// later as an unrelated chain verdict.
func hasOnlyDecodableExtensions(_ certificate: Certificate) -> Bool {
    for ext in certificate.extensions where (try? DER.parse(Array(ext.value))) == nil {
        return false
    }
    return true
}

func isCA(_ certificate: Certificate) -> Bool {
    guard let constraints = try? certificate.extensions.basicConstraints else { return false }
    if case .isCertificateAuthority = constraints { return true }
    return false
}

func certificateValid(_ certificate: Certificate, atMillis: Int64) -> Bool {
    let instant = dateFromMillis(atMillis)
    return certificate.notValidBefore <= instant && instant <= certificate.notValidAfter
}

/// The embedded certificates a pinned anchor vouched for, and the links that
/// proved it.
struct Authenticated {
    /// The authenticated certificates, in the order they were accepted.
    var certificates: [Certificate] = []
    /// Every (certificate index, issuer index or -1 for an anchor, answer)
    /// this walk already checked, so the path builder does not check one a
    /// second time. Indices are into `certificates`/`anchors`, identified by
    /// object identity via the certificate's DER encoding (a `Certificate`
    /// is a value type, so `===` is not available; the encoded bytes serve
    /// as the identity).
    private var checkedAgainstAnchor: [(certificate: Certificate, anchor: Certificate, verdict: Bool)] = []
    private var checkedAgainstCertificate:
        [(certificate: Certificate, issuer: Certificate, verdict: Bool)] = []

    mutating func recordAnchorCheck(_ certificate: Certificate, _ anchor: Certificate, _ verdict: Bool) {
        checkedAgainstAnchor.append((certificate, anchor, verdict))
    }

    mutating func recordCertificateCheck(_ certificate: Certificate, _ issuer: Certificate, _ verdict: Bool) {
        checkedAgainstCertificate.append((certificate, issuer, verdict))
    }

    func issuedByAnchor(_ certificate: Certificate, _ anchor: Certificate) -> Bool {
        if let cached = checkedAgainstAnchor.first(where: { $0.certificate == certificate && $0.anchor == anchor }) {
            return cached.verdict
        }
        return issuedBy(certificate, anchor)
    }

    /// Named differently from the free ``issuedBy(_:_:)`` on purpose: an
    /// unqualified call to `issuedBy` from inside this method would resolve
    /// to itself (member lookup shadows the free function of the same name),
    /// recursing forever instead of falling back to a real check.
    func cachedIssuedBy(_ certificate: Certificate, _ issuer: Certificate) -> Bool {
        if let cached = checkedAgainstCertificate.first(where: { $0.certificate == certificate && $0.issuer == issuer }) {
            return cached.verdict
        }
        return issuedBy(certificate, issuer)
    }
}

/// The embedded certificates whose signature verifies under a pinned anchor,
/// or under a certificate already accepted this way, walking down from the
/// anchors in at most ``maxPathLength`` rounds. Only these are handed to
/// ``buildAndValidatePath(target:authenticated:anchors:atMillis:)``.
func authenticatedTopDown(embedded: [Certificate], anchors: [Certificate]) -> Authenticated {
    var authenticated = Authenticated()
    var pending: [Certificate] = []
    for certificate in embedded {
        if let anchor = anchors.first(where: { $0 == certificate }) {
            authenticated.certificates.append(certificate)
            authenticated.recordAnchorCheck(certificate, anchor, true)
        } else {
            pending.append(certificate)
        }
    }
    var issuers: [Certificate] = anchors
    for _ in 0..<maxPathLength {
        if pending.isEmpty { break }
        var thisRound: [Certificate] = []
        var stillPending: [Certificate] = []
        for candidate in pending {
            var accepted = false
            for issuer in issuers {
                let verdict = issuedBy(candidate, issuer)
                if anchors.contains(issuer) {
                    authenticated.recordAnchorCheck(candidate, issuer, verdict)
                } else {
                    authenticated.recordCertificateCheck(candidate, issuer, verdict)
                }
                if verdict {
                    accepted = true
                    break
                }
            }
            if accepted {
                thisRound.append(candidate)
            } else {
                stillPending.append(candidate)
            }
        }
        pending = stillPending
        if thisRound.isEmpty { break }
        authenticated.certificates.append(contentsOf: thisRound)
        issuers = thisRound
    }
    return authenticated
}

/// Builds a path from `target` through `candidates` to one of the pinned
/// `anchors`, the shape a legacy receipt uses, where the intermediates are
/// embedded in the CMS blob; then checks every certificate on it is inside
/// its validity window at `atMillis`. Returns the path, target first, anchor
/// excluded.
///
/// The candidates are the ones ``authenticatedTopDown(embedded:anchors:)``
/// accepted, so the only keys the walk verifies with are ones an anchor
/// vouched for, and a link it already checked is not checked again.
func buildAndValidatePath(
    target: Certificate, authenticated: Authenticated, anchors: [Certificate], atMillis: Int64
) throws -> [Certificate] {
    var path: [Certificate] = [target]
    var current = target
    while true {
        if path.count > 1, !isCA(current) {
            throw untrusted("an intermediate is not a CA")
        }
        if anchors.contains(where: { authenticated.issuedByAnchor(current, $0) }) {
            break
        }
        if path.count >= maxPathLength {
            throw untrusted("chain exceeds the maximum length")
        }
        guard
            let issuer = authenticated.certificates.first(where: { candidate in
                !path.contains(candidate) && authenticated.cachedIssuedBy(current, candidate)
            })
        else {
            throw untrusted("chain does not reach a pinned root")
        }
        path.append(issuer)
        current = issuer
    }
    for certificate in path where !certificateValid(certificate, atMillis: atMillis) {
        throw outsideValidity()
    }
    for (index, certificate) in path.enumerated()
    where hasUnprocessedCriticalExtension(certificate, leaf: index == 0) {
        throw unprocessedCriticalExtension()
    }
    return path
}
