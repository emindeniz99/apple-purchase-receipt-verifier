import X509

/// ``Verifier/verifyReceipt(base64:)``: legacy PKCS#7 app receipts, verified
/// offline.
///
/// Checked in order: strict base64, the CMS envelope, the chain to a pinned
/// root walked top-down together with certificate validity at the receipt's
/// creation date, then Apple's marker OIDs on both the leaf (receipt
/// signing) and the WWDR intermediate, and last the signature. Validity is
/// part of the chain check, so it comes before the markers and the
/// signature: an expired chain whose signer lacks the marker, or whose
/// signature is broken, is ``Reason/invalidCertificate``.

/// The largest receipt string, in UTF-8 bytes: 3 MiB, Apple's own request
/// limit, checked before anything is decoded.
public let maxReceiptBytes = 3_145_728

func verifyReceipt(
    base64: String, roots: [Certificate], clock: @Sendable () -> Int64
) -> VerificationResult<ReceiptPayload> {
    let contentOutcome: Result<[UInt8], Failure> = {
        do {
            return .success(try verifyReceiptSignature(base64: base64, roots: roots, clock: clock))
        } catch let failure as Failure {
            return .failure(failure)
        } catch {
            // Nothing has verified yet, so an unexpected error here must not
            // raise the internal-error alarm at will — the format reason,
            // as it would be for any other broken structure.
            return .failure(Failure(.malformed, "unexpected failure while reading unverified input"))
        }
    }()
    switch contentOutcome {
    case .failure(let failure): return VerificationResult(failure: failure)
    case .success(let content):
        do {
            return VerificationResult(payload: try parseReceiptPayload(content))
        } catch let error as PayloadError {
            return VerificationResult(
                failure: Failure(
                    .unreadablePayload, "signed receipt content could not be read: \(error.detail)", cause: error))
        } catch {
            return VerificationResult(
                failure: Failure(.unreadablePayload, "signed receipt content could not be read"))
        }
    }
}

/// Every check up to and including a signature; returns the signed payload,
/// not yet decoded.
private func verifyReceiptSignature(
    base64: String, roots: [Certificate], clock: @Sendable () -> Int64
) throws -> [UInt8] {
    guard !base64.isEmpty else { throw malformedReceipt("receipt is empty") }
    guard base64.utf8.count <= maxReceiptBytes else {
        throw Failure(.tooLarge, "receipt exceeds the maximum accepted size of \(maxReceiptBytes) bytes")
    }
    guard let der = decodeReceiptBase64(base64) else {
        throw malformedReceipt("receipt is not valid base64")
    }
    let cms = try parseCms(der)

    // Only the creation date is read before trust is established, because
    // chain validity is anchored at signing time; nothing else in the
    // payload is decoded until the chain and a signature have passed.
    let creationDate = readCreationDate(cms.content)

    let decodedCertificates = cms.certificates
    // Signer-independent, so walked once for all SignerInfos, and only once
    // one of them has named an embedded certificate that decodes.
    var authenticated: Authenticated?
    var firstFailure: Failure?
    for info in cms.signerInfos {
        let matches: [Certificate]
        do {
            matches = try signerCertificates(info, cms: cms, decoded: decodedCertificates)
        } catch let failure as Failure {
            if firstFailure == nil { firstFailure = failure }
            continue
        }
        let atMillis = creationDate ?? clock()
        if authenticated == nil {
            authenticated = authenticatedTopDown(embedded: decodedCertificates, anchors: roots)
        }
        // The bag is unsigned, so a certificate carrying the signer's
        // identity can sit ahead of the genuine one. Each match is tried in
        // bag order: one passing is enough, and only when none does is the
        // first match's failure the verdict. No match's key is used before
        // its chain has passed.
        var firstMatchFailure: Failure?
        var signerSucceeded = false
        for signer in matches {
            do {
                try verifyOneSigner(
                    cms: cms, info: info, signer: signer, authenticated: authenticated!, roots: roots,
                    atMillis: atMillis)
                signerSucceeded = true
                break
            } catch let failure as Failure {
                if firstMatchFailure == nil { firstMatchFailure = failure }
            }
        }
        if signerSucceeded { return cms.content }
        // Every SignerInfo signs the same content, so another one passing
        // proves the same bytes; only when none does is the first one's
        // failure the verdict.
        if firstFailure == nil {
            firstFailure = firstMatchFailure ?? malformedReceipt("signer certificate not embedded")
        }
    }
    throw firstFailure ?? malformedReceipt("no signer info")
}

/// The certificates carrying the issuer and serial `info` names, never
/// empty, or the verdict for the bag. The signer's own entry not decoding is
/// ``Reason/invalidCertificate``, as an unreadable `x5c` entry is on the JWS
/// path; any other entry not decoding is ``Reason/malformed``, because the
/// bag is unsigned and bytes that cannot be read there are a defect of the
/// receipt, not of a certificate. A broken signer outranks a broken
/// stranger.
private func signerCertificates(
    _ info: CmsSignerInfo, cms: ParsedCms, decoded: [Certificate]
) throws -> [Certificate] {
    if cms.unreadableIdentities.contains(where: {
        $0.serial == info.serialContents && $0.issuer == info.issuerRaw
    }) {
        throw Failure(.invalidCertificate, "receipt signer certificate does not decode")
    }
    if cms.hasUnreadable {
        throw malformedReceipt("an embedded certificate is not a valid certificate")
    }
    var matches: [Certificate] = []
    for (index, identity) in cms.certificateIdentities.enumerated()
    where identity.serial == info.serialContents && identity.issuer == info.issuerRaw {
        matches.append(decoded[index])
    }
    guard !matches.isEmpty else { throw malformedReceipt("signer certificate not embedded") }
    return matches
}

private func verifyOneSigner(
    cms: ParsedCms, info: CmsSignerInfo, signer: Certificate, authenticated: Authenticated,
    roots: [Certificate], atMillis: Int64
) throws {
    // The signer is embedded and IS the certificate SignerInfo names, but a
    // corrupted extension value makes it "not a certificate all the way
    // down" — caught here, before the chain runs, so this reports
    // invalidCertificate rather than whatever verdict a chain built from a
    // half-read certificate would happen to produce.
    guard hasOnlyDecodableExtensions(signer) else {
        throw Failure(.invalidCertificate, "receipt signer certificate is not a valid certificate")
    }
    let path = try buildAndValidatePath(
        target: signer, authenticated: authenticated, anchors: roots, atMillis: atMillis)
    // Checked after the chain, so a foreign chain still reports
    // untrustedChain rather than invalidCertificatePurpose.
    guard signer.extensions.contains(where: { $0.oid == signingLeafOID }) else {
        throw Failure(
            .invalidCertificatePurpose,
            "receipt signer certificate lacks Apple receipt-signing marker OID \(signingLeafOID)")
    }
    // The certificate after the signer on the path. A signer issued straight
    // by a root has no WWDR certificate to carry the marker.
    guard path.count > 1, path[1].extensions.contains(where: { $0.oid == wwdrIntermediateOID }) else {
        throw Failure(
            .invalidCertificatePurpose,
            "receipt intermediate certificate lacks Apple WWDR marker OID \(wwdrIntermediateOID)")
    }
    // The chain is checked BEFORE the signature on purpose: checking the
    // signature first would run the attacker's own key (their choice of RSA
    // size and exponent) before anything about it is trusted.
    try verifyCmsSignature(cms: cms, info: info, signer: signer)
}

/// No algorithm or key-type allowlist beyond what this library's crypto
/// dependencies implement (``SignatureCrypto``): the signer is already
/// pinned to an Apple root and carries Apple's receipt-signing marker, so a
/// change of algorithm on Apple's side does not reject genuine receipts.
private func verifyCmsSignature(cms: ParsedCms, info: CmsSignerInfo, signer: Certificate) throws {
    guard let digest = digestAlgorithm(oid: info.digestAlgorithmOID) else {
        throw Failure(.invalidSignature, "unsupported digest algorithm")
    }
    let signedBytes: [UInt8]
    if let signedAttrsBytes = info.signedAttrsBytes {
        let contentDigest = digest.hash(cms.content)
        // RFC 5652 5.3 makes contentType and messageDigest mandatory
        // whenever signedAttrs are present: a set without one of them
        // cannot be checked, so it fails as a signature. Genuine receipts
        // carry no signedAttrs, so this branch is never reached for a real
        // receipt.
        let outcome = try signedAttributeValues(signedAttrsBytes)
        switch outcome {
        case .missingContentType, .missingMessageDigest, .duplicateAttribute:
            throw Failure(
                .invalidSignature,
                "signedAttrs lack a contentType or messageDigest attribute, or carry one twice")
        case .ok(let messageDigest, let contentType):
            // RFC 5652 11.1: the contentType attribute names the content the
            // signature covers, so one that names another type is a
            // signature over something else.
            guard contentType == cms.contentTypeOctets else {
                throw Failure(.invalidSignature, "contentType attribute differs from the eContentType")
            }
            guard constantTimeEqual(messageDigest, contentDigest) else {
                throw Failure(.invalidSignature, "messageDigest attribute does not match content")
            }
            signedBytes = signedAttrsBytes
        }
    } else {
        signedBytes = cms.content
    }
    let valid = verifySignerSignature(
        signer: signer, digestAlgorithmOID: info.digestAlgorithmOID,
        signatureAlgorithmOID: info.signatureAlgorithmOID, signature: info.signature, signedBytes: signedBytes)
    guard valid else { throw Failure(.invalidSignature, "CMS signature check failed") }
}

func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
    guard a.count == b.count else { return false }
    var diff: UInt8 = 0
    for i in 0..<a.count { diff |= a[i] ^ b[i] }
    return diff == 0
}
