import Foundation
import X509

/// ``Verifier/verifySignedData(jws:)``: any Apple-signed compact JWS
/// (StoreKit 2 `jwsRepresentation`, App Store Server `signedTransactionInfo`
/// and `signedRenewalInfo`, app transactions, Server Notifications V2),
/// verified offline.
///
/// ES256 only, exactly three `x5c` certificates, the chain to a pinned root
/// at the payload's `signedDate` (the clock when it states none), Apple's
/// marker OIDs on leaf and intermediate, then the signature. A broken outer
/// structure fails as ``Reason/malformed`` before any cryptography; a
/// payload that does not parse as a JSON object is carried past the chain
/// and signature checks with the clock standing in for its signing date, and
/// fails as ``Reason/invalidSignature`` if the signature does not verify,
/// ``Reason/unreadablePayload`` if it does.

/// The longest compact JWS, in UTF-8 bytes, checked before the string is
/// split or any segment decoded.
public let maxJwsBytes = 262_144

func verifySignedData(
    jws: String, roots: [Certificate], clock: @Sendable () -> Int64
) -> VerificationResult<JsonPayload> {
    let outcome: Result<(json: String, verified: Bool), Failure> = {
        do {
            return .success(try verifyJwsSignature(jws: jws, roots: roots, clock: clock))
        } catch let failure as Failure {
            return .failure(failure)
        } catch {
            return .failure(Failure(.malformed, "unexpected failure while reading unverified input"))
        }
    }()
    switch outcome {
    case .failure(let failure): return VerificationResult(failure: failure)
    case .success(let result):
        if result.verified {
            return VerificationResult(payload: JsonPayload(json: result.json))
        }
        return VerificationResult(failure: Failure(.unreadablePayload, "signed payload is not a JSON object"))
    }
}

/// Returns the payload text and whether it parsed as a JSON object — a
/// non-object payload still reaches here (the signature has already
/// verified by the time this returns), and the caller reports
/// ``Reason/unreadablePayload`` for it rather than throwing.
private func verifyJwsSignature(
    jws: String, roots: [Certificate], clock: @Sendable () -> Int64
) throws -> (json: String, verified: Bool) {
    guard !jws.isEmpty else { throw malformedJws("jws is empty") }
    guard jws.utf8.count <= maxJwsBytes else {
        throw Failure(.tooLarge, "jws exceeds the maximum accepted size of \(maxJwsBytes) bytes")
    }
    let parts = jws.components(separatedBy: ".")
    guard parts.count == 3 else {
        throw malformedJws("expected 3 dot-separated segments, got \(parts.count)")
    }
    // Strict, not lenient: a lenient reading would give one Apple-signed
    // payload unboundedly many accepted wire forms, and the signature
    // segment is not covered by the signature at all.
    guard let headerBytes = decodeBase64URLStrict(parts[0]) else {
        throw malformedJws("header is not canonical base64url")
    }
    guard let payloadBytes = decodeBase64URLStrict(parts[1]) else {
        throw malformedJws("payload is not canonical base64url")
    }
    guard let signature = decodeBase64URLStrict(parts[2]) else {
        throw malformedJws("signature is not canonical base64url")
    }

    let (alg, x5c) = try readHeader(headerBytes)
    guard alg == "ES256" else { throw malformedJws("alg must be ES256") }
    guard let x5c, x5c.count == 3 else { throw malformedJws("x5c must contain exactly 3 certificates") }
    // Sliced, not parsed: swift-certificates decodes a certificate's public
    // key while it parses it, so a `Certificate` is built only once a pinned
    // root has vouched for its signature (``validatePair``). The third entry
    // is trusted by nobody and is never built at all; slicing it decides
    // only whether it has the shape of a certificate.
    let leafSlice = try sliceX5cCertificate(x5c[0])
    let intermediateSlice = try sliceX5cCertificate(x5c[1])
    _ = try sliceX5cCertificate(x5c[2])

    let payload = readPayload(payloadBytes)
    // Chain validity is judged at the payload's signing date, so a payload
    // signed with a since-rotated certificate keeps verifying. An
    // in-range-for-Int64 signedDate is used as-is, however far from now: the
    // certificate validity comparison (``certificateValid(_:atMillis:)``) is
    // plain `Date` arithmetic, which never traps for an extreme instant —
    // unlike swift-certificates' own `GeneralizedTime`, so nothing here
    // needs to additionally bound the value to a representable calendar
    // date the way 0.6 did to avoid a crash in that type.
    let atMillis = payload?.signedDate ?? clock()
    let (leaf, intermediate) = try validatePair(
        leaf: leafSlice, intermediate: intermediateSlice, anchors: roots, atMillis: atMillis)
    // The marker OIDs after the chain, as on the receipt path: a foreign
    // chain is untrustedChain whatever it carries, and only a pinned chain
    // can be the wrong kind of Apple certificate.
    guard leaf.extensions.contains(where: { $0.oid == signingLeafOID }) else {
        throw Failure(.invalidCertificatePurpose, "leaf certificate lacks Apple marker OID \(signingLeafOID)")
    }
    guard intermediate.extensions.contains(where: { $0.oid == wwdrIntermediateOID }) else {
        throw Failure(
            .invalidCertificatePurpose, "intermediate certificate lacks Apple marker OID \(wwdrIntermediateOID)")
    }
    let signingInput = Array((parts[0] + "." + parts[1]).utf8)
    guard verifyES256(leaf: leaf, signature: signature, signingInput: signingInput) else {
        throw Failure(.invalidSignature, "ES256 signature does not match the leaf key")
    }
    if let payload {
        return (json: payload.json, verified: true)
    }
    return (json: "", verified: false)
}

private func malformedJws(_ detail: String) -> Failure { Failure(.malformed, detail) }

/// The last `alg` string and the last `x5c` array of strings, as a map would
/// keep them. The header is outer structure, so anything that stops the
/// read is ``Reason/malformed``: bytes that are not strict UTF-8, a
/// byte-order mark (RFC 8259 §8.1 forbids one), and anything but whitespace
/// after the object.
private func readHeader(_ bytes: [UInt8]) throws -> (alg: String?, x5c: [String]?) {
    // RFC 8259 §8.1 forbids a byte-order mark. It cannot be left to the
    // reader below (which would refuse it as "not `{`", since U+FEFF is not
    // JSON whitespace): `String(bytes:encoding:.utf8)` strips a leading BOM
    // during decoding, so by the time the text reaches the reader the BOM
    // is already gone and the object looks perfectly well-formed. Checked
    // on the raw bytes instead, before decoding.
    guard bytes.starts(with: [0xEF, 0xBB, 0xBF]) == false else { throw malformedJws("header starts with a byte-order mark") }
    guard let text = String(bytes: bytes, encoding: .utf8) else { throw malformedJws("header is not UTF-8") }
    let members: [(String, JsonValue)]
    do {
        members = try wholeObjectMembers(text)
    } catch {
        throw malformedJws("header is not a JSON object")
    }
    var alg: String?
    var x5c: [String]?
    for (name, value) in members {
        switch name {
        case "alg":
            if case .string(let text) = value { alg = text } else { alg = nil }
        case "x5c":
            if case .strings(let entries) = value { x5c = entries } else { x5c = nil }
        default: break
        }
    }
    return (alg, x5c)
}

/// The payload text and its last top-level `signedDate`, or `nil` when it is
/// not a JSON object in UTF-8. Reading it never fails verification by
/// itself. A `signedDate` that is not a number, or is a number no instant
/// can hold (`1e300`), counts as not stated: the clock stands in for it.
private func readPayload(_ bytes: [UInt8]) -> (json: String, signedDate: Int64?)? {
    guard let text = String(bytes: bytes, encoding: .utf8) else { return nil }
    guard let members = try? wholeObjectMembers(text) else { return nil }
    var signedDate: Int64?
    for (name, value) in members where name == "signedDate" {
        if case .number(let numberText, let integer) = value {
            signedDate = jsonNumberAsInstant(text: numberText, integer: integer)
        } else {
            signedDate = nil
        }
    }
    return (text, signedDate)
}

/// Decodes one `x5c` entry — standard base64 with canonical padding (RFC
/// 7515 §4.1.6) — and slices it into the parts a signature check needs,
/// without decoding its key. Anything that does not even have the shape of
/// a certificate is ``Reason/invalidCertificate``, as an entry that does not
/// parse always was; what swift-certificates would refuse inside the TBS (a
/// key it cannot use, an extension that does not decode) is found when the
/// certificate is built, after a pinned root has vouched for it.
func sliceX5cCertificate(_ entry: String) throws -> CertificateSlices {
    guard let der = decodeReceiptBase64(entry) else {
        throw Failure(.invalidCertificate, "x5c entry is not valid base64")
    }
    guard let slices = sliceCertificate(der) else {
        throw Failure(.invalidCertificate, "x5c entry is not a valid certificate")
    }
    return slices
}
