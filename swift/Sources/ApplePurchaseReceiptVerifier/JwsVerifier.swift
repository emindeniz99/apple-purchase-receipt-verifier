import Crypto
import Foundation
import SwiftASN1
import X509

/// Decoded `JWSTransactionDecodedPayload` — dates are milliseconds since
/// epoch as sent by Apple; `nil` means the claim was absent.
public struct TransactionPayload: Codable, Sendable {
    public let bundleId: String?
    public let environment: String?
    public let productId: String?
    public let transactionId: String?
    public let originalTransactionId: String?
    public let webOrderLineItemId: String?
    public let subscriptionGroupIdentifier: String?
    public let appAccountToken: String?
    public let inAppOwnershipType: String?
    public let type: String?
    public let transactionReason: String?
    public let storefront: String?
    public let currency: String?
    public let offerIdentifier: String?
    public let signedDate: Int64?
    public let purchaseDate: Int64?
    public let originalPurchaseDate: Int64?
    public let expiresDate: Int64?
    public let revocationDate: Int64?
    public let price: Int64?
    public let quantity: Int?
    public let offerType: Int?
    public let revocationReason: Int?

    /// Entitlement helper: not revoked, and (for subscriptions) not expired
    /// at `date`. Point-in-time on the signed claims only — later refunds
    /// or renewals are invisible (track status via transaction id).
    public func isActive(at date: Date) -> Bool {
        let millis = Int64(date.timeIntervalSince1970 * 1000)
        if let revocationDate, millis >= revocationDate { return false }
        if let expiresDate { return millis < expiresDate }
        return true
    }
}

/// Decoded `AppTransaction` payload; environment lives in ``receiptType``.
public struct AppTransactionPayload: Codable, Sendable {
    public let bundleId: String?
    public let receiptType: String?
    public let applicationVersion: String?
    public let originalApplicationVersion: String?
    public let deviceVerification: String?
    public let deviceVerificationNonce: String?
    public let appTransactionId: String?
    public let appAppleId: Int64?
    public let receiptCreationDate: Int64?
    public let originalPurchaseDate: Int64?
    public let preorderDate: Int64?
    public let versionExternalIdentifier: Int64?
}

extension TransactionPayload {
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        bundleId = try c.claimString(.bundleId)
        environment = try c.claimString(.environment)
        productId = try c.claimString(.productId)
        transactionId = try c.claimString(.transactionId)
        originalTransactionId = try c.claimString(.originalTransactionId)
        webOrderLineItemId = try c.claimString(.webOrderLineItemId)
        subscriptionGroupIdentifier = try c.claimString(.subscriptionGroupIdentifier)
        appAccountToken = try c.claimString(.appAccountToken)
        inAppOwnershipType = try c.claimString(.inAppOwnershipType)
        type = try c.claimString(.type)
        transactionReason = try c.claimString(.transactionReason)
        storefront = try c.claimString(.storefront)
        currency = try c.claimString(.currency)
        offerIdentifier = try c.claimString(.offerIdentifier)
        signedDate = try c.claimInteger(.signedDate)
        purchaseDate = try c.claimInteger(.purchaseDate)
        originalPurchaseDate = try c.claimInteger(.originalPurchaseDate)
        expiresDate = try c.claimInteger(.expiresDate)
        revocationDate = try c.claimInteger(.revocationDate)
        price = try c.claimInteger(.price)
        quantity = try c.claimInteger(.quantity)
        offerType = try c.claimInteger(.offerType)
        revocationReason = try c.claimInteger(.revocationReason)
    }
}

extension AppTransactionPayload {
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        bundleId = try c.claimString(.bundleId)
        receiptType = try c.claimString(.receiptType)
        applicationVersion = try c.claimString(.applicationVersion)
        originalApplicationVersion = try c.claimString(.originalApplicationVersion)
        deviceVerification = try c.claimString(.deviceVerification)
        deviceVerificationNonce = try c.claimString(.deviceVerificationNonce)
        appTransactionId = try c.claimString(.appTransactionId)
        appAppleId = try c.claimInteger(.appAppleId)
        receiptCreationDate = try c.claimInteger(.receiptCreationDate)
        originalPurchaseDate = try c.claimInteger(.originalPurchaseDate)
        preorderDate = try c.claimInteger(.preorderDate)
        versionExternalIdentifier = try c.claimInteger(.versionExternalIdentifier)
    }
}

/// The strict typed read of one signed claim. Absent and JSON null are nil;
/// anything else must be exactly the modelled JSON type, or the read throws
/// ``VerificationError/Reason/internalError``. Claims a model does not carry
/// are never looked at, whatever their type.
extension KeyedDecodingContainer {
    /// A string claim takes a JSON string only; JSONDecoder already refuses a
    /// number, a boolean or a structure for `String`.
    func claimString(_ key: Key) throws -> String? {
        guard contains(key), try !decodeNil(forKey: key) else { return nil }
        guard let value = try? decode(String.self, forKey: key) else {
            throw VerificationError(.internalError, "signed payload claim \(key.stringValue) is not a string")
        }
        return value
    }

    /// An integer claim takes a JSON number whose value is a whole number
    /// that fits `T`: 1.0 is 1, while 1.5, a boolean and a whole number
    /// outside `T` are refused. JSONDecoder is not left to decide on its own,
    /// because whether it reads 1.0 as an integer has varied by platform, so
    /// the number is read as a `Double` first and must have no fraction.
    func claimInteger<T: FixedWidthInteger & Decodable>(_ key: Key) throws -> T? {
        guard contains(key), try !decodeNil(forKey: key) else { return nil }
        if let number = try? decode(Double.self, forKey: key), number.rounded(.towardZero) == number {
            // The integer decode keeps full precision past 2^53; the Double
            // is the fallback for a decoder that refuses 1.0 as an integer.
            if let value = try? decode(T.self, forKey: key) { return value }
            if let value = T(exactly: number) { return value }
        }
        throw VerificationError(.internalError, "signed payload claim \(key.stringValue) is not an integer")
    }
}

/// Verifies Apple-signed JWS payloads (StoreKit 2 `jwsRepresentation`,
/// `signedTransactionInfo` / `signedRenewalInfo`, Server Notifications V2)
/// completely offline against pinned Apple roots — PLAN.md §2.1, mirroring
/// the Java implementation check-for-check.
public struct JwsVerifier: Sendable {
    /// Apple marker OID: leaf certificate used for App Store signing.
    static let leafOID: ASN1ObjectIdentifier = [1, 2, 840, 113635, 100, 6, 11, 1]
    /// Apple marker OID: Worldwide Developer Relations intermediate CA.
    static let intermediateOID: ASN1ObjectIdentifier = [1, 2, 840, 113635, 100, 6, 2, 1]

    /// Ceiling on a compact JWS, in UTF-8 bytes (`utf8.count`). A longer
    /// input is ``VerificationError/Reason/invalidJwsFormat`` before it is
    /// split or decoded. The number is the Java and PHP ports'. Every JWS in
    /// the shared corpus, Apple's own mock notification data included, is
    /// under 2.5 KB, so 256 KiB is a hundredfold headroom over anything Apple
    /// has signed. A compact JWS is base64url and dots, so its bytes and its
    /// characters are the same count for any input that could verify.
    public static let maxJwsBytes = 262_144

    /// How deep a JSON structure may nest inside the header or payload
    /// segment; the Java port's number. Both are parsed before the signature
    /// is checked, so this bounds attacker-chosen bytes. `JSONSerialization`
    /// and `JSONDecoder` take no depth option, so the depth is counted
    /// before either runs.
    static let maxJsonNestingDepth = 64

    private let roots: [Certificate]
    private let bundleId: String
    private let acceptedEnvironments: Set<AppleEnvironment>
    private let appAppleId: Int64?
    private let maxSignedAgeMillis: Int64?
    private let clock: @Sendable () -> Date

    /// - Parameters:
    ///   - trustedRoots: pinned DER roots (production: ``appleJwsRoots()``)
    ///   - bundleId: bundle id every payload must carry
    ///   - acceptedEnvironments: include `.sandbox` on endpoints App Review
    ///     can hit (PLAN.md D3)
    ///   - appAppleId: required to accept Production AppTransactions
    ///   - maxSignedAgeMillis: reject payloads signed longer ago (PLAN.md D5)
    ///   - clock: the source of "now" for the checks that genuinely depend on
    ///     wall-clock time — today the max-signed-age rule alone. Omitted, the
    ///     system clock is read, exactly as before this parameter existed.
    ///     The type is a `@Sendable () -> Date` rather than a `Clock`: Swift's
    ///     `Clock` protocol (`ContinuousClock`, `SuspendingClock`) measures
    ///     elapsed time from an arbitrary origin and cannot name a wall-clock
    ///     instant like 2025-01-01, which is exactly what pinning "now"
    ///     requires. A closure returning `Date` is the idiomatic injectable
    ///     wall-clock source on Apple platforms, and `@Sendable` keeps this
    ///     struct `Sendable`.
    public init(
        trustedRoots: [Data], bundleId: String,
        acceptedEnvironments: Set<AppleEnvironment>,
        appAppleId: Int64? = nil, maxSignedAgeMillis: Int64? = nil,
        clock: (@Sendable () -> Date)? = nil
    ) throws {
        guard !trustedRoots.isEmpty else {
            throw VerificationError(.invalidCertificate, "trustedRoots must not be empty")
        }
        guard !bundleId.isEmpty, !acceptedEnvironments.isEmpty else {
            throw VerificationError(.invalidJwsFormat, "bundleId and acceptedEnvironments are required")
        }
        self.roots = try trustedRoots.map { try Certificate(derEncoded: [UInt8]($0)) }
        self.bundleId = bundleId
        self.acceptedEnvironments = acceptedEnvironments
        self.appAppleId = appAppleId
        self.maxSignedAgeMillis = maxSignedAgeMillis
        self.clock = clock ?? { Date() }
    }

    /// Verifies a signed transaction and checks bundle id + environment.
    public func verifyTransaction(_ jws: String) async throws -> TransactionPayload {
        let payloadData = try await verifySignature(jws)
        let payload = try decodePayload(TransactionPayload.self, from: payloadData)
        try requireBundleId(payload.bundleId)
        _ = try requireAcceptedEnvironment(payload.environment)
        return payload
    }

    /// Verifies a signed AppTransaction and checks bundle id, environment
    /// (`receiptType`), and — in Production — the app Apple id.
    public func verifyAppTransaction(_ jws: String) async throws -> AppTransactionPayload {
        let payloadData = try await verifySignature(jws)
        let payload = try decodePayload(AppTransactionPayload.self, from: payloadData)
        try requireBundleId(payload.bundleId)
        let environment = try requireAcceptedEnvironment(payload.receiptType)
        if environment == .production, appAppleId == nil || appAppleId != payload.appAppleId {
            throw VerificationError(
                .wrongAppAppleId,
                "expected \(appAppleId.map(String.init) ?? "nil") but payload has \(payload.appAppleId.map(String.init) ?? "nil")")
        }
        return payload
    }

    /// Verifies the signature/chain only and returns the raw claims — for
    /// payload types without a dedicated model (renewal info, notification
    /// envelopes). The caller must check bundle id / environment /
    /// app Apple id in the returned claims itself.
    public func verifyRaw(_ jws: String) async throws -> [String: Any] {
        let payloadData = try await verifySignature(jws)
        guard let claims = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            throw VerificationError(.invalidJwsFormat, "payload is not a JSON object")
        }
        return claims
    }

    private func verifySignature(_ jws: String) async throws -> Data {
        // Before the split, so nothing downstream allocates in proportion to
        // an input this verifier has already decided not to look at.
        guard jws.utf8.count <= Self.maxJwsBytes else {
            throw VerificationError(
                .invalidJwsFormat,
                "jws exceeds the maximum accepted size of \(Self.maxJwsBytes) bytes")
        }
        let segments = jws.components(separatedBy: ".")
        guard segments.count == 3 else {
            throw VerificationError(
                .invalidJwsFormat,
                "expected 3 dot-separated segments, got \(segments.count)")
        }
        guard let headerData = base64URLDecode(segments[0]),
            let payloadData = base64URLDecode(segments[1])
        else {
            throw VerificationError(.invalidJwsFormat, "header/payload is not valid base64url JSON")
        }
        // Both segments, here, because the payload is parsed further down and
        // again by the typed decoders, and every one of those parses happens
        // before or without a signature check.
        guard !jsonNestingExceeds(headerData, limit: Self.maxJsonNestingDepth),
            !jsonNestingExceeds(payloadData, limit: Self.maxJsonNestingDepth)
        else {
            throw VerificationError(
                .invalidJwsFormat,
                "header/payload nests more than \(Self.maxJsonNestingDepth) levels deep")
        }
        // JSONDecoder, not JSONSerialization: the latter drops a leading
        // U+FEFF from a string value (always on Darwin), and an x5c entry
        // starting with one must be refused like any other character outside
        // the base64 alphabet. A header that is not an object, an alg or an
        // x5c of the wrong type, and an x5c entry that is not a string all
        // fail this decode.
        guard let header = try? JSONDecoder().decode(JwsHeader.self, from: headerData) else {
            throw VerificationError(.invalidJwsFormat, "header is not a JSON object with a string alg and string x5c entries")
        }
        guard header.alg == "ES256" else {
            throw VerificationError(.invalidJwsFormat, "alg must be ES256")
        }
        guard let x5c = header.x5c, x5c.count == 3 else {
            throw VerificationError(.invalidJwsFormat, "x5c must contain exactly 3 certificates")
        }
        // The third entry is decoded and parsed like the other two and then
        // dropped: it is never compared to an anchor and never trusted, so
        // swapping in a stranger's root still changes nothing — but an entry
        // that is not a certificate is INVALID_CERTIFICATE at every index
        // (transaction/reject-x5c-root-that-is-not-a-certificate).
        // Each entry is standard base64 with canonical padding (RFC 7515
        // §4.1.6), the receipt-data rule: junk, whitespace, base64url
        // characters and a wrong '=' count are refused rather than skipped
        // on the way to a genuine certificate.
        guard let leafDER = decodeReceiptBase64(x5c[0]),
            let intermediateDER = decodeReceiptBase64(x5c[1]),
            let rootDER = decodeReceiptBase64(x5c[2]),
            let leaf = try? Certificate(derEncoded: [UInt8](leafDER)),
            let intermediate = try? Certificate(derEncoded: [UInt8](intermediateDER)),
            let suppliedRoot = try? Certificate(derEncoded: [UInt8](rootDER))
        else {
            throw VerificationError(.invalidCertificate, "x5c entry is not a valid certificate")
        }
        for certificate in [leaf, intermediate, suppliedRoot] {
            try requireDecodableExtensions(certificate, what: "x5c entry")
        }
        guard leaf.extensions.contains(where: { $0.oid == Self.leafOID }) else {
            throw VerificationError(
                .invalidCertificatePurpose,
                "leaf certificate lacks Apple marker OID \(Self.leafOID)")
        }
        guard intermediate.extensions.contains(where: { $0.oid == Self.intermediateOID }) else {
            throw VerificationError(
                .invalidCertificatePurpose,
                "intermediate certificate lacks Apple marker OID \(Self.intermediateOID)")
        }

        // RFC 7515 7.1 makes the payload a JSON object, and reading a payload
        // that is not one as "no claims" fails OPEN: every claim then reads as
        // absent, certificate validity falls back to the current time, and the
        // staleness rule stops applying at all. An empty segment and a JSON
        // array are both that payload
        // (transaction/reject-empty-payload-segment,
        // transaction/reject-payload-that-is-a-json-array).
        guard let claims = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any] else {
            throw VerificationError(.invalidJwsFormat, "payload is not a JSON object")
        }

        // Chain validity is checked at signing time so payloads signed with
        // since-rotated certificates keep verifying (PLAN.md §2.1 step 4).
        let signedAtMillis =
            (claims["signedDate"] as? Double)
            ?? (claims["receiptCreationDate"] as? Double)
        // Deliberately NOT the injected clock: chain validity is judged at the
        // payload's signing date (PLAN.md 2.1 step 4), and the fallback for a
        // payload that carries no date stands in for that missing signing
        // date. Routing the clock here would let a caller move a
        // certificate-validity verdict, which the seam must never do.
        let validationTime = signedAtMillis.map { Date(timeIntervalSince1970: $0 / 1000) } ?? Date()
        // The claim is attacker-supplied JSON and is read before the signature
        // check, so a large enough number would trap inside the policy rather
        // than fail the payload. The verdict is .invalidChain, not
        // .invalidJwsFormat: the payload is well-formed JSON and the number is
        // a legal one, and what the claim decides is the instant the
        // certificate windows are judged at — an instant no calendar can
        // express is inside no window. That is the reading the other ports
        // reach through their own date types, and what the shared vector pins.
        guard isRepresentableAsCertificateValidationTime(validationTime) else {
            throw VerificationError(
                .invalidChain,
                "signed date out of representable range")
        }
        try await Self.validateChain(
            leaf: leaf, intermediate: intermediate,
            roots: roots, at: validationTime)

        guard let publicKey = P256.Signing.PublicKey(leaf.publicKey) else {
            throw VerificationError(.invalidSignature, "leaf key is not EC P-256")
        }
        guard let signatureBytes = base64URLDecode(segments[2]) else {
            throw VerificationError(.invalidJwsFormat, "signature segment is not valid base64url")
        }
        guard signatureBytes.count == 64,
            let signature = try? P256.Signing.ECDSASignature(rawRepresentation: signatureBytes)
        else {
            throw VerificationError(.invalidSignature, "ES256 signature must be 64 raw bytes")
        }
        let signingInput = Data("\(segments[0]).\(segments[1])".utf8)
        guard publicKey.isValidSignature(signature, for: signingInput) else {
            throw VerificationError(.invalidSignature, "ES256 signature check failed")
        }

        if let maxSignedAgeMillis, let signedAtMillis,
            clock().timeIntervalSince1970 * 1000 - signedAtMillis > Double(maxSignedAgeMillis)
        {
            throw VerificationError(
                .stalePayload,
                "payload signed at \(Int64(signedAtMillis)) exceeds max age \(maxSignedAgeMillis)ms")
        }
        return payloadData
    }

    /// The two header fields the verifier reads; the rest are ignored.
    private struct JwsHeader: Decodable {
        let alg: String?
        let x5c: [String]?
    }

    static func validateChain(
        leaf: Certificate, intermediate: Certificate,
        roots: [Certificate], at: Date
    ) async throws {
        var verifier = Verifier(rootCertificates: CertificateStore(roots)) {
            RFC5280Policy(validationTime: at)
        }
        let result = await verifier.validate(
            leafCertificate: leaf, intermediates: CertificateStore([intermediate]))
        if case .couldNotValidate = result {
            throw VerificationError(
                .invalidChain,
                "certificate chain does not validate to a pinned root")
        }
    }

    /// The typed read, after the chain and the signature pass: a claim of
    /// the wrong type was written by a trusted signer, so the payload models'
    /// `init(from:)` throws ``VerificationError/Reason/internalError`` for it
    /// and that passes through unchanged.
    private func decodePayload<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch let error as VerificationError {
            throw error
        } catch {
            throw VerificationError(.invalidJwsFormat, "unparseable payload: \(error)")
        }
    }

    private func requireBundleId(_ actual: String?) throws {
        guard actual == bundleId else {
            throw VerificationError(
                .wrongBundleId,
                "expected \(bundleId) but payload has \(actual ?? "nil")")
        }
    }

    private func requireAcceptedEnvironment(_ claim: String?) throws -> AppleEnvironment {
        guard let claim, let environment = AppleEnvironment(rawValue: claim),
            acceptedEnvironments.contains(environment)
        else {
            throw VerificationError(
                .wrongEnvironment,
                "payload environment \(claim ?? "nil") not in accepted set")
        }
        return environment
    }
}

/// The compact-JWS segment alphabet (RFC 7515 §2): unpadded base64url.
private let base64URLAlphabet = CharacterSet(
    charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

/// Strict base64url decoding for the three compact-JWS segments (header,
/// payload, signature). RFC 7515 §2 defines them as unpadded canonical
/// base64url, so a segment is rejected when it has a character outside the
/// alphabet above (which also excludes `=` padding), has an impossible
/// length (`count % 4 == 1`), or its final character carries non-zero
/// Rejects a certificate whose extension block does not decode all the way
/// down. swift-certificates keeps an extension's value as opaque bytes, so
/// a value that stops decoding partway through is invisible until something
/// asks for that extension — and then surfaces as a chain failure, i.e. as
/// a verdict about the path rather than about the certificate. Decoding
/// every one is also what makes reading a certificate different from
/// scanning it for a marker OID.
func requireDecodableExtensions(_ certificate: Certificate, what: String) throws {
    for ext in certificate.extensions where (try? DER.parse(ext.value)) == nil {
        throw VerificationError(.invalidCertificate, "\(what) is not a valid certificate")
    }
}

/// unused bits — checked by re-encoding the decoded bytes and requiring an
/// exact match against the padded input.
///
/// x5c certificate entries and the legacy receipt's base64 are decoded by
/// `decodeReceiptBase64`; only these three segments go through this
/// function.
func base64URLDecode(_ segment: String) -> Data? {
    guard segment.unicodeScalars.allSatisfy(base64URLAlphabet.contains),
        segment.utf8.count % 4 != 1
    else { return nil }
    var base64 = segment.replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    while base64.count % 4 != 0 { base64.append("=") }
    guard let data = Data(base64Encoded: base64), data.base64EncodedString() == base64 else {
        return nil
    }
    return data
}
