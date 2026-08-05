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

/// Verifies Apple-signed JWS payloads (StoreKit 2 `jwsRepresentation`,
/// `signedTransactionInfo` / `signedRenewalInfo`, Server Notifications V2)
/// completely offline against pinned Apple roots — PLAN.md §2.1, mirroring
/// the Java implementation check-for-check.
public struct JwsVerifier: Sendable {
    /// Apple marker OID: leaf certificate used for App Store signing.
    static let leafOID: ASN1ObjectIdentifier = [1, 2, 840, 113635, 100, 6, 11, 1]
    /// Apple marker OID: Worldwide Developer Relations intermediate CA.
    static let intermediateOID: ASN1ObjectIdentifier = [1, 2, 840, 113635, 100, 6, 2, 1]

    private let roots: [Certificate]
    private let bundleId: String
    private let acceptedEnvironments: Set<AppleEnvironment>
    private let appAppleId: Int64?
    private let maxSignedAgeMillis: Int64?

    /// - Parameters:
    ///   - trustedRoots: pinned DER roots (production: ``appleJwsRoots()``)
    ///   - bundleId: bundle id every payload must carry
    ///   - acceptedEnvironments: include `.sandbox` on endpoints App Review
    ///     can hit (PLAN.md D3)
    ///   - appAppleId: required to accept Production AppTransactions
    ///   - maxSignedAgeMillis: reject payloads signed longer ago (PLAN.md D5)
    public init(trustedRoots: [Data], bundleId: String,
                acceptedEnvironments: Set<AppleEnvironment>,
                appAppleId: Int64? = nil, maxSignedAgeMillis: Int64? = nil) throws {
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
            throw VerificationError(.wrongAppAppleId,
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
        let segments = jws.components(separatedBy: ".")
        guard segments.count == 3 else {
            throw VerificationError(.invalidJwsFormat,
                "expected 3 dot-separated segments, got \(segments.count)")
        }
        guard let headerData = base64URLDecode(segments[0]),
              let payloadData = base64URLDecode(segments[1]),
              let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any] else {
            throw VerificationError(.invalidJwsFormat, "header/payload is not valid base64url JSON")
        }
        guard header["alg"] as? String == "ES256" else {
            throw VerificationError(.invalidJwsFormat, "alg must be ES256")
        }
        guard let x5c = header["x5c"] as? [String], x5c.count == 3 else {
            throw VerificationError(.invalidJwsFormat, "x5c must contain exactly 3 certificates")
        }
        guard let leafDER = Data(base64Encoded: x5c[0]),
              let intermediateDER = Data(base64Encoded: x5c[1]),
              let leaf = try? Certificate(derEncoded: [UInt8](leafDER)),
              let intermediate = try? Certificate(derEncoded: [UInt8](intermediateDER)) else {
            throw VerificationError(.invalidCertificate, "x5c entry is not a valid certificate")
        }
        guard leaf.extensions.contains(where: { $0.oid == Self.leafOID }) else {
            throw VerificationError(.invalidCertificatePurpose,
                "leaf certificate lacks Apple marker OID \(Self.leafOID)")
        }
        guard intermediate.extensions.contains(where: { $0.oid == Self.intermediateOID }) else {
            throw VerificationError(.invalidCertificatePurpose,
                "intermediate certificate lacks Apple marker OID \(Self.intermediateOID)")
        }

        // Chain validity is checked at signing time so payloads signed with
        // since-rotated certificates keep verifying (PLAN.md §2.1 step 4).
        let claims = (try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any]) ?? [:]
        let signedAtMillis = (claims["signedDate"] as? Double)
            ?? (claims["receiptCreationDate"] as? Double)
        let validationTime = signedAtMillis.map { Date(timeIntervalSince1970: $0 / 1000) } ?? Date()
        try await Self.validateChain(leaf: leaf, intermediate: intermediate,
                                     roots: roots, at: validationTime)

        guard let publicKey = P256.Signing.PublicKey(leaf.publicKey) else {
            throw VerificationError(.invalidSignature, "leaf key is not EC P-256")
        }
        guard let signatureBytes = base64URLDecode(segments[2]), signatureBytes.count == 64,
              let signature = try? P256.Signing.ECDSASignature(rawRepresentation: signatureBytes) else {
            throw VerificationError(.invalidSignature, "ES256 signature must be 64 raw bytes")
        }
        let signingInput = Data("\(segments[0]).\(segments[1])".utf8)
        guard publicKey.isValidSignature(signature, for: signingInput) else {
            throw VerificationError(.invalidSignature, "ES256 signature check failed")
        }

        if let maxSignedAgeMillis, let signedAtMillis,
           Date().timeIntervalSince1970 * 1000 - signedAtMillis > Double(maxSignedAgeMillis) {
            throw VerificationError(.stalePayload,
                "payload signed at \(Int64(signedAtMillis)) exceeds max age \(maxSignedAgeMillis)ms")
        }
        return payloadData
    }

    static func validateChain(leaf: Certificate, intermediate: Certificate,
                              roots: [Certificate], at: Date) async throws {
        var verifier = Verifier(rootCertificates: CertificateStore(roots)) {
            RFC5280Policy(validationTime: at)
        }
        let result = await verifier.validate(
            leafCertificate: leaf, intermediates: CertificateStore([intermediate]))
        if case .couldNotValidate = result {
            throw VerificationError(.invalidChain,
                "certificate chain does not validate to a pinned root")
        }
    }

    private func decodePayload<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw VerificationError(.invalidJwsFormat, "unparseable payload: \(error)")
        }
    }

    private func requireBundleId(_ actual: String?) throws {
        guard actual == bundleId else {
            throw VerificationError(.wrongBundleId,
                "expected \(bundleId) but payload has \(actual ?? "nil")")
        }
    }

    private func requireAcceptedEnvironment(_ claim: String?) throws -> AppleEnvironment {
        guard let claim, let environment = AppleEnvironment(rawValue: claim),
              acceptedEnvironments.contains(environment) else {
            throw VerificationError(.wrongEnvironment,
                "payload environment \(claim ?? "nil") not in accepted set")
        }
        return environment
    }
}

func base64URLDecode(_ segment: String) -> Data? {
    var base64 = segment.replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    while base64.count % 4 != 0 { base64.append("=") }
    return Data(base64Encoded: base64)
}
