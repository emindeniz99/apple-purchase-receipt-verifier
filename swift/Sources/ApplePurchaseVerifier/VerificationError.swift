import Foundation

/// Thrown when a signed payload fails verification. ``reason`` is the
/// machine-readable cause (same reason codes as the Java/Node/Python
/// implementations — PLAN.md §3). A payload that throws must be treated as
/// fully untrusted.
public struct VerificationError: Error, Sendable, CustomStringConvertible {
    public enum Reason: String, Sendable {
        case invalidJwsFormat = "INVALID_JWS_FORMAT"
        case invalidCertificate = "INVALID_CERTIFICATE"
        case invalidCertificatePurpose = "INVALID_CERTIFICATE_PURPOSE"
        case invalidChain = "INVALID_CHAIN"
        case invalidSignature = "INVALID_SIGNATURE"
        case wrongBundleId = "WRONG_BUNDLE_ID"
        case wrongEnvironment = "WRONG_ENVIRONMENT"
        case wrongAppAppleId = "WRONG_APP_APPLE_ID"
        case invalidReceiptFormat = "INVALID_RECEIPT_FORMAT"
        case deviceHashMismatch = "DEVICE_HASH_MISMATCH"
        case stalePayload = "STALE_PAYLOAD"
    }

    public let reason: Reason
    public let message: String

    public init(_ reason: Reason, _ message: String) {
        self.reason = reason
        self.message = message
    }

    public var description: String { "\(reason.rawValue): \(message)" }
}

/// The App Store server environment a signed payload was produced in.
public enum AppleEnvironment: String, CaseIterable, Sendable {
    case production = "Production"
    case sandbox = "Sandbox"
    case xcode = "Xcode"
    case localTesting = "LocalTesting"
}
