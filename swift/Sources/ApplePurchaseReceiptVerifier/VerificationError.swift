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
        /// The verifyReceipt request envelope is unusable: the body is not a
        /// JSON object or nests more than 64 levels deep, or `receipt-data`
        /// is missing, empty or not a string. Reported only by
        /// ``VerifyReceiptResult/failureReason``; never thrown.
        case malformedRequest = "MALFORMED_REQUEST"
        /// The raw request body is over
        /// ``VerifyReceiptEndpoint/maxRequestBytes`` UTF-8 bytes, answered as
        /// status 21002 before it is parsed. Apple answers such a body with
        /// HTTP 413; this reason lets an HTTP layer do the same. Reported
        /// only by ``VerifyReceiptResult/failureReason``; never thrown.
        case requestTooLarge = "REQUEST_TOO_LARGE"
        /// Not the client's fault, status 21009 at the endpoint. Thrown when a
        /// trusted signer signed receipt content this library cannot read
        /// (found only after the chain and the signature passed; the parser's
        /// error is ``VerificationError/cause``) or a JWS claim the typed
        /// payload models cannot hold (same point, same reasoning), and
        /// reported by the endpoint for an unexpected error inside it. Alert and retry or escalate; do
        /// not deny the user on it.
        case internalError = "INTERNAL_ERROR"
    }

    public let reason: Reason
    public let message: String
    /// What is behind this error, when there is something: for
    /// ``Reason/internalError`` on a receipt, the parser's own error for
    /// signed content that could not be read. Never part of the verdict.
    public let cause: (any Error)?

    public init(_ reason: Reason, _ message: String, cause: (any Error)? = nil) {
        self.reason = reason
        self.message = message
        self.cause = cause
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
