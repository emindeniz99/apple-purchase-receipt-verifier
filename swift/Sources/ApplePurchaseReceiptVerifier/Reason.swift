/// Why a verification failed.
///
/// The set is closed: these eight values are the whole contract, and adding
/// one is a breaking change.
public enum Reason: String, Sendable, CaseIterable {
    /// The base64, ASN.1, CMS or JWS structure is broken, or a structural
    /// bound (JSON depth, embedded certificates, SignerInfos) is exceeded.
    case malformed = "MALFORMED"
    /// The input is over one of the fixed size caps.
    case tooLarge = "TOO_LARGE"
    /// The signature does not match the content.
    case invalidSignature = "INVALID_SIGNATURE"
    /// The chain does not reach a pinned root.
    case untrustedChain = "UNTRUSTED_CHAIN"
    /// A certificate does not decode, or is outside its validity window at
    /// the chain instant.
    case invalidCertificate = "INVALID_CERTIFICATE"
    /// A valid Apple certificate of the wrong kind: an Apple marker OID is
    /// missing.
    case invalidCertificatePurpose = "INVALID_CERTIFICATE_PURPOSE"
    /// Apple signed it, but the content does not parse.
    case unreadablePayload = "UNREADABLE_PAYLOAD"
    /// The library failed before it could decide. Alert; do not retry.
    case internalError = "INTERNAL_ERROR"
}

/// A verification verdict of "no".
///
/// Match on ``reason``. ``message`` is safe to log (it never embeds raw
/// input) but is not meant to be parsed, and may change between releases.
/// ``cause`` carries the parser error behind ``Reason/unreadablePayload``, so
/// an operator can see why Apple-signed content did not parse.
public struct Failure: Error, Sendable, CustomStringConvertible {
    public let reason: Reason
    public let message: String
    /// What is behind this failure, when there is something. Never part of
    /// the verdict — match on ``reason``.
    public let cause: (any Error & Sendable)?

    public init(_ reason: Reason, _ message: String, cause: (any Error & Sendable)? = nil) {
        self.reason = reason
        self.message = message
        self.cause = cause
    }

    public var description: String { "\(reason.rawValue): \(message)" }
}
