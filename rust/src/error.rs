//! The error vocabulary shared by all nine ports of this library.

use core::fmt;

/// Why a verification failed.
///
/// The vocabulary is **closed** by the cross-port contract: the twelve
/// reasons in [`Reason::all`] are the whole observability surface of the
/// verifiers, and adding a thirteenth requires changing
/// `fixtures/cases.schema.json`, `PLAN.md` and every port in one change.
///
/// Two more values, [`Reason::MalformedRequest`] and
/// [`Reason::RequestTooLarge`], exist only as the failure reason of a
/// `VerifyReceiptResult` from the `verifyReceipt` endpoint. No verifier ever
/// returns a [`VerificationError`] carrying either, and neither is in
/// [`Reason::all`].
///
/// The enum is nonetheless `#[non_exhaustive]` so that, if that ever
/// happens, a Rust caller with a `_ => reject` arm keeps compiling and keeps
/// failing closed. That arm is a safety net, not an extension point.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Reason {
    /// The compact JWS is not three segments, or a segment is not
    /// base64url-encoded JSON, or the header is not an ES256/x5c header.
    InvalidJwsFormat,
    /// An `x5c` entry is not a parseable X.509 certificate.
    InvalidCertificate,
    /// A certificate is well-formed but lacks the Apple marker OID that
    /// says it may be used for this purpose.
    InvalidCertificatePurpose,
    /// The certificate path does not reach a pinned trust anchor, or a
    /// certificate on it was not valid at the signing instant.
    InvalidChain,
    /// The payload or receipt signature did not verify.
    InvalidSignature,
    /// The verified payload names a different bundle id.
    WrongBundleId,
    /// The verified payload's environment is outside the accepted set.
    WrongEnvironment,
    /// A Production `AppTransaction` does not name the configured app
    /// Apple id.
    WrongAppAppleId,
    /// The legacy PKCS#7 receipt could not be parsed.
    InvalidReceiptFormat,
    /// `SHA1(guid ‖ opaqueValue ‖ bundleIdBytes)` does not equal
    /// attribute 5.
    DeviceHashMismatch,
    /// The payload was signed longer ago than the configured maximum.
    StalePayload,
    /// The `verifyReceipt` request envelope is unusable: the body is not a
    /// JSON object or nests deeper than 64, or `receipt-data` is missing,
    /// empty or not a string.
    /// Reported only as a `VerifyReceiptResult` failure reason (status
    /// 21002); never returned by a verifier.
    MalformedRequest,
    /// Not the client's fault, status 21009 at the endpoint. Either a
    /// trusted signer signed receipt or JWS content this library cannot
    /// read, found only after the chain and the signature passed, or a panic
    /// inside the `verifyReceipt` endpoint was contained. Alert and retry
    /// or escalate; do not deny the user on it.
    InternalError,
    /// The raw `verifyReceipt` request body is over
    /// [`MAX_REQUEST_BYTES`](crate::MAX_REQUEST_BYTES) (3,145,728 UTF-8
    /// bytes), the size at which Apple's endpoint answers HTTP 413. Status
    /// 21002 in the response body; an HTTP layer can map it to 413 as Apple
    /// does. Reported only as a `VerifyReceiptResult` failure reason; never
    /// returned by a verifier.
    RequestTooLarge,
}

impl Reason {
    /// The canonical `SCREAMING_SNAKE` token, identical in every port.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Reason::InvalidJwsFormat => "INVALID_JWS_FORMAT",
            Reason::InvalidCertificate => "INVALID_CERTIFICATE",
            Reason::InvalidCertificatePurpose => "INVALID_CERTIFICATE_PURPOSE",
            Reason::InvalidChain => "INVALID_CHAIN",
            Reason::InvalidSignature => "INVALID_SIGNATURE",
            Reason::WrongBundleId => "WRONG_BUNDLE_ID",
            Reason::WrongEnvironment => "WRONG_ENVIRONMENT",
            Reason::WrongAppAppleId => "WRONG_APP_APPLE_ID",
            Reason::InvalidReceiptFormat => "INVALID_RECEIPT_FORMAT",
            Reason::DeviceHashMismatch => "DEVICE_HASH_MISMATCH",
            Reason::StalePayload => "STALE_PAYLOAD",
            Reason::MalformedRequest => "MALFORMED_REQUEST",
            Reason::InternalError => "INTERNAL_ERROR",
            Reason::RequestTooLarge => "REQUEST_TOO_LARGE",
        }
    }

    /// Every reason a verifier can return, in the order the contract lists
    /// them. [`Reason::InternalError`] is last because it joined the list
    /// last, which keeps every earlier position (and the C ABI code derived
    /// from it) where it was. The two endpoint-only reasons,
    /// [`Reason::MalformedRequest`] and [`Reason::RequestTooLarge`], are not
    /// in it.
    #[must_use]
    pub const fn all() -> &'static [Reason] {
        &[
            Reason::InvalidJwsFormat,
            Reason::InvalidCertificate,
            Reason::InvalidCertificatePurpose,
            Reason::InvalidChain,
            Reason::InvalidSignature,
            Reason::WrongBundleId,
            Reason::WrongEnvironment,
            Reason::WrongAppAppleId,
            Reason::InvalidReceiptFormat,
            Reason::DeviceHashMismatch,
            Reason::StalePayload,
            Reason::InternalError,
        ]
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The error [`Reason::from_str`](core::str::FromStr) returns for a token
/// outside the closed vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownReason(pub String);

impl fmt::Display for UnknownReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown verification reason: {}", self.0)
    }
}

impl std::error::Error for UnknownReason {}

impl core::str::FromStr for Reason {
    type Err = UnknownReason;

    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        let endpoint_only = [Reason::MalformedRequest, Reason::RequestTooLarge];
        for reason in Reason::all().iter().chain(&endpoint_only) {
            if reason.as_str() == s {
                return Ok(*reason);
            }
        }
        Err(UnknownReason(s.to_owned()))
    }
}

/// A verification verdict of "no".
///
/// The machine-readable part is [`reason`](VerificationError::reason); the
/// [`detail`](VerificationError::detail) is a short human string that never
/// contains receipt bytes, claims or key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationError {
    reason: Reason,
    detail: String,
}

impl VerificationError {
    pub(crate) fn new(reason: Reason, detail: impl Into<String>) -> Self {
        VerificationError {
            reason,
            detail: detail.into(),
        }
    }

    /// The machine-readable cause. Match on this; never parse the message.
    #[must_use]
    pub const fn reason(&self) -> Reason {
        self.reason
    }

    /// A short, non-sensitive description of what failed.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.reason.as_str(), self.detail)
    }
}

impl std::error::Error for VerificationError {}

/// A programming mistake in how a verifier was configured — empty trust
/// anchors, an empty bundle id, an empty accepted-environment set, an
/// unparseable anchor.
///
/// Deliberately **not** a [`VerificationError`]: misconfiguration is not a
/// verification verdict, and a caller must not be able to catch it as one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    detail: String,
}

impl ConfigError {
    pub(crate) fn new(detail: impl Into<String>) -> Self {
        ConfigError {
            detail: detail.into(),
        }
    }

    /// What was wrong with the configuration.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for ConfigError {}

/// What [`verify_receipt_core`](crate::verify_receipt_core) can fail with.
///
/// The free function is the one public entry point that takes its trust
/// anchors as a plain argument rather than through a builder, so it is the
/// one place where a caller can still get the configuration wrong at the
/// call site. The two failures are kept apart in the type because they mean
/// opposite things: [`CoreError::Verification`] is a verdict about the
/// receipt, [`CoreError::Config`] is a bug in the calling program.
///
/// Reporting an empty anchor set as `INVALID_CHAIN` — which this crate did
/// until the cross-port review — makes an anchor-loading bug (a typo'd path,
/// an empty environment variable, a `Vec` filtered to nothing) look exactly
/// like a forged receipt. Java, Node and Python all raise their
/// argument-error type here; this enum is Rust's spelling of that, in a
/// crate whose library target denies `clippy::panic`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoreError {
    /// The caller passed no trust anchors. Not a verdict about the receipt:
    /// nothing about it was checked.
    Config(ConfigError),
    /// The receipt failed a verification check.
    Verification(VerificationError),
}

impl CoreError {
    /// The verification reason, or `None` when this is a configuration
    /// mistake and no verdict was reached.
    ///
    /// A caller that treats `None` as "rejected" is treating its own bug as
    /// a forgery; handle it as a configuration failure instead.
    #[must_use]
    pub const fn reason(&self) -> Option<Reason> {
        match self {
            CoreError::Config(_) => None,
            CoreError::Verification(error) => Some(error.reason()),
        }
    }

    /// The verification error, when there was a verdict.
    #[must_use]
    pub const fn as_verification(&self) -> Option<&VerificationError> {
        match self {
            CoreError::Config(_) => None,
            CoreError::Verification(error) => Some(error),
        }
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::Config(error) => write!(f, "configuration error: {error}"),
            CoreError::Verification(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for CoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CoreError::Config(error) => Some(error),
            CoreError::Verification(error) => Some(error),
        }
    }
}

impl From<VerificationError> for CoreError {
    fn from(error: VerificationError) -> Self {
        CoreError::Verification(error)
    }
}

impl From<ConfigError> for CoreError {
    fn from(error: ConfigError) -> Self {
        CoreError::Config(error)
    }
}

/// Shorthand for the result of a verification entry point.
pub type Result<T> = core::result::Result<T, VerificationError>;
