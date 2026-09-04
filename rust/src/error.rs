//! The error vocabulary shared by all nine ports of this library.

use core::fmt;

/// Why a verification failed.
///
/// The vocabulary is **closed** by the cross-port contract: these eleven
/// reasons are the whole observability surface of the library, and adding a
/// twelfth requires changing `fixtures/cases.schema.json`, `PLAN.md` and
/// every port in one change.
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
        }
    }

    /// Every reason, in the order the contract lists them.
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
        for reason in Reason::all() {
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
