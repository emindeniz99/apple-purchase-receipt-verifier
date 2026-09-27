//! The failure vocabulary shared by all nine ports of this library.

use core::fmt;
use std::error::Error;
use std::sync::Arc;

/// Why a verification failed.
///
/// The set is closed by the cross-port contract (`docs/design/0.7-api.md`,
/// Result): every port returns the same eight values for the same input, and
/// adding one is a breaking change in all nine at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Reason {
    /// The base64, ASN.1, CMS or JWS structure is broken, or a structural
    /// bound (JSON depth, embedded certificates, `SignerInfo`s) is exceeded.
    Malformed,
    /// The input is over one of the fixed size caps.
    TooLarge,
    /// The signature does not match the content.
    InvalidSignature,
    /// The chain does not reach a pinned root.
    UntrustedChain,
    /// A certificate does not decode, or is outside its validity window at
    /// the chain instant.
    InvalidCertificate,
    /// A valid Apple certificate of the wrong kind: an Apple marker OID is
    /// missing.
    InvalidCertificatePurpose,
    /// Apple signed it, but the content does not parse.
    UnreadablePayload,
    /// The library failed before it could decide. Alert; do not retry.
    InternalError,
}

impl Reason {
    /// The canonical `SCREAMING_SNAKE` token, identical in every port.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Reason::Malformed => "MALFORMED",
            Reason::TooLarge => "TOO_LARGE",
            Reason::InvalidSignature => "INVALID_SIGNATURE",
            Reason::UntrustedChain => "UNTRUSTED_CHAIN",
            Reason::InvalidCertificate => "INVALID_CERTIFICATE",
            Reason::InvalidCertificatePurpose => "INVALID_CERTIFICATE_PURPOSE",
            Reason::UnreadablePayload => "UNREADABLE_PAYLOAD",
            Reason::InternalError => "INTERNAL_ERROR",
        }
    }

    /// Every reason, in the order the contract lists them.
    #[must_use]
    pub const fn all() -> &'static [Reason] {
        &[
            Reason::Malformed,
            Reason::TooLarge,
            Reason::InvalidSignature,
            Reason::UntrustedChain,
            Reason::InvalidCertificate,
            Reason::InvalidCertificatePurpose,
            Reason::UnreadablePayload,
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
/// outside the closed set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownReason(pub String);

impl fmt::Display for UnknownReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown verification reason: {}", self.0)
    }
}

impl Error for UnknownReason {}

impl core::str::FromStr for Reason {
    type Err = UnknownReason;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Reason::all()
            .iter()
            .copied()
            .find(|reason| reason.as_str() == s)
            .ok_or_else(|| UnknownReason(s.to_owned()))
    }
}

/// A verification verdict of "no".
///
/// Match on [`reason`](Failure::reason). The [`message`](Failure::message)
/// is safe to log (it never embeds raw input) but is not meant to be parsed,
/// and may change between releases. [`source`](Error::source) carries the
/// parser error behind [`Reason::UnreadablePayload`], so an operator can see
/// why Apple-signed content did not parse.
///
/// Two failures are equal when their reason and message are; the source is
/// not compared.
#[derive(Clone)]
pub struct Failure {
    reason: Reason,
    message: String,
    source: Option<Arc<dyn Error + Send + Sync + 'static>>,
}

impl Failure {
    /// A failure with no source. Public so callers can build one in their
    /// own tests.
    #[must_use]
    pub fn new(reason: Reason, message: impl Into<String>) -> Self {
        Failure {
            reason,
            message: message.into(),
            source: None,
        }
    }

    /// The same failure, carrying `source` as its [`Error::source`].
    #[must_use]
    pub fn with_source(mut self, source: impl Error + Send + Sync + 'static) -> Self {
        self.source = Some(Arc::new(source));
        self
    }

    /// Why verification failed. Match on this.
    #[must_use]
    pub const fn reason(&self) -> Reason {
        self.reason
    }

    /// A short description, safe to log, not meant to be parsed.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Debug for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Failure")
            .field("reason", &self.reason)
            .field("message", &self.message)
            .field("source", &self.source.as_ref().map(ToString::to_string))
            .finish()
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.reason.as_str(), self.message)
    }
}

impl PartialEq for Failure {
    fn eq(&self, other: &Self) -> bool {
        self.reason == other.reason && self.message == other.message
    }
}

impl Eq for Failure {}

impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

/// A programming mistake in how a [`Config`](crate::Config) was built: no
/// trust anchors, or bytes that are not a certificate.
///
/// Deliberately not a [`Failure`]: misconfiguration is not a verdict about
/// any input, and happens once, at startup.
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

impl Error for ConfigError {}
