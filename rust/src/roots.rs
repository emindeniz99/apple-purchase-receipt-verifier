//! The pinned trust anchors.
//!
//! Anchors come from exactly two places: the caller's argument, or the three
//! Apple roots bundled here. **No code path in this crate reads an operating
//! system trust store, a distribution CA bundle, or anything downloaded.**
//! There is no function to disable that with, because there is no such path
//! to disable.
//!
//! The bundled roots are `include_bytes!`-embedded, not read from disk at
//! call time, so they work unchanged in a `FROM scratch` container. `certs/`
//! in this directory is a byte-for-byte copy of the repository's root
//! `certs/`, and CI diffs the two.

use crate::error::ConfigError;
use crate::x509::Certificate;
use std::sync::{Arc, OnceLock};

/// The three published Apple roots, embedded at compile time.
///
/// All three are pinned in both sets (`PLAN.md` D15). Apple deliberately
/// does not commit to a specific root for either verification path, and G2
/// is already published — anchoring on one root would break silently the day
/// Apple re-anchored a chain under another.
static APPLE_ROOT_DER: [&[u8]; 3] = [
    include_bytes!("../certs/AppleIncRootCertificate.cer"),
    include_bytes!("../certs/AppleRootCA-G2.cer"),
    include_bytes!("../certs/AppleRootCA-G3.cer"),
];

/// A certificate a chain may terminate at.
///
/// A trust anchor is trusted by fiat: **its own expiry is not checked**,
/// which is standard PKIX trust-anchor semantics and is what lets a receipt
/// signed years ago under a since-expired chain still verify at its own
/// creation date.
#[derive(Debug, Clone)]
pub struct TrustAnchor(Arc<Certificate>);

impl TrustAnchor {
    /// Parses a DER certificate as an anchor.
    ///
    /// # Errors
    /// [`ConfigError`] when the bytes are not a certificate. A bad anchor is
    /// a configuration mistake, not a verification verdict.
    pub fn from_der(der: &[u8]) -> Result<TrustAnchor, ConfigError> {
        Certificate::from_der(der)
            .map(|cert| TrustAnchor(Arc::new(cert)))
            .map_err(|err| ConfigError::new(format!("trust anchor is not a certificate: {err}")))
    }

    /// Parses a PEM certificate as an anchor.
    ///
    /// # Errors
    /// [`ConfigError`] when the input holds no usable `CERTIFICATE` block.
    pub fn from_pem(pem: &str) -> Result<TrustAnchor, ConfigError> {
        Certificate::from_pem(pem)
            .map(|cert| TrustAnchor(Arc::new(cert)))
            .map_err(|err| ConfigError::new(format!("trust anchor is not a certificate: {err}")))
    }

    /// The parsed certificate.
    #[must_use]
    pub fn certificate(&self) -> &Certificate {
        &self.0
    }
}

impl From<Certificate> for TrustAnchor {
    fn from(certificate: Certificate) -> Self {
        TrustAnchor(Arc::new(certificate))
    }
}

fn apple_roots() -> &'static [TrustAnchor] {
    static ROOTS: OnceLock<Vec<TrustAnchor>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        APPLE_ROOT_DER
            .iter()
            .filter_map(|der| TrustAnchor::from_der(der).ok())
            .collect()
    })
}

/// Trust anchors for `StoreKit` 2 / App Store Server JWS chains.
///
/// Parsed once and shared; calling this per verification costs nothing.
#[must_use]
pub fn apple_jws_roots() -> &'static [TrustAnchor] {
    apple_roots()
}

/// Trust anchors for legacy PKCS#7 app-receipt chains.
#[must_use]
pub fn apple_receipt_roots() -> &'static [TrustAnchor] {
    apple_roots()
}

/// The raw DER of the bundled roots, for callers that want to inspect or
/// re-export them.
#[must_use]
pub fn apple_root_der() -> &'static [&'static [u8]; 3] {
    &APPLE_ROOT_DER
}

pub(crate) fn normalize_anchors(
    anchors: Vec<TrustAnchor>,
) -> Result<Arc<[TrustAnchor]>, ConfigError> {
    if anchors.is_empty() {
        return Err(ConfigError::new("trustedRoots must not be empty"));
    }
    Ok(anchors.into())
}
