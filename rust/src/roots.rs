//! The pinned trust anchors.
//!
//! Anchors come from exactly two places: the caller's
//! [`Config`](crate::Config), or the three Apple roots bundled here, which
//! [`Config::defaults`](crate::Config::defaults) uses. **No code path in
//! this crate reads an
//! operating system trust store, a distribution CA bundle, or anything
//! downloaded.** There is no function to disable that with, because there is
//! no such path to disable.
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
/// All three are pinned for both formats. Apple does not commit to a specific
/// root for either, and G2 is already published: anchoring on one root would
/// break silently the day Apple re-anchored a chain under another.
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

    /// The anchor's DER encoding.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        self.0.der()
    }

    pub(crate) fn certificate(&self) -> &Certificate {
        &self.0
    }
}

/// The bundled Apple roots, parsed once per process and shared.
pub(crate) fn apple_roots() -> &'static [TrustAnchor] {
    static ROOTS: OnceLock<Vec<TrustAnchor>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        APPLE_ROOT_DER
            .iter()
            .filter_map(|der| TrustAnchor::from_der(der).ok())
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::{apple_roots, APPLE_ROOT_DER};

    #[test]
    fn every_bundled_root_parses() {
        // Config::defaults cannot report a failure, so a bundled root that
        // stopped parsing would silently shrink the anchor set. This is the
        // check that it has not.
        assert_eq!(apple_roots().len(), APPLE_ROOT_DER.len());
    }
}
