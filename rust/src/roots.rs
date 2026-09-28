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
use core::fmt::Write;
use sha2::{Digest, Sha256};
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

/// The SHA-256 of each of [`APPLE_ROOT_DER`], in the same order, as Apple
/// publishes them. Checked when the roots are loaded, so a `certs/` file
/// swapped at build time does not become an anchor.
static APPLE_ROOT_SHA256: [&str; 3] = [
    "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
    "c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050",
    "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179",
];

/// Apple marker OID on the leaf that signs App Store JWS payloads and legacy
/// receipts alike. The chain check alone is not enough: developer
/// certificates ("Apple Distribution", "Apple Development") chain through the
/// same WWDR intermediate to the same pinned root, so without this purpose
/// check any developer could sign a forged payload or receipt.
pub(crate) const SIGNING_LEAF_OID: &str = "1.2.840.113635.100.6.11.1";

/// Apple marker OID on the Worldwide Developer Relations intermediate CA
/// that issues the signing leaf.
pub(crate) const WWDR_INTERMEDIATE_OID: &str = "1.2.840.113635.100.6.2.1";

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

/// The bundled Apple roots, parsed once per process and shared: all three,
/// or none. An empty set is refused by
/// [`ConfigBuilder::build`](crate::ConfigBuilder::build), and a
/// [`Verifier`](crate::Verifier) built from [`Config::defaults`](crate::Config::defaults)
/// with it answers `INTERNAL_ERROR` to every call.
pub(crate) fn apple_roots() -> &'static [TrustAnchor] {
    static ROOTS: OnceLock<Vec<TrustAnchor>> = OnceLock::new();
    ROOTS.get_or_init(|| load_roots(&APPLE_ROOT_DER, &APPLE_ROOT_SHA256))
}

/// Every one of `ders` as an anchor, each only when its SHA-256 is the
/// matching entry of `fingerprints` and it parses; nothing at all when any
/// one is not. A set silently one root short would verify until the day
/// Apple signed under the missing one.
fn load_roots(ders: &[&[u8]], fingerprints: &[&str]) -> Vec<TrustAnchor> {
    if ders.len() != fingerprints.len() {
        return Vec::new();
    }
    ders.iter()
        .zip(fingerprints)
        .map(|(der, fingerprint)| {
            if sha256_hex(der) == *fingerprint {
                TrustAnchor::from_der(der).ok()
            } else {
                None
            }
        })
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        // Writing to a String cannot fail.
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::{apple_roots, load_roots, sha256_hex, APPLE_ROOT_DER, APPLE_ROOT_SHA256};

    #[test]
    fn every_bundled_root_parses() {
        // Config::defaults cannot report a failure, so a bundled root that
        // stopped parsing or matching its fingerprint would empty the anchor
        // set. This is the check that it has not.
        assert_eq!(apple_roots().len(), APPLE_ROOT_DER.len());
    }

    #[test]
    fn the_bundled_roots_are_the_ones_apple_publishes() {
        // Written out here rather than read from APPLE_ROOT_SHA256, so a
        // change to the pinned list has to change this test too.
        let published = [
            "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
            "c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050",
            "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179",
        ];
        let bundled: Vec<String> = APPLE_ROOT_DER.iter().map(|der| sha256_hex(der)).collect();
        assert_eq!(bundled, published);
        assert_eq!(APPLE_ROOT_SHA256, published);
        let loaded: Vec<String> = apple_roots().iter().map(|a| sha256_hex(a.der())).collect();
        assert_eq!(loaded, published);
    }

    #[test]
    fn one_root_that_does_not_load_empties_the_set() {
        let [first, second, third] = APPLE_ROOT_DER;
        assert_eq!(load_roots(&APPLE_ROOT_DER, &APPLE_ROOT_SHA256).len(), 3);
        // A swapped file: parses, but is not the pinned root.
        assert!(load_roots(&[first, third, second], &APPLE_ROOT_SHA256).is_empty());
        // A file that does not parse, fingerprint and all.
        let broken: &[u8] = b"not a certificate";
        let broken_fingerprint = sha256_hex(broken);
        assert!(load_roots(
            &[first, second, broken],
            &[
                APPLE_ROOT_SHA256[0],
                APPLE_ROOT_SHA256[1],
                &broken_fingerprint
            ]
        )
        .is_empty());
        assert!(load_roots(&[first, second], &APPLE_ROOT_SHA256).is_empty());
    }
}
