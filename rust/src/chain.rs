//! Certificate path validation.
//!
//! This is the security core, and it is this crate's own: no library in the
//! Rust ecosystem does "path-validate to *these* anchors, with *these*
//! marker OIDs, at *that* instant, with no revocation and no name checks".
//!
//! Two properties are structural rather than documented:
//!
//! - every entry point takes `anchors` as a required parameter, so there is
//!   no default anchor set to fall back to and no system store to reach;
//! - every entry point takes `at_millis` as a required parameter with no
//!   default, so "forgot to pass the signing time" cannot compile.

use crate::crypto::verify_certificate_signature;
use crate::error::{Reason, Result, VerificationError};
use crate::roots::TrustAnchor;
use crate::x509::{Certificate, KEY_CERT_SIGN_BIT};

/// The longest path the builder will walk, anchor excluded.
pub const MAX_PATH_LENGTH: usize = 6;

fn invalid_chain(detail: &'static str) -> VerificationError {
    VerificationError::new(Reason::InvalidChain, detail)
}

/// What `X509_check_issued` accepts, minus the parts that need a name
/// canonicaliser: the names chain by DER equality, the authority key
/// identifier agrees with the issuer's subject key identifier and serial
/// where it names them, and the issuer's `keyUsage` — if it has one —
/// permits `keyCertSign`.
///
/// Comparing names as DER rather than in OpenSSL's canonical (case- and
/// whitespace-folded) form is the one deliberate difference, and it is the
/// safe direction: a chain whose issuer and subject names differ only in
/// encoding is rejected here and accepted there.
fn check_issued(cert: &Certificate, issuer: &Certificate) -> bool {
    if cert.issuer_der() != issuer.subject_der() {
        return false;
    }
    if let (Some(akid), Some(skid)) = (cert.authority_key_id(), issuer.subject_key_id()) {
        if akid != skid {
            return false;
        }
    }
    if let Some(serial) = cert.authority_cert_serial() {
        if serial != issuer.serial_number() {
            return false;
        }
    }
    match issuer.key_usage() {
        Some(bits) => bits.get(KEY_CERT_SIGN_BIT) == Some(&true),
        None => true,
    }
}

fn issued_by(cert: &Certificate, issuer: &Certificate) -> bool {
    check_issued(cert, issuer) && verify_certificate_signature(cert, issuer)
}

fn issued_by_any_anchor(cert: &Certificate, anchors: &[TrustAnchor]) -> bool {
    anchors
        .iter()
        .any(|anchor| issued_by(cert, anchor.certificate()))
}

/// Validates the fixed JWS path leaf → intermediate → pinned anchor.
///
/// `at_millis` is the instant the validity windows are judged at — the
/// payload's signing date, never a caller-injected clock.
///
/// # Errors
/// [`Reason::InvalidChain`] for every failure: an expired or not-yet-valid
/// certificate, an intermediate that is not a CA, a broken link, or a chain
/// that does not terminate at one of `anchors`.
pub fn validate_pair(
    leaf: &Certificate,
    intermediate: &Certificate,
    anchors: &[TrustAnchor],
    at_millis: i64,
) -> Result<()> {
    if !leaf.valid_at(at_millis) || !intermediate.valid_at(at_millis) {
        return Err(invalid_chain("certificate not valid at signing time"));
    }
    if !intermediate.is_ca() {
        return Err(invalid_chain("intermediate is not a CA"));
    }
    if !issued_by(leaf, intermediate) {
        return Err(invalid_chain("leaf not issued by intermediate"));
    }
    if !issued_by_any_anchor(intermediate, anchors) {
        return Err(invalid_chain("intermediate not issued by a pinned root"));
    }
    Ok(())
}

/// Builds and validates a path from `target` through `candidates` to one of
/// the pinned `anchors` — the shape a legacy receipt uses, where the
/// intermediates are embedded in the CMS blob.
///
/// The depth bound is this crate's own [`MAX_PATH_LENGTH`], and each
/// candidate is tried once per hop, so a cross-signed certificate mesh
/// cannot make the walk exponential.
///
/// # Errors
/// [`Reason::InvalidChain`], as [`validate_pair`].
pub fn build_and_validate_path(
    target: &Certificate,
    candidates: &[Certificate],
    anchors: &[TrustAnchor],
    at_millis: i64,
) -> Result<()> {
    let mut current = target;
    for depth in 0..MAX_PATH_LENGTH {
        if !current.valid_at(at_millis) {
            return Err(invalid_chain("certificate not valid at signing time"));
        }
        if depth > 0 && !current.is_ca() {
            return Err(invalid_chain("intermediate is not a CA"));
        }
        if issued_by_any_anchor(current, anchors) {
            return Ok(());
        }
        let issuer = candidates
            .iter()
            .find(|candidate| !core::ptr::eq(*candidate, current) && issued_by(current, candidate));
        match issuer {
            Some(next) => current = next,
            None => return Err(invalid_chain("chain does not reach a pinned root")),
        }
    }
    Err(invalid_chain("chain exceeds maximum length"))
}
