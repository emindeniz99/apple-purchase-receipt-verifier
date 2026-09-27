//! Certificate path validation.
//!
//! This is the security core, and it is this crate's own: no library in the
//! Rust ecosystem does "path-validate to *these* anchors, with *these*
//! marker OIDs, at *that* instant, with no revocation and no name checks".
//!
//! Every entry point takes `anchors` and `at_millis` as required parameters,
//! so there is no default anchor set to fall back to and "forgot to pass the
//! signing time" cannot compile.
//!
//! A path is found first and judged second, as a PKIX walk does: a chain
//! that reaches no pinned root is `UNTRUSTED_CHAIN` whatever its dates say,
//! and only a path that does reach one has its certificates' validity
//! windows checked, where a certificate outside its window at `at_millis` is
//! `INVALID_CERTIFICATE`.

use crate::crypto::{has_unimplemented_curve, verify_certificate_signature};
use crate::error::{Failure, Reason};
use crate::roots::TrustAnchor;
use crate::x509::{Certificate, KEY_CERT_SIGN_BIT};

/// The longest path the builder will walk, anchor excluded.
pub const MAX_PATH_LENGTH: usize = 6;

fn untrusted(detail: &'static str) -> Failure {
    Failure::new(Reason::UntrustedChain, detail)
}

fn outside_validity() -> Failure {
    Failure::new(
        Reason::InvalidCertificate,
        "certificate is outside its validity window at the chain instant",
    )
}

/// What `X509_check_issued` accepts, minus the parts that need a name
/// canonicaliser: the names chain by DER equality, the authority key
/// identifier agrees with the issuer's subject key identifier and serial
/// where it names them, and the issuer's `keyUsage`, if it has one, permits
/// `keyCertSign`.
///
/// Comparing names as DER rather than in a canonical (case- and
/// whitespace-folded) form is the one deliberate difference, and it is the
/// safe direction: a chain whose issuer and subject names differ only in
/// encoding is rejected here.
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

/// Validates the fixed JWS path leaf, intermediate, pinned anchor.
///
/// The two signatures are checked from the anchor down first, so no key an
/// anchor did not vouch for is used; then the intermediate's window, its CA
/// flag and the leaf's window, at `at_millis`.
///
/// # Errors
/// `UNTRUSTED_CHAIN` for a broken link or an intermediate that is not a CA,
/// `INVALID_CERTIFICATE` for a certificate outside its validity window, or
/// a vouched-for intermediate whose EC key is on a curve this crate does
/// not implement.
pub fn validate_pair(
    leaf: &Certificate,
    intermediate: &Certificate,
    anchors: &[TrustAnchor],
    at_millis: i64,
) -> Result<(), Failure> {
    if !issued_by_any_anchor(intermediate, anchors) {
        return Err(untrusted("intermediate is not issued by a pinned root"));
    }
    // Vouched for, and its key is about to check the leaf: a curve this
    // crate does not implement is the certificate's defect.
    if has_unimplemented_curve(intermediate) {
        return Err(Failure::new(
            Reason::InvalidCertificate,
            "x5c entry uses an unimplemented elliptic curve",
        ));
    }
    if !issued_by(leaf, intermediate) {
        return Err(untrusted("leaf is not issued by the intermediate"));
    }
    if !intermediate.valid_at(at_millis) {
        return Err(outside_validity());
    }
    if !intermediate.is_ca() {
        return Err(untrusted("intermediate is not a CA"));
    }
    if !leaf.valid_at(at_millis) {
        return Err(outside_validity());
    }
    Ok(())
}

/// The embedded certificates a pinned anchor vouched for, and the links
/// that proved it, from [`authenticated_top_down`].
#[derive(Debug)]
pub struct Authenticated<'a> {
    certificates: Vec<&'a Certificate>,
    /// Every (certificate, issuer) pair the walk checked, with the answer,
    /// so the path builder does not check one a second time.
    checked: Vec<(&'a Certificate, &'a Certificate, bool)>,
}

impl<'a> Authenticated<'a> {
    /// The authenticated certificates, in the order they were accepted.
    #[must_use]
    pub fn certificates(&self) -> &[&'a Certificate] {
        &self.certificates
    }

    fn issued_by(&self, cert: &Certificate, issuer: &Certificate) -> bool {
        self.checked
            .iter()
            .find(|(c, i, _)| core::ptr::eq(*c, cert) && core::ptr::eq(*i, issuer))
            .map_or_else(|| issued_by(cert, issuer), |(_, _, verdict)| *verdict)
    }
}

/// The embedded certificates whose signature verifies under a pinned anchor,
/// or under a certificate already accepted this way, walking down from the
/// anchors in at most [`MAX_PATH_LENGTH`] rounds. Only these are handed to
/// [`build_and_validate_path`].
///
/// Walking down means no key an anchor did not vouch for, directly or
/// through a certificate it vouched for, is ever used to check a signature:
/// a receipt padded with certificates carrying the attacker's own keys (their
/// choice of size and exponent) costs one name comparison per issuer for
/// each of them, and they are simply left out. An embedded copy of an
/// anchor is the anchor, and is accepted without a signature check.
pub fn authenticated_top_down<'a>(
    embedded: &'a [Certificate],
    anchors: &'a [TrustAnchor],
) -> Authenticated<'a> {
    let mut authenticated = Authenticated {
        certificates: Vec::new(),
        checked: Vec::new(),
    };
    let mut pending: Vec<&'a Certificate> = Vec::new();
    for certificate in embedded {
        match anchors
            .iter()
            .find(|anchor| anchor.certificate().der() == certificate.der())
        {
            Some(anchor) => {
                authenticated.certificates.push(certificate);
                authenticated
                    .checked
                    .push((certificate, anchor.certificate(), true));
            }
            None => pending.push(certificate),
        }
    }
    let mut issuers: Vec<&'a Certificate> = anchors.iter().map(TrustAnchor::certificate).collect();
    issuers.extend_from_slice(&authenticated.certificates);
    for _ in 0..MAX_PATH_LENGTH {
        if pending.is_empty() {
            break;
        }
        let mut this_round = Vec::new();
        let checked = &mut authenticated.checked;
        pending.retain(|candidate| {
            let accepted = issuers.iter().any(|issuer| {
                let verdict = issued_by(candidate, issuer);
                checked.push((candidate, issuer, verdict));
                verdict
            });
            if accepted {
                this_round.push(*candidate);
            }
            !accepted
        });
        if this_round.is_empty() {
            break;
        }
        authenticated.certificates.extend_from_slice(&this_round);
        issuers = this_round;
    }
    authenticated
}

/// Builds a path from `target` through `candidates` to one of the pinned
/// `anchors`, the shape a legacy receipt uses, where the intermediates are
/// embedded in the CMS blob; then checks every certificate on it is inside
/// its validity window at `at_millis`. Returns the path, target first,
/// anchor excluded.
///
/// The candidates are the ones [`authenticated_top_down`] accepted, so the
/// only keys the walk verifies with are ones an anchor vouched for, and a
/// link it already checked is not checked again.
///
/// The depth bound is [`MAX_PATH_LENGTH`], and each candidate is tried once
/// per hop, so a cross-signed certificate mesh cannot make the walk
/// exponential.
///
/// # Errors
/// `UNTRUSTED_CHAIN` when no path reaches an anchor, a certificate above the
/// target is not a CA, or the path is too long; `INVALID_CERTIFICATE` when
/// a certificate on the path is outside its validity window.
pub fn build_and_validate_path<'a>(
    target: &'a Certificate,
    authenticated: &Authenticated<'a>,
    anchors: &[TrustAnchor],
    at_millis: i64,
) -> Result<Vec<&'a Certificate>, Failure> {
    let mut path = vec![target];
    let mut current = target;
    loop {
        if path.len() > 1 && !current.is_ca() {
            return Err(untrusted("an intermediate is not a CA"));
        }
        if anchors
            .iter()
            .any(|anchor| authenticated.issued_by(current, anchor.certificate()))
        {
            break;
        }
        if path.len() >= MAX_PATH_LENGTH {
            return Err(untrusted("chain exceeds the maximum length"));
        }
        let issuer = authenticated
            .certificates
            .iter()
            .copied()
            .find(|candidate| {
                !path
                    .iter()
                    .any(|on_path| core::ptr::eq(*on_path, *candidate))
                    && authenticated.issued_by(current, candidate)
            });
        match issuer {
            Some(next) => {
                path.push(next);
                current = next;
            }
            None => return Err(untrusted("chain does not reach a pinned root")),
        }
    }
    if path
        .iter()
        .any(|certificate| !certificate.valid_at(at_millis))
    {
        return Err(outside_validity());
    }
    Ok(path)
}
