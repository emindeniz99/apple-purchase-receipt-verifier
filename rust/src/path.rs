//! Certificate path policy: which certificates may be tried, at which
//! instant, and what each problem OpenSSL reports means as a reason.
//!
//! OpenSSL (`aprv_openssl::verify_path`, `X509_verify_cert` over a store of
//! the pinned anchors alone) builds the path and checks its signatures,
//! CA flags, length, validity windows and critical extensions. This module
//! decides what goes in and what comes out:
//!
//! - **Top-down first.** Only certificates a pinned anchor vouched for,
//!   directly or through a certificate it vouched for, are handed to
//!   OpenSSL, so no key an anchor did not vouch for is ever used, and a bag
//!   padded with look-alike issuers cannot steer the path builder.
//! - **Found first, judged second.** A path that reaches no pinned anchor
//!   is `UNTRUSTED_CHAIN` whatever its dates say; only a path that does
//!   reach one has its validity windows judged, where a certificate outside
//!   its window at the chain instant is `INVALID_CERTIFICATE`.
//! - **Milliseconds.** OpenSSL judges validity in whole seconds. The path is
//!   checked at the second the instant falls in, which decides `notBefore`
//!   exactly, and every certificate below the anchor must then also have a
//!   `notAfter` at or after the instant rounded up.

use crate::error::{Failure, Reason};
use crate::roots::TrustAnchor;
use aprv_openssl::{verify_path, Certificate, PathOutcome, PathProblem, PathProblemKind};

/// The longest path, anchor excluded: the target and five certificates
/// above it.
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

fn unprocessed_critical_extension() -> Failure {
    untrusted("a certificate on the path has an unsupported critical extension")
}

fn anchor_certificates(anchors: &[TrustAnchor]) -> Vec<Certificate> {
    anchors
        .iter()
        .map(|anchor| anchor.certificate().clone())
        .collect()
}

/// The embedded certificates a pinned anchor vouched for, directly or
/// through a certificate accepted this way, walking down from the anchors
/// in at most [`MAX_PATH_LENGTH`] rounds. An embedded copy of an anchor is
/// the anchor, and is accepted without a signature check.
///
/// Walking down means the only keys used are ones an anchor vouched for: a
/// certificate carrying the attacker's own key (their choice of size and
/// exponent) costs a name comparison per issuer, and is simply left out.
#[must_use]
pub fn authenticated_top_down(
    embedded: &[Certificate],
    anchors: &[TrustAnchor],
) -> Vec<Certificate> {
    let mut accepted: Vec<Certificate> = Vec::new();
    let mut pending: Vec<&Certificate> = Vec::new();
    for certificate in embedded {
        if anchors
            .iter()
            .any(|anchor| anchor.certificate().same_as(certificate))
        {
            accepted.push(certificate.clone());
        } else {
            pending.push(certificate);
        }
    }
    let mut issuers: Vec<Certificate> = anchor_certificates(anchors);
    issuers.extend(accepted.iter().cloned());
    for _ in 0..MAX_PATH_LENGTH {
        if pending.is_empty() {
            break;
        }
        let mut this_round: Vec<Certificate> = Vec::new();
        pending.retain(|candidate| {
            let vouched = issuers.iter().any(|issuer| candidate.issued_by(issuer));
            if vouched {
                this_round.push((*candidate).clone());
            }
            !vouched
        });
        if this_round.is_empty() {
            break;
        }
        accepted.extend(this_round.iter().cloned());
        issuers = this_round;
    }
    accepted
}

/// The second an instant falls in, and that instant rounded up to a second.
fn seconds(at_millis: i64) -> (i64, i64) {
    let second = at_millis.div_euclid(1000);
    let rounded_up = second.saturating_add(i64::from(at_millis.rem_euclid(1000) != 0));
    (second, rounded_up)
}

/// Asks OpenSSL for the path from `target` through `untrusted` to one of
/// `anchors` at `at_millis`, and adds the millisecond `notAfter` check.
fn checked_path(
    target: &Certificate,
    untrusted: &[Certificate],
    anchors: &[TrustAnchor],
    at_millis: i64,
    max_intermediates: usize,
) -> PathOutcome {
    if !target.has_usable_key() {
        return keyless_target_path(target, untrusted, anchors, at_millis, max_intermediates);
    }
    let (second, rounded_up) = seconds(at_millis);
    let mut outcome = verify_path(
        target,
        untrusted,
        &anchor_certificates(anchors),
        second,
        u32::try_from(max_intermediates).unwrap_or(0),
    );
    let below_anchor = if outcome.anchored {
        outcome.chain.len().saturating_sub(1)
    } else {
        outcome.chain.len()
    };
    let late: Vec<PathProblem> = outcome
        .chain
        .iter()
        .take(below_anchor)
        .enumerate()
        .filter(|(_, certificate)| !certificate.not_after_at_least(rounded_up))
        .map(|(depth, _)| PathProblem {
            depth,
            kind: PathProblemKind::Expired,
        })
        .collect();
    outcome.problems.extend(late);
    outcome
}

/// The path of a target whose public key OpenSSL cannot build.
///
/// `X509_verify_cert` stops on such a target before it judges anything
/// else (it copies key parameters along the whole path first), so the
/// path is judged in two parts instead: the target's issuer, found by the
/// issuer's signature over the target (the target's own key is never
/// used), is validated by OpenSSL as a target of its own; the target's
/// window and critical extensions, and the issuer's right to issue, are
/// judged here the way OpenSSL judges them. The problems come back at the
/// depths they would have had on the whole path.
fn keyless_target_path(
    target: &Certificate,
    untrusted: &[Certificate],
    anchors: &[TrustAnchor],
    at_millis: i64,
    max_intermediates: usize,
) -> PathOutcome {
    let (second, rounded_up) = seconds(at_millis);
    let mut problems = Vec::new();
    if !target.not_before_at_most(second) {
        problems.push(PathProblem {
            depth: 0,
            kind: PathProblemKind::NotYetValid,
        });
    }
    if !target.not_after_at_least(rounded_up) {
        problems.push(PathProblem {
            depth: 0,
            kind: PathProblemKind::Expired,
        });
    }
    if target.has_unhandled_critical_extension() {
        problems.push(PathProblem {
            depth: 0,
            kind: PathProblemKind::UnhandledCriticalExtension,
        });
    }
    if let Some(anchor) = anchors
        .iter()
        .map(TrustAnchor::certificate)
        .find(|anchor| target.issued_by(anchor))
    {
        return PathOutcome {
            chain: vec![target.clone(), anchor.clone()],
            anchored: true,
            problems,
        };
    }
    let Some(issuer) = untrusted
        .iter()
        .find(|candidate| target.issued_by(candidate))
    else {
        problems.push(PathProblem {
            depth: 0,
            kind: PathProblemKind::NoIssuer,
        });
        return PathOutcome {
            chain: vec![target.clone()],
            anchored: false,
            problems,
        };
    };
    let Some(above) = max_intermediates.checked_sub(1) else {
        problems.push(PathProblem {
            depth: 1,
            kind: PathProblemKind::TooLong,
        });
        return PathOutcome {
            chain: vec![target.clone()],
            anchored: false,
            problems,
        };
    };
    if !issuer.may_issue_certificates() {
        problems.push(PathProblem {
            depth: 1,
            kind: PathProblemKind::NotCa,
        });
    }
    let upper = checked_path(issuer, untrusted, anchors, at_millis, above);
    problems.extend(upper.problems.into_iter().map(|problem| PathProblem {
        depth: problem.depth.saturating_add(1),
        kind: problem.kind,
    }));
    let mut chain = vec![target.clone()];
    chain.extend(upper.chain);
    PathOutcome {
        chain,
        anchored: upper.anchored,
        problems,
    }
}

/// A problem that means no path reaches a pinned anchor, or that a link on
/// it is broken.
fn is_structural(kind: PathProblemKind) -> bool {
    !matches!(
        kind,
        PathProblemKind::NotYetValid
            | PathProblemKind::Expired
            | PathProblemKind::UnhandledCriticalExtension
    )
}

fn structural_failure(kind: PathProblemKind) -> Failure {
    match kind {
        PathProblemKind::NotCa => untrusted("an intermediate is not a CA"),
        PathProblemKind::TooLong => untrusted("chain exceeds the maximum length"),
        _ => untrusted("chain does not reach a pinned root"),
    }
}

/// Builds and validates the path of a legacy receipt's signer, whose
/// intermediates are embedded in the CMS blob. `authenticated` is what
/// [`authenticated_top_down`] accepted.
///
/// Returns the path below the anchor, signer first.
///
/// # Errors
/// `UNTRUSTED_CHAIN` when no path reaches a pinned anchor, a certificate
/// above the signer is not a CA, or the path is too long;
/// `INVALID_CERTIFICATE` when a certificate on the path is outside its
/// validity window at `at_millis`; `UNTRUSTED_CHAIN` when one marks
/// critical an extension OpenSSL does not process.
pub fn receipt_path(
    signer: &Certificate,
    authenticated: &[Certificate],
    anchors: &[TrustAnchor],
    at_millis: i64,
) -> Result<Vec<Certificate>, Failure> {
    let outcome = checked_path(
        signer,
        authenticated,
        anchors,
        at_millis,
        MAX_PATH_LENGTH.saturating_sub(1),
    );
    if let Some(problem) = outcome.problems.iter().find(|p| is_structural(p.kind)) {
        return Err(structural_failure(problem.kind));
    }
    if !outcome.anchored {
        return Err(untrusted("chain does not reach a pinned root"));
    }
    if outcome.problems.iter().any(|p| {
        matches!(
            p.kind,
            PathProblemKind::NotYetValid | PathProblemKind::Expired
        )
    }) {
        return Err(outside_validity());
    }
    if !outcome.problems.is_empty() {
        return Err(unprocessed_critical_extension());
    }
    let mut path = outcome.chain;
    path.pop();
    Ok(path)
}

/// Validates the fixed JWS path: leaf, intermediate, pinned anchor.
///
/// The two signatures are checked from the anchor down first, so no key an
/// anchor did not vouch for is used. Then OpenSSL judges the path, and its
/// problems are read in this order: a broken link, then the intermediate's
/// window, its CA flag and its critical extensions, then the leaf's window
/// and its critical extensions.
///
/// # Errors
/// `UNTRUSTED_CHAIN` for a broken link, an intermediate that is not a CA,
/// a certificate that marks critical an extension OpenSSL does not
/// process, or a path other than leaf, intermediate, anchor;
/// `INVALID_CERTIFICATE` for a certificate outside its validity window, or
/// a vouched-for intermediate whose key OpenSSL cannot build.
pub fn validate_pair(
    leaf: &Certificate,
    intermediate: &Certificate,
    anchors: &[TrustAnchor],
    at_millis: i64,
) -> Result<(), Failure> {
    if !anchors
        .iter()
        .any(|anchor| intermediate.issued_by(anchor.certificate()))
    {
        return Err(untrusted("intermediate is not issued by a pinned root"));
    }
    // Vouched for, and its key is about to check the leaf: a key OpenSSL
    // cannot build is the certificate's defect.
    if !intermediate.has_usable_key() {
        return Err(Failure::new(
            Reason::InvalidCertificate,
            "x5c entry has a public key this library cannot use",
        ));
    }
    if !leaf.issued_by(intermediate) {
        return Err(untrusted("leaf is not issued by the intermediate"));
    }
    let outcome = checked_path(
        leaf,
        std::slice::from_ref(intermediate),
        anchors,
        at_millis,
        1,
    );
    if let Some(problem) = outcome
        .problems
        .iter()
        .find(|p| is_structural(p.kind) && p.kind != PathProblemKind::NotCa)
    {
        return Err(structural_failure(problem.kind));
    }
    let at = |depth: usize, kinds: &[PathProblemKind]| {
        outcome
            .problems
            .iter()
            .any(|p| p.depth == depth && kinds.contains(&p.kind))
    };
    let validity = [PathProblemKind::NotYetValid, PathProblemKind::Expired];
    let critical = [PathProblemKind::UnhandledCriticalExtension];
    if at(1, &validity) {
        return Err(outside_validity());
    }
    if at(1, &[PathProblemKind::NotCa]) {
        return Err(untrusted("intermediate is not a CA"));
    }
    if at(1, &critical) {
        return Err(unprocessed_critical_extension());
    }
    if at(0, &validity) {
        return Err(outside_validity());
    }
    if at(0, &critical) {
        return Err(unprocessed_critical_extension());
    }
    if !outcome.problems.is_empty() {
        return Err(untrusted(
            "certificate chain does not validate to a pinned root",
        ));
    }
    let [path_leaf, path_intermediate, _anchor] = outcome.chain.as_slice() else {
        return Err(untrusted("path is not leaf, x5c[1], pinned root"));
    };
    if !outcome.anchored || !path_leaf.same_as(leaf) || !path_intermediate.same_as(intermediate) {
        return Err(untrusted("path is not leaf, x5c[1], pinned root"));
    }
    Ok(())
}
