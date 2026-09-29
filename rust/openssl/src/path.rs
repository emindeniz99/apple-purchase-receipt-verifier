//! Certificate path validation with `X509_verify_cert`, over a store that
//! holds the caller's anchors and nothing else, at a caller-given second.
//!
//! OpenSSL builds and checks the path; this module reports every problem it
//! finds, with the depth it found it at, and decides nothing: the core
//! turns the problems into a reason in its own order. To see every problem
//! rather than the first, the verify callback records each one and lets
//! the verification continue; a path is good only when OpenSSL answers 1
//! and nothing was recorded.

use crate::certificate::{same_x509, Certificate};
use crate::{drain_errors, init, sys};
use foreign_types::ForeignTypeRef;
use libc::c_int;
use openssl::asn1::Asn1Time;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::{X509VerifyFlags, X509VerifyParam};
use openssl::x509::{X509StoreContext, X509StoreContextRef, X509VerifyResult, X509};
use openssl_sys as ffi;
use std::cell::{Cell, RefCell};

/// What kind of problem a path has, grouped the way the core judges them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathProblemKind {
    /// No issuer for a certificate, or a path that ends at a certificate
    /// no anchor is: the path does not reach a pinned anchor.
    NoIssuer,
    /// A signature on the path does not verify.
    BadSignature,
    /// A certificate above the target may not issue certificates, or a
    /// path length constraint is exceeded.
    NotCa,
    /// The path is longer than allowed.
    TooLong,
    /// A certificate is not yet valid at the check time, or its
    /// `notBefore` does not read as a time.
    NotYetValid,
    /// A certificate has expired at the check time, or its `notAfter` does
    /// not read as a time.
    Expired,
    /// A certificate marks critical an extension OpenSSL does not process.
    UnhandledCriticalExtension,
    /// Anything else OpenSSL reports, with its `X509_V_ERR_*` code.
    Other(i32),
}

/// One problem, at the depth OpenSSL found it (0 is the target).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathProblem {
    /// Where on the path: 0 is the target, 1 its issuer, and so on.
    pub depth: usize,
    /// What.
    pub kind: PathProblemKind,
}

/// What a path validation found.
#[derive(Debug, Clone)]
pub struct PathOutcome {
    /// The path OpenSSL built, target first. When `anchored`, the last
    /// certificate is the anchor it reached.
    pub chain: Vec<Certificate>,
    /// Whether the path ends at one of the anchors.
    pub anchored: bool,
    /// Every problem found. Empty only for a path that passed.
    pub problems: Vec<PathProblem>,
}

impl PathOutcome {
    /// Whether the path passed: anchored, and not one problem.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.anchored && self.problems.is_empty()
    }

    fn failed(kind: PathProblemKind) -> PathOutcome {
        PathOutcome {
            chain: Vec::new(),
            anchored: false,
            problems: vec![PathProblem { depth: 0, kind }],
        }
    }
}

std::thread_local! {
    /// The anchors and the check time of the verification running on this
    /// thread, for the verify callback, which is a plain C function with no
    /// user data; and the problems it has recorded.
    static ANCHORS: RefCell<Vec<X509>> = const { RefCell::new(Vec::new()) };
    static CHECK_TIME: Cell<i64> = const { Cell::new(0) };
    static PROBLEMS: RefCell<Vec<PathProblem>> = const { RefCell::new(Vec::new()) };
}

/// Builds and validates a path from `target` through `untrusted` to one of
/// `anchors`, at `at_secs` (Unix seconds), with at most `max_intermediates`
/// certificates between the target and the anchor.
///
/// The store holds `anchors` and nothing else. `X509_V_FLAG_PARTIAL_CHAIN`
/// makes each of them a trust anchor whether or not it is self-signed, as a
/// pinned anchor is. No purpose, policy, revocation or host check is asked
/// for. An anchor is trusted by fiat: its own validity window, CA flag and
/// path length constraint are not judged. An expiry reported at exactly the
/// `notAfter` second is waived, since RFC 5280 includes that second.
#[must_use]
pub fn verify_path(
    target: &Certificate,
    untrusted: &[Certificate],
    anchors: &[Certificate],
    at_secs: i64,
    max_intermediates: u32,
) -> PathOutcome {
    init();
    let outcome = run(target, untrusted, anchors, at_secs, max_intermediates)
        .unwrap_or_else(|| PathOutcome::failed(PathProblemKind::Other(-1)));
    ANCHORS.with(|slot| slot.replace(Vec::new()));
    PROBLEMS.with(|slot| slot.replace(Vec::new()));
    drain_errors();
    outcome
}

fn run(
    target: &Certificate,
    untrusted: &[Certificate],
    anchors: &[Certificate],
    at_secs: i64,
    max_intermediates: u32,
) -> Option<PathOutcome> {
    let mut builder = X509StoreBuilder::new().ok()?;
    for anchor in anchors {
        builder.add_cert(anchor.x509().to_owned()).ok()?;
    }
    let mut param = X509VerifyParam::new().ok()?;
    param.set_time(libc::time_t::try_from(at_secs).ok()?);
    param.set_depth(c_int::try_from(max_intermediates).ok()?);
    param.set_flags(X509VerifyFlags::PARTIAL_CHAIN).ok()?;
    builder.set_param(&param).ok()?;
    let store = builder.build();
    let mut chain = Stack::new().ok()?;
    for certificate in untrusted {
        chain.push(certificate.x509().to_owned()).ok()?;
    }
    ANCHORS.with(|slot| slot.replace(anchors.iter().map(|a| a.x509().to_owned()).collect()));
    CHECK_TIME.with(|slot| slot.set(at_secs));
    PROBLEMS.with(|slot| slot.replace(Vec::new()));
    let mut context = X509StoreContext::new().ok()?;
    let verified = context
        .init(&store, target.x509(), &chain, |ctx| {
            install_callback(ctx);
            let verified = ctx.verify_cert()?;
            let built: Vec<Certificate> = ctx
                .chain()
                .map(|stack| {
                    stack
                        .iter()
                        .map(|x509| Certificate::from_x509(x509.to_owned()))
                        .collect()
                })
                .unwrap_or_default();
            Ok((verified, built))
        })
        .ok();
    let mut problems = PROBLEMS.with(|slot| slot.replace(Vec::new()));
    let (verified, built) = verified?;
    // The path is anchored when it ends at one of the caller's anchors;
    // with PARTIAL_CHAIN OpenSSL stops at the first store certificate.
    let anchored = built
        .last()
        .is_some_and(|top| anchors.iter().any(|anchor| top.same_as(anchor)));
    if !verified && problems.is_empty() {
        problems.push(PathProblem {
            depth: 0,
            kind: PathProblemKind::Other(-1),
        });
    }
    Some(PathOutcome {
        chain: built,
        anchored,
        problems,
    })
}

fn install_callback(ctx: &mut X509StoreContextRef) {
    // SAFETY: installs a plain function pointer on the live context, which
    // `init` keeps initialised for the duration of this verification only.
    unsafe { sys::X509_STORE_CTX_set_verify_cb(ctx.as_ptr(), Some(record_problem)) };
}

/// The verify callback: records each problem OpenSSL reports and lets it
/// continue, except the ones [`waived`] says an anchor or the notAfter
/// second may have. Returns 1, so every problem is seen, unless a problem
/// cannot be recorded; the verdict is taken from the record, never from
/// OpenSSL's return value alone.
unsafe extern "C" fn record_problem(ok: c_int, ctx: *mut ffi::X509_STORE_CTX) -> c_int {
    if ok == 1 {
        return 1;
    }
    // SAFETY: OpenSSL calls this with the live context it is verifying;
    // it is borrowed for this call only.
    let ctx = unsafe { X509StoreContextRef::from_ptr_mut(ctx) };
    let error = ctx.error();
    if waived(ctx, error) {
        ctx.set_error(X509VerifyResult::OK);
        return 1;
    }
    let problem = PathProblem {
        depth: usize::try_from(ctx.error_depth()).unwrap_or(usize::MAX),
        kind: kind_of(error.as_raw()),
    };
    // A problem that cannot be recorded stops the verification instead of
    // passing unseen (fail closed; no caller holds that borrow today).
    let recorded = PROBLEMS.with(|slot| {
        slot.try_borrow_mut()
            .map(|mut problems| problems.push(problem))
            .is_ok()
    });
    c_int::from(recorded)
}

/// A trust anchor is trusted by fiat, as a PKIX trust anchor is: its own
/// validity window, CA flag and path length constraint are not judged,
/// which OpenSSL does for a certificate in the store. An expiry reported at
/// exactly the check second is waived for every certificate, because
/// RFC 5280 section 4.1.2.5 includes the `notAfter` second, as OpenSSL 4.0
/// does and OpenSSL 1.1.1 to 3.6 do not.
fn waived(ctx: &X509StoreContextRef, error: X509VerifyResult) -> bool {
    let raw = error.as_raw();
    let Some(current) = ctx.current_cert() else {
        return false;
    };
    let anchor_errors = [
        ffi::X509_V_ERR_CERT_NOT_YET_VALID,
        ffi::X509_V_ERR_CERT_HAS_EXPIRED,
        ffi::X509_V_ERR_INVALID_CA,
        ffi::X509_V_ERR_PATH_LENGTH_EXCEEDED,
    ];
    if anchor_errors.contains(&raw)
        && ANCHORS.with(|slot| {
            slot.try_borrow()
                .is_ok_and(|anchors| anchors.iter().any(|anchor| same_x509(anchor, current)))
        })
    {
        return true;
    }
    raw == ffi::X509_V_ERR_CERT_HAS_EXPIRED && {
        let at = CHECK_TIME.with(Cell::get);
        let at_notafter = libc::time_t::try_from(at)
            .ok()
            .and_then(|at| Asn1Time::from_unix(at).ok())
            .is_some_and(|at| current.not_after() == at);
        drain_errors();
        at_notafter
    }
}

fn kind_of(code: c_int) -> PathProblemKind {
    match code {
        ffi::X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
        | ffi::X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
        | ffi::X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
        | ffi::X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
        | ffi::X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
        | ffi::X509_V_ERR_CERT_UNTRUSTED => PathProblemKind::NoIssuer,
        ffi::X509_V_ERR_CERT_SIGNATURE_FAILURE
        | ffi::X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY
        | ffi::X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE => PathProblemKind::BadSignature,
        ffi::X509_V_ERR_INVALID_CA | ffi::X509_V_ERR_PATH_LENGTH_EXCEEDED => PathProblemKind::NotCa,
        ffi::X509_V_ERR_CERT_CHAIN_TOO_LONG => PathProblemKind::TooLong,
        ffi::X509_V_ERR_CERT_NOT_YET_VALID | ffi::X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD => {
            PathProblemKind::NotYetValid
        }
        ffi::X509_V_ERR_CERT_HAS_EXPIRED | ffi::X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD => {
            PathProblemKind::Expired
        }
        ffi::X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION => PathProblemKind::UnhandledCriticalExtension,
        other => PathProblemKind::Other(other),
    }
}
