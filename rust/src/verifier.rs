//! The one entry point: [`Verifier`].

use crate::config::{ClockFn, Config};
use crate::endpoint;
use crate::environment::Environment;
use crate::error::{Failure, Reason};
use crate::jws::{self, JsonPayload};
use crate::receipt;
use crate::receipt_payload::ReceiptPayload;
use crate::roots::TrustAnchor;
use core::cell::Cell;
use core::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

/// Verifies what Apple signed, offline, against the pinned roots of a
/// [`Config`].
///
/// Immutable and cheap to clone; share one across threads. The verify
/// methods never panic for any input: a panic inside one is contained and
/// reported by where it happened, with a fixed message. Before a signature
/// has verified it is [`Reason::Malformed`], as the input nobody vouched for
/// must not be able to raise an internal-error alert at will; while the
/// signed receipt payload is read it is [`Reason::UnreadablePayload`]; after
/// that, or a clock that panics, it is [`Reason::InternalError`]. The
/// endpoint answers each with its status. Containment needs unwinding: under
/// `panic = "abort"` a panic ends the process.
///
/// The clock is read only when a verdict needs it, so input that fails its
/// own checks never reaches it.
///
/// ```no_run
/// use apple_purchase_receipt_verifier::{Config, Verifier};
///
/// let verifier = Verifier::new(Config::defaults());
/// match verifier.verify_receipt("MIIT...") {
///     Ok(receipt) => println!("{}", receipt.to_json()),
///     Err(failure) => eprintln!("rejected: {}", failure.reason()),
/// }
/// ```
#[derive(Clone)]
pub struct Verifier {
    roots: Arc<[TrustAnchor]>,
    clock: Arc<ClockFn>,
}

impl Verifier {
    /// A verifier for `config`. The roots are parsed once, when the
    /// [`Config`] is built, and never per call.
    #[must_use]
    pub fn new(config: Config) -> Verifier {
        let (roots, clock) = config.into_parts();
        Verifier { roots, clock }
    }

    /// Verifies a legacy PKCS#7 app receipt, given as the base64 string a
    /// client sends, and decodes its payload.
    ///
    /// # Errors
    /// A [`Failure`] naming the first check that failed.
    pub fn verify_receipt(&self, base64: &str) -> Result<ReceiptPayload, Failure> {
        self.contained(|clock| receipt::verify(base64, &self.roots, clock))
    }

    /// Verifies an Apple-signed compact JWS and returns its payload,
    /// unchanged.
    ///
    /// # Errors
    /// A [`Failure`] naming the first check that failed.
    pub fn verify_signed_data(&self, jws: &str) -> Result<JsonPayload, Failure> {
        self.contained(|clock| jws::verify(jws, &self.roots, clock))
    }

    /// The response body Apple's `verifyReceipt` endpoint at `environment`
    /// would return for `request_json`. Never fails: every verdict is the
    /// `status` inside the body.
    #[must_use]
    pub fn verify_receipt_endpoint(&self, environment: Environment, request_json: &str) -> String {
        if self.roots.is_empty() {
            return endpoint::status_only(endpoint::status(Reason::InternalError));
        }
        let clock = Clock::new(&*self.clock);
        staged(|| endpoint::respond(environment, request_json, &self.roots, &clock))
            .unwrap_or_else(|stage| endpoint::status_only(endpoint::status(stage.reason())))
    }

    /// Runs `verify` with a lazy clock, containing a panic by stage.
    fn contained<T>(
        &self,
        verify: impl FnOnce(&Clock<'_>) -> Result<T, Failure>,
    ) -> Result<T, Failure> {
        // Only Config::defaults can hand over an empty set, when the bundled
        // roots did not load; every verdict without an anchor would be a
        // misleading UNTRUSTED_CHAIN.
        if self.roots.is_empty() {
            return Err(Failure::new(
                Reason::InternalError,
                "no trust anchors: the bundled Apple roots did not load",
            ));
        }
        let clock = Clock::new(&*self.clock);
        staged(|| verify(&clock))
            .unwrap_or_else(|stage| Err(Failure::new(stage.reason(), stage.message())))
    }
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verifier")
            .field("roots", &self.roots.len())
            .finish_non_exhaustive()
    }
}

/// Where a verification is, for mapping a panic to a verdict: nothing that
/// is only known after a panic, its text included, reaches the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    /// Reading input no signature has vouched for yet.
    BeforeSignature,
    /// Decoding a receipt payload a trusted signer signed.
    PayloadParse,
    /// Everything after that.
    AfterSignature,
}

impl Stage {
    const fn reason(self) -> Reason {
        match self {
            Stage::BeforeSignature => Reason::Malformed,
            Stage::PayloadParse => Reason::UnreadablePayload,
            Stage::AfterSignature => Reason::InternalError,
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Stage::BeforeSignature => "unexpected failure while reading unverified input",
            Stage::PayloadParse => "unexpected failure while reading the signed payload",
            Stage::AfterSignature => "unexpected internal failure",
        }
    }
}

thread_local! {
    static STAGE: Cell<Stage> = const { Cell::new(Stage::BeforeSignature) };
}

/// Marks the stage the current verification has reached.
pub(crate) fn enter(stage: Stage) {
    STAGE.with(|current| current.set(stage));
}

/// Runs `work` from [`Stage::BeforeSignature`], and on a panic returns the
/// stage it happened in. The caller's stage is restored either way, so a
/// verification that runs inside another one (from a clock, say) leaves the
/// outer one's stage as it found it.
fn staged<R>(work: impl FnOnce() -> R) -> Result<R, Stage> {
    let outer = STAGE.with(|current| current.replace(Stage::BeforeSignature));
    let result = catch_unwind(AssertUnwindSafe(work));
    let reached = STAGE.with(|current| current.replace(outer));
    result.map_err(|_| reached)
}

/// The configured clock, read at most once and only when asked.
pub(crate) struct Clock<'a> {
    read: &'a ClockFn,
    millis: Cell<Option<i64>>,
}

impl<'a> Clock<'a> {
    pub(crate) fn new(read: &'a ClockFn) -> Clock<'a> {
        Clock {
            read,
            millis: Cell::new(None),
        }
    }

    /// The current time in epoch milliseconds, the same value on every call.
    ///
    /// # Errors
    /// [`Reason::InternalError`] when the clock panics: the caller's clock,
    /// not the input, broke.
    pub(crate) fn now(&self) -> Result<i64, Failure> {
        if let Some(millis) = self.millis.get() {
            return Ok(millis);
        }
        let millis = catch_unwind(AssertUnwindSafe(|| (self.read)()))
            .map_err(|_| Failure::new(Reason::InternalError, "the configured clock panicked"))?;
        self.millis.set(Some(millis));
        Ok(millis)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::{enter, staged, Clock, Stage, Verifier, STAGE};
    use crate::environment::Environment;
    use crate::error::Reason;
    use std::sync::Arc;

    #[test]
    fn a_verifier_without_anchors_answers_internal_error() {
        // What Config::defaults hands over when the bundled roots did not
        // load: not UNTRUSTED_CHAIN, which would blame every input.
        let verifier = Verifier {
            roots: Arc::from(Vec::new()),
            clock: Arc::new(|| 0),
        };
        for failure in [
            verifier.verify_receipt("AAAA").unwrap_err(),
            verifier.verify_signed_data("a.b.c").unwrap_err(),
        ] {
            assert_eq!(failure.reason(), Reason::InternalError);
            assert!(failure.message().starts_with("no trust anchors"));
        }
        assert_eq!(
            verifier.verify_receipt_endpoint(Environment::Sandbox, "{}"),
            "{\"status\":21009}"
        );
    }

    #[test]
    fn a_panic_is_judged_by_the_stage_it_happened_in() {
        // Before a signature the input is nobody's, so a panic there must
        // not raise the internal-error alarm; after it, it must.
        let cases = [
            (Stage::BeforeSignature, Reason::Malformed),
            (Stage::PayloadParse, Reason::UnreadablePayload),
            (Stage::AfterSignature, Reason::InternalError),
        ];
        for (stage, reason) in cases {
            let reached = staged(|| {
                enter(stage);
                panic!("secret panic text");
            })
            .unwrap_err();
            assert_eq!(reached, stage);
            assert_eq!(reached.reason(), reason);
            assert!(!reached.message().contains("secret"));
        }
    }

    #[test]
    fn every_verification_starts_before_the_signature_and_restores_the_caller() {
        enter(Stage::AfterSignature);
        let inner = staged(|| STAGE.with(std::cell::Cell::get));
        assert_eq!(inner, Ok(Stage::BeforeSignature));
        assert_eq!(STAGE.with(std::cell::Cell::get), Stage::AfterSignature);
        enter(Stage::BeforeSignature);
    }

    #[test]
    fn the_clock_is_read_once_and_its_panic_is_an_internal_error() {
        let reads = std::sync::atomic::AtomicUsize::new(0);
        let counting = move || {
            reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            i64::try_from(reads.load(std::sync::atomic::Ordering::Relaxed)).unwrap_or(0)
        };
        let clock = Clock::new(&counting);
        assert_eq!(clock.now(), Ok(1));
        assert_eq!(clock.now(), Ok(1));

        let broken = || -> i64 { panic!("secret panic text") };
        let failure = Clock::new(&broken).now().unwrap_err();
        assert_eq!(failure.reason(), Reason::InternalError);
        assert_eq!(failure.message(), "the configured clock panicked");
    }
}
