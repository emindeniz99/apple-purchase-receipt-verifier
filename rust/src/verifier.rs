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
/// methods never panic for any input: a panic inside one is contained as
/// [`Reason::InternalError`] with a fixed message, wherever it happened, and
/// so is a clock that panics; the endpoint answers 21009. A panic is a bug
/// in this library, never a verdict on the input, so it must raise the
/// operator's alarm rather than read as a client "deny". Containment needs
/// unwinding, so it holds in native builds only: `aprv.wasm` is built with
/// the `wasm` profile's `panic = "abort"` (`rust/Cargo.toml`), where a panic
/// traps the module, which every host reports as `INTERNAL_ERROR` too.
///
/// The clock is read only when a verdict needs it, so input that fails its
/// own checks never reaches it.
///
/// ```no_run
/// use apple_purchase_receipt_verifier::{Config, Verifier};
///
/// let verifier = Verifier::new(Config::default());
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
        self.verify_receipt_bytes(base64.as_bytes())
    }

    /// [`verify_receipt`](Verifier::verify_receipt) for a caller that holds
    /// the base64 text as bytes, as the Wasm module and other bindings do.
    /// The checks and the verdicts are the same; bytes that are not UTF-8
    /// cannot be base64 and fail as it does.
    ///
    /// # Errors
    /// A [`Failure`] naming the first check that failed.
    pub fn verify_receipt_bytes(&self, base64: &[u8]) -> Result<ReceiptPayload, Failure> {
        self.contained(|clock| receipt::verify(base64, &self.roots, clock))
    }

    /// Verifies an Apple-signed compact JWS and returns its payload,
    /// unchanged.
    ///
    /// # Errors
    /// A [`Failure`] naming the first check that failed.
    pub fn verify_signed_data(&self, jws: &str) -> Result<JsonPayload, Failure> {
        self.verify_signed_data_bytes(jws.as_bytes())
    }

    /// [`verify_signed_data`](Verifier::verify_signed_data) for a caller
    /// that holds the JWS as bytes. The checks and the verdicts are the
    /// same; bytes that are not UTF-8 cannot be base64url and fail as it
    /// does.
    ///
    /// # Errors
    /// A [`Failure`] naming the first check that failed.
    pub fn verify_signed_data_bytes(&self, jws: &[u8]) -> Result<JsonPayload, Failure> {
        self.contained(|clock| jws::verify(jws, &self.roots, clock))
    }

    /// The response body Apple's `verifyReceipt` endpoint at `environment`
    /// would return for `request_json`. Never fails: every verdict is the
    /// `status` inside the body.
    #[must_use]
    pub fn verify_receipt_endpoint(&self, environment: Environment, request_json: &str) -> String {
        self.verify_receipt_endpoint_bytes(environment, request_json.as_bytes())
    }

    /// [`verify_receipt_endpoint`](Verifier::verify_receipt_endpoint) for a
    /// caller that holds the request body as bytes. A body that is not
    /// UTF-8 is not JSON, and answers as any other body that is not.
    #[must_use]
    pub fn verify_receipt_endpoint_bytes(
        &self,
        environment: Environment,
        request_json: &[u8],
    ) -> String {
        if let Err(failure) = self.check_anchors() {
            return endpoint::status_only(endpoint::status(failure.reason()));
        }
        let clock = Clock::new(&*self.clock);
        catch_unwind(AssertUnwindSafe(|| {
            endpoint::respond(environment, request_json, &self.roots, &clock)
        }))
        .unwrap_or_else(|_| endpoint::status_only(endpoint::status(Reason::InternalError)))
    }

    /// Runs `verify` with a lazy clock, containing a panic.
    fn contained<T>(
        &self,
        verify: impl FnOnce(&Clock<'_>) -> Result<T, Failure>,
    ) -> Result<T, Failure> {
        self.check_anchors()?;
        let clock = Clock::new(&*self.clock);
        catch_unwind(AssertUnwindSafe(|| verify(&clock))).unwrap_or_else(|_| {
            // Nothing that is only known after a panic, its text included,
            // reaches the caller.
            Err(Failure::new(
                Reason::InternalError,
                "unexpected internal failure",
            ))
        })
    }

    /// `INTERNAL_ERROR` when there is no anchor. Only `Config::default` can
    /// hand over an empty set, when the bundled roots did not load; every
    /// verdict without an anchor would be a misleading `UNTRUSTED_CHAIN`.
    fn check_anchors(&self) -> Result<(), Failure> {
        if self.roots.is_empty() {
            return Err(Failure::new(
                Reason::InternalError,
                "no trust anchors: the bundled Apple roots did not load",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verifier")
            .field("roots", &self.roots.len())
            .finish_non_exhaustive()
    }
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
    use super::{Clock, Verifier};
    use crate::environment::Environment;
    use crate::error::Reason;
    use std::sync::Arc;

    #[test]
    fn a_verifier_without_anchors_answers_internal_error() {
        // What Config::default hands over when the bundled roots did not
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
    fn a_panic_is_an_internal_error_wherever_it_happens() {
        // A panic is a bug in this library, whatever input it met: it must
        // raise the operator's alarm, as aprv.wasm's trap does, never read
        // as a client "deny". Its text never reaches the caller.
        let verifier = Verifier::new(crate::Config::default());
        let failure = verifier
            .contained(|_| -> Result<(), crate::Failure> { panic!("secret panic text") })
            .unwrap_err();
        assert_eq!(failure.reason(), Reason::InternalError);
        assert_eq!(failure.message(), "unexpected internal failure");
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
