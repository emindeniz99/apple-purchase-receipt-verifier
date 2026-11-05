//! The one entry point: [`Verifier`].

use crate::config::{ClockFn, Config};
use crate::endpoint;
use crate::environment::Environment;
use crate::error::{Failure, Reason};
use crate::jws::{self, JsonPayload};
use crate::receipt;
use crate::receipt_payload::ReceiptPayload;
use crate::revocation::Revocation;
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
/// Every method has an `_at` twin that takes the instant as an argument,
/// `now_ms` in epoch milliseconds, in place of the [`Config`] clock, which
/// it never reads. The instant is used where the clock would be: the chain
/// instant of a receipt or JWS that carries no usable signing date, and
/// the endpoint's `request_date`. At the same instant the two forms give
/// the same answer.
///
/// ```no_run
/// use apple_purchase_receipt_verifier::{Config, Verifier};
///
/// let verifier = Verifier::new(Config::default());
/// match verifier.verify_receipt("MIIT...") {
///     Ok(receipt) => println!("{}", receipt.to_json()),
///     Err(failure) => eprintln!("rejected: {}", failure.reason()),
/// }
/// // The same check at a given instant, whatever the configured clock says.
/// let _ = verifier.verify_receipt_at("MIIT...", 1_735_689_600_000);
/// ```
#[derive(Clone)]
pub struct Verifier {
    roots: Arc<[TrustAnchor]>,
    revocation: Option<Arc<Revocation>>,
    clock: Arc<ClockFn>,
}

impl Verifier {
    /// A verifier for `config`. The roots and the revocation settings are
    /// parsed and checked once, when the [`Config`] is built, and never per
    /// call.
    #[must_use]
    pub fn new(config: Config) -> Verifier {
        let (roots, revocation, clock) = config.into_parts();
        Verifier {
            roots,
            revocation,
            clock,
        }
    }

    /// The URLs of the revocation lists this verifier would use, for a
    /// host to download and pass to
    /// [`ConfigBuilder::revocation_lists`](crate::ConfigBuilder::revocation_lists)
    /// (docs/design/revocation.md §7): the list of each built-in issuer
    /// that chains to the configured roots, then the http and https
    /// cRLDistributionPoints of each added issuer, each once, in that
    /// order. With Apple's roots, four plain-HTTP URLs on `crl.apple.com`:
    /// `root.crl`, `applerootcag3.crl`, `wwdrg5.crl` and `wwdrg6.crl`
    /// (`certs/revocations.json` holds them). An added issuer's own list URL
    /// cannot be known from its certificate; add it by hand.
    #[must_use]
    pub fn revocation_urls(&self) -> &[String] {
        self.revocation.as_deref().map_or(&[], Revocation::urls)
    }

    /// The earliest `nextUpdate`, epoch milliseconds, among the lists
    /// held for the built-in issuers that chain to the configured roots and
    /// for the added issuers; `None` when one of them has no list held
    /// (none passed, or the one passed is ignored) or there is none of
    /// them. `None` means live revocation is not fully in force; an
    /// instant in the past means a list is stale. Alert on either, and
    /// refresh by building a new verifier.
    #[must_use]
    pub fn revocation_valid_until(&self) -> Option<i64> {
        self.revocation
            .as_deref()
            .and_then(Revocation::valid_until_ms)
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
        self.receipt(base64, &*self.clock)
    }

    /// [`verify_receipt`](Verifier::verify_receipt) at `now_ms`, epoch
    /// milliseconds, in place of the [`Config`] clock.
    ///
    /// # Errors
    /// A [`Failure`] naming the first check that failed.
    pub fn verify_receipt_at(&self, base64: &str, now_ms: i64) -> Result<ReceiptPayload, Failure> {
        self.verify_receipt_bytes_at(base64.as_bytes(), now_ms)
    }

    /// [`verify_receipt_bytes`](Verifier::verify_receipt_bytes) at
    /// `now_ms`, epoch milliseconds, in place of the [`Config`] clock.
    ///
    /// # Errors
    /// A [`Failure`] naming the first check that failed.
    pub fn verify_receipt_bytes_at(
        &self,
        base64: &[u8],
        now_ms: i64,
    ) -> Result<ReceiptPayload, Failure> {
        self.receipt(base64, &move || now_ms)
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
        self.signed_data(jws, &*self.clock)
    }

    /// [`verify_signed_data`](Verifier::verify_signed_data) at `now_ms`,
    /// epoch milliseconds, in place of the [`Config`] clock.
    ///
    /// # Errors
    /// A [`Failure`] naming the first check that failed.
    pub fn verify_signed_data_at(&self, jws: &str, now_ms: i64) -> Result<JsonPayload, Failure> {
        self.verify_signed_data_bytes_at(jws.as_bytes(), now_ms)
    }

    /// [`verify_signed_data_bytes`](Verifier::verify_signed_data_bytes) at
    /// `now_ms`, epoch milliseconds, in place of the [`Config`] clock.
    ///
    /// # Errors
    /// A [`Failure`] naming the first check that failed.
    pub fn verify_signed_data_bytes_at(
        &self,
        jws: &[u8],
        now_ms: i64,
    ) -> Result<JsonPayload, Failure> {
        self.signed_data(jws, &move || now_ms)
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
        self.endpoint(environment, request_json, &*self.clock)
    }

    /// [`verify_receipt_endpoint`](Verifier::verify_receipt_endpoint) at
    /// `now_ms`, epoch milliseconds, in place of the [`Config`] clock:
    /// `request_date` is `now_ms`.
    #[must_use]
    pub fn verify_receipt_endpoint_at(
        &self,
        environment: Environment,
        request_json: &str,
        now_ms: i64,
    ) -> String {
        self.verify_receipt_endpoint_bytes_at(environment, request_json.as_bytes(), now_ms)
    }

    /// [`verify_receipt_endpoint_bytes`](Verifier::verify_receipt_endpoint_bytes)
    /// at `now_ms`, epoch milliseconds, in place of the [`Config`] clock:
    /// `request_date` is `now_ms`.
    #[must_use]
    pub fn verify_receipt_endpoint_bytes_at(
        &self,
        environment: Environment,
        request_json: &[u8],
        now_ms: i64,
    ) -> String {
        self.endpoint(environment, request_json, &move || now_ms)
    }

    // The one implementation of each operation. `now` is how to get the
    // time, never the time itself: the Config clock for the plain methods,
    // a closure returning `now_ms` for the `_at` ones. It is wrapped in a
    // lazy `Clock`, read at most once and only where a verdict needs it.

    fn receipt(&self, base64: &[u8], now: &dyn Fn() -> i64) -> Result<ReceiptPayload, Failure> {
        self.contained(now, |revocation, clock| {
            receipt::verify(base64, &self.roots, revocation, clock)
        })
    }

    fn signed_data(&self, jws: &[u8], now: &dyn Fn() -> i64) -> Result<JsonPayload, Failure> {
        self.contained(now, |revocation, clock| {
            jws::verify(jws, &self.roots, revocation, clock)
        })
    }

    fn endpoint(
        &self,
        environment: Environment,
        request_json: &[u8],
        now: &dyn Fn() -> i64,
    ) -> String {
        let revocation = match self.check_anchors() {
            Ok(revocation) => revocation,
            Err(failure) => return endpoint::status_only(endpoint::status(failure.reason())),
        };
        let clock = Clock::new(now);
        catch_unwind(AssertUnwindSafe(|| {
            endpoint::respond(environment, request_json, &self.roots, revocation, &clock)
        }))
        .unwrap_or_else(|_| endpoint::status_only(endpoint::status(Reason::InternalError)))
    }

    /// Runs `verify` with a lazy clock over `now`, containing a panic.
    fn contained<T>(
        &self,
        now: &dyn Fn() -> i64,
        verify: impl FnOnce(&Revocation, &Clock<'_>) -> Result<T, Failure>,
    ) -> Result<T, Failure> {
        let revocation = self.check_anchors()?;
        let clock = Clock::new(now);
        catch_unwind(AssertUnwindSafe(|| verify(revocation, &clock))).unwrap_or_else(|_| {
            // Nothing that is only known after a panic, its text included,
            // reaches the caller.
            Err(Failure::new(
                Reason::InternalError,
                "unexpected internal failure",
            ))
        })
    }

    /// `INTERNAL_ERROR` when there is no anchor, or no revocation state.
    /// Only `Config::default` can hand over an empty set, when the bundled
    /// roots did not load, and no revocation state, when the built-in
    /// revocation list did not load; every verdict without an anchor would
    /// be a misleading `UNTRUSTED_CHAIN`, and one without the built-in list
    /// would pass a revoked certificate.
    fn check_anchors(&self) -> Result<&Revocation, Failure> {
        if self.roots.is_empty() {
            return Err(Failure::new(
                Reason::InternalError,
                "no trust anchors: the bundled Apple roots did not load",
            ));
        }
        self.revocation.as_deref().ok_or_else(|| {
            Failure::new(
                Reason::InternalError,
                "the built-in revocation list did not load",
            )
        })
    }
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verifier")
            .field("roots", &self.roots.len())
            .field("revocation_urls", &self.revocation_urls())
            .field("revocation_valid_until", &self.revocation_valid_until())
            .finish_non_exhaustive()
    }
}

/// How to get the time (the configured clock, or a fixed `now_ms`), read
/// at most once and only when asked.
pub(crate) struct Clock<'a> {
    read: &'a dyn Fn() -> i64,
    millis: Cell<Option<i64>>,
}

impl<'a> Clock<'a> {
    pub(crate) fn new(read: &'a dyn Fn() -> i64) -> Clock<'a> {
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
            revocation: None,
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
            .contained(&|| 0, |_, _| -> Result<(), crate::Failure> {
                panic!("secret panic text")
            })
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
