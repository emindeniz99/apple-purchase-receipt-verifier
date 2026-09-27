//! The one entry point: [`Verifier`].

use crate::config::{ClockFn, Config};
use crate::endpoint;
use crate::environment::Environment;
use crate::error::{Failure, Reason};
use crate::jws::{self, JsonPayload};
use crate::receipt;
use crate::receipt_payload::ReceiptPayload;
use crate::roots::TrustAnchor;
use core::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

/// Verifies what Apple signed, offline, against the pinned roots of a
/// [`Config`].
///
/// Immutable and cheap to clone; share one across threads. The verify
/// methods never panic for any input: a panic inside one (a bug, or a clock
/// that panics) is contained and reported as [`Reason::InternalError`], or as
/// status 21009 by the endpoint.
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
        self.contained(|now| receipt::verify(base64, &self.roots, now))
    }

    /// Verifies an Apple-signed compact JWS and returns its payload,
    /// unchanged.
    ///
    /// # Errors
    /// A [`Failure`] naming the first check that failed.
    pub fn verify_signed_data(&self, jws: &str) -> Result<JsonPayload, Failure> {
        self.contained(|now| jws::verify(jws, &self.roots, now))
    }

    /// The response body Apple's `verifyReceipt` endpoint at `environment`
    /// would return for `request_json`. Never fails: every verdict is the
    /// `status` inside the body.
    #[must_use]
    pub fn verify_receipt_endpoint(&self, environment: Environment, request_json: &str) -> String {
        catch_unwind(AssertUnwindSafe(|| {
            endpoint::respond(environment, request_json, &self.roots, (self.clock)())
        }))
        .unwrap_or_else(|_| endpoint::status_only(endpoint::status(Reason::InternalError)))
    }

    /// Reads the clock once and runs `verify`, containing a panic in either.
    fn contained<T>(&self, verify: impl FnOnce(i64) -> Result<T, Failure>) -> Result<T, Failure> {
        catch_unwind(AssertUnwindSafe(|| verify((self.clock)()))).unwrap_or_else(|panic| {
            Err(Failure::new(
                Reason::InternalError,
                format!("unexpected panic: {}", panic_message(panic.as_ref())),
            ))
        })
    }
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verifier")
            .field("roots", &self.roots.len())
            .finish_non_exhaustive()
    }
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    if let Some(text) = payload.downcast_ref::<&str>() {
        text
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text
    } else {
        "a panic with a non-string payload"
    }
}
