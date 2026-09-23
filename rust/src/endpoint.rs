//! A drop-in local replacement for Apple's deprecated `verifyReceipt`
//! endpoint: the same request body, the same response body, the same status
//! codes — verified offline against pinned anchors instead of by calling
//! Apple.
//!
//! Field-by-field fidelity and the unavoidable gaps (fields that exist only
//! in Apple's server-side subscription database, such as
//! `latest_receipt_info` and `pending_renewal_info`) are documented in
//! `COMPARISON.md`.
//!
//! Like Apple's endpoint, this does **not** check the bundle id — the caller
//! compares `receipt.bundle_id`, exactly as with the real endpoint.

use crate::clock::{default_clock, unix_millis, Clock};
use crate::datetime::{format_etc_gmt, format_pacific, unix_millis_of};
use crate::environment::Environment;
use crate::error::{ConfigError, Reason, VerificationError};
use crate::json_depth::nesting_exceeds_limit;
use crate::receipt::{
    decode_receipt_string, verify_receipt_core_unchecked, AppReceipt, InAppPurchase,
};
use crate::roots::{normalize_anchors, TrustAnchor};
use serde_json::{Map, Value};
use std::sync::Arc;
use std::time::SystemTime;

/// The largest request body [`VerifyReceiptEndpoint`] will parse, in UTF-8
/// bytes (`str::len`), checked before the depth scan and the JSON parser.
///
/// 3 MiB (3,145,728 bytes), Apple's own limit, fixed and the same in every
/// port of this library. Measured on 2026-09-23 against both of Apple's
/// `verifyReceipt` endpoints, a body of 3,145,728 bytes is answered and one
/// of 3,145,729 bytes gets HTTP 413, and the count is UTF-8 bytes, not
/// characters. A `&str` is UTF-8, so `str::len` is that count.
///
/// A larger body fails with [`Reason::RequestTooLarge`], status 21002,
/// before it is parsed: JSON parsing allocates a multiple of the body, all
/// of it before any verification.
pub const MAX_REQUEST_BYTES: usize = 3_145_728;

/// The Apple status codes this local implementation can produce.
///
/// `21000`, `21004`, `21005`, `21006`, `21010`, `21100`–`21199` and
/// `is_retryable` are **never** produced: they describe conditions that only
/// exist on Apple's server (`COMPARISON.md`).
pub mod status {
    /// The receipt verified.
    pub const OK: i64 = 0;
    /// The `receipt-data` property was malformed or missing.
    pub const MALFORMED: i64 = 21002;
    /// The receipt could not be authenticated.
    pub const NOT_AUTHENTICATED: i64 = 21003;
    /// A sandbox receipt was sent to the production environment.
    pub const SANDBOX_RECEIPT_ON_PRODUCTION: i64 = 21007;
    /// A production receipt was sent to the sandbox environment.
    pub const PRODUCTION_RECEIPT_ON_SANDBOX: i64 = 21008;
    /// Not the client's fault: signed receipt content this library cannot
    /// read, or a contained panic
    /// ([`Reason::InternalError`](crate::Reason::InternalError)). Alert and
    /// retry or escalate; do not deny the user on it.
    pub const INTERNAL: i64 = 21009;
}

/// One `verifyReceipt` request body.
///
/// <https://developer.apple.com/documentation/appstorereceipts/requestbody>
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifyReceiptRequest {
    /// The base64 receipt.
    pub receipt_data: Option<String>,
    /// Accepted for compatibility; cannot be validated locally and is never
    /// read (`COMPARISON.md`).
    pub password: Option<String>,
    /// Accepted for compatibility; has no effect, because this endpoint
    /// never produces `latest_receipt_info`.
    pub exclude_old_transactions: Option<bool>,
}

impl VerifyReceiptRequest {
    /// A request carrying just `receipt-data`.
    #[must_use]
    pub fn new(receipt_data: impl Into<String>) -> Self {
        VerifyReceiptRequest {
            receipt_data: Some(receipt_data.into()),
            ..VerifyReceiptRequest::default()
        }
    }
}

/// One `verifyReceipt` response body, as [`VerifyReceiptResult::to_response`]
/// renders it.
///
/// <https://developer.apple.com/documentation/appstorereceipts/responsebody>
#[derive(Debug, Clone, PartialEq)]
pub struct VerifyReceiptResponse {
    /// The Apple status code. See [`status`].
    pub status: i64,
    /// The environment the body was rendered for, on success only.
    pub environment: Option<Environment>,
    /// The Apple-shaped receipt object, on success only.
    pub receipt: Option<Map<String, Value>>,
}

impl VerifyReceiptResponse {
    fn failure(status: i64) -> Self {
        VerifyReceiptResponse {
            status,
            environment: None,
            receipt: None,
        }
    }

    /// The response as the JSON body Apple would have returned.
    #[must_use]
    pub fn to_json_value(&self) -> Value {
        let mut body = Map::new();
        body.insert("status".to_owned(), Value::from(self.status));
        if let Some(environment) = self.environment {
            body.insert("environment".to_owned(), Value::from(environment.as_str()));
        }
        if let Some(receipt) = &self.receipt {
            body.insert("receipt".to_owned(), Value::Object(receipt.clone()));
        }
        Value::Object(body)
    }
}

/// What one `verifyReceipt` call concluded: a verified receipt, or the reason
/// there is none.
// Unboxed on purpose: one outcome exists per call, the verified variant is
// the common one, and boxing it would add an allocation to that path and a
// `Box` to every caller's pattern.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum VerifyReceiptOutcome {
    /// The receipt's signature and chain verified. This holds for statuses
    /// 21007 and 21008 too: those say the receipt belongs to the other
    /// environment, not that it failed to verify.
    Verified(AppReceipt),
    /// There is no verified receipt.
    Failed {
        /// Why. [`Reason::MalformedRequest`] and [`Reason::RequestTooLarge`]
        /// appear only here, never from a verifier.
        reason: Reason,
        /// What is behind [`Reason::InternalError`]: the panic message, or
        /// the detail of the signed content that could not be read. `None`
        /// for every other reason.
        cause: Option<String>,
    },
}

/// The result of one [`VerifyReceiptEndpoint`] call: the Apple status, the
/// verified receipt or the reason there is none, and the Apple-shaped
/// response, rendered only when asked for.
///
/// The receipt is kept whenever its bytes verified, including when the
/// endpoint's own environment answers 21007 or 21008, so a caller can
/// [re-render](VerifyReceiptResult::to_json_in) for the other environment
/// without verifying twice. Every render recomputes the status from the
/// receipt's own `receipt_type`, so no render answers 0 for a receipt from
/// the wrong environment.
///
/// Immutable. Only the endpoint creates one, so a caller cannot construct a
/// result carrying status 0.
#[derive(Debug, Clone)]
pub struct VerifyReceiptResult {
    environment: Environment,
    outcome: VerifyReceiptOutcome,
    request_date: SystemTime,
}

impl VerifyReceiptResult {
    /// The Apple status for the endpoint's own environment. See [`status`].
    #[must_use]
    pub fn status(&self) -> i64 {
        self.status_in(self.environment)
    }

    /// `true` when the receipt verified, for statuses 0, 21007 and 21008
    /// alike. Not the same as `status() == 0`.
    #[must_use]
    pub fn verified(&self) -> bool {
        matches!(self.outcome, VerifyReceiptOutcome::Verified(_))
    }

    /// The verified receipt or the failure.
    #[must_use]
    pub fn outcome(&self) -> &VerifyReceiptOutcome {
        &self.outcome
    }

    /// The verified receipt, or `None` when verification failed.
    #[must_use]
    pub fn receipt(&self) -> Option<&AppReceipt> {
        match &self.outcome {
            VerifyReceiptOutcome::Verified(receipt) => Some(receipt),
            VerifyReceiptOutcome::Failed { .. } => None,
        }
    }

    /// Why there is no receipt; `Some` exactly when
    /// [`receipt`](Self::receipt) is `None`.
    #[must_use]
    pub fn failure_reason(&self) -> Option<Reason> {
        match &self.outcome {
            VerifyReceiptOutcome::Verified(_) => None,
            VerifyReceiptOutcome::Failed { reason, .. } => Some(*reason),
        }
    }

    /// What is behind [`Reason::InternalError`] (a panic message, or the
    /// detail of signed content that could not be read); `None` for every
    /// other outcome.
    #[must_use]
    pub fn failure_cause(&self) -> Option<&str> {
        match &self.outcome {
            VerifyReceiptOutcome::Verified(_) => None,
            VerifyReceiptOutcome::Failed { cause, .. } => cause.as_deref(),
        }
    }

    /// The instant rendered as `request_date`, fixed when the call was made.
    #[must_use]
    pub fn request_date(&self) -> SystemTime {
        self.request_date
    }

    /// The response the endpoint's own environment answers, rendered on
    /// each call.
    #[must_use]
    pub fn to_response(&self) -> VerifyReceiptResponse {
        self.render(self.environment)
    }

    /// [`to_response`](Self::to_response) as the JSON response body, byte
    /// for byte what [`VerifyReceiptEndpoint::verify_receipt_json`] answers.
    #[must_use]
    pub fn to_json(&self) -> String {
        render_json(&self.to_response())
    }

    /// The response an endpoint of `environment` would answer for the same
    /// receipt, at the same [`request_date`](Self::request_date). A
    /// production receipt answers 0 on Production and 21008 on Sandbox; any
    /// other receipt answers 21007 on Production and 0 on Sandbox; a failed
    /// result answers its own status on both.
    ///
    /// # Errors
    /// [`ConfigError`] for an environment other than
    /// [`Environment::Production`] or [`Environment::Sandbox`], exactly as
    /// [`VerifyReceiptEndpointBuilder::build`] refuses it.
    pub fn to_response_in(
        &self,
        environment: Environment,
    ) -> core::result::Result<VerifyReceiptResponse, ConfigError> {
        Ok(self.render(endpoint_environment(Some(environment))?))
    }

    /// [`to_response_in`](Self::to_response_in) as the JSON response body.
    ///
    /// # Errors
    /// As [`to_response_in`](Self::to_response_in).
    pub fn to_json_in(
        &self,
        environment: Environment,
    ) -> core::result::Result<String, ConfigError> {
        Ok(render_json(&self.to_response_in(environment)?))
    }

    fn render(&self, environment: Environment) -> VerifyReceiptResponse {
        let status = self.status_in(environment);
        match &self.outcome {
            VerifyReceiptOutcome::Verified(receipt) if status == status::OK => {
                VerifyReceiptResponse {
                    status,
                    environment: Some(environment),
                    receipt: Some(receipt_json(receipt, unix_millis(self.request_date))),
                }
            }
            _ => VerifyReceiptResponse::failure(status),
        }
    }

    /// `environment` is Production or Sandbox; both callers check it.
    fn status_in(&self, environment: Environment) -> i64 {
        let receipt = match &self.outcome {
            VerifyReceiptOutcome::Verified(receipt) => receipt,
            VerifyReceiptOutcome::Failed { reason, .. } => {
                return match reason {
                    Reason::MalformedRequest
                    | Reason::RequestTooLarge
                    | Reason::InvalidReceiptFormat => status::MALFORMED,
                    Reason::InternalError => status::INTERNAL,
                    _ => status::NOT_AUTHENTICATED,
                };
            }
        };
        // 21007 / 21008 routing from the receipt_type attribute, failing
        // closed: production is exactly "Production" and "ProductionVPP".
        // Everything else — "ProductionSandbox", "ProductionVPPSandbox",
        // "Xcode", or a missing attribute — is non-production
        // (`PLAN.md` D10). "Xcode" is listed for completeness only: an
        // Xcode-generated receipt is not Apple-signed, so it fails
        // verification and never gets here.
        let production_receipt = matches!(
            receipt.receipt_type.as_deref(),
            Some("Production" | "ProductionVPP")
        );
        if environment == Environment::Production && !production_receipt {
            return status::SANDBOX_RECEIPT_ON_PRODUCTION;
        }
        if environment == Environment::Sandbox && production_receipt {
            return status::PRODUCTION_RECEIPT_ON_SANDBOX;
        }
        status::OK
    }
}

fn render_json(response: &VerifyReceiptResponse) -> String {
    serde_json::to_string(&response.to_json_value())
        .unwrap_or_else(|_| format!("{{\"status\":{}}}", status::MALFORMED))
}

/// Apple's endpoint has exactly two environments.
fn endpoint_environment(
    environment: Option<Environment>,
) -> core::result::Result<Environment, ConfigError> {
    match environment {
        Some(environment @ (Environment::Production | Environment::Sandbox)) => Ok(environment),
        Some(other) => Err(ConfigError::new(format!(
            "environment must be Production or Sandbox, got {other}"
        ))),
        None => Err(ConfigError::new("environment is required")),
    }
}

/// Builds a [`VerifyReceiptEndpoint`].
#[derive(Debug, Default, Clone)]
pub struct VerifyReceiptEndpointBuilder {
    trusted_roots: Vec<TrustAnchor>,
    environment: Option<Environment>,
    clock: Option<Arc<dyn Clock>>,
}

impl VerifyReceiptEndpointBuilder {
    /// The pinned trust anchors. In production, [`apple_receipt_roots`].
    ///
    /// [`apple_receipt_roots`]: crate::apple_receipt_roots
    #[must_use]
    pub fn trusted_roots(mut self, roots: impl IntoIterator<Item = TrustAnchor>) -> Self {
        self.trusted_roots.extend(roots);
        self
    }

    /// Which environment this endpoint instance emulates. Drives the
    /// 21007 / 21008 routing.
    #[must_use]
    pub fn environment(mut self, environment: Environment) -> Self {
        self.environment = Some(environment);
        self
    }

    /// The source of "now" for the `request_date` triple — the only
    /// wall-clock-dependent output this endpoint has. It is read once per
    /// call, and not at all when the call passes its own request date.
    ///
    /// It reaches nothing else: certificate validity is judged at the
    /// receipt's own creation date, or at the system clock when it states
    /// none.
    #[must_use]
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Builds the endpoint.
    ///
    /// # Errors
    /// [`ConfigError`] for empty trust anchors, or an environment other
    /// than [`Environment::Production`] or [`Environment::Sandbox`] —
    /// Apple's endpoint has exactly two.
    pub fn build(self) -> core::result::Result<VerifyReceiptEndpoint, ConfigError> {
        let anchors = normalize_anchors(self.trusted_roots)?;
        let environment = endpoint_environment(self.environment)?;
        Ok(VerifyReceiptEndpoint {
            anchors,
            environment,
            clock: self.clock.unwrap_or_else(default_clock),
        })
    }
}

/// The local `verifyReceipt` endpoint.
///
/// No method returns an error or panics: like Apple's endpoint, every
/// failure is reported through the status of the [`VerifyReceiptResult`] or
/// of the body it answers.
///
/// Each entry point has an `_at` variant taking the instant to render as
/// `request_date`. That instant reaches `request_date` and nothing else:
/// certificate validity never sees it.
#[derive(Debug, Clone)]
pub struct VerifyReceiptEndpoint {
    anchors: Arc<[TrustAnchor]>,
    environment: Environment,
    clock: Arc<dyn Clock>,
}

impl VerifyReceiptEndpoint {
    /// A builder.
    #[must_use]
    pub fn builder() -> VerifyReceiptEndpointBuilder {
        VerifyReceiptEndpointBuilder::default()
    }

    /// Handles one request body. `request_date` is the endpoint's clock,
    /// read once.
    #[must_use]
    pub fn verify_receipt_result(&self, request: &VerifyReceiptRequest) -> VerifyReceiptResult {
        self.contained(None, || self.verify_base64(request.receipt_data.as_deref()))
    }

    /// [`verify_receipt_result`](Self::verify_receipt_result) with
    /// `request_date` set to `request_date` instead of the endpoint's clock.
    #[must_use]
    pub fn verify_receipt_result_at(
        &self,
        request: &VerifyReceiptRequest,
        request_date: SystemTime,
    ) -> VerifyReceiptResult {
        self.contained(Some(request_date), || {
            self.verify_base64(request.receipt_data.as_deref())
        })
    }

    /// Handles one request body in its raw wire form, the JSON text a
    /// framework hands over.
    ///
    /// A body longer than [`MAX_REQUEST_BYTES`] fails with
    /// [`Reason::RequestTooLarge`], status 21002, where Apple answers HTTP
    /// 413. A body that is not a JSON object (unparseable, `null`, an array,
    /// a scalar) fails with [`Reason::MalformedRequest`], status 21002. Apple
    /// has no status code for "that wasn't JSON"; 21002 is the closest, and
    /// it is what a JSON object without usable `receipt-data` gets anyway.
    /// A body nesting deeper than
    /// [`MAX_JSON_NESTING_DEPTH`](crate::MAX_JSON_NESTING_DEPTH) gets the
    /// same answer without being parsed. The size is checked first.
    #[must_use]
    pub fn verify_receipt_result_from_json(&self, body: &str) -> VerifyReceiptResult {
        self.contained(None, || self.verify_body(body))
    }

    /// [`verify_receipt_result_from_json`](Self::verify_receipt_result_from_json)
    /// with `request_date` set to `request_date` instead of the endpoint's
    /// clock.
    #[must_use]
    pub fn verify_receipt_result_from_json_at(
        &self,
        body: &str,
        request_date: SystemTime,
    ) -> VerifyReceiptResult {
        self.contained(Some(request_date), || self.verify_body(body))
    }

    /// Verifies a bare base64 receipt, the value a request body carries as
    /// `receipt-data`, with no envelope around it. An empty string fails
    /// with [`Reason::MalformedRequest`], as a missing `receipt-data` does.
    #[must_use]
    pub fn verify_receipt_data(&self, receipt_data: &str) -> VerifyReceiptResult {
        self.contained(None, || self.verify_base64(Some(receipt_data)))
    }

    /// [`verify_receipt_data`](Self::verify_receipt_data) with
    /// `request_date` set to `request_date` instead of the endpoint's clock.
    #[must_use]
    pub fn verify_receipt_data_at(
        &self,
        receipt_data: &str,
        request_date: SystemTime,
    ) -> VerifyReceiptResult {
        self.contained(Some(request_date), || {
            self.verify_base64(Some(receipt_data))
        })
    }

    /// Handles one request body in its raw wire form: the JSON request in,
    /// the JSON response out, so a framework's body can be piped through
    /// without a DTO in between. The same as
    /// `verify_receipt_result_from_json(body).to_json()`.
    #[must_use]
    pub fn verify_receipt_json(&self, body: &str) -> String {
        self.verify_receipt_result_from_json(body).to_json()
    }

    /// Runs one verification with the "never fails" contract applied.
    ///
    /// A panic anywhere below would break that contract, so it is contained
    /// and reported as [`Reason::InternalError`] (21009), the same
    /// containment Go's `recover` and Java's catch-all give the other ports.
    /// Nothing here is expected to panic: the library target denies
    /// `unwrap`, `expect`, slice indexing and `panic!`. The clock is read
    /// inside the containment, because it is caller code; if it is the part
    /// that panicked, the result's request date is the system clock.
    fn contained(
        &self,
        request_date: Option<SystemTime>,
        verify: impl FnOnce() -> core::result::Result<AppReceipt, Failure>,
    ) -> VerifyReceiptResult {
        let mut at = request_date;
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            at.get_or_insert_with(|| self.clock.now());
            verify()
        }));
        let outcome = match caught {
            Ok(Ok(receipt)) => VerifyReceiptOutcome::Verified(receipt),
            Ok(Err(Failure { reason, cause })) => VerifyReceiptOutcome::Failed { reason, cause },
            Err(payload) => VerifyReceiptOutcome::Failed {
                reason: Reason::InternalError,
                cause: Some(panic_message(payload.as_ref())),
            },
        };
        VerifyReceiptResult {
            environment: self.environment,
            outcome,
            request_date: at.unwrap_or_else(SystemTime::now),
        }
    }

    fn verify_body(&self, body: &str) -> core::result::Result<AppReceipt, Failure> {
        // Both bounds before the parser: it allocates in proportion to the
        // body, and its own recursion limit (128) cannot be lowered. The size
        // first, so a huge malformed body is REQUEST_TOO_LARGE, as Apple's
        // 413 is.
        if body.len() > MAX_REQUEST_BYTES {
            return Err(Reason::RequestTooLarge.into());
        }
        if nesting_exceeds_limit(body.as_bytes()) {
            return Err(Reason::MalformedRequest.into());
        }
        let Ok(Value::Object(parsed)) = serde_json::from_str::<Value>(body) else {
            return Err(Reason::MalformedRequest.into());
        };
        match parsed.get("receipt-data") {
            Some(Value::String(text)) => self.verify_base64(Some(text)),
            _ => Err(Reason::MalformedRequest.into()),
        }
    }

    /// The one verification path every entry point ends in.
    fn verify_base64(
        &self,
        receipt_data: Option<&str>,
    ) -> core::result::Result<AppReceipt, Failure> {
        let Some(receipt_data) = receipt_data.filter(|d| !d.is_empty()) else {
            return Err(Reason::MalformedRequest.into());
        };
        // Capped before decoding, by the same check and with the same reason
        // as ReceiptVerifier::verify_base64.
        let der = decode_receipt_string(receipt_data).map_err(Failure::from)?;
        // The primitive itself, not a ReceiptVerifier built around a
        // wildcard bundle id: like Apple's endpoint, no bundle-id claim is
        // checked here (callers compare receipt.bundle_id).
        verify_receipt_core_unchecked(&der, &self.anchors).map_err(Failure::from)
    }
}

/// Why one endpoint call has no receipt: the reason, and for
/// [`Reason::InternalError`] the underlying failure, which becomes the
/// result's `failure_cause`.
struct Failure {
    reason: Reason,
    cause: Option<String>,
}

impl From<Reason> for Failure {
    fn from(reason: Reason) -> Self {
        Failure {
            reason,
            cause: None,
        }
    }
}

impl From<VerificationError> for Failure {
    /// Only an `INTERNAL_ERROR` keeps its detail: it is the one reason whose
    /// cause an integrator needs to see (what the library could not read).
    fn from(error: VerificationError) -> Self {
        let cause = (error.reason() == Reason::InternalError).then(|| error.detail().to_owned());
        Failure {
            reason: error.reason(),
            cause,
        }
    }
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_owned()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "panic with a non-string payload".to_owned()
    }
}

fn receipt_json(fields: &AppReceipt, request_date_millis: i64) -> Map<String, Value> {
    let mut receipt = Map::new();
    put_str(&mut receipt, "receipt_type", fields.receipt_type.as_deref());
    // Attribute 1 twice: Apple's response reference defines adam_id as
    // "See app_item_id", and both carry the same value.
    put_int(&mut receipt, "adam_id", fields.app_item_id);
    put_int(&mut receipt, "app_item_id", fields.app_item_id);
    put_str(&mut receipt, "bundle_id", fields.bundle_id.as_deref());
    put_str(
        &mut receipt,
        "application_version",
        fields.app_version.as_deref(),
    );
    // The three app-level ids are JSON numbers, unlike the in-app integers
    // Apple renders as strings, and download_id is wider than an IEEE-754
    // double: it crosses the wire with every digit it was decoded with.
    put_int(&mut receipt, "download_id", fields.download_id);
    put_int(
        &mut receipt,
        "version_external_identifier",
        fields.version_external_identifier,
    );
    put_str(
        &mut receipt,
        "original_application_version",
        fields.original_app_version.as_deref(),
    );
    apple_dates(
        &mut receipt,
        "receipt_creation_date",
        millis_of(fields.creation_date),
    );
    apple_dates(&mut receipt, "request_date", Some(request_date_millis));
    apple_dates(
        &mut receipt,
        "original_purchase_date",
        millis_of(fields.original_purchase_date),
    );
    apple_dates(
        &mut receipt,
        "expiration_date",
        millis_of(fields.expiration_date),
    );
    receipt.insert(
        "in_app".to_owned(),
        Value::Array(fields.in_app_purchases.iter().map(in_app_json).collect()),
    );
    receipt
}

fn in_app_json(purchase: &InAppPurchase) -> Value {
    let mut entry = Map::new();
    put_str(
        &mut entry,
        "quantity",
        purchase.quantity.map(|q| q.to_string()).as_deref(),
    );
    put_str(&mut entry, "product_id", purchase.product_id.as_deref());
    put_str(
        &mut entry,
        "transaction_id",
        purchase.transaction_id.as_deref(),
    );
    put_str(
        &mut entry,
        "original_transaction_id",
        purchase.original_transaction_id.as_deref(),
    );
    apple_dates(
        &mut entry,
        "purchase_date",
        millis_of(purchase.purchase_date),
    );
    apple_dates(
        &mut entry,
        "original_purchase_date",
        millis_of(purchase.original_purchase_date),
    );
    apple_dates(&mut entry, "expires_date", millis_of(purchase.expires_date));
    apple_dates(
        &mut entry,
        "cancellation_date",
        millis_of(purchase.cancellation_date),
    );
    put_str(
        &mut entry,
        "web_order_line_item_id",
        purchase
            .web_order_line_item_id
            .map(|id| id.to_string())
            .as_deref(),
    );
    put_str(
        &mut entry,
        "is_trial_period",
        purchase
            .is_trial_period
            .map(|flag| (flag == 1).to_string())
            .as_deref(),
    );
    put_str(
        &mut entry,
        "is_in_intro_offer_period",
        purchase
            .is_in_intro_offer_period
            .map(|flag| (flag == 1).to_string())
            .as_deref(),
    );
    Value::Object(entry)
}

fn millis_of(at: Option<SystemTime>) -> Option<i64> {
    at.map(unix_millis_of)
}

fn put_str(target: &mut Map<String, Value>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        target.insert(key.to_owned(), Value::from(value));
    }
}

/// An attribute Apple renders as a bare JSON number. Absent leaves the key
/// out rather than emitting `null`; a present zero is a value.
fn put_int(target: &mut Map<String, Value>, key: &str, value: Option<i64>) {
    if let Some(value) = value {
        target.insert(key.to_owned(), Value::from(value));
    }
}

/// Apple's three renderings of every date: `x` in GMT, `x_ms` in epoch
/// milliseconds (as a string), and `x_pst` in US Pacific time.
fn apple_dates(target: &mut Map<String, Value>, prefix: &str, millis: Option<i64>) {
    let Some(millis) = millis else { return };
    target.insert(prefix.to_owned(), Value::from(format_etc_gmt(millis)));
    target.insert(format!("{prefix}_ms"), Value::from(millis.to_string()));
    target.insert(format!("{prefix}_pst"), Value::from(format_pacific(millis)));
}
