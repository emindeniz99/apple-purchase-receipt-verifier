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

use crate::base64::decode_lenient;
use crate::clock::{default_clock, unix_millis, Clock};
use crate::datetime::{format_etc_gmt, format_pacific, unix_millis_of};
use crate::environment::Environment;
use crate::error::{ConfigError, Reason};
use crate::receipt::{verify_receipt_core_unchecked, AppReceipt, InAppPurchase};
use crate::roots::{normalize_anchors, TrustAnchor};
use serde_json::{Map, Value};
use std::sync::Arc;
use std::time::SystemTime;

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
    /// An internal error.
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

/// One `verifyReceipt` response body.
///
/// <https://developer.apple.com/documentation/appstorereceipts/responsebody>
#[derive(Debug, Clone, PartialEq)]
pub struct VerifyReceiptResponse {
    /// The Apple status code. See [`status`].
    pub status: i64,
    /// The environment this endpoint emulates, on success only.
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
    /// wall-clock-dependent output this endpoint has.
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
        let environment = match self.environment {
            Some(environment @ (Environment::Production | Environment::Sandbox)) => environment,
            Some(other) => {
                return Err(ConfigError::new(format!(
                    "environment must be Production or Sandbox, got {other}"
                )))
            }
            None => return Err(ConfigError::new("environment is required")),
        };
        Ok(VerifyReceiptEndpoint {
            anchors,
            environment,
            clock: self.clock.unwrap_or_else(default_clock),
        })
    }
}

/// The local `verifyReceipt` endpoint.
///
/// It never returns an error: like Apple's endpoint, every failure is
/// reported through the `status` field of the body it answers.
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

    /// Handles one request body.
    ///
    /// Never fails: the Apple status code is a field of the returned body.
    #[must_use]
    pub fn verify_receipt(&self, request: &VerifyReceiptRequest) -> VerifyReceiptResponse {
        // The documented contract is "never throws". A panic anywhere below
        // would break that, so it is contained and reported as 21009 —
        // the same containment Go's `recover` and Java's catch-all give the
        // other ports. Nothing here is expected to panic: the library target
        // denies `unwrap`, `expect`, slice indexing and `panic!`.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.verify_receipt_inner(request)
        }));
        outcome.unwrap_or_else(|_| VerifyReceiptResponse::failure(status::INTERNAL))
    }

    fn verify_receipt_inner(&self, request: &VerifyReceiptRequest) -> VerifyReceiptResponse {
        let Some(receipt_data) = request.receipt_data.as_deref().filter(|d| !d.is_empty()) else {
            return VerifyReceiptResponse::failure(status::MALFORMED);
        };
        let der = decode_lenient(receipt_data);
        let fields = match verify_receipt_core_unchecked(&der, &self.anchors) {
            Ok(fields) => fields,
            Err(error) => {
                let code = if error.reason() == Reason::InvalidReceiptFormat {
                    status::MALFORMED
                } else {
                    status::NOT_AUTHENTICATED
                };
                return VerifyReceiptResponse::failure(code);
            }
        };

        // 21007 / 21008 routing from the receipt_type attribute, failing
        // closed: production is exactly "Production" and "ProductionVPP".
        // Everything else — "ProductionSandbox", "ProductionVPPSandbox",
        // "Xcode", or a missing attribute — is non-production
        // (`PLAN.md` D10). "Xcode" is listed for completeness only: an
        // Xcode-generated receipt is not Apple-signed, so it fails
        // verification above and never reaches this branch.
        let production_receipt = matches!(
            fields.receipt_type.as_deref(),
            Some("Production" | "ProductionVPP")
        );
        if self.environment == Environment::Production && !production_receipt {
            return VerifyReceiptResponse::failure(status::SANDBOX_RECEIPT_ON_PRODUCTION);
        }
        if self.environment == Environment::Sandbox && production_receipt {
            return VerifyReceiptResponse::failure(status::PRODUCTION_RECEIPT_ON_SANDBOX);
        }
        VerifyReceiptResponse {
            status: status::OK,
            environment: Some(self.environment),
            receipt: Some(receipt_json(&fields, unix_millis(self.clock.now()))),
        }
    }

    /// Handles one request body in its raw wire form: the JSON request in,
    /// the JSON response out, so a framework's body can be piped through
    /// without a DTO in between.
    ///
    /// A body that is not a JSON object — unparseable, `null`, an array, a
    /// scalar — answers `{"status":21002}`. Apple has no status code for
    /// "that wasn't JSON"; 21002 is the closest, and it is what a JSON
    /// object without usable `receipt-data` gets anyway.
    #[must_use]
    pub fn verify_receipt_json(&self, body: &str) -> String {
        let malformed = format!("{{\"status\":{}}}", status::MALFORMED);
        let Ok(Value::Object(parsed)) = serde_json::from_str::<Value>(body) else {
            return malformed;
        };
        let receipt_data = match parsed.get("receipt-data") {
            Some(Value::String(text)) => text.clone(),
            _ => return malformed,
        };
        let request = VerifyReceiptRequest {
            receipt_data: Some(receipt_data),
            password: parsed
                .get("password")
                .and_then(Value::as_str)
                .map(str::to_owned),
            exclude_old_transactions: parsed
                .get("exclude-old-transactions")
                .and_then(Value::as_bool),
        };
        let response = self.verify_receipt(&request);
        serde_json::to_string(&response.to_json_value()).unwrap_or(malformed)
    }
}

fn receipt_json(fields: &AppReceipt, request_date_millis: i64) -> Map<String, Value> {
    let mut receipt = Map::new();
    put_str(&mut receipt, "receipt_type", fields.receipt_type.as_deref());
    put_str(&mut receipt, "bundle_id", fields.bundle_id.as_deref());
    put_str(
        &mut receipt,
        "application_version",
        fields.app_version.as_deref(),
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

/// Apple's three renderings of every date: `x` in GMT, `x_ms` in epoch
/// milliseconds (as a string), and `x_pst` in US Pacific time.
fn apple_dates(target: &mut Map<String, Value>, prefix: &str, millis: Option<i64>) {
    let Some(millis) = millis else { return };
    target.insert(prefix.to_owned(), Value::from(format_etc_gmt(millis)));
    target.insert(format!("{prefix}_ms"), Value::from(millis.to_string()));
    target.insert(format!("{prefix}_pst"), Value::from(format_pacific(millis)));
}
