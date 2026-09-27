//! [`Verifier::verify_receipt_endpoint`](crate::Verifier::verify_receipt_endpoint):
//! a local stand-in for Apple's deprecated `verifyReceipt` endpoint. Same
//! request body, same response body, same status codes, but verified offline
//! against the pinned roots instead of by calling Apple.
//!
//! Fields that exist only in Apple's server-side database, such as
//! `latest_receipt_info` and `pending_renewal_info`, are not produced. Like
//! Apple's endpoint, it checks no bundle id: the caller compares
//! `receipt.bundle_id`.

use crate::datetime::{format_etc_gmt, format_pacific};
use crate::environment::Environment;
use crate::error::{Failure, Reason};
use crate::json::{top_level_members, Value};
use crate::receipt;
use crate::receipt_payload::{InAppPurchase, Object, ReceiptPayload};
use crate::roots::TrustAnchor;
use crate::verifier::Clock;

/// The status codes Apple documents for `verifyReceipt`, so callers do not
/// write `21007` by hand.
///
/// This endpoint returns [`OK`](AppleStatus::OK),
/// [`MALFORMED_RECEIPT_DATA`](AppleStatus::MALFORMED_RECEIPT_DATA),
/// [`RECEIPT_NOT_AUTHENTICATED`](AppleStatus::RECEIPT_NOT_AUTHENTICATED),
/// [`SANDBOX_RECEIPT_ON_PRODUCTION`](AppleStatus::SANDBOX_RECEIPT_ON_PRODUCTION),
/// [`PRODUCTION_RECEIPT_ON_SANDBOX`](AppleStatus::PRODUCTION_RECEIPT_ON_SANDBOX)
/// and [`INTERNAL_DATA_ACCESS_ERROR`](AppleStatus::INTERNAL_DATA_ACCESS_ERROR),
/// and never the others. 21009 is deterministic for the same input: alert on
/// it, do not retry.
#[derive(Debug)]
pub enum AppleStatus {}

impl AppleStatus {
    /// 0: the receipt is valid.
    pub const OK: i32 = 0;
    /// 21000: the request was not an HTTP POST.
    pub const REQUEST_NOT_POST: i32 = 21000;
    /// 21001: no longer sent by Apple.
    pub const NO_LONGER_SENT: i32 = 21001;
    /// 21002: the `receipt-data` was malformed or missing.
    pub const MALFORMED_RECEIPT_DATA: i32 = 21002;
    /// 21003: the receipt could not be authenticated.
    pub const RECEIPT_NOT_AUTHENTICATED: i32 = 21003;
    /// 21004: the shared secret does not match.
    pub const SHARED_SECRET_MISMATCH: i32 = 21004;
    /// 21005: Apple's receipt server was unavailable.
    pub const SERVER_UNAVAILABLE: i32 = 21005;
    /// 21006: the receipt is valid but the subscription has expired.
    pub const SUBSCRIPTION_EXPIRED: i32 = 21006;
    /// 21007: a sandbox receipt was sent to the production endpoint.
    pub const SANDBOX_RECEIPT_ON_PRODUCTION: i32 = 21007;
    /// 21008: a production receipt was sent to the sandbox endpoint.
    pub const PRODUCTION_RECEIPT_ON_SANDBOX: i32 = 21008;
    /// 21009: internal data access error.
    pub const INTERNAL_DATA_ACCESS_ERROR: i32 = 21009;
    /// 21010: the user account cannot be found or has been deleted.
    pub const ACCOUNT_NOT_FOUND: i32 = 21010;
    /// 21100: first of Apple's internal data access error range.
    pub const INTERNAL_DATA_ACCESS_ERROR_RANGE_FIRST: i32 = 21100;
    /// 21199: last of Apple's internal data access error range.
    pub const INTERNAL_DATA_ACCESS_ERROR_RANGE_LAST: i32 = 21199;
}

/// The request body cap, in UTF-8 bytes: 3 MiB, Apple's own limit. Both of
/// Apple's endpoints answer a 3,145,728-byte body and send HTTP 413 for
/// 3,145,729; this answers 21002 instead, decided before any parsing.
pub(crate) const MAX_REQUEST_BYTES: usize = 3_145_728;

/// Apple's response body for one request.
pub(crate) fn respond(
    environment: Environment,
    request_json: &str,
    anchors: &[TrustAnchor],
    clock: &Clock<'_>,
) -> String {
    let verified =
        receipt_data(request_json).and_then(|data| receipt::verify(&data, anchors, clock));
    match verified {
        Ok(payload) => {
            let production = Environment::from_receipt_type(payload.receipt_type.as_deref())
                == Some(Environment::Production);
            let status = match environment {
                Environment::Production if !production => {
                    AppleStatus::SANDBOX_RECEIPT_ON_PRODUCTION
                }
                Environment::Sandbox if production => AppleStatus::PRODUCTION_RECEIPT_ON_SANDBOX,
                _ => AppleStatus::OK,
            };
            if status == AppleStatus::OK {
                match clock.now() {
                    Ok(now_millis) => render(environment, &payload, now_millis),
                    Err(failure) => status_only(self::status(failure.reason())),
                }
            } else {
                status_only(status)
            }
        }
        Err(failure) => status_only(status(failure.reason())),
    }
}

/// The status the endpoint answers for a failure, the same table in every
/// port.
pub(crate) const fn status(reason: Reason) -> i32 {
    match reason {
        Reason::Malformed | Reason::TooLarge => AppleStatus::MALFORMED_RECEIPT_DATA,
        Reason::InvalidSignature
        | Reason::UntrustedChain
        | Reason::InvalidCertificate
        | Reason::InvalidCertificatePurpose => AppleStatus::RECEIPT_NOT_AUTHENTICATED,
        Reason::UnreadablePayload | Reason::InternalError => {
            AppleStatus::INTERNAL_DATA_ACCESS_ERROR
        }
    }
}

/// A response carrying only `status`.
pub(crate) fn status_only(status: i32) -> String {
    format!("{{\"status\":{status}}}")
}

/// The `receipt-data` string of a request body. A body over
/// [`MAX_REQUEST_BYTES`] is `TOO_LARGE`; a body that is not a JSON object
/// (unparseable, empty, an array, a scalar) or nests deeper than 64, and a
/// `receipt-data` that is missing or not a string, are `MALFORMED`.
///
/// The whole object is read, so a body that breaks after `receipt-data` is
/// still refused, and the last `receipt-data` wins, as it would in a map.
/// Anything after the object is not read. `password` and
/// `exclude-old-transactions` are read and ignored.
fn receipt_data(request_json: &str) -> Result<String, Failure> {
    if request_json.len() > MAX_REQUEST_BYTES {
        return Err(Failure::new(
            Reason::TooLarge,
            format!("request body exceeds the maximum of {MAX_REQUEST_BYTES} bytes"),
        ));
    }
    let members = top_level_members(request_json).map_err(|err| {
        Failure::new(Reason::Malformed, "request body is not valid JSON").with_source(err)
    })?;
    let mut receipt_data = None;
    for (name, value) in members {
        if name == "receipt-data" {
            receipt_data = match value {
                Value::String(text) => Some(text),
                _ => None,
            };
        }
    }
    receipt_data
        .ok_or_else(|| Failure::new(Reason::Malformed, "receipt-data is missing or not a string"))
}

/// The status-0 response. Keys and value types follow Apple's endpoint; key
/// order is deterministic but not part of the contract. `in_app_ownership_type`
/// and everything that lives only in Apple's server-side database are never
/// present.
fn render(environment: Environment, receipt: &ReceiptPayload, request_date_millis: i64) -> String {
    let mut out = String::with_capacity(1024 + 1024 * receipt.in_app.len());
    let mut response = Object::open(&mut out);
    response.number("status", Some(i64::from(AppleStatus::OK)));
    response.string("environment", Some(environment.as_str()));
    response.key("receipt");
    write_receipt(response.out(), receipt, request_date_millis);
    response.close();
    out
}

fn write_receipt(out: &mut String, receipt: &ReceiptPayload, request_date_millis: i64) {
    let mut json = Object::open(out);
    present_string(&mut json, "receipt_type", receipt.receipt_type.as_deref());
    // Apple echoes attribute 1 under both names (its response reference
    // defines adam_id as "See app_item_id") and as JSON numbers, not as the
    // strings the in-app integers are rendered with.
    present_number(&mut json, "adam_id", receipt.app_item_id);
    present_number(&mut json, "app_item_id", receipt.app_item_id);
    present_string(&mut json, "bundle_id", receipt.bundle_id.as_deref());
    present_string(
        &mut json,
        "application_version",
        receipt.application_version.as_deref(),
    );
    present_number(&mut json, "download_id", receipt.download_id);
    present_number(
        &mut json,
        "version_external_identifier",
        receipt.version_external_identifier,
    );
    present_string(
        &mut json,
        "original_application_version",
        receipt.original_application_version.as_deref(),
    );
    apple_dates(
        &mut json,
        "receipt_creation_date",
        receipt.receipt_creation_date_ms,
    );
    apple_dates(&mut json, "request_date", Some(request_date_millis));
    apple_dates(
        &mut json,
        "original_purchase_date",
        receipt.original_purchase_date_ms,
    );
    apple_dates(&mut json, "expiration_date", receipt.expiration_date_ms);
    json.key("in_app");
    json.out().push('[');
    for (index, purchase) in receipt.in_app.iter().enumerate() {
        if index > 0 {
            json.out().push(',');
        }
        write_purchase(json.out(), purchase);
    }
    json.out().push(']');
    json.close();
}

fn write_purchase(out: &mut String, purchase: &InAppPurchase) {
    let mut json = Object::open(out);
    present_string(
        &mut json,
        "quantity",
        purchase.quantity.map(|q| q.to_string()).as_deref(),
    );
    present_string(&mut json, "product_id", purchase.product_id.as_deref());
    present_string(
        &mut json,
        "transaction_id",
        purchase.transaction_id.as_deref(),
    );
    present_string(
        &mut json,
        "original_transaction_id",
        purchase.original_transaction_id.as_deref(),
    );
    apple_dates(&mut json, "purchase_date", purchase.purchase_date_ms);
    apple_dates(
        &mut json,
        "original_purchase_date",
        purchase.original_purchase_date_ms,
    );
    apple_dates(&mut json, "expires_date", purchase.expires_date_ms);
    apple_dates(
        &mut json,
        "cancellation_date",
        purchase.cancellation_date_ms,
    );
    // Apple omits the key when attribute 1711 is 0, as it is for
    // consumables.
    if let Some(id) = purchase.web_order_line_item_id.filter(|id| *id != 0) {
        json.string("web_order_line_item_id", Some(&id.to_string()));
    }
    present_string(
        &mut json,
        "is_trial_period",
        purchase
            .is_trial_period
            .map(|flag| flag.to_string())
            .as_deref(),
    );
    present_string(
        &mut json,
        "is_in_intro_offer_period",
        purchase
            .is_in_intro_offer_period
            .map(|flag| flag.to_string())
            .as_deref(),
    );
    json.close();
}

fn present_string(json: &mut Object<'_>, key: &str, value: Option<&str>) {
    if value.is_some() {
        json.string(key, value);
    }
}

fn present_number(json: &mut Object<'_>, key: &str, value: Option<i64>) {
    if value.is_some() {
        json.number(key, value);
    }
}

/// Apple's three renderings of every date: `x` in GMT, `x_ms` in epoch
/// milliseconds (as a string), and `x_pst` in US Pacific time.
fn apple_dates(json: &mut Object<'_>, prefix: &str, millis: Option<i64>) {
    let Some(millis) = millis else { return };
    json.string(prefix, Some(&format_etc_gmt(millis)));
    json.string(&format!("{prefix}_ms"), Some(&millis.to_string()));
    json.string(&format!("{prefix}_pst"), Some(&format_pacific(millis)));
}
