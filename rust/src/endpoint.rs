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
use crate::json::{string, top_level_members};
use crate::receipt;
use crate::receipt_payload::{InAppPurchase, ReceiptPayload};
use crate::roots::TrustAnchor;
use crate::verifier::Clock;
use serde_json::{Map, Value as JsonValue};

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
    request_json: &[u8],
    anchors: &[TrustAnchor],
    clock: &Clock<'_>,
) -> String {
    let verified = receipt_data(request_json)
        .and_then(|data| receipt::verify(data.as_bytes(), anchors, clock));
    match verified {
        Ok(payload) => {
            let production = payload.environment() == Some(Environment::Production);
            let status = match environment {
                Environment::Production if !production => {
                    AppleStatus::SANDBOX_RECEIPT_ON_PRODUCTION
                }
                Environment::Sandbox if production => AppleStatus::PRODUCTION_RECEIPT_ON_SANDBOX,
                _ => AppleStatus::OK,
            };
            // An in-app purchase Apple signed that does not decode (it went
            // to unknown_attributes[17]) answers 21009, as UNREADABLE_PAYLOAD
            // does, rather than a 0 whose in_app silently lacks it (owner
            // Q71, 2026-10-06).
            if status == AppleStatus::OK && payload.unknown_attributes.contains_key(&17) {
                status_only(AppleStatus::INTERNAL_DATA_ACCESS_ERROR)
            } else if status == AppleStatus::OK {
                match clock.now() {
                    // A clock outside the instants the dates render
                    // (datetime::renders) is broken, like one that panics:
                    // every receipt date the grammar accepts renders, so
                    // only request_date can make this None.
                    Ok(now_millis) => render(environment, &payload, now_millis)
                        .unwrap_or_else(|| status_only(AppleStatus::INTERNAL_DATA_ACCESS_ERROR)),
                    Err(failure) => status_only(self::status(failure.reason())),
                }
            } else {
                status_only(status)
            }
        }
        Err(failure) => status_only(status(failure.reason())),
    }
}

/// The status the endpoint answers for a failure.
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
/// (unparseable, empty, an array, a scalar), and a `receipt-data` that is
/// missing or not a string, are `MALFORMED`.
///
/// The whole object is read, so a body that breaks after `receipt-data` is
/// still refused, and the last `receipt-data` wins, as it would in a map.
/// Anything after the object is not read. `password` and
/// `exclude-old-transactions` are read and ignored.
fn receipt_data(request_json: &[u8]) -> Result<String, Failure> {
    if request_json.len() > MAX_REQUEST_BYTES {
        return Err(Failure::new(
            Reason::TooLarge,
            format!("request body exceeds the maximum of {MAX_REQUEST_BYTES} bytes"),
        ));
    }
    // JSON text is UTF-8 (RFC 8259 section 8.1), so bytes that are not are
    // no JSON at all.
    let request_json = core::str::from_utf8(request_json).map_err(|err| {
        Failure::new(Reason::Malformed, "request body is not valid JSON").with_source(err)
    })?;
    let members = top_level_members(request_json).map_err(|err| {
        Failure::new(Reason::Malformed, "request body is not valid JSON").with_source(err)
    })?;
    string(&members, "receipt-data")
        .ok_or_else(|| Failure::new(Reason::Malformed, "receipt-data is missing or not a string"))
}

/// The status-0 response. Keys and value types follow Apple's endpoint; key
/// order is deterministic but not part of the contract. `in_app_ownership_type`
/// and everything that lives only in Apple's server-side database are never
/// present. `None` when a date does not render.
fn render(
    environment: Environment,
    receipt: &ReceiptPayload,
    request_date_millis: i64,
) -> Option<String> {
    Some(format!(
        "{{\"status\":{},\"environment\":{},\"receipt\":{}}}",
        AppleStatus::OK,
        JsonValue::from(environment.as_str()),
        receipt_json(receipt, request_date_millis)?
    ))
}

fn receipt_json(receipt: &ReceiptPayload, request_date_millis: i64) -> Option<JsonValue> {
    let mut json = Map::new();
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
    )?;
    apple_dates(&mut json, "request_date", Some(request_date_millis))?;
    apple_dates(
        &mut json,
        "original_purchase_date",
        receipt.original_purchase_date_ms,
    )?;
    apple_dates(&mut json, "expiration_date", receipt.expiration_date_ms)?;
    json.insert(
        "in_app".to_owned(),
        receipt
            .in_app
            .iter()
            .map(purchase_json)
            .collect::<Option<_>>()?,
    );
    Some(JsonValue::Object(json))
}

fn purchase_json(purchase: &InAppPurchase) -> Option<JsonValue> {
    let mut json = Map::new();
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
    apple_dates(&mut json, "purchase_date", purchase.purchase_date_ms)?;
    apple_dates(
        &mut json,
        "original_purchase_date",
        purchase.original_purchase_date_ms,
    )?;
    apple_dates(&mut json, "expires_date", purchase.expires_date_ms)?;
    apple_dates(
        &mut json,
        "cancellation_date",
        purchase.cancellation_date_ms,
    )?;
    // Apple omits the key when attribute 1711 is 0, as it is for
    // consumables.
    if let Some(id) = purchase.web_order_line_item_id.filter(|id| *id != 0) {
        present_string(&mut json, "web_order_line_item_id", Some(&id.to_string()));
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
    Some(JsonValue::Object(json))
}

fn present_string(json: &mut Map<String, JsonValue>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        json.insert(key.to_owned(), JsonValue::from(value));
    }
}

fn present_number(json: &mut Map<String, JsonValue>, key: &str, value: Option<i64>) {
    if let Some(value) = value {
        json.insert(key.to_owned(), JsonValue::from(value));
    }
}

/// Apple's three renderings of every date: `x` in GMT, `x_ms` in epoch
/// milliseconds (as a string), and `x_pst` in US Pacific time. `None` when
/// the instant does not render (`datetime::renders`).
fn apple_dates(json: &mut Map<String, JsonValue>, prefix: &str, millis: Option<i64>) -> Option<()> {
    let Some(millis) = millis else {
        return Some(());
    };
    present_string(json, prefix, Some(&format_etc_gmt(millis)?));
    present_string(json, &format!("{prefix}_ms"), Some(&millis.to_string()));
    present_string(
        json,
        &format!("{prefix}_pst"),
        Some(&format_pacific(millis)?),
    );
    Some(())
}
