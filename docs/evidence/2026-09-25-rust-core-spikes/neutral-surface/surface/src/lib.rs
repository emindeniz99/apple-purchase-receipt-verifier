//! Binding-neutral surface: boring types, checked conversions, no generator.
#![forbid(unsafe_code)]
use std::time::{SystemTime, UNIX_EPOCH};

/// Why verification failed. One vocabulary for every language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason { InvalidJwsFormat, InvalidCertificate, InvalidCertificatePurpose, InvalidChain,
    InvalidSignature, WrongBundleId, WrongEnvironment, WrongAppAppleId, InvalidReceiptFormat,
    DeviceHashMismatch, MalformedRequest, InternalError, RequestTooLarge }

impl Reason {
    /// Every core reason maps to exactly one surface reason (tested exhaustively).
    pub fn from_core(r: aprv::Reason) -> Self {
        match r.as_str() {
            "INVALID_JWS_FORMAT" => Self::InvalidJwsFormat, "INVALID_CERTIFICATE" => Self::InvalidCertificate,
            "INVALID_CERTIFICATE_PURPOSE" => Self::InvalidCertificatePurpose, "INVALID_CHAIN" => Self::InvalidChain,
            "INVALID_SIGNATURE" => Self::InvalidSignature, "WRONG_BUNDLE_ID" => Self::WrongBundleId,
            "WRONG_ENVIRONMENT" => Self::WrongEnvironment, "WRONG_APP_APPLE_ID" => Self::WrongAppAppleId,
            "INVALID_RECEIPT_FORMAT" => Self::InvalidReceiptFormat, "DEVICE_HASH_MISMATCH" => Self::DeviceHashMismatch,
            "MALFORMED_REQUEST" => Self::MalformedRequest, "REQUEST_TOO_LARGE" => Self::RequestTooLarge,
            _ => Self::InternalError,
        }
    }
}

/// A verified receipt, portable form. Dates are epoch milliseconds.
#[derive(Debug, Clone)]
pub struct AppReceipt { pub bundle_id: Option<String>, pub app_version: Option<String>,
    pub opaque_value: Option<Vec<u8>>, pub creation_date_ms: Option<i64>, pub in_app_purchase_count: i64 }

/// Verification failed.
#[derive(Debug)]
pub struct VerificationError { pub reason: Reason, pub detail: String }

fn ms(t: Option<SystemTime>) -> Result<Option<i64>, String> {
    match t {
        None => Ok(None),
        Some(t) => {
            let d = t.duration_since(UNIX_EPOCH).map_err(|_| "date before 1970".to_owned())?;
            i64::try_from(d.as_millis()).map(Some).map_err(|_| "date overflows i64 ms".to_owned())
        }
    }
}

impl TryFrom<aprv::AppReceipt> for AppReceipt {
    type Error = String;
    fn try_from(r: aprv::AppReceipt) -> Result<Self, String> {
        Ok(Self { bundle_id: r.bundle_id, app_version: r.app_version, opaque_value: r.opaque_value,
            creation_date_ms: ms(r.creation_date)?,
            in_app_purchase_count: i64::try_from(r.in_app_purchases.len()).map_err(|_| "count")?.into() })
    }
}

/// The one operation (sketch): verify base64 against Apple's roots.
pub fn verify_base64(bundle_id: &str, b64: &str) -> Result<AppReceipt, VerificationError> {
    let v = aprv::ReceiptVerifier::builder().bundle_id(bundle_id)
        .trusted_roots(aprv::apple_receipt_roots().to_vec()).build()
        .map_err(|e| VerificationError { reason: Reason::InternalError, detail: e.detail().to_owned() })?;
    let r = v.verify_base64(b64).map_err(|e| VerificationError { reason: Reason::from_core(e.reason()), detail: e.detail().to_owned() })?;
    AppReceipt::try_from(r).map_err(|d| VerificationError { reason: Reason::InternalError, detail: d })
}
