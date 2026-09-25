//! UniFFI adapter. ALL UniFFI annotations live here; the surface stays generator-free.
uniffi::setup_scaffolding!();
use surface::{AppReceipt, Reason};

#[uniffi::remote(Enum)]
pub enum Reason { InvalidJwsFormat, InvalidCertificate, InvalidCertificatePurpose, InvalidChain,
    InvalidSignature, WrongBundleId, WrongEnvironment, WrongAppAppleId, InvalidReceiptFormat,
    DeviceHashMismatch, MalformedRequest, InternalError, RequestTooLarge }

#[uniffi::remote(Record)]
pub struct AppReceipt { pub bundle_id: Option<String>, pub app_version: Option<String>,
    pub opaque_value: Option<Vec<u8>>, pub creation_date_ms: Option<i64>, pub in_app_purchase_count: i64 }

/// Verification failed (adapter-local error wrapper; the reason comes from the surface).
#[derive(Debug, uniffi::Error)]
pub enum VerifyError { Verification { reason: Reason, detail: String } }
impl std::fmt::Display for VerifyError { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{self:?}") } }
impl std::error::Error for VerifyError {}

/// Verifies a base64 receipt against Apple's pinned roots.
#[uniffi::export]
pub fn verify_base64(bundle_id: String, b64: String) -> Result<AppReceipt, VerifyError> {
    surface::verify_base64(&bundle_id, &b64).map_err(|e| VerifyError::Verification { reason: e.reason, detail: e.detail })
}
