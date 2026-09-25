//! Spike: a thin UniFFI adapter over the canonical core. No verification logic.
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

uniffi::setup_scaffolding!();

/// Why verification failed. Same tokens as every port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Reason {
    InvalidJwsFormat, InvalidCertificate, InvalidCertificatePurpose, InvalidChain,
    InvalidSignature, WrongBundleId, WrongEnvironment, WrongAppAppleId,
    InvalidReceiptFormat, DeviceHashMismatch, MalformedRequest, InternalError, RequestTooLarge,
}

impl Reason {
    fn from_core(r: aprv::Reason) -> Self {
        // Token round-trip keeps the adapter free of a hand-kept mapping table.
        match r.as_str() {
            "INVALID_JWS_FORMAT" => Self::InvalidJwsFormat,
            "INVALID_CERTIFICATE" => Self::InvalidCertificate,
            "INVALID_CERTIFICATE_PURPOSE" => Self::InvalidCertificatePurpose,
            "INVALID_CHAIN" => Self::InvalidChain,
            "INVALID_SIGNATURE" => Self::InvalidSignature,
            "WRONG_BUNDLE_ID" => Self::WrongBundleId,
            "WRONG_ENVIRONMENT" => Self::WrongEnvironment,
            "WRONG_APP_APPLE_ID" => Self::WrongAppAppleId,
            "INVALID_RECEIPT_FORMAT" => Self::InvalidReceiptFormat,
            "DEVICE_HASH_MISMATCH" => Self::DeviceHashMismatch,
            "MALFORMED_REQUEST" => Self::MalformedRequest,
            "REQUEST_TOO_LARGE" => Self::RequestTooLarge,
            _ => Self::InternalError,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum Environment { Production, Sandbox, Xcode, LocalTesting }

impl From<Environment> for aprv::Environment {
    fn from(e: Environment) -> Self {
        match e {
            Environment::Production => Self::Production,
            Environment::Sandbox => Self::Sandbox,
            Environment::Xcode => Self::Xcode,
            Environment::LocalTesting => Self::LocalTesting,
        }
    }
}

/// Verification failed, or the verifier was misconfigured.
#[derive(Debug, uniffi::Error)]
pub enum VerifyError {
    Verification { reason: Reason, detail: String },
    Config { detail: String },
}
impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Verification { reason, detail } => write!(f, "{reason:?}: {detail}"),
            Self::Config { detail } => write!(f, "config: {detail}"),
        }
    }
}
impl std::error::Error for VerifyError {}
impl From<aprv::VerificationError> for VerifyError {
    fn from(e: aprv::VerificationError) -> Self {
        Self::Verification { reason: Reason::from_core(e.reason()), detail: e.detail().to_owned() }
    }
}
impl From<aprv::ConfigError> for VerifyError {
    fn from(e: aprv::ConfigError) -> Self { Self::Config { detail: e.detail().to_owned() } }
}

fn ms(t: Option<SystemTime>) -> Option<i64> {
    t.and_then(|t| t.duration_since(UNIX_EPOCH).ok()).and_then(|d| i64::try_from(d.as_millis()).ok())
}

fn anchors(ders: Option<Vec<Vec<u8>>>, default: &[aprv::TrustAnchor]) -> Result<Vec<aprv::TrustAnchor>, VerifyError> {
    match ders {
        None => Ok(default.to_vec()),
        Some(v) => v.iter().map(|d| aprv::TrustAnchor::from_der(d).map_err(VerifyError::from)).collect(),
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct InAppPurchase {
    pub product_id: Option<String>,
    pub transaction_id: Option<String>,
    pub original_transaction_id: Option<String>,
    pub quantity: Option<i64>,
    pub purchase_date_ms: Option<i64>,
    pub expires_date_ms: Option<i64>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct AppReceipt {
    pub receipt_type: Option<String>,
    pub bundle_id: Option<String>,
    pub app_version: Option<String>,
    pub original_app_version: Option<String>,
    pub opaque_value: Option<Vec<u8>>,
    pub sha1_hash: Option<Vec<u8>>,
    pub creation_date_ms: Option<i64>,
    pub in_app_purchases: Vec<InAppPurchase>,
}

impl From<aprv::AppReceipt> for AppReceipt {
    fn from(r: aprv::AppReceipt) -> Self {
        Self {
            receipt_type: r.receipt_type, bundle_id: r.bundle_id, app_version: r.app_version,
            original_app_version: r.original_app_version, opaque_value: r.opaque_value,
            sha1_hash: r.sha1_hash, creation_date_ms: ms(r.creation_date),
            in_app_purchases: r.in_app_purchases.into_iter().map(|p| InAppPurchase {
                product_id: p.product_id, transaction_id: p.transaction_id,
                original_transaction_id: p.original_transaction_id, quantity: p.quantity,
                purchase_date_ms: ms(p.purchase_date), expires_date_ms: ms(p.expires_date),
            }).collect(),
        }
    }
}

/// Verifies legacy PKCS#7 app receipts against pinned Apple roots.
#[derive(uniffi::Object)]
pub struct ReceiptVerifier { inner: aprv::ReceiptVerifier }

#[uniffi::export]
impl ReceiptVerifier {
    /// `trusted_roots` defaults to Apple's three published roots.
    #[uniffi::constructor(default(trusted_roots = None))]
    pub fn new(bundle_id: String, trusted_roots: Option<Vec<Vec<u8>>>) -> Result<Arc<Self>, VerifyError> {
        let inner = aprv::ReceiptVerifier::builder()
            .bundle_id(bundle_id)
            .trusted_roots(anchors(trusted_roots, aprv::apple_receipt_roots())?)
            .build()?;
        Ok(Arc::new(Self { inner }))
    }

    /// Verifies DER receipt bytes.
    pub fn verify(&self, receipt: Vec<u8>) -> Result<AppReceipt, VerifyError> {
        Ok(self.inner.verify(&receipt)?.into())
    }

    /// Verifies a base64 receipt, as apps upload it.
    pub fn verify_base64(&self, receipt: String) -> Result<AppReceipt, VerifyError> {
        Ok(self.inner.verify_base64(&receipt)?.into())
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct TransactionPayload {
    pub bundle_id: Option<String>,
    pub environment: Option<String>,
    pub product_id: Option<String>,
    pub transaction_id: Option<String>,
    pub signed_date: Option<i64>,
    pub purchase_date: Option<i64>,
    /// Every claim, as JSON text.
    pub claims_json: String,
}

/// Verifies StoreKit 2 JWS against pinned Apple roots.
#[derive(uniffi::Object)]
pub struct JwsVerifier { inner: aprv::JwsVerifier }

#[uniffi::export]
impl JwsVerifier {
    #[uniffi::constructor(default(app_apple_id = None, trusted_roots = None))]
    pub fn new(bundle_id: String, environments: Vec<Environment>, app_apple_id: Option<i64>, trusted_roots: Option<Vec<Vec<u8>>>) -> Result<Arc<Self>, VerifyError> {
        let mut b = aprv::JwsVerifier::builder()
            .bundle_id(bundle_id)
            .accepted_environments(environments.into_iter().map(Into::into))
            .trusted_roots(anchors(trusted_roots, aprv::apple_jws_roots())?);
        if let Some(id) = app_apple_id { b = b.app_apple_id(u64::try_from(id).map_err(|_| VerifyError::Config { detail: "appAppleId must be positive".into() })?); }
        Ok(Arc::new(Self { inner: b.build()? }))
    }

    pub fn verify_transaction(&self, jws: String) -> Result<TransactionPayload, VerifyError> {
        let p = self.inner.verify_transaction(&jws)?;
        Ok(TransactionPayload {
            claims_json: aprv::serde_json::to_string(&p.claims).unwrap_or_default(),
            bundle_id: p.bundle_id, environment: p.environment, product_id: p.product_id,
            transaction_id: p.transaction_id, signed_date: p.signed_date, purchase_date: p.purchase_date,
        })
    }
}

/// A drop-in for Apple's deprecated `verifyReceipt` endpoint, answered
/// locally. Takes the same JSON request body (`receipt-data`, `password`,
/// `exclude-old-transactions`) and returns the same JSON response shape
/// (`status`, `environment`, `receipt`), so an existing client keeps working.
///
/// The environment this instance emulates drives Apple's routing statuses:
/// a sandbox receipt sent to a production endpoint answers 21007, and a
/// production receipt sent to a sandbox endpoint answers 21008.
///
/// It never throws on a bad request: every failure is a status code.
#[derive(uniffi::Object)]
pub struct VerifyReceiptEndpoint { inner: aprv::VerifyReceiptEndpoint }

/// The outcome of one request: the Apple status plus the verified receipt
/// or the reason it failed. Render it with `toJson`, or re-render it for the
/// other environment with `toJsonIn` without verifying twice.
#[derive(uniffi::Object)]
pub struct VerifyReceiptResult { inner: aprv::VerifyReceiptResult }

#[uniffi::export]
impl VerifyReceiptEndpoint {
    /// Creates an endpoint emulating `environment` (Production or Sandbox).
    /// Pass no trusted roots to use Apple's three pinned root certificates.
    #[uniffi::constructor(default(trusted_roots = None))]
    pub fn new(environment: Environment, trusted_roots: Option<Vec<Vec<u8>>>) -> Result<Arc<Self>, VerifyError> {
        let inner = aprv::VerifyReceiptEndpoint::builder()
            .environment(environment.into())
            .trusted_roots(anchors(trusted_roots, aprv::apple_receipt_roots())?)
            .build()?;
        Ok(Arc::new(Self { inner }))
    }

    /// Raw JSON request body in, raw JSON response body out. Never throws.
    pub fn verify_receipt_json(&self, request_body: String) -> String {
        self.inner.verify_receipt_json(&request_body)
    }

    /// Verifies one JSON request body and returns the result object.
    pub fn verify_receipt_result(&self, request_body: String) -> Arc<VerifyReceiptResult> {
        Arc::new(VerifyReceiptResult { inner: self.inner.verify_receipt_result_from_json(&request_body) })
    }

    /// As `verifyReceiptResult`, with the response's `request_date` fixed to
    /// the given epoch milliseconds. It changes that timestamp and nothing
    /// else: certificate validity never uses it.
    pub fn verify_receipt_result_at(&self, request_body: String, request_date_millis: i64) -> Arc<VerifyReceiptResult> {
        let at = UNIX_EPOCH + std::time::Duration::from_millis(u64::try_from(request_date_millis).unwrap_or(0));
        Arc::new(VerifyReceiptResult { inner: self.inner.verify_receipt_result_from_json_at(&request_body, at) })
    }
}

#[uniffi::export]
impl VerifyReceiptResult {
    /// Apple's status: 0, 21002, 21003, 21007, 21008 or 21009.
    pub fn status(&self) -> i64 { self.inner.status() }
    /// True when the receipt verified, whichever environment it belongs to.
    pub fn verified(&self) -> bool { self.inner.verified() }
    /// The verified receipt, or nothing when verification failed.
    pub fn receipt(&self) -> Option<AppReceipt> { self.inner.receipt().cloned().map(Into::into) }
    /// Why verification failed, or nothing when it succeeded.
    pub fn failure_reason(&self) -> Option<Reason> { self.inner.failure_reason().map(Reason::from_core) }
    /// The response body Apple would send.
    pub fn to_json(&self) -> String { self.inner.to_json() }
    /// The response body as the other environment's endpoint would send it.
    pub fn to_json_in(&self, environment: Environment) -> Result<String, VerifyError> {
        Ok(self.inner.to_json_in(environment.into())?)
    }
}

#[uniffi::export]
impl JwsVerifier {
    /// Verifies a JWS and returns every claim: name to JSON-encoded value.
    pub fn verify_raw_map(&self, jws: String) -> Result<std::collections::HashMap<String, String>, VerifyError> {
        let claims = self.inner.verify_raw(&jws)?;
        Ok(claims.into_iter().map(|(k, v)| (k, v.to_string())).collect())
    }
}
