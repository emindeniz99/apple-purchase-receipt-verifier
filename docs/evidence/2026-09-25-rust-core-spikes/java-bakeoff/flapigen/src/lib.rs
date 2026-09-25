//! Bake-off: flapigen JNI adapter over the canonical core. Conversion only;
//! the core decides everything.
#![allow(non_snake_case, clippy::all)]

use std::time::{SystemTime, UNIX_EPOCH};

#[allow(non_upper_case_globals, non_camel_case_types, dead_code, improper_ctypes)]
mod jni_c_header {
    include!(concat!(env!("OUT_DIR"), "/jni_c_header.rs"));
}

mod java_glue {
    include!(concat!(env!("OUT_DIR"), "/java_glue.rs"));
}

/// Mirror of the core's `#[non_exhaustive]` Reason (flapigen's
/// `foreign_enum!` needs an exhaustive match, so the core enum can't be used).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    InvalidJwsFormat, InvalidCertificate, InvalidCertificatePurpose, InvalidChain,
    InvalidSignature, WrongBundleId, WrongEnvironment, WrongAppAppleId,
    InvalidReceiptFormat, DeviceHashMismatch, MalformedRequest, InternalError, RequestTooLarge,
}

impl Reason {
    pub fn from_core(r: aprv::Reason) -> Self {
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

/// Error crossing the boundary; the interface file's typemap turns it into
/// VerificationException / ConfigurationException.
pub enum VerifyError {
    Verification(Reason, String),
    Config(String),
}

impl From<aprv::VerificationError> for VerifyError {
    fn from(e: aprv::VerificationError) -> Self {
        Self::Verification(Reason::from_core(e.reason()), e.detail().to_owned())
    }
}
impl From<aprv::ConfigError> for VerifyError {
    fn from(e: aprv::ConfigError) -> Self {
        Self::Config(e.detail().to_owned())
    }
}

pub fn ms(t: Option<SystemTime>) -> Option<i64> {
    t.and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_millis()).ok())
}

pub fn bytes_out(v: &Option<Vec<u8>>) -> Option<Vec<i8>> {
    v.as_ref().map(|v| v.iter().map(|&b| b as i8).collect())
}

pub fn bytes_in(v: &[i8]) -> Vec<u8> {
    v.iter().map(|&b| b as u8).collect()
}

/// Splits the `[u32 BE length][bytes]...` packing the Java side of the
/// `List<byte[]>` typemap produces.
pub fn unpack_roots(packed: &[i8]) -> Vec<Vec<u8>> {
    let packed = bytes_in(packed);
    let mut out = Vec::new();
    let mut rest = packed.as_slice();
    while let Some((len, tail)) = rest.split_first_chunk::<4>() {
        let n = (u32::from_be_bytes(*len) as usize).min(tail.len());
        out.push(tail[..n].to_vec());
        rest = &tail[n..];
    }
    out
}

pub fn anchors(ders: Option<Vec<Vec<u8>>>, default: &[aprv::TrustAnchor]) -> Result<Vec<aprv::TrustAnchor>, VerifyError> {
    match ders {
        None => Ok(default.to_vec()),
        Some(v) => v.iter().map(|d| aprv::TrustAnchor::from_der(d).map_err(VerifyError::from)).collect(),
    }
}

pub fn receipt_verifier(bundle_id: &str, roots: Option<Vec<Vec<u8>>>) -> Result<aprv::ReceiptVerifier, VerifyError> {
    Ok(aprv::ReceiptVerifier::builder()
        .bundle_id(bundle_id)
        .trusted_roots(anchors(roots, aprv::apple_receipt_roots())?)
        .build()?)
}

pub fn jws_verifier(
    bundle_id: &str,
    envs: Vec<aprv::Environment>,
    app_apple_id: Option<i64>,
    roots: Option<Vec<Vec<u8>>>,
) -> Result<aprv::JwsVerifier, VerifyError> {
    let mut b = aprv::JwsVerifier::builder()
        .bundle_id(bundle_id)
        .accepted_environments(envs)
        .trusted_roots(anchors(roots, aprv::apple_jws_roots())?);
    if let Some(id) = app_apple_id {
        let id = u64::try_from(id).map_err(|_| VerifyError::Config("appAppleId must be positive".into()))?;
        b = b.app_apple_id(id);
    }
    Ok(b.build()?)
}

pub fn endpoint(env: aprv::Environment) -> Result<aprv::VerifyReceiptEndpoint, VerifyError> {
    Ok(aprv::VerifyReceiptEndpoint::builder()
        .environment(env)
        .trusted_roots(aprv::apple_receipt_roots().to_vec())
        .build()?)
}
