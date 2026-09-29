//! Spike only. The WIT exports of `wit/aprv.wit`, implemented by calling
//! the unchanged C ABI (rust/ffi) in-process, so the component answers
//! byte-for-byte what every other build of this bake-off answers. No
//! verification logic lives here: each method converts its arguments,
//! calls one `aprv_*` function and converts the result.
//!
//! A production component would sit on `aprv-surface` (SURFACE.md) and
//! need none of the `unsafe` below; this glue exists only to reuse the
//! exact C ABI the corpora were compared through.
#![allow(clippy::missing_safety_doc)]

#[cfg(feature = "world-minimal")]
wit_bindgen::generate!({ path: "wit", world: "aprv-minimal" });
#[cfg(not(feature = "world-minimal"))]
wit_bindgen::generate!({ path: "wit", world: "aprv-wasi" });

use apple_purchase_receipt_verifier_ffi as ffi;
use crate::aprv::verifier::types::{Environment, Error, Reason, VerificationError};
use exports::aprv::verifier::verifier::{
    Endpoint, Guest, GuestEndpoint, GuestJwsVerifier, GuestReceiptVerifier, JwsVerifier,
    ReceiptVerifier,
};
use std::ffi::{c_char, CStr, CString};

struct Component;
export!(Component);

impl Guest for Component {
    type ReceiptVerifier = Rv;
    type JwsVerifier = Jv;
    type Endpoint = Ep;
}

// The minimal world's clock: installed once, before the first object.
fn init() {
    #[cfg(all(feature = "world-minimal", feature = "clock-seam"))]
    {
        use std::time::{Duration, SystemTime, UNIX_EPOCH};
        fn now() -> SystemTime {
            let ms = clock_now_ms();
            if ms.is_finite() && ms >= 0.0 {
                UNIX_EPOCH + Duration::from_millis(ms as u64)
            } else {
                UNIX_EPOCH // fails closed: no Apple chain is valid in 1970
            }
        }
        let _ = ::aprv::platform::install_clock(now);
    }
}

fn reason_of(code: i32) -> Option<Reason> {
    Some(match code {
        1 => Reason::InvalidJwsFormat,
        2 => Reason::InvalidCertificate,
        3 => Reason::InvalidCertificatePurpose,
        4 => Reason::InvalidChain,
        5 => Reason::InvalidSignature,
        6 => Reason::WrongBundleId,
        7 => Reason::WrongEnvironment,
        8 => Reason::WrongAppAppleId,
        9 => Reason::InvalidReceiptFormat,
        10 => Reason::DeviceHashMismatch,
        12 => Reason::InternalError,
        _ => return None,
    })
}

fn config(detail: &str) -> Error {
    Error::Configuration(detail.to_string())
}

fn cstring(s: String) -> Result<CString, Error> {
    CString::new(s).map_err(|_| config("NUL byte in a string argument"))
}

/// Takes the C ABI's result: frees its string and maps the status.
unsafe fn take(status: i32, json: *mut c_char) -> Result<String, Error> {
    let text = if json.is_null() {
        None
    } else {
        let s = CStr::from_ptr(json).to_string_lossy().into_owned();
        ffi::aprv_string_free(json);
        Some(s)
    };
    match (status, reason_of(status)) {
        (0, _) => Ok(text.unwrap_or_default()),
        (_, Some(reason)) => Err(Error::Verification(VerificationError { reason, message: text })),
        (code, None) => Err(config(&format!("status {code}"))),
    }
}

/// Root DER blobs as the C ABI's (pointers, lengths, count).
struct Roots(Vec<*const u8>, Vec<usize>);
impl Roots {
    fn of(roots: &Option<Vec<Vec<u8>>>) -> Option<Roots> {
        roots.as_ref().map(|r| Roots(r.iter().map(|v| v.as_ptr()).collect(), r.iter().map(Vec::len).collect()))
    }
}

pub struct Rv(*mut ffi::AprvReceiptVerifier);
pub struct Jv(*mut ffi::AprvJwsVerifier);
pub struct Ep(*mut ffi::AprvReceiptEndpoint);

impl Drop for Rv {
    fn drop(&mut self) {
        unsafe { ffi::aprv_verifier_free_receipt(self.0) }
    }
}
impl Drop for Jv {
    fn drop(&mut self) {
        unsafe { ffi::aprv_verifier_free_jws(self.0) }
    }
}
impl Drop for Ep {
    fn drop(&mut self) {
        unsafe { ffi::aprv_endpoint_free(self.0) }
    }
}

fn env_bit(e: Environment) -> u32 {
    match e {
        Environment::Production => 1,
        Environment::Sandbox => 2,
        Environment::Xcode => 4,
        Environment::LocalTesting => 8,
    }
}

impl GuestReceiptVerifier for Rv {
    fn create(bundle_id: String, trusted_roots: Option<Vec<Vec<u8>>>) -> Result<ReceiptVerifier, Error> {
        init();
        let b = cstring(bundle_id)?;
        let h = unsafe {
            match Roots::of(&trusted_roots) {
                None => ffi::aprv_verifier_new_receipt(b.as_ptr()),
                Some(r) => ffi::aprv_verifier_new_receipt_with_roots(b.as_ptr(), r.0.as_ptr(), r.1.as_ptr(), r.0.len()),
            }
        };
        if h.is_null() { Err(config("receipt verifier refused")) } else { Ok(ReceiptVerifier::new(Rv(h))) }
    }

    fn verify(&self, receipt: Vec<u8>, device_guid: Option<Vec<u8>>) -> Result<String, Error> {
        let mut out = ffi::AprvResult { status: 0, json: std::ptr::null_mut() };
        unsafe {
            match &device_guid {
                None => ffi::aprv_verify_receipt_der(self.0, receipt.as_ptr(), receipt.len(), &mut out),
                Some(g) => ffi::aprv_verify_receipt_der_with_device_guid(
                    self.0, receipt.as_ptr(), receipt.len(), g.as_ptr(), g.len(), &mut out),
            };
            take(out.status, out.json)
        }
    }

    fn verify_base64(&self, receipt: String, device_guid: Option<Vec<u8>>) -> Result<String, Error> {
        let r = cstring(receipt)?;
        let mut out = ffi::AprvResult { status: 0, json: std::ptr::null_mut() };
        unsafe {
            match &device_guid {
                None => ffi::aprv_verify_receipt_base64(self.0, r.as_ptr(), &mut out),
                Some(g) => ffi::aprv_verify_receipt_base64_with_device_guid(self.0, r.as_ptr(), g.as_ptr(), g.len(), &mut out),
            };
            take(out.status, out.json)
        }
    }
}

impl GuestJwsVerifier for Jv {
    fn create(bundle_id: String, environments: Vec<Environment>, app_apple_id: Option<i64>,
              trusted_roots: Option<Vec<Vec<u8>>>) -> Result<JwsVerifier, Error> {
        init();
        let b = cstring(bundle_id)?;
        let mask = environments.into_iter().fold(0, |m, e| m | env_bit(e));
        // SURFACE.md: i64 -> u64 by TryFrom; a negative id is a configuration error.
        let app = u64::try_from(app_apple_id.unwrap_or(0)).map_err(|_| config("negative app apple id"))?;
        let h = unsafe {
            match Roots::of(&trusted_roots) {
                None => ffi::aprv_verifier_new_jws(b.as_ptr(), mask, app),
                Some(r) => ffi::aprv_verifier_new_jws_with_roots(b.as_ptr(), mask, app, r.0.as_ptr(), r.1.as_ptr(), r.0.len()),
            }
        };
        if h.is_null() { Err(config("JWS verifier refused")) } else { Ok(JwsVerifier::new(Jv(h))) }
    }

    fn verify_transaction(&self, jws: String) -> Result<String, Error> {
        self.call(jws, 0)
    }
    fn verify_app_transaction(&self, jws: String) -> Result<String, Error> {
        self.call(jws, 1)
    }
    fn verify_raw(&self, jws: String) -> Result<String, Error> {
        self.call(jws, 2)
    }
}

impl Jv {
    fn call(&self, jws: String, op: u8) -> Result<String, Error> {
        let j = cstring(jws)?;
        let mut out = ffi::AprvResult { status: 0, json: std::ptr::null_mut() };
        unsafe {
            match op {
                0 => ffi::aprv_verify_transaction(self.0, j.as_ptr(), &mut out),
                1 => ffi::aprv_verify_app_transaction(self.0, j.as_ptr(), &mut out),
                _ => ffi::aprv_verify_raw(self.0, j.as_ptr(), &mut out),
            };
            take(out.status, out.json)
        }
    }
}

impl GuestEndpoint for Ep {
    fn create(environment: Environment, trusted_roots: Option<Vec<Vec<u8>>>, now_ms: Option<i64>) -> Result<Endpoint, Error> {
        init();
        let clock = now_ms;
        let h = unsafe {
            let c = clock.as_ref().map_or(std::ptr::null(), |v| v as *const i64);
            match Roots::of(&trusted_roots) {
                None => ffi::aprv_endpoint_new_with_roots_and_clock(env_bit(environment), std::ptr::null(), std::ptr::null(), 0, c),
                Some(r) => ffi::aprv_endpoint_new_with_roots_and_clock(env_bit(environment), r.0.as_ptr(), r.1.as_ptr(), r.0.len(), c),
            }
        };
        if h.is_null() { Err(config("endpoint refused")) } else { Ok(Endpoint::new(Ep(h))) }
    }

    fn verify_receipt_json(&self, request_body: String) -> String {
        let Ok(body) = CString::new(request_body) else { return String::new() };
        let mut out: *mut c_char = std::ptr::null_mut();
        unsafe {
            ffi::aprv_verify_receipt_endpoint_json(self.0, body.as_ptr(), &mut out);
            take(0, out).unwrap_or_default()
        }
    }
}
