#![no_main]

//! The C ABI (`rust/ffi`), entered as a C caller enters it: the first byte
//! picks a call, the rest is the input. Invariants beyond "no panic":
//!
//! - the `_bytes` calls never answer a call mistake (100 and up) for a
//!   live handle and a real range, and their document is byte for byte
//!   `aprv-wire`'s over the surface's own answer, as `aprv.wasm`'s is;
//! - the 0.7 C-string calls answer a verdict or `INVALID_UTF8`, never a
//!   panic, and agree with the `_bytes` call on the input up to its first
//!   NUL whenever that input is UTF-8;
//! - both endpoint calls answer a body that starts with `{"status":`.

use apple_purchase_receipt_verifier_ffi::{
    aprv_string_free, aprv_verifier_new, aprv_verify_receipt, aprv_verify_receipt_bytes,
    aprv_verify_receipt_endpoint, aprv_verify_receipt_endpoint_bytes, aprv_verify_signed_data,
    aprv_verify_signed_data_bytes, AprvResult, AprvVerifier,
};
use aprv_surface::{Environment, Verifier};
use libfuzzer_sys::fuzz_target;
use std::ffi::{c_char, CStr, CString};
use std::sync::OnceLock;

const NOW: i64 = 1_790_640_000_000; // 2026-09-29T00:00:00Z
const JWS_ROOT: &[u8] = include_bytes!("../../../fixtures/generated/jws-root.der");
const INVALID_UTF8: i32 = 101;

struct Handles {
    ffi: usize,
    surface: Verifier,
}

fn handles() -> &'static Handles {
    static HANDLES: OnceLock<Handles> = OnceLock::new();
    HANDLES.get_or_init(|| {
        let ders = [JWS_ROOT.as_ptr()];
        let lens = [JWS_ROOT.len()];
        let now = NOW;
        // SAFETY: one readable DER certificate and one readable instant.
        let ffi = unsafe { aprv_verifier_new(ders.as_ptr(), lens.as_ptr(), 1, &raw const now) };
        assert!(!ffi.is_null(), "the fixture root builds a verifier");
        Handles {
            ffi: ffi as usize,
            surface: Verifier::new(&[JWS_ROOT.to_vec()]).expect("the fixture root"),
        }
    })
}

/// The document and status of one `AprvResult`, the string freed.
fn take(status: i32, out: AprvResult) -> (i32, Option<String>) {
    assert_eq!(out.status, status, "out->status is the return value");
    if out.json.is_null() {
        return (status, None);
    }
    // SAFETY: a string the library handed out, freed once, here.
    let text = unsafe { CStr::from_ptr(out.json) }
        .to_str()
        .expect("UTF-8")
        .to_owned();
    // SAFETY: as above.
    unsafe { aprv_string_free(out.json) };
    (status, Some(text))
}

fn body(response: *mut c_char) -> String {
    assert!(!response.is_null(), "an endpoint body");
    // SAFETY: a string the library handed out, freed once, here.
    let text = unsafe { CStr::from_ptr(response) }
        .to_str()
        .expect("UTF-8")
        .to_owned();
    // SAFETY: as above.
    unsafe { aprv_string_free(response) };
    text
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, input)) = data.split_first() else {
        return;
    };
    let handles = handles();
    let verifier = handles.ffi as *const AprvVerifier;
    let receipt = selector % 3 == 0;
    let endpoint = selector % 3 == 2;
    let prefix = &input[..input.iter().position(|b| *b == 0).unwrap_or(input.len())];
    let c_input = CString::new(prefix).expect("no NUL before the first NUL");

    if endpoint {
        let environment = if selector & 4 == 0 { 1 } else { 2 };
        let mut response: *mut c_char = std::ptr::null_mut();
        // SAFETY: a live handle, `input.len()` readable bytes, a writable pointer.
        let status = unsafe {
            aprv_verify_receipt_endpoint_bytes(
                verifier,
                environment,
                input.as_ptr(),
                input.len(),
                &raw mut response,
            )
        };
        assert_eq!(status, 0, "the endpoint answers a body for every input");
        let answer = body(response);
        let env = if environment == 1 {
            Environment::Production
        } else {
            Environment::Sandbox
        };
        assert_eq!(
            answer,
            handles.surface.verify_receipt_endpoint(env, input, NOW),
            "aprv.wasm's body"
        );
        let mut response: *mut c_char = std::ptr::null_mut();
        // SAFETY: a live handle, a NUL-terminated string, a writable pointer.
        let status = unsafe {
            aprv_verify_receipt_endpoint(verifier, environment, c_input.as_ptr(), &raw mut response)
        };
        if status == INVALID_UTF8 {
            assert!(std::str::from_utf8(prefix).is_err());
        } else {
            assert_eq!(status, 0);
            assert!(body(response).starts_with("{\"status\":"));
        }
        return;
    }

    let mut out = AprvResult {
        status: -1,
        json: std::ptr::null_mut(),
    };
    // SAFETY: a live handle, `input.len()` readable bytes, a writable result.
    let status = unsafe {
        if receipt {
            aprv_verify_receipt_bytes(verifier, input.as_ptr(), input.len(), &raw mut out)
        } else {
            aprv_verify_signed_data_bytes(verifier, input.as_ptr(), input.len(), &raw mut out)
        }
    };
    let (status, document) = take(status, out);
    assert!(
        status < 100,
        "a call mistake ({status}) for a live handle and a real range"
    );
    let expected = if receipt {
        aprv_wire::verify_receipt_result(&handles.surface.verify_receipt(input, NOW))
    } else {
        aprv_wire::verify_signed_data_result(&handles.surface.verify_signed_data(input, NOW))
    };
    assert_eq!(
        document.as_deref(),
        Some(expected.as_str()),
        "aprv.wasm's document"
    );

    let mut out = AprvResult {
        status: -1,
        json: std::ptr::null_mut(),
    };
    // SAFETY: a live handle, a NUL-terminated string, a writable result.
    let old = unsafe {
        if receipt {
            aprv_verify_receipt(verifier, c_input.as_ptr(), &raw mut out)
        } else {
            aprv_verify_signed_data(verifier, c_input.as_ptr(), &raw mut out)
        }
    };
    let (old, _) = take(old, out);
    assert_ne!(old, 103, "a panic crossed into the guard");
    if std::str::from_utf8(prefix).is_ok() {
        let mut out = AprvResult {
            status: -1,
            json: std::ptr::null_mut(),
        };
        // SAFETY: as above, over the prefix.
        let bytes = unsafe {
            if receipt {
                aprv_verify_receipt_bytes(verifier, prefix.as_ptr(), prefix.len(), &raw mut out)
            } else {
                aprv_verify_signed_data_bytes(verifier, prefix.as_ptr(), prefix.len(), &raw mut out)
            }
        };
        let (bytes, _) = take(bytes, out);
        assert_eq!(
            old, bytes,
            "the C-string call and the bytes call over the same text"
        );
    } else {
        assert_eq!(old, INVALID_UTF8);
    }
});
