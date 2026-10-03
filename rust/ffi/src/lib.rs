//! The C ABI over [`apple_purchase_receipt_verifier`].
//!
//! Everything a C caller needs is in this one file, and the header that
//! ships with it (`include/apple_purchase_receipt_verifier.h`) is generated
//! from it by cbindgen. The shape follows the 0.7 Rust API one to one: one
//! opaque [`AprvVerifier`] built from roots and a clock, its three calls,
//! one result struct, one free function.
//!
//! # Why JSON is the interchange
//!
//! A verified JWS is an open-ended JSON claim set and a verified receipt is
//! a tree with repeated groups and raw byte attributes. Modelling either as
//! C structs would put every field of a wire format Apple extends at will
//! into the ABI, and every addition would then be a breaking change for
//! every consumer. Handing back one UTF-8 JSON document instead keeps the
//! ABI at a handful of functions and moves the schema question into a
//! parser the caller already has. The documents are the library's own, and
//! the same bytes `aprv.wasm` returns: a receipt is `aprv-wire`'s receipt
//! payload (0.7's `ReceiptPayload.toJson()` value), a JWS payload exactly
//! the signed JSON text.
//!
//! # One layer below
//!
//! This crate reaches the library through `aprv-surface` (the calls) and
//! `aprv-wire` (the JSON), the boundary `aprv.wasm` uses too
//! (docs/rust-core/SURFACE.md §9), so the two cannot drift apart.
//!
//! # The clock is an instant, not a callback
//!
//! The Rust `Config` takes a closure. Handing one across a C boundary would
//! mean a function pointer the library calls back into, and this surface is
//! deliberately callback-free: a callback would have to be thread-safe, live
//! as long as the handle, and unwind-proof, and getting any of that wrong is
//! a crash rather than a rejected argument. So the ABI takes the one thing a
//! fixed clock actually is, a single instant in milliseconds since the Unix
//! epoch, and a null pointer means the system clock, read once per call.
//!
//! # Panics never cross the boundary
//!
//! Unwinding out of an `extern "C"` function is undefined behaviour. Every
//! exported function here is a single call to [`guard`] or [`guard_ptr`],
//! which run the real body inside [`std::panic::catch_unwind`] and report a
//! caught panic as [`AprvReason::Panic`] (or a null handle). The
//! `every_exported_function_is_guarded` test reads this file and fails if an
//! export is ever added that does not do that.
//!
//! # Bytes in, the module's JSON out
//!
//! The `_bytes` calls take a pointer and a length, as `aprv.wasm` takes a
//! `list<u8>`, and answer the document `aprv.wasm` answers, byte for byte:
//! `aprv-wire`'s `{"verified":true,"payload":...,"environment":...}` or
//! `{"verified":false,"reason":...,"message":...}`, or the endpoint's body.
//! Every input is a verdict there, an embedded NUL and bytes that are not
//! UTF-8 included. The 0.7 calls without the suffix take C strings: the
//! input ends at its first NUL, bytes that are not UTF-8 are
//! [`AprvReason::InvalidUtf8`] rather than a verdict, and they answer 0.7's
//! documents (the bare payload, or `{"reason","message"}`). They stay for
//! 0.7 callers; a new caller uses the `_bytes` calls.

#![deny(
    unsafe_op_in_unsafe_fn,
    improper_ctypes,
    improper_ctypes_definitions,
    ffi_unwind_calls
)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::missing_panics_doc)]

use aprv_surface::{Environment, Failure, Reason, Verifier};
use std::ffi::{c_char, CStr, CString};
use std::sync::OnceLock;

// --- status codes --------------------------------------------------------

/// The value of [`AprvResult::status`], and the return value of every
/// verification call.
///
/// Two bands, and the split is the point: `1..=99` is a **verdict about the
/// input**, the canonical cross-port [`Reason`] vocabulary, while `100..` is
/// a **mistake in the call itself**, where nothing about the input was
/// checked. A caller that treats `APRV_REASON_NULL_POINTER` as "the receipt
/// is forged" is reporting its own bug as an attack.
///
/// **Stable and append-only.** These numbers are part of the ABI: a value is
/// never reused for a different meaning and an existing value never changes.
/// The 0.7 reason set kept the four codes whose meaning did not change and
/// took new numbers for the rest. Retired and never reused: `1`
/// (`INVALID_JWS_FORMAT`), `4` (`INVALID_CHAIN`), `6` to `10` (the 0.6
/// policy and format reasons) and `11` (`STALE_PAYLOAD`).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AprvReason {
    /// The call succeeded. `AprvResult::json` holds the payload.
    Ok = 0,

    /// A certificate cannot be used: it does not decode, or it is outside
    /// its validity window at the chain instant.
    InvalidCertificate = 2,
    /// A certificate lacks the Apple marker OID for its place in the chain.
    InvalidCertificatePurpose = 3,
    /// The signature did not verify.
    InvalidSignature = 5,
    /// Not the caller's fault: the library failed. Alert and reconcile; do
    /// not deny the user on it.
    InternalError = 12,
    /// The base64, ASN.1, CMS or JWS structure is broken, or a structural
    /// bound is exceeded.
    Malformed = 13,
    /// The input is over a size cap and was not decoded.
    TooLarge = 14,
    /// The chain does not reach a pinned root.
    UntrustedChain = 15,
    /// A trusted signer signed content the library cannot read, found only
    /// after the chain and the signature passed. Not the caller's fault.
    UnreadablePayload = 16,

    /// A required pointer argument was `NULL`. Nothing was verified.
    NullPointer = 100,
    /// A `const char *` argument of a 0.7 call was not valid UTF-8. Nothing
    /// was verified. The `_bytes` calls never answer it: bytes that are not
    /// UTF-8 are input like any other there.
    InvalidUtf8 = 101,
    /// A configuration argument was rejected: an unknown environment, bytes
    /// that are not a certificate, an anchor array that disagrees with its
    /// count, a length over `PTRDIFF_MAX`. Nothing was verified.
    InvalidArgument = 102,
    /// A panic was caught at the boundary. Nothing crossed it. This is a bug
    /// in the library; please report it.
    Panic = 103,
    /// The library returned a verification reason this ABI has no code for,
    /// which can only happen if the two are built from different versions.
    /// Treat it as a rejection.
    UnknownReason = 104,
}

/// The environment [`aprv_verify_receipt_endpoint`] answers as.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AprvEnvironment {
    /// `Production`
    Production = 1,
    /// `Sandbox`
    Sandbox = 2,
}

/// The outcome of one verification call.
///
/// `json` is owned by the caller and must be released with
/// [`aprv_string_free`].
///
/// From the `_bytes` calls ([`aprv_verify_receipt_bytes`],
/// [`aprv_verify_signed_data_bytes`]):
///
/// * `status` below 100 (a verdict): `json` is the document `aprv.wasm`
///   answers for the same input, byte for byte, which validates against
///   `rust/bindings/wire/schema/`:
///   `{"verified":true,"payload":...,"environment":...}` or
///   `{"verified":false,"reason":"<token>","message":"<detail>"}`.
/// * `status` 100 or above (a mistake in the call): `json` is `NULL`.
///
/// From the 0.7 calls ([`aprv_verify_receipt`], [`aprv_verify_signed_data`]):
///
/// * `status == APRV_REASON_OK`: `json` is the verified payload: for a
///   receipt the 0.7 `ReceiptPayload` JSON, the bytes `aprv.wasm` returns
///   as its payload; for a JWS the signed JSON text, exactly.
/// * anything else: `json` is `{"reason":"<token>","message":"<detail>"}`.
///
/// A token is the `SCREAMING_SNAKE` spelling every port of this library
/// shares; a message is a short, non-sensitive description that never
/// contains receipt bytes, claims or key material. Match on `status`, or on
/// `reason`; never parse `message`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AprvResult {
    /// An [`AprvReason`] value.
    pub status: i32,
    /// Owned, NUL-terminated UTF-8 JSON. Free with [`aprv_string_free`].
    pub json: *mut c_char,
}

// --- the opaque handle ---------------------------------------------------

/// A verifier: pinned roots and a clock. Created by `aprv_verifier_new`,
/// released by `aprv_verifier_free`.
///
/// Immutable once built, and safe to share between threads: any number of
/// threads may verify through the same handle at the same time. Freeing it
/// while another thread is inside a call is not.
pub struct AprvVerifier {
    inner: Verifier,
    /// The pinned instant, or `None` for the system clock.
    fixed_now: Option<i64>,
}

impl AprvVerifier {
    /// The instant of one call: the pinned one, or the system clock read
    /// now, once.
    fn now_ms(&self) -> i64 {
        self.fixed_now.unwrap_or_else(system_millis)
    }
}

/// The system clock in milliseconds since the Unix epoch; negative before
/// it, and saturated at the ends of `i64`, which no clock reaches.
fn system_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_millis()).unwrap_or(i64::MAX),
        Err(before) => i64::try_from(before.duration().as_millis()).map_or(i64::MIN, |ms| -ms),
    }
}

// --- the panic boundary --------------------------------------------------

/// Runs `body` with unwinding contained, reporting a caught panic as
/// [`AprvReason::Panic`].
fn guard<F: FnOnce() -> i32>(body: F) -> i32 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(code) => code,
        Err(_) => AprvReason::Panic as i32,
    }
}

/// [`guard`] for the constructor: a caught panic yields a null handle,
/// which is what every other construction failure yields too.
fn guard_ptr<T, F: FnOnce() -> *mut T>(body: F) -> *mut T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(pointer) => pointer,
        Err(_) => std::ptr::null_mut(),
    }
}

// --- small conversions ---------------------------------------------------

/// Each ABI reason code beside its canonical token, in the order `Reason`
/// declares them. The codes are pinned here rather than derived from a
/// position, so a retired reason retires its number instead of shifting
/// every later one. `reason_codes_mirror_the_library` asserts this against
/// `Reason::all()`.
const REASON_CODES: [(i32, &str); 8] = [
    (13, "MALFORMED"),
    (14, "TOO_LARGE"),
    (5, "INVALID_SIGNATURE"),
    (15, "UNTRUSTED_CHAIN"),
    (2, "INVALID_CERTIFICATE"),
    (3, "INVALID_CERTIFICATE_PURPOSE"),
    (16, "UNREADABLE_PAYLOAD"),
    (12, "INTERNAL_ERROR"),
];

/// The ABI code for a library reason, looked up by token so the table above
/// is the single statement of the mapping.
fn reason_code(reason: Reason) -> i32 {
    REASON_CODES
        .iter()
        .find(|(_, token)| *token == reason.token())
        .map_or(AprvReason::UnknownReason as i32, |(code, _)| *code)
}

/// The `SCREAMING_SNAKE` token for a status code, for the error JSON.
fn status_token(status: i32) -> &'static str {
    match status {
        0 => "OK",
        100 => "NULL_POINTER",
        101 => "INVALID_UTF8",
        102 => "INVALID_ARGUMENT",
        103 => "PANIC",
        104 => "UNKNOWN_REASON",
        other => REASON_CODES
            .iter()
            .find(|(code, _)| *code == other)
            .map_or("UNKNOWN_REASON", |(_, token)| *token),
    }
}

/// Borrows a C string as UTF-8, distinguishing "no string" from "not UTF-8".
///
/// # Safety
/// `pointer`, when non-null, must point at a NUL-terminated string that
/// stays valid for the duration of the call.
unsafe fn borrow_str<'a>(pointer: *const c_char) -> Result<&'a str, i32> {
    if pointer.is_null() {
        return Err(AprvReason::NullPointer as i32);
    }
    // SAFETY: non-null, and the caller guarantees a NUL-terminated string
    // valid for the call.
    unsafe { CStr::from_ptr(pointer) }
        .to_str()
        .map_err(|_| AprvReason::InvalidUtf8 as i32)
}

/// Borrows `len` bytes at `input`. `NULL` with a length of zero is the
/// empty input; `NULL` with any other length is refused, and so is a length
/// no Rust slice can have.
///
/// # Safety
/// `input`, when non-null, must point at `len` readable bytes that stay
/// valid and unmodified for the duration of the call.
unsafe fn borrow_bytes<'a>(input: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if input.is_null() {
        return if len == 0 {
            Ok(&[])
        } else {
            Err(AprvReason::NullPointer as i32)
        };
    }
    if isize::try_from(len).is_err() {
        return Err(AprvReason::InvalidArgument as i32);
    }
    // SAFETY: non-null, `len` fits a slice, and the caller guarantees `len`
    // readable bytes valid for the call.
    Ok(unsafe { std::slice::from_raw_parts(input, len) })
}

/// Copies the caller's anchors, each DER or PEM bytes. `NULL`, `NULL`, `0`
/// means "not given", an empty list, which the surface reads as the bundled
/// Apple roots. A `count` or an anchor length over `PTRDIFF_MAX` is
/// `InvalidArgument`, as [`borrow_bytes`] answers for the `_bytes` calls,
/// before any slice is built.
///
/// # Safety
/// When `count` is non-zero, `ders` must point at `count` readable pointers
/// and `lens` at `count` readable lengths, each pair describing readable
/// anchor bytes.
unsafe fn anchors_of(
    ders: *const *const u8,
    lens: *const usize,
    count: usize,
) -> Result<Vec<Vec<u8>>, i32> {
    if count == 0 {
        if ders.is_null() && lens.is_null() {
            return Ok(Vec::new());
        }
        return Err(AprvReason::InvalidArgument as i32);
    }
    if ders.is_null() || lens.is_null() {
        return Err(AprvReason::NullPointer as i32);
    }
    // Both arrays hold elements the size of a pointer.
    let array_bytes = count.checked_mul(std::mem::size_of::<*const u8>());
    if array_bytes.is_none_or(|bytes| isize::try_from(bytes).is_err()) {
        return Err(AprvReason::InvalidArgument as i32);
    }
    // SAFETY: both non-null, `count` elements fit a slice, and the caller
    // guarantees `count` readable elements behind each.
    let pointers = unsafe { std::slice::from_raw_parts(ders, count) };
    // SAFETY: as above.
    let lengths = unsafe { std::slice::from_raw_parts(lens, count) };
    let mut anchors = Vec::with_capacity(count);
    for (pointer, len) in pointers.iter().zip(lengths) {
        if pointer.is_null() {
            return Err(AprvReason::NullPointer as i32);
        }
        // SAFETY: the caller guarantees `len` readable bytes behind the
        // pointer; `borrow_bytes` refuses a length over `isize::MAX`.
        let der = unsafe { borrow_bytes(*pointer, *len) }?;
        anchors.push(der.to_vec());
    }
    Ok(anchors)
}

/// Moves an owned Rust string across the boundary. `None` becomes `NULL`,
/// which is what a caller sees if the string held an interior NUL; nothing
/// this crate produces does.
fn into_c_string(text: Option<String>) -> *mut c_char {
    match text.and_then(|text| CString::new(text).ok()) {
        Some(owned) => owned.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// The error document: the same two keys for a verdict and for a call
/// mistake, so a caller has one shape to parse. `serde_json` writes the two
/// strings; the frame stays literal because `json!` would sort the keys,
/// putting `message` before `reason`.
fn error_json(status: i32, message: &str) -> String {
    format!(
        "{{\"reason\":{},\"message\":{}}}",
        serde_json::Value::from(status_token(status)),
        serde_json::Value::from(message)
    )
}

/// Writes one outcome into the caller's `out`, and returns the status so a
/// caller that only wants the code can ignore `out` entirely.
///
/// # Safety
/// `out`, when non-null, must point at a writable `AprvResult`.
unsafe fn finish(out: *mut AprvResult, status: i32, json: String) -> i32 {
    if !out.is_null() {
        // SAFETY: non-null, and the caller guarantees a writable
        // `AprvResult`.
        unsafe {
            out.write(AprvResult {
                status,
                json: into_c_string(Some(json)),
            });
        }
    }
    status
}

/// Turns a library result into the `(status, json)` pair the ABI reports.
fn outcome(result: Result<String, Failure>) -> (i32, String) {
    match result {
        Ok(json) => (AprvReason::Ok as i32, json),
        Err(failure) => {
            let status = reason_code(failure.reason);
            (status, error_json(status, &failure.message))
        }
    }
}

// --- exported: version ---------------------------------------------------

/// The library version, as a static NUL-terminated string. **Do not free
/// it**, and do not assume it stays valid across a `dlclose`.
///
/// It is the Rust library's own `VERSION`, so it names the library this
/// ABI is compiled against and needs no file outside the crate.
#[no_mangle]
pub extern "C" fn aprv_version() -> *const c_char {
    static VERSION: OnceLock<CString> = OnceLock::new();
    let version = VERSION
        .get_or_init(|| CString::new(aprv_surface::VERSION).unwrap_or_else(|_| CString::default()));
    version.as_ptr()
}

// --- exported: the verifier ----------------------------------------------

/// A verifier: the pinned roots and the clock.
///
/// * `ders[i]` / `lens[i]` describe one trust anchor entry: DER or PEM
///   bytes. DER is one certificate; PEM text may hold several, and each
///   becomes an anchor. The library tells the two apart by the bytes. They
///   are parsed during the call and never retained. `NULL`, `NULL`, `0`
///   selects the three bundled Apple roots. A `count` of zero with either
///   array non-null is refused.
/// * `fixed_clock_unix_millis`, when non-null, pins the clock at that
///   instant in milliseconds since the Unix epoch; `NULL` reads the system
///   clock on every call. A pointer rather than a sentinel value, because
///   every `int64_t` names a real instant.
///
/// The clock is read at most once per call, and only for one of two things:
/// the certificate-validity instant when the input states no usable signing
/// date, and the endpoint's `request_date`. No payload is rejected for its age.
///
/// Returns `NULL` if any argument is rejected. The handle is owned by the
/// caller and must be released with [`aprv_verifier_free`].
///
/// # Safety
/// The three anchor arguments must describe `count` readable byte ranges
/// (DER or PEM), and `fixed_clock_unix_millis` must be `NULL` or point at
/// one readable, aligned `int64_t`.
#[no_mangle]
pub unsafe extern "C" fn aprv_verifier_new(
    ders: *const *const u8,
    lens: *const usize,
    count: usize,
    fixed_clock_unix_millis: *const i64,
) -> *mut AprvVerifier {
    guard_ptr(|| {
        // SAFETY: the anchor arguments are passed through under this
        // function's own contract.
        let Ok(anchors) = (unsafe { anchors_of(ders, lens, count) }) else {
            return std::ptr::null_mut();
        };
        let fixed_now = if fixed_clock_unix_millis.is_null() {
            None
        } else {
            // SAFETY: non-null, and the caller guarantees one readable,
            // aligned `int64_t`.
            Some(unsafe { *fixed_clock_unix_millis })
        };
        match Verifier::new(&anchors) {
            Ok(inner) => Box::into_raw(Box::new(AprvVerifier { inner, fixed_now })),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Releases a handle from [`aprv_verifier_new`]. `NULL` is a no-op. Calling
/// it twice on the same handle, or while another thread is inside a call on
/// it, is undefined behaviour.
///
/// # Safety
/// `verifier` must be `NULL` or a live handle from [`aprv_verifier_new`].
#[no_mangle]
pub unsafe extern "C" fn aprv_verifier_free(verifier: *mut AprvVerifier) {
    guard(|| {
        if !verifier.is_null() {
            // SAFETY: a live handle from `aprv_verifier_new`, which made it
            // with `Box::into_raw`, freed once, per the caller's contract.
            drop(unsafe { Box::from_raw(verifier) });
        }
        AprvReason::Ok as i32
    });
}

/// Verifies a legacy app receipt given as the base64 string an app sends.
/// On success `out->json` is the 0.7 `ReceiptPayload` JSON.
///
/// The 0.7 C-string form: the input ends at its first NUL, and bytes that
/// are not UTF-8 are [`AprvReason::InvalidUtf8`], not a verdict. So a
/// genuine receipt followed by a NUL and anything verifies here and is
/// `MALFORMED` everywhere else. [`aprv_verify_receipt_bytes`] answers as
/// `aprv.wasm` does for every input.
///
/// Returns the status, which is also written to `out->status`. `out` may be
/// `NULL` for a caller that only wants the status.
///
/// # Safety
/// `verifier` must be a live handle, `receipt_base64` a NUL-terminated
/// string, and `out` `NULL` or a writable `AprvResult`.
#[no_mangle]
pub unsafe extern "C" fn aprv_verify_receipt(
    verifier: *const AprvVerifier,
    receipt_base64: *const c_char,
    out: *mut AprvResult,
) -> i32 {
    guard(|| {
        // SAFETY: the arguments are passed through under this function's
        // own contract, which is `call`'s.
        unsafe {
            call(verifier, receipt_base64, out, |verifier, input| {
                verifier
                    .inner
                    .verify_receipt(input.as_bytes(), verifier.now_ms())
                    .map(|payload| aprv_wire::receipt_payload(&payload))
            })
        }
    })
}

/// Verifies any Apple-signed compact JWS: a transaction, a renewal info, an
/// app transaction or a notification. On success `out->json` is the signed
/// payload's JSON text, exactly as signed.
///
/// The 0.7 C-string form, with [`aprv_verify_receipt`]'s limits;
/// [`aprv_verify_signed_data_bytes`] has none.
///
/// # Safety
/// As [`aprv_verify_receipt`], with `jws` for the input.
#[no_mangle]
pub unsafe extern "C" fn aprv_verify_signed_data(
    verifier: *const AprvVerifier,
    jws: *const c_char,
    out: *mut AprvResult,
) -> i32 {
    guard(|| {
        // SAFETY: as in `aprv_verify_receipt`.
        unsafe {
            call(verifier, jws, out, |verifier, input| {
                verifier
                    .inner
                    .verify_signed_data(input.as_bytes(), verifier.now_ms())
                    .map(|payload| payload.json)
            })
        }
    })
}

/// The body both verification calls share: the argument checks, the call,
/// and the result.
///
/// # Safety
/// `verifier` must be `NULL` or a live handle, `input` `NULL` or a
/// NUL-terminated string, and `out` `NULL` or a writable `AprvResult`.
unsafe fn call(
    verifier: *const AprvVerifier,
    input: *const c_char,
    out: *mut AprvResult,
    verify: impl FnOnce(&AprvVerifier, &str) -> Result<String, Failure>,
) -> i32 {
    if verifier.is_null() {
        let status = AprvReason::NullPointer as i32;
        // SAFETY: `out` is passed through under this function's contract.
        return unsafe { finish(out, status, error_json(status, "verifier is NULL")) };
    }
    // SAFETY: `input` is `NULL` or a NUL-terminated string, per the contract.
    let input = match unsafe { borrow_str(input) } {
        Ok(input) => input,
        Err(status) => {
            let message = if status == AprvReason::NullPointer as i32 {
                "input is NULL"
            } else {
                "input is not UTF-8"
            };
            // SAFETY: as above.
            return unsafe { finish(out, status, error_json(status, message)) };
        }
    };
    // SAFETY: non-null, and a live handle per the contract.
    let verifier = unsafe { &*verifier };
    let (status, json) = outcome(verify(verifier, input));
    // SAFETY: as above.
    unsafe { finish(out, status, json) }
}

/// Apple's `verifyReceipt`, answered locally: `request_json` is the request
/// body, `*response_json` receives Apple's response body. The 0.7
/// C-string form: the body ends at its first NUL, and a body that is not
/// UTF-8 is [`AprvReason::InvalidUtf8`] rather than `{"status":21002}`;
/// [`aprv_verify_receipt_endpoint_bytes`] answers as `aprv.wasm` does.
///
/// `environment` is an [`AprvEnvironment`] value. Like Apple's endpoint this
/// never reports a verification failure through the return value: every
/// verdict is the `status` field **inside** the JSON. A non-zero return means
/// the call itself was malformed (a null argument, a non-UTF-8 body, an
/// unknown environment) and `*response_json` is then left untouched.
///
/// `*response_json` is owned by the caller and must be released with
/// [`aprv_string_free`].
///
/// # Safety
/// `verifier` must be a live handle, `request_json` a NUL-terminated
/// string, and `response_json` a writable `char *`.
#[no_mangle]
pub unsafe extern "C" fn aprv_verify_receipt_endpoint(
    verifier: *const AprvVerifier,
    environment: u32,
    request_json: *const c_char,
    response_json: *mut *mut c_char,
) -> i32 {
    guard(|| {
        if verifier.is_null() || response_json.is_null() {
            return AprvReason::NullPointer as i32;
        }
        let environment = match environment {
            1 => Environment::Production,
            2 => Environment::Sandbox,
            _ => return AprvReason::InvalidArgument as i32,
        };
        // SAFETY: a NUL-terminated string or `NULL`, per the contract.
        let body = match unsafe { borrow_str(request_json) } {
            Ok(body) => body,
            Err(status) => return status,
        };
        // SAFETY: non-null, and a live handle per the contract.
        let verifier = unsafe { &*verifier };
        let response =
            verifier
                .inner
                .verify_receipt_endpoint(environment, body.as_bytes(), verifier.now_ms());
        // SAFETY: non-null, and a writable `char *` per the contract.
        unsafe { response_json.write(into_c_string(Some(response))) };
        AprvReason::Ok as i32
    })
}

/// Verifies a legacy app receipt given as the `len` bytes of the base64
/// text an app sends. `out->json` is the document `aprv.wasm` answers for
/// the same bytes (see [`AprvResult`]): every input is a verdict, an
/// embedded NUL and bytes that are not UTF-8 included.
///
/// Returns the status, which is also written to `out->status`. `out` may be
/// `NULL` for a caller that only wants the status. `receipt_base64` may be
/// `NULL` when `len` is 0.
///
/// # Safety
/// `verifier` must be a live handle, `receipt_base64` `NULL` or `len`
/// readable bytes, and `out` `NULL` or a writable `AprvResult`.
#[no_mangle]
pub unsafe extern "C" fn aprv_verify_receipt_bytes(
    verifier: *const AprvVerifier,
    receipt_base64: *const u8,
    len: usize,
    out: *mut AprvResult,
) -> i32 {
    guard(|| {
        // SAFETY: the arguments are passed through under this function's
        // own contract, which is `call_bytes`'s.
        unsafe {
            call_bytes(verifier, receipt_base64, len, out, |verifier, input| {
                let result = verifier.inner.verify_receipt(input, verifier.now_ms());
                let status = result
                    .as_ref()
                    .map_or_else(|failure| reason_code(failure.reason), |_| 0);
                (status, aprv_wire::verify_receipt_result(&result))
            })
        }
    })
}

/// Verifies any Apple-signed compact JWS given as `len` bytes. `out->json`
/// is the document `aprv.wasm` answers for the same bytes (see
/// [`AprvResult`]); a verified payload is a JSON string holding the signed
/// text, exactly.
///
/// # Safety
/// As [`aprv_verify_receipt_bytes`], with `jws` for the input.
#[no_mangle]
pub unsafe extern "C" fn aprv_verify_signed_data_bytes(
    verifier: *const AprvVerifier,
    jws: *const u8,
    len: usize,
    out: *mut AprvResult,
) -> i32 {
    guard(|| {
        // SAFETY: as in `aprv_verify_receipt_bytes`.
        unsafe {
            call_bytes(verifier, jws, len, out, |verifier, input| {
                let result = verifier.inner.verify_signed_data(input, verifier.now_ms());
                let status = result
                    .as_ref()
                    .map_or_else(|failure| reason_code(failure.reason), |_| 0);
                (status, aprv_wire::verify_signed_data_result(&result))
            })
        }
    })
}

/// The body both `_bytes` calls share: the argument checks, the call, and
/// the result. A call mistake leaves `json` `NULL`.
///
/// # Safety
/// `verifier` must be `NULL` or a live handle, `input` `NULL` or `len`
/// readable bytes, and `out` `NULL` or a writable `AprvResult`.
unsafe fn call_bytes(
    verifier: *const AprvVerifier,
    input: *const u8,
    len: usize,
    out: *mut AprvResult,
    verify: impl FnOnce(&AprvVerifier, &[u8]) -> (i32, String),
) -> i32 {
    let checked = if verifier.is_null() {
        Err(AprvReason::NullPointer as i32)
    } else {
        // SAFETY: `input` is `NULL` or `len` readable bytes, per the contract.
        unsafe { borrow_bytes(input, len) }
    };
    let (status, json) = match checked {
        // SAFETY: non-null (checked above), and a live handle per the contract.
        Ok(input) => verify(unsafe { &*verifier }, input),
        Err(status) => (status, String::new()),
    };
    if !out.is_null() {
        let json = if status >= 100 {
            std::ptr::null_mut()
        } else {
            into_c_string(Some(json))
        };
        // SAFETY: non-null, and the caller guarantees a writable
        // `AprvResult`.
        unsafe { out.write(AprvResult { status, json }) };
    }
    status
}

/// Apple's `verifyReceipt`, answered locally, over the `len` bytes of the
/// request body: `*response_json` receives the body `aprv.wasm` answers for
/// the same bytes. As with [`aprv_verify_receipt_endpoint`], every verdict
/// is the `status` field inside the body; a non-zero return means the call
/// itself was malformed (a null argument, an unknown environment) and
/// `*response_json` is then left untouched. Bytes that are not UTF-8, or
/// that hold a NUL, are a body like any other (`{"status":21002}`).
///
/// # Safety
/// `verifier` must be a live handle, `request_json` `NULL` or `len` readable
/// bytes, and `response_json` a writable `char *`.
#[no_mangle]
pub unsafe extern "C" fn aprv_verify_receipt_endpoint_bytes(
    verifier: *const AprvVerifier,
    environment: u32,
    request_json: *const u8,
    len: usize,
    response_json: *mut *mut c_char,
) -> i32 {
    guard(|| {
        if verifier.is_null() || response_json.is_null() {
            return AprvReason::NullPointer as i32;
        }
        let environment = match environment {
            1 => Environment::Production,
            2 => Environment::Sandbox,
            _ => return AprvReason::InvalidArgument as i32,
        };
        // SAFETY: `NULL` or `len` readable bytes, per the contract.
        let body = match unsafe { borrow_bytes(request_json, len) } {
            Ok(body) => body,
            Err(status) => return status,
        };
        // SAFETY: non-null, and a live handle per the contract.
        let verifier = unsafe { &*verifier };
        let response = verifier
            .inner
            .verify_receipt_endpoint(environment, body, verifier.now_ms());
        // SAFETY: non-null, and a writable `char *` per the contract.
        unsafe { response_json.write(into_c_string(Some(response))) };
        AprvReason::Ok as i32
    })
}

/// Releases a string this library handed out: an `AprvResult::json` or a
/// `verifyReceipt` response body. `NULL` is a no-op. Never call it on
/// [`aprv_version`]'s return value, and never free one of these with the C
/// runtime's own `free`: the allocator is Rust's.
///
/// # Safety
/// `text` must be `NULL` or a string this library returned and that has not
/// already been freed.
#[no_mangle]
pub unsafe extern "C" fn aprv_string_free(text: *mut c_char) {
    guard(|| {
        if !text.is_null() {
            // SAFETY: a string this library made with `CString::into_raw`,
            // not yet freed, per the caller's contract.
            drop(unsafe { CString::from_raw(text) });
        }
        AprvReason::Ok as i32
    });
}

#[cfg(test)]
// The tests call the exports as a C caller would; each unsafe block's
// contract is the export's own, met by the arguments beside it.
#[allow(clippy::undocumented_unsafe_blocks)]
mod tests {
    use super::*;

    const NOW: i64 = 1_735_689_600_000; // 2025-01-01T00:00:00Z

    fn bundled() -> *mut AprvVerifier {
        unsafe { aprv_verifier_new(std::ptr::null(), std::ptr::null(), 0, std::ptr::null()) }
    }

    /// A verifier pinned to one fixture root, at [`NOW`].
    fn pinned(root: &str) -> *mut AprvVerifier {
        let root = std::fs::read(fixture(root)).unwrap();
        let ders = [root.as_ptr()];
        let lens = [root.len()];
        let now = NOW;
        let verifier =
            unsafe { aprv_verifier_new(ders.as_ptr(), lens.as_ptr(), 1, &raw const now) };
        assert!(!verifier.is_null());
        verifier
    }

    fn take_json(result: AprvResult) -> String {
        assert!(!result.json.is_null(), "result carried no JSON");
        let text = unsafe { CStr::from_ptr(result.json) }
            .to_str()
            .unwrap()
            .to_owned();
        unsafe { aprv_string_free(result.json) };
        text
    }

    fn empty_result() -> AprvResult {
        AprvResult {
            status: -1,
            json: std::ptr::null_mut(),
        }
    }

    // --- the reason contract ---------------------------------------------

    /// The ABI table follows the library's declaration order. This is the
    /// test that fails if a new `Reason` is ever added without the header's
    /// enum growing a name to match.
    #[test]
    fn reason_codes_mirror_the_library() {
        assert_eq!(Reason::ALL.len(), REASON_CODES.len());
        for (reason, (code, token)) in Reason::ALL.iter().zip(REASON_CODES.iter()) {
            assert_eq!(reason_code(*reason), *code, "code for {reason:?}");
            assert_eq!(*token, reason.token(), "token for {reason:?}");
            assert_eq!(
                status_token(*code),
                reason.token(),
                "status_token for {code}"
            );
        }
        for (variant, code) in [
            (AprvReason::InvalidCertificate, 2),
            (AprvReason::InvalidCertificatePurpose, 3),
            (AprvReason::InvalidSignature, 5),
            (AprvReason::InternalError, 12),
            (AprvReason::Malformed, 13),
            (AprvReason::TooLarge, 14),
            (AprvReason::UntrustedChain, 15),
            (AprvReason::UnreadablePayload, 16),
        ] {
            assert_eq!(variant as i32, code);
        }
        // Retired numbers are never a verdict again.
        for retired in [1, 4, 6, 7, 8, 9, 10, 11] {
            assert_eq!(status_token(retired), "UNKNOWN_REASON", "{retired}");
        }
    }

    #[test]
    fn abi_status_tokens_are_distinct_from_the_reason_band() {
        assert_eq!(status_token(AprvReason::NullPointer as i32), "NULL_POINTER");
        assert_eq!(status_token(AprvReason::InvalidUtf8 as i32), "INVALID_UTF8");
        assert_eq!(
            status_token(AprvReason::InvalidArgument as i32),
            "INVALID_ARGUMENT"
        );
        assert_eq!(status_token(AprvReason::Panic as i32), "PANIC");
    }

    #[test]
    fn the_error_document_escapes_its_message() {
        assert_eq!(
            error_json(13, "a \"b\"\\\n\u{1}\t\r\u{8}\u{c}\u{1F600}"),
            r#"{"reason":"MALFORMED","message":"a \"b\"\\\n\u0001\t\r\b\f😀"}"#
        );
    }

    // --- panic containment ------------------------------------------------

    /// The mechanism every export shares, exercised directly: a panic inside
    /// the guarded body becomes a status code and does not unwind.
    #[test]
    fn a_panic_inside_the_guard_becomes_a_status() {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let code = guard(|| panic!("deliberate"));
        let pointer = guard_ptr(|| -> *mut AprvVerifier { panic!("deliberate") });
        std::panic::set_hook(previous);
        assert_eq!(code, AprvReason::Panic as i32);
        assert!(pointer.is_null());
    }

    /// Panic containment is only a property of the ABI if EVERY export has
    /// it. Source-level, because there is no way to ask the linker whether a
    /// symbol can unwind.
    #[test]
    fn every_exported_function_is_guarded() {
        let lines: Vec<&str> = include_str!("lib.rs").lines().collect();
        let mut exports = 0;
        for (index, line) in lines.iter().enumerate() {
            if line.trim() != "#[no_mangle]" {
                continue;
            }
            exports += 1;
            let head = lines[index + 1..].iter().take(24);
            let mut name = "<unnamed>";
            let mut guarded = false;
            for candidate in head {
                if let Some(rest) = candidate.split("fn ").nth(1) {
                    if name == "<unnamed>" {
                        name = rest.split('(').next().unwrap_or(rest);
                    }
                }
                if candidate.contains("guard(") || candidate.contains("guard_ptr(") {
                    guarded = true;
                    break;
                }
            }
            assert!(
                guarded || name == "aprv_version",
                "exported fn {name} does not run its body inside a panic guard"
            );
        }
        assert_eq!(
            exports, 10,
            "the ABI exports {exports} symbols; update this count deliberately, \
             it is the check that a new export was not added unguarded"
        );
    }

    // --- null and invalid input ------------------------------------------

    #[test]
    fn anchor_arguments_that_disagree_are_refused() {
        let junk: [u8; 4] = [0, 1, 2, 3];
        let ders = [junk.as_ptr()];
        let lens = [junk.len()];
        unsafe {
            // Not a certificate.
            assert!(aprv_verifier_new(ders.as_ptr(), lens.as_ptr(), 1, std::ptr::null()).is_null());
            // A count of zero with an array.
            assert!(aprv_verifier_new(ders.as_ptr(), lens.as_ptr(), 0, std::ptr::null()).is_null());
            // A count with no array.
            assert!(
                aprv_verifier_new(std::ptr::null(), lens.as_ptr(), 1, std::ptr::null()).is_null()
            );
            // A null entry inside the array.
            let null_entry = [std::ptr::null::<u8>()];
            assert!(
                aprv_verifier_new(null_entry.as_ptr(), lens.as_ptr(), 1, std::ptr::null())
                    .is_null()
            );
        }
    }

    #[test]
    fn anchor_lengths_over_ptrdiff_max_are_refused_before_a_slice_is_built() {
        // Round-3 review F8: the header promises INVALID_ARGUMENT for a
        // length over PTRDIFF_MAX, and building a slice that long is
        // undefined behaviour before a byte is read.
        let junk: [u8; 4] = [0, 1, 2, 3];
        let ders = [junk.as_ptr()];
        let too_long = [usize::try_from(isize::MAX).unwrap() + 1];
        let invalid = Err(AprvReason::InvalidArgument as i32);
        unsafe {
            assert_eq!(anchors_of(ders.as_ptr(), too_long.as_ptr(), 1), invalid);
            let lens = [junk.len()];
            assert_eq!(
                anchors_of(ders.as_ptr(), lens.as_ptr(), usize::MAX),
                invalid
            );
            let count = usize::try_from(isize::MAX).unwrap() / 4;
            assert_eq!(anchors_of(ders.as_ptr(), lens.as_ptr(), count), invalid);
            assert_eq!(
                anchors_of(ders.as_ptr(), lens.as_ptr(), 1),
                Ok(vec![junk.to_vec()])
            );
            assert!(
                aprv_verifier_new(ders.as_ptr(), too_long.as_ptr(), 1, std::ptr::null()).is_null()
            );
        }
    }

    #[test]
    fn a_null_verifier_handle_is_reported_not_dereferenced() {
        let jws = CString::new("not.a.jws").unwrap();
        let mut out = empty_result();
        let status =
            unsafe { aprv_verify_signed_data(std::ptr::null(), jws.as_ptr(), &raw mut out) };
        assert_eq!(status, AprvReason::NullPointer as i32);
        assert_eq!(out.status, status);
        assert!(take_json(out).contains("NULL_POINTER"));
    }

    #[test]
    fn a_null_input_string_is_reported() {
        let verifier = bundled();
        let mut out = empty_result();
        let status = unsafe { aprv_verify_receipt(verifier, std::ptr::null(), &raw mut out) };
        assert_eq!(status, AprvReason::NullPointer as i32);
        assert!(take_json(out).contains("NULL_POINTER"));
        unsafe { aprv_verifier_free(verifier) };
    }

    #[test]
    fn invalid_utf8_is_its_own_status_and_never_a_verdict() {
        let verifier = bundled();
        // 0xFF is not a valid UTF-8 byte in any position.
        let bytes: [c_char; 4] = [0x65, -1_i8 as c_char, 0x65, 0];
        for call in [aprv_verify_signed_data, aprv_verify_receipt] {
            let mut out = empty_result();
            let status = unsafe { call(verifier, bytes.as_ptr(), &raw mut out) };
            assert_eq!(status, AprvReason::InvalidUtf8 as i32);
            assert!(take_json(out).contains("INVALID_UTF8"));
        }
        unsafe { aprv_verifier_free(verifier) };
    }

    #[test]
    fn a_null_out_parameter_still_returns_the_status() {
        let verifier = bundled();
        let jws = CString::new("not.a.jws").unwrap();
        let status =
            unsafe { aprv_verify_signed_data(verifier, jws.as_ptr(), std::ptr::null_mut()) };
        assert_eq!(status, AprvReason::Malformed as i32);
        unsafe { aprv_verifier_free(verifier) };
    }

    // --- verdicts ---------------------------------------------------------

    #[test]
    fn a_malformed_jws_is_a_verdict_with_the_canonical_token() {
        let verifier = bundled();
        let jws = CString::new("not.a.jws").unwrap();
        let mut out = empty_result();
        let status = unsafe { aprv_verify_signed_data(verifier, jws.as_ptr(), &raw mut out) };
        assert_eq!(status, AprvReason::Malformed as i32);
        let json = take_json(out);
        assert!(json.contains("\"reason\":\"MALFORMED\""), "{json}");
        assert!(json.contains("\"message\":"), "{json}");
        unsafe { aprv_verifier_free(verifier) };
    }

    #[test]
    fn an_empty_receipt_is_a_format_verdict_not_a_crash() {
        let verifier = bundled();
        let empty = CString::new("").unwrap();
        let mut out = empty_result();
        let status = unsafe { aprv_verify_receipt(verifier, empty.as_ptr(), &raw mut out) };
        assert_eq!(status, AprvReason::Malformed as i32);
        assert!(take_json(out).contains("MALFORMED"));
        unsafe { aprv_verifier_free(verifier) };
    }

    /// The receipt document is aprv-wire's, byte for byte: the bytes
    /// aprv.wasm returns as its payload, which is what the design promises
    /// the ABI returns.
    #[test]
    fn a_verified_receipt_is_exactly_the_wire_payload() {
        let der = std::fs::read(fixture("generated-0.7/receipt.der")).unwrap();
        let root = std::fs::read(fixture("generated-0.7/receipt-root.der")).unwrap();
        let base64 = CString::new(base64_encode(&der)).unwrap();
        let expected = aprv_wire::receipt_payload(
            &Verifier::new(&[root])
                .unwrap()
                .verify_receipt(base64.as_bytes(), NOW)
                .unwrap(),
        );
        let verifier = pinned("generated-0.7/receipt-root.der");
        let mut out = empty_result();
        let status = unsafe { aprv_verify_receipt(verifier, base64.as_ptr(), &raw mut out) };
        assert_eq!(status, AprvReason::Ok as i32);
        assert_eq!(take_json(out), expected);
        unsafe { aprv_verifier_free(verifier) };
    }

    /// A JWS payload comes back as the signed text, not a re-serialisation.
    #[test]
    fn a_verified_jws_is_the_signed_payload_text() {
        let jws = std::fs::read_to_string(fixture("generated/transaction.jws")).unwrap();
        let verifier = pinned("generated/jws-root.der");
        let jws = CString::new(jws.trim()).unwrap();
        let mut out = empty_result();
        let status = unsafe { aprv_verify_signed_data(verifier, jws.as_ptr(), &raw mut out) };
        assert_eq!(status, AprvReason::Ok as i32);
        let json = take_json(out);
        assert!(json.contains("\"signedDate\":1722945600000"), "{json}");
        unsafe { aprv_verifier_free(verifier) };
    }

    /// The endpoint's contract: never an error return, always a status
    /// inside the body.
    #[test]
    fn the_endpoint_answers_a_body_for_junk() {
        let verifier = bundled();
        let body = CString::new("not json at all").unwrap();
        let mut response: *mut c_char = std::ptr::null_mut();
        let status = unsafe {
            aprv_verify_receipt_endpoint(
                verifier,
                AprvEnvironment::Sandbox as u32,
                body.as_ptr(),
                &raw mut response,
            )
        };
        assert_eq!(status, AprvReason::Ok as i32);
        let text = unsafe { CStr::from_ptr(response) }
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(text, "{\"status\":21002}");
        unsafe { aprv_string_free(response) };
        unsafe { aprv_verifier_free(verifier) };
    }

    #[test]
    fn the_endpoint_takes_exactly_production_or_sandbox() {
        let verifier = bundled();
        let body = CString::new("{}").unwrap();
        for environment in [0, 3, 4] {
            let mut response: *mut c_char = std::ptr::null_mut();
            let status = unsafe {
                aprv_verify_receipt_endpoint(
                    verifier,
                    environment,
                    body.as_ptr(),
                    &raw mut response,
                )
            };
            assert_eq!(status, AprvReason::InvalidArgument as i32);
            assert!(response.is_null());
        }
        unsafe { aprv_verifier_free(verifier) };
    }

    #[test]
    fn a_null_endpoint_handle_leaves_the_out_parameter_untouched() {
        let body = CString::new("{}").unwrap();
        let mut response: *mut c_char = std::ptr::null_mut();
        let status = unsafe {
            aprv_verify_receipt_endpoint(std::ptr::null(), 2, body.as_ptr(), &raw mut response)
        };
        assert_eq!(status, AprvReason::NullPointer as i32);
        assert!(response.is_null());
    }

    // --- the clock --------------------------------------------------------

    /// The pinned clock stamps the endpoint's `request_date`;
    /// `receipt_creation_date` comes from the signed bytes and does not
    /// move.
    #[test]
    fn a_pinned_clock_stamps_the_endpoint_request_date() {
        let der = std::fs::read(fixture("generated-0.7/receipt.der")).unwrap();
        let body = format!("{{\"receipt-data\":\"{}\"}}", base64_encode(&der));
        let body = CString::new(body).unwrap();
        let verifier = pinned("generated-0.7/receipt-root.der");
        let mut response: *mut c_char = std::ptr::null_mut();
        let status = unsafe {
            aprv_verify_receipt_endpoint(
                verifier,
                AprvEnvironment::Sandbox as u32,
                body.as_ptr(),
                &raw mut response,
            )
        };
        assert_eq!(status, AprvReason::Ok as i32);
        let text = unsafe { CStr::from_ptr(response) }
            .to_str()
            .unwrap()
            .to_owned();
        unsafe { aprv_string_free(response) };
        unsafe { aprv_verifier_free(verifier) };

        assert!(text.contains("\"status\":0"), "{text}");
        assert!(
            text.contains("\"request_date_ms\":\"1735689600000\""),
            "{text}"
        );
        assert!(
            text.contains("\"receipt_creation_date_ms\":\"1722945600000\""),
            "{text}"
        );
    }

    /// The pinned clock also stands in for a missing signing date: a
    /// dateless receipt is judged at it, so moving it past the chain's
    /// window moves the verdict.
    #[test]
    fn a_pinned_clock_judges_a_dateless_receipt() {
        let der = std::fs::read(fixture("generated-0.7/receipt-no-creation-date.der")).unwrap();
        let root = std::fs::read(fixture("generated-0.7/divergence-receipt-root.der")).unwrap();
        let base64 = CString::new(base64_encode(&der)).unwrap();
        let ders = [root.as_ptr()];
        let lens = [root.len()];
        for (now, expected) in [
            (NOW, AprvReason::Ok),
            (4_070_908_800_000, AprvReason::InvalidCertificate),
        ] {
            let verifier =
                unsafe { aprv_verifier_new(ders.as_ptr(), lens.as_ptr(), 1, &raw const now) };
            let status =
                unsafe { aprv_verify_receipt(verifier, base64.as_ptr(), std::ptr::null_mut()) };
            assert_eq!(status, expected as i32, "at {now}");
            unsafe { aprv_verifier_free(verifier) };
        }
    }

    // --- the rest of the surface -----------------------------------------

    #[test]
    fn the_version_is_the_library_version() {
        let version = unsafe { CStr::from_ptr(aprv_version()) }.to_str().unwrap();
        assert_eq!(version, aprv_surface::VERSION);
        assert_eq!(version.split('.').count(), 3, "{version} is not x.y.z");
        assert!(version.split('.').all(|part| part.parse::<u32>().is_ok()));
        // Static: the same pointer every call, and never freed.
        assert_eq!(aprv_version(), aprv_version());
    }

    #[test]
    fn freeing_null_is_a_no_op() {
        unsafe {
            aprv_verifier_free(std::ptr::null_mut());
            aprv_string_free(std::ptr::null_mut());
        }
    }

    /// The caller-supplied-anchor path really is pinned: the fixture that
    /// verifies under its own generated root is rejected under the bundled
    /// Apple roots.
    #[test]
    fn the_bundled_roots_do_not_accept_the_fixture_chain() {
        let jws = std::fs::read_to_string(fixture("generated/transaction.jws")).unwrap();
        let jws = CString::new(jws.trim()).unwrap();
        let verifier = bundled();
        let mut out = empty_result();
        let status = unsafe { aprv_verify_signed_data(verifier, jws.as_ptr(), &raw mut out) };
        assert_eq!(status, AprvReason::UntrustedChain as i32);
        assert!(take_json(out).contains("UNTRUSTED_CHAIN"));
        unsafe { aprv_verifier_free(verifier) };
    }

    // --- the _bytes calls: aprv.wasm's answer for every input -------------

    fn receipt_bytes(verifier: *const AprvVerifier, input: &[u8]) -> (i32, String) {
        let mut out = empty_result();
        let status = unsafe {
            aprv_verify_receipt_bytes(verifier, input.as_ptr(), input.len(), &raw mut out)
        };
        assert_eq!(out.status, status);
        (status, take_json(out))
    }

    /// The document is `aprv-wire`'s over the surface's answer, which is
    /// what `aprv.wasm`'s body writes for the same bytes.
    #[test]
    fn a_bytes_call_answers_the_modules_document() {
        let der = std::fs::read(fixture("generated-0.7/receipt.der")).unwrap();
        let root = std::fs::read(fixture("generated-0.7/receipt-root.der")).unwrap();
        let base64 = base64_encode(&der);
        let surface = Verifier::new(&[root]).unwrap();
        let verifier = pinned("generated-0.7/receipt-root.der");
        let inputs: [&[u8]; 4] = [base64.as_bytes(), b"", b"QUJD", b"\xff\xfe"];
        for input in inputs {
            let expected = aprv_wire::verify_receipt_result(&surface.verify_receipt(input, NOW));
            assert_eq!(receipt_bytes(verifier, input).1, expected, "{input:?}");
        }
        let (status, json) = receipt_bytes(verifier, base64.as_bytes());
        assert_eq!(status, AprvReason::Ok as i32);
        assert!(
            json.starts_with("{\"verified\":true,\"payload\":{"),
            "{json}"
        );
        unsafe { aprv_verifier_free(verifier) };
    }

    /// A C string ends at its first NUL; bytes do not. A genuine receipt
    /// followed by a NUL and junk verifies through the 0.7 call and is
    /// `MALFORMED` through the bytes call, as through `aprv.wasm` (review
    /// round 2, F3).
    #[test]
    fn an_embedded_nul_is_part_of_the_input() {
        let der = std::fs::read(fixture("generated-0.7/receipt.der")).unwrap();
        let mut input = base64_encode(&der).into_bytes();
        input.extend_from_slice(b"\0this is not base64");
        let verifier = pinned("generated-0.7/receipt-root.der");
        let (status, json) = receipt_bytes(verifier, &input);
        assert_eq!(status, AprvReason::Malformed as i32, "{json}");
        assert!(
            json.starts_with("{\"verified\":false,\"reason\":\"MALFORMED\""),
            "{json}"
        );
        let c_string = CString::new(&input[..input.iter().position(|b| *b == 0).unwrap()]).unwrap();
        let old = unsafe { aprv_verify_receipt(verifier, c_string.as_ptr(), std::ptr::null_mut()) };
        assert_eq!(
            old,
            AprvReason::Ok as i32,
            "the 0.7 call reads up to the NUL"
        );
        unsafe { aprv_verifier_free(verifier) };
    }

    /// Bytes that are not UTF-8 are a verdict, never `INVALID_UTF8`.
    #[test]
    fn bytes_that_are_not_utf8_are_a_verdict() {
        let verifier = bundled();
        let input = [0x65, 0xff, 0x2e, 0x65, 0x2e, 0x65];
        let mut out = empty_result();
        let status = unsafe {
            aprv_verify_signed_data_bytes(verifier, input.as_ptr(), input.len(), &raw mut out)
        };
        assert_eq!(status, AprvReason::Malformed as i32);
        assert!(take_json(out).starts_with("{\"verified\":false,\"reason\":\"MALFORMED\""));
        let (status, _) = receipt_bytes(verifier, &input);
        assert_eq!(status, AprvReason::Malformed as i32);
        let mut response: *mut c_char = std::ptr::null_mut();
        let status = unsafe {
            aprv_verify_receipt_endpoint_bytes(
                verifier,
                2,
                input.as_ptr(),
                input.len(),
                &raw mut response,
            )
        };
        assert_eq!(status, AprvReason::Ok as i32);
        let body = unsafe { CStr::from_ptr(response) }
            .to_str()
            .unwrap()
            .to_owned();
        unsafe { aprv_string_free(response) };
        assert_eq!(body, "{\"status\":21002}");
        unsafe { aprv_verifier_free(verifier) };
    }

    /// `NULL` with a length of zero is the empty input; `NULL` with a length
    /// is a call mistake, and a call mistake carries no document.
    #[test]
    fn a_null_range_is_empty_only_at_length_zero() {
        let verifier = bundled();
        let mut out = empty_result();
        let status =
            unsafe { aprv_verify_receipt_bytes(verifier, std::ptr::null(), 0, &raw mut out) };
        assert_eq!(status, AprvReason::Malformed as i32);
        assert!(take_json(out).contains("\"verified\":false"));
        let mut out = empty_result();
        let status =
            unsafe { aprv_verify_receipt_bytes(verifier, std::ptr::null(), 4, &raw mut out) };
        assert_eq!(status, AprvReason::NullPointer as i32);
        assert!(out.json.is_null());
        let byte = [0u8];
        let mut out = empty_result();
        let status = unsafe {
            aprv_verify_signed_data_bytes(verifier, byte.as_ptr(), usize::MAX, &raw mut out)
        };
        assert_eq!(status, AprvReason::InvalidArgument as i32);
        assert!(out.json.is_null());
        let mut out = empty_result();
        let status = unsafe {
            aprv_verify_signed_data_bytes(std::ptr::null(), byte.as_ptr(), 1, &raw mut out)
        };
        assert_eq!(status, AprvReason::NullPointer as i32);
        assert!(out.json.is_null());
        unsafe { aprv_verifier_free(verifier) };
    }

    // --- the header and the exports ----------------------------------------

    /// Every export is declared in the committed header with its parameter
    /// count, and the header declares nothing this file does not export.
    /// The exact bytes are cbindgen's and are checked by
    /// `rust/ffi/check-header.sh`; this catches a stale header without it.
    #[test]
    fn the_committed_header_declares_exactly_the_exports() {
        let source = include_str!("lib.rs");
        let header = include_str!("../include/apple_purchase_receipt_verifier.h");
        let lines: Vec<&str> = source.lines().collect();
        let mut exports = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            if line.trim() != "#[no_mangle]" {
                continue;
            }
            let signature: String = lines[index + 1..]
                .iter()
                .take_while(|l| !l.contains('{'))
                .chain(lines[index + 1..].iter().find(|l| l.contains('{')))
                .copied()
                .collect();
            let name = signature
                .split("fn ")
                .nth(1)
                .unwrap()
                .split('(')
                .next()
                .unwrap()
                .to_owned();
            let params = signature
                .split('(')
                .nth(1)
                .unwrap()
                .split(')')
                .next()
                .unwrap();
            let count = params.split(',').filter(|p| !p.trim().is_empty()).count();
            exports.push((name, count));
        }
        // The declarations: code lines (not comments) naming `aprv_...(`,
        // each with its parameter list up to the closing parenthesis.
        let code: Vec<&str> = header
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !(t.starts_with("//") || t.starts_with("/*") || t.starts_with('*'))
            })
            .collect();
        let text = code.join("\n");
        let mut declared: Vec<(String, usize)> = Vec::new();
        for (at, _) in text.match_indices("aprv_") {
            let before = text[..at].chars().last().unwrap_or(' ');
            let rest = &text[at..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !(before == ' ' || before == '*') || !rest[name.len()..].starts_with('(') {
                continue;
            }
            let params = rest[name.len() + 1..].split(')').next().unwrap();
            let count = if params.trim() == "void" {
                0
            } else {
                params.split(',').count()
            };
            declared.push((name, count));
        }
        exports.sort();
        declared.sort();
        assert_eq!(
            declared, exports,
            "the header's declarations against the exports"
        );
        for (variant, value) in [
            ("APRV_REASON_NULL_POINTER", 100),
            ("APRV_REASON_INVALID_ARGUMENT", 102),
            ("APRV_REASON_UNREADABLE_PAYLOAD", 16),
        ] {
            assert!(
                header.contains(&format!("{variant} = {value}")),
                "{variant}"
            );
        }
    }

    fn base64_encode(bytes: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    /// Walks up from this crate to the repository's `fixtures/`, never a
    /// `../../..` literal, so moving the crate fails loudly rather than
    /// pointing the tests at nothing.
    fn fixture(relative: &str) -> std::path::PathBuf {
        let mut dir: &std::path::Path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        loop {
            let candidate = dir.join("fixtures");
            if candidate.join("cases.json").is_file() {
                return candidate.join(relative);
            }
            dir = dir
                .parent()
                .expect("no fixtures/ above the crate directory");
        }
    }
}
