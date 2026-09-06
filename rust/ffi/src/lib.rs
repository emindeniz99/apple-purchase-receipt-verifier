//! The C ABI over [`apple_purchase_receipt_verifier`].
//!
//! Everything a C caller needs is in this one file, and the header that
//! ships with it (`include/apple_purchase_receipt_verifier.h`) is generated
//! from it by cbindgen. The shape is deliberately narrow: three opaque
//! handles, seven verification calls, one result struct, one free function.
//!
//! # Why JSON is the interchange
//!
//! A verified transaction is an open-ended JSON claim set and a verified
//! receipt is a tree with repeated groups and raw byte attributes. Modelling
//! either as C structs would put every field of a wire format Apple extends
//! at will into the ABI, and every addition would then be a breaking change
//! for every consumer. Handing back one UTF-8 JSON document instead keeps
//! the ABI at a handful of functions and moves the schema question into a
//! parser the caller already has.
//!
//! # Panics never cross the boundary
//!
//! Unwinding out of an `extern "C"` function is undefined behaviour. Every
//! exported function here is a single call to [`guard`] or [`guard_ptr`],
//! which run the real body inside [`std::panic::catch_unwind`] and report a
//! caught panic as [`AprvReason::Panic`] (or a null handle). The
//! `every_exported_function_is_guarded` test reads this file and fails if an
//! export is ever added that does not do that.

#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::missing_panics_doc)]

use apple_purchase_receipt_verifier::serde_json::{Map, Value};
use apple_purchase_receipt_verifier::{
    apple_jws_roots, apple_receipt_roots, datetime, AppReceipt, Environment, InAppPurchase,
    JwsVerifier, Reason, ReceiptVerifier, TrustAnchor, VerificationError, VerifyReceiptEndpoint,
};
use std::ffi::{c_char, CStr, CString};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

// --- status codes --------------------------------------------------------

/// The value of [`AprvResult::status`], and the return value of every
/// verification call.
///
/// Two bands, and the split is the point: `1..=11` is a **verdict about the
/// input** — the canonical cross-port [`Reason`] vocabulary, in the order
/// `Reason` declares it — while `100..` is a **mistake in the call itself**,
/// where nothing about the input was checked. A caller that treats
/// `APRV_REASON_NULL_POINTER` as "the receipt is forged" is reporting its own
/// bug as an attack.
///
/// **Stable and append-only.** These numbers are part of the ABI: a value is
/// never reused for a different meaning and an existing value never changes.
/// A twelfth verification reason — which the cross-port contract makes a
/// deliberate, all-nine-ports change — would be 12.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AprvReason {
    /// The call succeeded. `AprvResult::json` holds the payload.
    Ok = 0,

    /// The compact JWS is not three base64url segments of the right shape.
    InvalidJwsFormat = 1,
    /// An `x5c` entry is not a parseable X.509 certificate.
    InvalidCertificate = 2,
    /// A certificate lacks the Apple marker OID for this purpose.
    InvalidCertificatePurpose = 3,
    /// The path does not reach a pinned anchor, or was not valid then.
    InvalidChain = 4,
    /// The signature did not verify.
    InvalidSignature = 5,
    /// The verified payload names a different bundle id.
    WrongBundleId = 6,
    /// The verified environment is outside the accepted set.
    WrongEnvironment = 7,
    /// A Production `AppTransaction` names a different app Apple id.
    WrongAppAppleId = 8,
    /// The legacy PKCS#7 receipt could not be parsed.
    InvalidReceiptFormat = 9,
    /// `SHA1(guid || opaqueValue || bundleIdBytes)` does not match.
    DeviceHashMismatch = 10,
    /// The payload was signed longer ago than the configured maximum.
    StalePayload = 11,

    /// A required pointer argument was `NULL`. Nothing was verified.
    NullPointer = 100,
    /// A `const char *` argument was not valid UTF-8. Nothing was verified.
    InvalidUtf8 = 101,
    /// A configuration argument was rejected — an empty bundle id, an empty
    /// or unknown environment mask, no trust anchors, bytes that are not a
    /// certificate. Nothing was verified.
    InvalidArgument = 102,
    /// A panic was caught at the boundary. Nothing crossed it. This is a bug
    /// in the library; please report it.
    Panic = 103,
    /// The library returned a verification reason this ABI has no code for,
    /// which can only happen if the two are built from different versions.
    /// Treat it as a rejection.
    UnknownReason = 104,
}

/// The four App Store environments, as bits of the `accepted_environments`
/// mask. OR them together; `0` is rejected.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AprvEnvironment {
    /// `Production`
    Production = 1,
    /// `Sandbox`
    Sandbox = 2,
    /// `Xcode` — `StoreKit` Testing in Xcode; not Apple-signed.
    Xcode = 4,
    /// `LocalTesting` — `StoreKit` Test in a simulator.
    LocalTesting = 8,
}

/// The outcome of one verification call.
///
/// `json` is owned by the caller and must be released with
/// [`aprv_string_free`]. It is `NULL` only when the allocation itself could
/// not be made.
///
/// * `status == APRV_REASON_OK` — `json` is the verified payload: the claim
///   object for the JWS calls, the normalised receipt object for the receipt
///   calls.
/// * anything else — `json` is `{"reason":"<token>","message":"<detail>"}`.
///   The token is the `SCREAMING_SNAKE` spelling every port of this library
///   shares; the message is a short, non-sensitive description that never
///   contains receipt bytes, claims or key material. Match on `status`, or
///   on `reason`; never parse `message`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AprvResult {
    /// An [`AprvReason`] value.
    pub status: i32,
    /// Owned, NUL-terminated UTF-8 JSON. Free with [`aprv_string_free`].
    pub json: *mut c_char,
}

// --- opaque handles ------------------------------------------------------

/// A verifier for Apple-signed JWS payloads. Created by
/// `aprv_verifier_new_jws`, released by `aprv_verifier_free_jws`.
///
/// Immutable once built, and safe to share between threads: any number of
/// threads may verify through the same handle at the same time. Freeing it
/// while another thread is inside a call is not.
pub struct AprvJwsVerifier {
    inner: JwsVerifier,
}

/// A verifier for legacy PKCS#7 app receipts. Same thread-safety rule as
/// [`AprvJwsVerifier`].
pub struct AprvReceiptVerifier {
    inner: ReceiptVerifier,
}

/// The local `verifyReceipt` endpoint. Same thread-safety rule as
/// [`AprvJwsVerifier`].
pub struct AprvReceiptEndpoint {
    inner: VerifyReceiptEndpoint,
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

/// [`guard`] for the constructors: a caught panic yields a null handle,
/// which is what every other construction failure yields too.
fn guard_ptr<T, F: FnOnce() -> *mut T>(body: F) -> *mut T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(pointer) => pointer,
        Err(_) => std::ptr::null_mut(),
    }
}

// --- small conversions ---------------------------------------------------

/// The canonical reason tokens, in the order `Reason` declares them. The
/// index of a token here is its ABI code minus one, and
/// `reason_codes_mirror_the_library` asserts that against `Reason::all()`.
const REASON_TOKENS: [&str; 11] = [
    "INVALID_JWS_FORMAT",
    "INVALID_CERTIFICATE",
    "INVALID_CERTIFICATE_PURPOSE",
    "INVALID_CHAIN",
    "INVALID_SIGNATURE",
    "WRONG_BUNDLE_ID",
    "WRONG_ENVIRONMENT",
    "WRONG_APP_APPLE_ID",
    "INVALID_RECEIPT_FORMAT",
    "DEVICE_HASH_MISMATCH",
    "STALE_PAYLOAD",
];

/// The ABI code for a library reason.
///
/// Derived from position in `Reason::all()` rather than written out as a
/// `match`, because `Reason` is `#[non_exhaustive]`: a match would need a
/// wildcard arm, and a wildcard arm is exactly how a newly added twelfth
/// reason would silently become an existing code.
fn reason_code(reason: Reason) -> i32 {
    match Reason::all().iter().position(|known| *known == reason) {
        Some(index) if index < REASON_TOKENS.len() => {
            i32::try_from(index).unwrap_or(0).saturating_add(1)
        }
        _ => AprvReason::UnknownReason as i32,
    }
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
        other => usize::try_from(other)
            .ok()
            .and_then(|index| index.checked_sub(1))
            .and_then(|index| REASON_TOKENS.get(index))
            .copied()
            .unwrap_or("UNKNOWN_REASON"),
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
    CStr::from_ptr(pointer)
        .to_str()
        .map_err(|_| AprvReason::InvalidUtf8 as i32)
}

/// Borrows a caller-owned byte slice.
///
/// # Safety
/// `pointer`, when non-null, must point at `len` readable bytes.
unsafe fn borrow_bytes<'a>(pointer: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if pointer.is_null() {
        return Err(AprvReason::NullPointer as i32);
    }
    // A zero length is legal input, and `from_raw_parts` still wants a
    // non-null, aligned pointer; the null check above has already run.
    Ok(std::slice::from_raw_parts(pointer, len))
}

/// The environments a mask names, or `Err` for `0` or an unknown bit. An
/// unknown bit is refused rather than ignored: silently dropping it would
/// build a verifier that accepts less than the caller asked for, and the
/// failure would show up as `WRONG_ENVIRONMENT` on a genuine payload.
fn environments_of(mask: u32) -> Result<Vec<Environment>, i32> {
    const KNOWN: [(u32, Environment); 4] = [
        (1, Environment::Production),
        (2, Environment::Sandbox),
        (4, Environment::Xcode),
        (8, Environment::LocalTesting),
    ];
    if mask == 0 || mask & !0b1111 != 0 {
        return Err(AprvReason::InvalidArgument as i32);
    }
    Ok(KNOWN
        .iter()
        .filter(|(bit, _)| mask & bit != 0)
        .map(|(_, environment)| *environment)
        .collect())
}

/// Parses the caller's DER anchors, or falls back to the bundled Apple roots
/// when `count` is zero and no array was passed.
///
/// # Safety
/// When `count` is non-zero, `ders` must point at `count` readable pointers
/// and `lens` at `count` readable lengths, each pair describing a readable
/// DER certificate.
unsafe fn anchors_of(
    ders: *const *const u8,
    lens: *const usize,
    count: usize,
    fallback: &'static [TrustAnchor],
) -> Result<Vec<TrustAnchor>, i32> {
    if count == 0 {
        if ders.is_null() && lens.is_null() {
            return Ok(fallback.to_vec());
        }
        return Err(AprvReason::InvalidArgument as i32);
    }
    if ders.is_null() || lens.is_null() {
        return Err(AprvReason::NullPointer as i32);
    }
    let pointers = std::slice::from_raw_parts(ders, count);
    let lengths = std::slice::from_raw_parts(lens, count);
    let mut anchors = Vec::with_capacity(count);
    for (pointer, len) in pointers.iter().zip(lengths.iter()) {
        let der = borrow_bytes(*pointer, *len)?;
        anchors.push(TrustAnchor::from_der(der).map_err(|_| AprvReason::InvalidArgument as i32)?);
    }
    Ok(anchors)
}

/// Moves an owned Rust string across the boundary. `None` becomes `NULL`,
/// which is what a caller sees if the string held an interior NUL — nothing
/// this crate produces does.
fn into_c_string(text: Option<String>) -> *mut c_char {
    match text.and_then(|text| CString::new(text).ok()) {
        Some(owned) => owned.into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// The error document: the same two keys for a verdict and for a call
/// mistake, so a caller has one shape to parse.
fn error_json(status: i32, message: &str) -> String {
    let mut object = Map::new();
    object.insert("reason".to_owned(), Value::from(status_token(status)));
    object.insert("message".to_owned(), Value::from(message));
    Value::Object(object).to_string()
}

/// Writes one outcome into the caller's `out`, and returns the status so a
/// caller that only wants the code can ignore `out` entirely.
///
/// # Safety
/// `out`, when non-null, must point at a writable `AprvResult`.
unsafe fn finish(out: *mut AprvResult, status: i32, json: Option<String>) -> i32 {
    if !out.is_null() {
        out.write(AprvResult {
            status,
            json: into_c_string(json),
        });
    }
    status
}

/// Turns a library result into the `(status, json)` pair the ABI reports.
fn outcome(result: Result<Value, VerificationError>) -> (i32, Option<String>) {
    match result {
        Ok(value) => (AprvReason::Ok as i32, Some(value.to_string())),
        Err(error) => {
            let status = reason_code(error.reason());
            (status, Some(error_json(status, error.detail())))
        }
    }
}

// --- the language-neutral receipt view -----------------------------------
//
// A verified `AppReceipt` holds `SystemTime`s, raw byte attributes and a map
// keyed by attribute number, none of which has an obvious JSON spelling. The
// one used here is the shared cross-port view the conformance vectors are
// written against: dates as ISO-8601 UTC, byte fields as lowercase hex
// mirrored under `<name>Hex`, the unknown-attribute map as an object keyed by
// the attribute number as a string. Keeping it identical to
// `rust/tests/conformance.rs` is what lets the same vector file check this
// ABI without a translation layer in between.

fn hex_of(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

fn put_bytes(target: &mut Map<String, Value>, key: &str, bytes: Option<&[u8]>) {
    let value = bytes.map_or(Value::Null, |bytes| Value::from(hex_of(bytes)));
    target.insert(key.to_owned(), value.clone());
    target.insert(format!("{key}Hex"), value);
}

fn put_date(target: &mut Map<String, Value>, key: &str, at: Option<SystemTime>) {
    let value = at.map_or(Value::Null, |at| Value::from(datetime::to_rfc3339_utc(at)));
    target.insert(key.to_owned(), value);
}

fn put_int(target: &mut Map<String, Value>, key: &str, value: Option<i64>) {
    target.insert(key.to_owned(), value.map_or(Value::Null, Value::from));
}

fn put_string(target: &mut Map<String, Value>, key: &str, value: Option<&str>) {
    target.insert(key.to_owned(), value.map_or(Value::Null, Value::from));
}

fn unknown_attributes_json(map: &std::collections::BTreeMap<u32, Vec<Vec<u8>>>) -> Value {
    let mut out = Map::new();
    for (attribute_type, values) in map {
        out.insert(
            attribute_type.to_string(),
            Value::Array(
                values
                    .iter()
                    .map(|value| Value::from(hex_of(value)))
                    .collect(),
            ),
        );
    }
    Value::Object(out)
}

fn in_app_json(purchase: &InAppPurchase) -> Value {
    let mut out = Map::new();
    out.insert(
        "unknownAttributes".to_owned(),
        unknown_attributes_json(&purchase.unknown_attributes),
    );
    put_int(&mut out, "quantity", purchase.quantity);
    put_string(&mut out, "productId", purchase.product_id.as_deref());
    put_string(
        &mut out,
        "transactionId",
        purchase.transaction_id.as_deref(),
    );
    put_string(
        &mut out,
        "originalTransactionId",
        purchase.original_transaction_id.as_deref(),
    );
    put_date(&mut out, "purchaseDate", purchase.purchase_date);
    put_date(
        &mut out,
        "originalPurchaseDate",
        purchase.original_purchase_date,
    );
    put_date(&mut out, "expiresDate", purchase.expires_date);
    put_date(&mut out, "cancellationDate", purchase.cancellation_date);
    put_int(
        &mut out,
        "webOrderLineItemId",
        purchase.web_order_line_item_id,
    );
    put_int(
        &mut out,
        "isInIntroOfferPeriod",
        purchase.is_in_intro_offer_period,
    );
    Value::Object(out)
}

fn app_receipt_json(receipt: &AppReceipt) -> Value {
    let mut out = Map::new();
    out.insert(
        "unknownAttributes".to_owned(),
        unknown_attributes_json(&receipt.unknown_attributes),
    );
    put_string(&mut out, "receiptType", receipt.receipt_type.as_deref());
    put_string(&mut out, "bundleId", receipt.bundle_id.as_deref());
    put_bytes(
        &mut out,
        "bundleIdBytes",
        receipt.bundle_id_bytes.as_deref(),
    );
    put_string(&mut out, "appVersion", receipt.app_version.as_deref());
    put_bytes(&mut out, "opaqueValue", receipt.opaque_value.as_deref());
    put_bytes(&mut out, "sha1Hash", receipt.sha1_hash.as_deref());
    put_date(&mut out, "creationDate", receipt.creation_date);
    put_date(
        &mut out,
        "originalPurchaseDate",
        receipt.original_purchase_date,
    );
    put_string(
        &mut out,
        "originalAppVersion",
        receipt.original_app_version.as_deref(),
    );
    put_date(&mut out, "expirationDate", receipt.expiration_date);
    out.insert(
        "inAppPurchases".to_owned(),
        Value::Array(receipt.in_app_purchases.iter().map(in_app_json).collect()),
    );
    Value::Object(out)
}

// --- exported: version ---------------------------------------------------

/// The library version, as a static NUL-terminated string. **Do not free
/// it**, and do not assume it stays valid across a `dlclose`.
///
/// It is the repository's own `version.txt`, the single file every port's
/// version is bumped from, so it can never drift from the Rust library this
/// ABI is compiled against.
#[no_mangle]
pub extern "C" fn aprv_version() -> *const c_char {
    static VERSION: OnceLock<CString> = OnceLock::new();
    let version = VERSION.get_or_init(|| {
        CString::new(include_str!("../../../version.txt").trim())
            .unwrap_or_else(|_| CString::default())
    });
    version.as_ptr()
}

// --- exported: constructors ----------------------------------------------

/// A JWS verifier pinned to the three bundled Apple roots.
///
/// * `bundle_id` — required, non-empty.
/// * `accepted_environments` — a non-zero OR of [`AprvEnvironment`] bits.
/// * `app_apple_id` — `0` means "not configured"; required to accept a
///   Production `AppTransaction`.
/// * `max_signed_age_secs` — `0` means "no staleness rule".
///
/// Returns `NULL` if any argument is rejected. The handle is owned by the
/// caller and must be released with [`aprv_verifier_free_jws`].
///
/// # Safety
/// `bundle_id` must be `NULL` or a NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn aprv_verifier_new_jws(
    bundle_id: *const c_char,
    accepted_environments: u32,
    app_apple_id: u64,
    max_signed_age_secs: u64,
) -> *mut AprvJwsVerifier {
    guard_ptr(|| {
        new_jws(
            bundle_id,
            accepted_environments,
            app_apple_id,
            max_signed_age_secs,
            std::ptr::null(),
            std::ptr::null(),
            0,
        )
    })
}

/// [`aprv_verifier_new_jws`] with caller-supplied DER trust anchors.
///
/// `ders[i]` / `lens[i]` describe one DER certificate; `count` must be
/// non-zero. Nothing is retained: the bytes are parsed during the call.
///
/// # Safety
/// `bundle_id` must be `NULL` or a NUL-terminated UTF-8 string, and the
/// three anchor arguments must describe `count` readable DER certificates.
#[no_mangle]
pub unsafe extern "C" fn aprv_verifier_new_jws_with_roots(
    bundle_id: *const c_char,
    accepted_environments: u32,
    app_apple_id: u64,
    max_signed_age_secs: u64,
    ders: *const *const u8,
    lens: *const usize,
    count: usize,
) -> *mut AprvJwsVerifier {
    guard_ptr(|| {
        new_jws(
            bundle_id,
            accepted_environments,
            app_apple_id,
            max_signed_age_secs,
            ders,
            lens,
            count,
        )
    })
}

unsafe fn new_jws(
    bundle_id: *const c_char,
    accepted_environments: u32,
    app_apple_id: u64,
    max_signed_age_secs: u64,
    ders: *const *const u8,
    lens: *const usize,
    count: usize,
) -> *mut AprvJwsVerifier {
    let (Ok(bundle_id), Ok(environments), Ok(anchors)) = (
        borrow_str(bundle_id),
        environments_of(accepted_environments),
        anchors_of(ders, lens, count, apple_jws_roots()),
    ) else {
        return std::ptr::null_mut();
    };
    let mut builder = JwsVerifier::builder()
        .trusted_roots(anchors)
        .bundle_id(bundle_id)
        .accepted_environments(environments);
    if app_apple_id != 0 {
        builder = builder.app_apple_id(app_apple_id);
    }
    if max_signed_age_secs != 0 {
        builder = builder.max_signed_age(Duration::from_secs(max_signed_age_secs));
    }
    match builder.build() {
        Ok(inner) => Box::into_raw(Box::new(AprvJwsVerifier { inner })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Releases a handle from `aprv_verifier_new_jws*`. `NULL` is a no-op.
/// Calling it twice on the same handle, or while another thread is inside a
/// verification call on it, is undefined behaviour.
///
/// # Safety
/// `verifier` must be `NULL` or a handle this library returned and that has
/// not been freed.
#[no_mangle]
pub unsafe extern "C" fn aprv_verifier_free_jws(verifier: *mut AprvJwsVerifier) {
    guard(|| {
        if !verifier.is_null() {
            drop(Box::from_raw(verifier));
        }
        AprvReason::Ok as i32
    });
}

/// A legacy-receipt verifier pinned to the three bundled Apple roots.
/// Returns `NULL` if `bundle_id` is null, not UTF-8, or empty.
///
/// # Safety
/// `bundle_id` must be `NULL` or a NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn aprv_verifier_new_receipt(
    bundle_id: *const c_char,
) -> *mut AprvReceiptVerifier {
    guard_ptr(|| new_receipt(bundle_id, std::ptr::null(), std::ptr::null(), 0))
}

/// [`aprv_verifier_new_receipt`] with caller-supplied DER trust anchors.
///
/// # Safety
/// As [`aprv_verifier_new_jws_with_roots`].
#[no_mangle]
pub unsafe extern "C" fn aprv_verifier_new_receipt_with_roots(
    bundle_id: *const c_char,
    ders: *const *const u8,
    lens: *const usize,
    count: usize,
) -> *mut AprvReceiptVerifier {
    guard_ptr(|| new_receipt(bundle_id, ders, lens, count))
}

unsafe fn new_receipt(
    bundle_id: *const c_char,
    ders: *const *const u8,
    lens: *const usize,
    count: usize,
) -> *mut AprvReceiptVerifier {
    let (Ok(bundle_id), Ok(anchors)) = (
        borrow_str(bundle_id),
        anchors_of(ders, lens, count, apple_receipt_roots()),
    ) else {
        return std::ptr::null_mut();
    };
    match ReceiptVerifier::builder()
        .trusted_roots(anchors)
        .bundle_id(bundle_id)
        .build()
    {
        Ok(inner) => Box::into_raw(Box::new(AprvReceiptVerifier { inner })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Releases a handle from `aprv_verifier_new_receipt*`. `NULL` is a no-op.
///
/// # Safety
/// As [`aprv_verifier_free_jws`].
#[no_mangle]
pub unsafe extern "C" fn aprv_verifier_free_receipt(verifier: *mut AprvReceiptVerifier) {
    guard(|| {
        if !verifier.is_null() {
            drop(Box::from_raw(verifier));
        }
        AprvReason::Ok as i32
    });
}

/// A local `verifyReceipt` endpoint pinned to the bundled Apple roots.
///
/// `environment` is exactly one of `APRV_ENVIRONMENT_PRODUCTION` or
/// `APRV_ENVIRONMENT_SANDBOX` — Apple's endpoint has two, and the choice is
/// what drives the local 21007/21008 routing. Anything else returns `NULL`.
///
/// # Safety
/// This function dereferences nothing; it is `unsafe` only for symmetry with
/// the variant that takes anchors.
#[no_mangle]
pub unsafe extern "C" fn aprv_endpoint_new(environment: u32) -> *mut AprvReceiptEndpoint {
    guard_ptr(|| new_endpoint(environment, std::ptr::null(), std::ptr::null(), 0))
}

/// [`aprv_endpoint_new`] with caller-supplied DER trust anchors.
///
/// # Safety
/// As [`aprv_verifier_new_jws_with_roots`].
#[no_mangle]
pub unsafe extern "C" fn aprv_endpoint_new_with_roots(
    environment: u32,
    ders: *const *const u8,
    lens: *const usize,
    count: usize,
) -> *mut AprvReceiptEndpoint {
    guard_ptr(|| new_endpoint(environment, ders, lens, count))
}

unsafe fn new_endpoint(
    environment: u32,
    ders: *const *const u8,
    lens: *const usize,
    count: usize,
) -> *mut AprvReceiptEndpoint {
    let environment = match environment {
        1 => Environment::Production,
        2 => Environment::Sandbox,
        _ => return std::ptr::null_mut(),
    };
    let Ok(anchors) = anchors_of(ders, lens, count, apple_receipt_roots()) else {
        return std::ptr::null_mut();
    };
    match VerifyReceiptEndpoint::builder()
        .trusted_roots(anchors)
        .environment(environment)
        .build()
    {
        Ok(inner) => Box::into_raw(Box::new(AprvReceiptEndpoint { inner })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Releases a handle from `aprv_endpoint_new*`. `NULL` is a no-op.
///
/// # Safety
/// As [`aprv_verifier_free_jws`].
#[no_mangle]
pub unsafe extern "C" fn aprv_endpoint_free(endpoint: *mut AprvReceiptEndpoint) {
    guard(|| {
        if !endpoint.is_null() {
            drop(Box::from_raw(endpoint));
        }
        AprvReason::Ok as i32
    });
}

// --- exported: verification ----------------------------------------------

/// Verifies a signed transaction, then checks bundle id and environment.
///
/// On success `out->json` is the claim object, with Apple's own claim names
/// and Apple's own date spelling (epoch milliseconds).
///
/// # Safety
/// `verifier` must be a live handle, `jws` a NUL-terminated string, and
/// `out` a writable `AprvResult`. Any of them may be `NULL`, which is
/// reported rather than dereferenced.
#[no_mangle]
pub unsafe extern "C" fn aprv_verify_transaction(
    verifier: *const AprvJwsVerifier,
    jws: *const c_char,
    out: *mut AprvResult,
) -> i32 {
    guard(|| jws_call(verifier, jws, out, JwsCall::Transaction))
}

/// Verifies a signed `AppTransaction`, then checks bundle id, environment
/// (`receiptType`) and — in Production — the app Apple id.
///
/// # Safety
/// As [`aprv_verify_transaction`].
#[no_mangle]
pub unsafe extern "C" fn aprv_verify_app_transaction(
    verifier: *const AprvJwsVerifier,
    jws: *const c_char,
    out: *mut AprvResult,
) -> i32 {
    guard(|| jws_call(verifier, jws, out, JwsCall::AppTransaction))
}

/// Verifies the certificate chain and signature only, and returns every
/// claim. **No claim is enforced** — for renewal info and notification
/// envelopes, where the caller must check bundle id, environment and app
/// Apple id itself.
///
/// # Safety
/// As [`aprv_verify_transaction`].
#[no_mangle]
pub unsafe extern "C" fn aprv_verify_raw(
    verifier: *const AprvJwsVerifier,
    jws: *const c_char,
    out: *mut AprvResult,
) -> i32 {
    guard(|| jws_call(verifier, jws, out, JwsCall::Raw))
}

#[derive(Clone, Copy)]
enum JwsCall {
    Transaction,
    AppTransaction,
    Raw,
}

unsafe fn jws_call(
    verifier: *const AprvJwsVerifier,
    jws: *const c_char,
    out: *mut AprvResult,
    which: JwsCall,
) -> i32 {
    if verifier.is_null() {
        return finish(
            out,
            AprvReason::NullPointer as i32,
            Some(error_json(
                AprvReason::NullPointer as i32,
                "verifier handle is NULL",
            )),
        );
    }
    let jws = match borrow_str(jws) {
        Ok(jws) => jws,
        Err(status) => return finish(out, status, Some(error_json(status, "jws argument"))),
    };
    let verifier = &(*verifier).inner;
    let result = match which {
        JwsCall::Transaction => verifier
            .verify_transaction(jws)
            .map(|payload| Value::Object(payload.claims)),
        JwsCall::AppTransaction => verifier
            .verify_app_transaction(jws)
            .map(|payload| Value::Object(payload.claims)),
        JwsCall::Raw => verifier.verify_raw(jws).map(Value::Object),
    };
    let (status, json) = outcome(result);
    finish(out, status, json)
}

/// Verifies a legacy PKCS#7 app receipt in its raw DER form.
///
/// On success `out->json` is the normalised receipt object: dates as
/// ISO-8601 UTC strings, byte attributes as lowercase hex (mirrored under
/// `<name>Hex`), `unknownAttributes` keyed by the attribute number.
///
/// # Safety
/// `verifier` must be a live handle and `der`/`len` must describe `len`
/// readable bytes. `out` must be writable or `NULL`.
#[no_mangle]
pub unsafe extern "C" fn aprv_verify_receipt_der(
    verifier: *const AprvReceiptVerifier,
    der: *const u8,
    len: usize,
    out: *mut AprvResult,
) -> i32 {
    guard(|| receipt_der_call(verifier, der, len, std::ptr::null(), 0, out))
}

/// [`aprv_verify_receipt_der`] that also checks the SHA-1 device hash
/// against `guid`/`guid_len` — attribute 5 must equal
/// `SHA1(guid || opaqueValue || bundleIdBytes)`, or the call fails with
/// `APRV_REASON_DEVICE_HASH_MISMATCH`.
///
/// # Safety
/// As [`aprv_verify_receipt_der`], plus `guid`/`guid_len` describing
/// `guid_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn aprv_verify_receipt_der_with_device_guid(
    verifier: *const AprvReceiptVerifier,
    der: *const u8,
    len: usize,
    guid: *const u8,
    guid_len: usize,
    out: *mut AprvResult,
) -> i32 {
    guard(|| receipt_der_call(verifier, der, len, guid, guid_len, out))
}

unsafe fn receipt_der_call(
    verifier: *const AprvReceiptVerifier,
    der: *const u8,
    len: usize,
    guid: *const u8,
    guid_len: usize,
    out: *mut AprvResult,
) -> i32 {
    if verifier.is_null() {
        return finish(
            out,
            AprvReason::NullPointer as i32,
            Some(error_json(
                AprvReason::NullPointer as i32,
                "verifier handle is NULL",
            )),
        );
    }
    let receipt = match borrow_bytes(der, len) {
        Ok(bytes) => bytes,
        Err(status) => return finish(out, status, Some(error_json(status, "receipt argument"))),
    };
    let verifier = &(*verifier).inner;
    let result = if guid.is_null() && guid_len == 0 {
        verifier.verify(receipt)
    } else {
        match borrow_bytes(guid, guid_len) {
            Ok(guid) => verifier.verify_with_device_guid(receipt, guid),
            Err(status) => return finish(out, status, Some(error_json(status, "guid argument"))),
        }
    };
    let (status, json) = outcome(result.map(|receipt| app_receipt_json(&receipt)));
    finish(out, status, json)
}

/// Verifies a legacy app receipt given as the base64 string a client sends.
///
/// # Safety
/// `verifier` must be a live handle and `receipt_base64` a NUL-terminated
/// string. `out` must be writable or `NULL`.
#[no_mangle]
pub unsafe extern "C" fn aprv_verify_receipt_base64(
    verifier: *const AprvReceiptVerifier,
    receipt_base64: *const c_char,
    out: *mut AprvResult,
) -> i32 {
    guard(|| receipt_base64_call(verifier, receipt_base64, std::ptr::null(), 0, out))
}

/// [`aprv_verify_receipt_base64`] with the SHA-1 device-hash check.
///
/// # Safety
/// As [`aprv_verify_receipt_base64`], plus `guid`/`guid_len` describing
/// `guid_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn aprv_verify_receipt_base64_with_device_guid(
    verifier: *const AprvReceiptVerifier,
    receipt_base64: *const c_char,
    guid: *const u8,
    guid_len: usize,
    out: *mut AprvResult,
) -> i32 {
    guard(|| receipt_base64_call(verifier, receipt_base64, guid, guid_len, out))
}

unsafe fn receipt_base64_call(
    verifier: *const AprvReceiptVerifier,
    receipt_base64: *const c_char,
    guid: *const u8,
    guid_len: usize,
    out: *mut AprvResult,
) -> i32 {
    if verifier.is_null() {
        return finish(
            out,
            AprvReason::NullPointer as i32,
            Some(error_json(
                AprvReason::NullPointer as i32,
                "verifier handle is NULL",
            )),
        );
    }
    let text = match borrow_str(receipt_base64) {
        Ok(text) => text,
        Err(status) => return finish(out, status, Some(error_json(status, "receipt argument"))),
    };
    let verifier = &(*verifier).inner;
    let result = if guid.is_null() && guid_len == 0 {
        verifier.verify_base64(text)
    } else {
        match borrow_bytes(guid, guid_len) {
            Ok(guid) => verifier.verify_base64_with_device_guid(text, guid),
            Err(status) => return finish(out, status, Some(error_json(status, "guid argument"))),
        }
    };
    let (status, json) = outcome(result.map(|receipt| app_receipt_json(&receipt)));
    finish(out, status, json)
}

/// Handles one `verifyReceipt` request body and writes Apple's response body
/// to `*response_json`.
///
/// Like Apple's endpoint this never reports a verification failure through
/// the return value: every verdict is the `status` field **inside** the JSON.
/// A non-zero return means the call itself was malformed — a null argument,
/// a non-UTF-8 body — and `*response_json` is then left untouched.
///
/// `*response_json` is owned by the caller and must be released with
/// [`aprv_string_free`].
///
/// # Safety
/// `endpoint` must be a live handle, `request_json` a NUL-terminated string,
/// and `response_json` a writable `char *`.
#[no_mangle]
pub unsafe extern "C" fn aprv_verify_receipt_endpoint_json(
    endpoint: *const AprvReceiptEndpoint,
    request_json: *const c_char,
    response_json: *mut *mut c_char,
) -> i32 {
    guard(|| {
        if endpoint.is_null() || response_json.is_null() {
            return AprvReason::NullPointer as i32;
        }
        let body = match borrow_str(request_json) {
            Ok(body) => body,
            Err(status) => return status,
        };
        let response = (*endpoint).inner.verify_receipt_json(body);
        response_json.write(into_c_string(Some(response)));
        AprvReason::Ok as i32
    })
}

/// Releases a string this library handed out — an `AprvResult::json` or a
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
            drop(CString::from_raw(text));
        }
        AprvReason::Ok as i32
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every fixture-free assertion here builds its verifier against the
    /// bundled Apple roots, so nothing in this module reads a file.
    fn jws_verifier() -> *mut AprvJwsVerifier {
        let bundle = CString::new("com.example.app").unwrap();
        unsafe { aprv_verifier_new_jws(bundle.as_ptr(), 1 | 2, 0, 0) }
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

    /// The ABI numbers ARE the library's declaration order. This is the test
    /// that fails if a twelfth `Reason` is ever added without the header's
    /// enum growing a twelfth name to match — the append-only promise made
    /// mechanical rather than written down.
    #[test]
    fn reason_codes_mirror_the_library() {
        assert_eq!(
            Reason::all().len(),
            REASON_TOKENS.len(),
            "the library has {} reasons, the ABI enumerates {}",
            Reason::all().len(),
            REASON_TOKENS.len()
        );
        for (index, reason) in Reason::all().iter().enumerate() {
            let code = i32::try_from(index).unwrap() + 1;
            assert_eq!(reason_code(*reason), code, "code for {reason}");
            assert_eq!(REASON_TOKENS[index], reason.as_str(), "token for {reason}");
            assert_eq!(
                status_token(code),
                reason.as_str(),
                "status_token for {code}"
            );
        }
        assert_eq!(AprvReason::InvalidJwsFormat as i32, 1);
        assert_eq!(AprvReason::StalePayload as i32, 11);
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

    // --- panic containment ------------------------------------------------

    /// The mechanism every export shares, exercised directly: a panic inside
    /// the guarded body becomes a status code and does not unwind.
    #[test]
    fn a_panic_inside_the_guard_becomes_a_status() {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let code = guard(|| panic!("deliberate"));
        let pointer = guard_ptr(|| -> *mut AprvJwsVerifier { panic!("deliberate") });
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
            exports, 19,
            "the ABI exports {exports} symbols; update this count deliberately, \
             it is the check that a new export was not added unguarded"
        );
    }

    // --- null and invalid input ------------------------------------------

    #[test]
    fn null_bundle_id_yields_no_handle() {
        let verifier = unsafe { aprv_verifier_new_jws(std::ptr::null(), 1, 0, 0) };
        assert!(verifier.is_null());
        assert!(unsafe { aprv_verifier_new_receipt(std::ptr::null()) }.is_null());
    }

    #[test]
    fn an_empty_bundle_id_is_a_configuration_failure() {
        let empty = CString::new("").unwrap();
        assert!(unsafe { aprv_verifier_new_jws(empty.as_ptr(), 1, 0, 0) }.is_null());
        assert!(unsafe { aprv_verifier_new_receipt(empty.as_ptr()) }.is_null());
    }

    #[test]
    fn an_empty_or_unknown_environment_mask_is_refused() {
        let bundle = CString::new("com.example.app").unwrap();
        assert!(unsafe { aprv_verifier_new_jws(bundle.as_ptr(), 0, 0, 0) }.is_null());
        assert!(unsafe { aprv_verifier_new_jws(bundle.as_ptr(), 0b1_0000, 0, 0) }.is_null());
        assert!(unsafe { aprv_verifier_new_jws(bundle.as_ptr(), 1 | 0b1_0000, 0, 0) }.is_null());
    }

    #[test]
    fn the_endpoint_takes_exactly_production_or_sandbox() {
        assert!(!unsafe { aprv_endpoint_new(1) }.is_null());
        assert!(!unsafe { aprv_endpoint_new(2) }.is_null());
        assert!(unsafe { aprv_endpoint_new(0) }.is_null());
        assert!(unsafe { aprv_endpoint_new(3) }.is_null());
        assert!(unsafe { aprv_endpoint_new(4) }.is_null());
    }

    #[test]
    fn anchor_bytes_that_are_not_a_certificate_are_refused() {
        let bundle = CString::new("com.example.app").unwrap();
        let junk: [u8; 4] = [0, 1, 2, 3];
        let ders = [junk.as_ptr()];
        let lens = [junk.len()];
        let verifier = unsafe {
            aprv_verifier_new_jws_with_roots(
                bundle.as_ptr(),
                1,
                0,
                0,
                ders.as_ptr(),
                lens.as_ptr(),
                1,
            )
        };
        assert!(verifier.is_null());
    }

    #[test]
    fn a_null_verifier_handle_is_reported_not_dereferenced() {
        let jws = CString::new("not.a.jws").unwrap();
        let mut out = empty_result();
        let status = unsafe { aprv_verify_transaction(std::ptr::null(), jws.as_ptr(), &mut out) };
        assert_eq!(status, AprvReason::NullPointer as i32);
        assert_eq!(out.status, status);
        assert!(take_json(out).contains("NULL_POINTER"));
    }

    #[test]
    fn a_null_input_string_is_reported() {
        let verifier = jws_verifier();
        let mut out = empty_result();
        let status = unsafe { aprv_verify_transaction(verifier, std::ptr::null(), &mut out) };
        assert_eq!(status, AprvReason::NullPointer as i32);
        assert!(take_json(out).contains("NULL_POINTER"));
        unsafe { aprv_verifier_free_jws(verifier) };
    }

    #[test]
    fn invalid_utf8_is_its_own_status_and_never_a_verdict() {
        let verifier = jws_verifier();
        // 0xFF is not a valid UTF-8 byte in any position.
        let bytes: [c_char; 4] = [0x65, -1_i8 as c_char, 0x65, 0];
        let mut out = empty_result();
        let status = unsafe { aprv_verify_transaction(verifier, bytes.as_ptr(), &mut out) };
        assert_eq!(status, AprvReason::InvalidUtf8 as i32);
        assert!(take_json(out).contains("INVALID_UTF8"));

        let receipt = {
            let bundle = CString::new("com.example.app").unwrap();
            unsafe { aprv_verifier_new_receipt(bundle.as_ptr()) }
        };
        let mut out = empty_result();
        let status = unsafe { aprv_verify_receipt_base64(receipt, bytes.as_ptr(), &mut out) };
        assert_eq!(status, AprvReason::InvalidUtf8 as i32);
        drop(take_json(out));
        unsafe { aprv_verifier_free_receipt(receipt) };
        unsafe { aprv_verifier_free_jws(verifier) };
    }

    #[test]
    fn a_null_receipt_pointer_is_reported() {
        let bundle = CString::new("com.example.app").unwrap();
        let verifier = unsafe { aprv_verifier_new_receipt(bundle.as_ptr()) };
        let mut out = empty_result();
        let status = unsafe { aprv_verify_receipt_der(verifier, std::ptr::null(), 0, &mut out) };
        assert_eq!(status, AprvReason::NullPointer as i32);
        drop(take_json(out));
        unsafe { aprv_verifier_free_receipt(verifier) };
    }

    #[test]
    fn a_null_out_parameter_still_returns_the_status() {
        let verifier = jws_verifier();
        let jws = CString::new("not.a.jws").unwrap();
        let status =
            unsafe { aprv_verify_transaction(verifier, jws.as_ptr(), std::ptr::null_mut()) };
        assert_eq!(status, AprvReason::InvalidJwsFormat as i32);
        unsafe { aprv_verifier_free_jws(verifier) };
    }

    // --- verdicts ---------------------------------------------------------

    #[test]
    fn a_malformed_jws_is_a_verdict_with_the_canonical_token() {
        let verifier = jws_verifier();
        let jws = CString::new("not.a.jws").unwrap();
        let mut out = empty_result();
        let status = unsafe { aprv_verify_transaction(verifier, jws.as_ptr(), &mut out) };
        assert_eq!(status, AprvReason::InvalidJwsFormat as i32);
        let json = take_json(out);
        assert!(json.contains("\"reason\":\"INVALID_JWS_FORMAT\""), "{json}");
        assert!(json.contains("\"message\":"), "{json}");
        unsafe { aprv_verifier_free_jws(verifier) };
    }

    #[test]
    fn an_empty_receipt_is_a_format_verdict_not_a_crash() {
        let bundle = CString::new("com.example.app").unwrap();
        let verifier = unsafe { aprv_verifier_new_receipt(bundle.as_ptr()) };
        let empty: [u8; 0] = [];
        let mut out = empty_result();
        let status = unsafe { aprv_verify_receipt_der(verifier, empty.as_ptr(), 0, &mut out) };
        assert_eq!(status, AprvReason::InvalidReceiptFormat as i32);
        assert!(take_json(out).contains("INVALID_RECEIPT_FORMAT"));
        unsafe { aprv_verifier_free_receipt(verifier) };
    }

    /// The endpoint's contract: never an error return, always a status
    /// inside the body.
    #[test]
    fn the_endpoint_answers_a_body_for_junk() {
        let endpoint = unsafe { aprv_endpoint_new(2) };
        let body = CString::new("not json at all").unwrap();
        let mut response: *mut c_char = std::ptr::null_mut();
        let status =
            unsafe { aprv_verify_receipt_endpoint_json(endpoint, body.as_ptr(), &mut response) };
        assert_eq!(status, AprvReason::Ok as i32);
        let text = unsafe { CStr::from_ptr(response) }
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(text, "{\"status\":21002}");
        unsafe { aprv_string_free(response) };
        unsafe { aprv_endpoint_free(endpoint) };
    }

    #[test]
    fn a_null_endpoint_handle_leaves_the_out_parameter_untouched() {
        let body = CString::new("{}").unwrap();
        let mut response: *mut c_char = std::ptr::null_mut();
        let status = unsafe {
            aprv_verify_receipt_endpoint_json(std::ptr::null(), body.as_ptr(), &mut response)
        };
        assert_eq!(status, AprvReason::NullPointer as i32);
        assert!(response.is_null());
    }

    // --- the rest of the surface -----------------------------------------

    #[test]
    fn the_version_is_the_repository_version() {
        let version = unsafe { CStr::from_ptr(aprv_version()) }.to_str().unwrap();
        assert_eq!(version, include_str!("../../../version.txt").trim());
        assert_eq!(version.split('.').count(), 3, "{version} is not x.y.z");
        assert!(version.split('.').all(|part| part.parse::<u32>().is_ok()));
        // Static: the same pointer every call, and never freed.
        assert_eq!(aprv_version(), aprv_version());
    }

    #[test]
    fn freeing_null_is_a_no_op() {
        unsafe {
            aprv_verifier_free_jws(std::ptr::null_mut());
            aprv_verifier_free_receipt(std::ptr::null_mut());
            aprv_endpoint_free(std::ptr::null_mut());
            aprv_string_free(std::ptr::null_mut());
        }
    }

    /// The staleness seam, which the conformance vectors cannot reach
    /// through this ABI: every case that exercises it also pins a clock, and
    /// the ABI has no clock argument. A one-second maximum against a fixture
    /// signed in 2024 is stale on any real clock, so the rule is proven
    /// wired without one — and the same call with no maximum must succeed,
    /// or the test would pass for the wrong reason.
    #[test]
    fn max_signed_age_rejects_an_old_payload_and_zero_means_no_rule() {
        let root = std::fs::read(fixture("generated/jws-root.der")).unwrap();
        let jws = std::fs::read_to_string(fixture("generated/transaction.jws")).unwrap();
        let jws = CString::new(jws.trim()).unwrap();
        let bundle = CString::new("com.example.app").unwrap();
        let ders = [root.as_ptr()];
        let lens = [root.len()];

        for (max_age, expected) in [
            (0_u64, AprvReason::Ok as i32),
            (1_u64, AprvReason::StalePayload as i32),
        ] {
            let verifier = unsafe {
                aprv_verifier_new_jws_with_roots(
                    bundle.as_ptr(),
                    AprvEnvironment::Sandbox as u32,
                    0,
                    max_age,
                    ders.as_ptr(),
                    lens.as_ptr(),
                    1,
                )
            };
            assert!(!verifier.is_null(), "max_signed_age_secs={max_age}");
            let mut out = empty_result();
            let status = unsafe { aprv_verify_transaction(verifier, jws.as_ptr(), &mut out) };
            assert_eq!(status, expected, "max_signed_age_secs={max_age}");
            let json = take_json(out);
            if expected == AprvReason::Ok as i32 {
                assert!(
                    json.contains("\"productId\":\"com.example.app.pro\""),
                    "{json}"
                );
            } else {
                assert!(json.contains("STALE_PAYLOAD"), "{json}");
            }
            unsafe { aprv_verifier_free_jws(verifier) };
        }
    }

    /// The caller-supplied-anchor path really is pinned: the same fixture
    /// that verifies under its own generated root is rejected under the
    /// bundled Apple roots.
    #[test]
    fn the_bundled_roots_do_not_accept_the_fixture_chain() {
        let jws = std::fs::read_to_string(fixture("generated/transaction.jws")).unwrap();
        let jws = CString::new(jws.trim()).unwrap();
        let verifier = jws_verifier();
        let mut out = empty_result();
        let status = unsafe { aprv_verify_transaction(verifier, jws.as_ptr(), &mut out) };
        assert_eq!(status, AprvReason::InvalidChain as i32);
        assert!(take_json(out).contains("INVALID_CHAIN"));
        unsafe { aprv_verifier_free_jws(verifier) };
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
