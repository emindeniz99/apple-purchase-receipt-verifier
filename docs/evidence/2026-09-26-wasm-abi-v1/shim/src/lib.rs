//! Spike only (2026-09-26): Wasm ABI v1.
//!
//! One generic call over four policy-free operations:
//!
//! ```text
//! aprv_abi_version() -> i32                                  == 1
//! aprv_alloc(len) -> ptr ; aprv_dealloc(ptr, len)
//! aprv_call(abi_version, operation, input_ptr, input_len) -> result handle
//! aprv_result_ptr(h) -> ptr ; aprv_result_len(h) -> len ; aprv_result_free(h)
//! ```
//!
//! Rules, in the order `aprv_call` applies them:
//! 1. `abi_version` is checked FIRST, before `operation`, `input_ptr` or
//!    `input_len` is read. A mismatch traps (`unreachable`); the host bridge
//!    reports "APRV Wasm ABI mismatch: module=1, caller=N" by asking
//!    `aprv_abi_version()`.
//! 2. An unknown operation traps (a programmer error, never a verdict).
//! 3. The input range must lie inside linear memory (no overflow, and a
//!    null pointer only with length 0), or it traps.
//! 4. The operation runs. Every verification outcome, success or failure,
//!    is a value: the result bytes (JSON) behind a handle.
//!
//! Inputs (no policy: no bundle id, environment or appAppleId anywhere):
//! - 1 VERIFY_RECEIPT: the `receipt-data` string, UTF-8 standard base64,
//!   decoded here by the Apple-measured strict rule.
//! - 2 VERIFY_SIGNED_DATA: the compact JWS, UTF-8.
//! - 3/4 ENDPOINT_PRODUCTION/SANDBOX: the verifyReceipt request body.
//!
//! Result handles: 1-based indices into a table. `aprv_result_ptr/len/free`
//! on a handle that is not live (0, never issued, or already freed) traps.
//!
//! The module imports exactly `aprv.clock_now_ms` and `aprv.random_get`
//! (the latter from the linked wasi-none.c, for OpenSSL's RNG).

use aprv::serde_json::{self, Map, Value};
use aprv::{
    apple_jws_roots, apple_receipt_roots, datetime, verify_receipt_core, AppReceipt, CoreError,
    Environment, FixedClock, InAppPurchase, JwsVerifier, TrustAnchor, VerifyReceiptEndpoint,
};
use std::alloc::{alloc, dealloc, Layout};
use std::cell::RefCell;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// The receipt JSON view, extracted verbatim at build time from rust/ffi
// (`fn hex_of` .. `fn app_receipt_json`) into src/wire_view.rs by
// scripts/build.sh: the view `aprv-wire` would own.
include!("wire_view.rs");

/// The one ABI version: names, signatures, operation numbers, encodings,
/// the JSON contract, ownership and errors.
const ABI_VERSION: i32 = 1;

// Operation numbers: stable, never reused.
const VERIFY_RECEIPT: i32 = 1;
const VERIFY_SIGNED_DATA: i32 = 2;
const VERIFY_RECEIPT_ENDPOINT_PRODUCTION: i32 = 3;
const VERIFY_RECEIPT_ENDPOINT_SANDBOX: i32 = 4;
// Spike-only conformance variants: the same four operations, with the input
// prefixed by a test envelope carrying trust anchors and (endpoint only) a
// fixed clock, so the repository's corpus (generated chains, pinned clocks)
// can run through ABI v1. Whether they ship is an open question; see the
// evidence note.
const TEST_OFFSET: i32 = 256;

#[cold]
fn fail_hard() -> ! {
    // A trap, not a panic: nothing is formatted or written, and every host
    // sees the same `unreachable`.
    core::arch::wasm32::unreachable()
}

// --- memory ----------------------------------------------------------------

fn layout(len: usize) -> Option<Layout> {
    Layout::from_size_align(len.max(1), 8).ok()
}

/// `len` bytes of guest memory, 8-byte aligned, or 0 when it cannot be had
/// (an absurd length, or memory exhausted).
#[no_mangle]
pub extern "C" fn aprv_alloc(len: usize) -> *mut u8 {
    match layout(len) {
        // SAFETY: the layout has a non-zero size.
        Some(l) => unsafe { alloc(l) },
        None => std::ptr::null_mut(),
    }
}

/// Releases memory from `aprv_alloc`; `len` must be the value passed to it.
///
/// # Safety
/// `ptr` must come from `aprv_alloc(len)` and not have been released.
#[no_mangle]
pub unsafe extern "C" fn aprv_dealloc(ptr: *mut u8, len: usize) {
    if let (false, Some(l)) = (ptr.is_null(), layout(len)) {
        dealloc(ptr, l);
    }
}

fn memory_bytes() -> usize {
    core::arch::wasm32::memory_size(0) * 65_536
}

/// The input range, or a trap when it is not inside linear memory.
fn input<'a>(ptr: usize, len: usize) -> &'a [u8] {
    if len == 0 {
        return &[];
    }
    match ptr.checked_add(len) {
        Some(end) if ptr != 0 && end <= memory_bytes() => {
            // SAFETY: [ptr, ptr+len) lies inside linear memory, which is
            // always mapped; the host owns the bytes for the call.
            unsafe { std::slice::from_raw_parts(ptr as *const u8, len) }
        }
        _ => fail_hard(),
    }
}

// --- result handles ----------------------------------------------------------

thread_local! {
    static RESULTS: RefCell<Vec<Option<Box<[u8]>>>> = const { RefCell::new(Vec::new()) };
}

fn store(bytes: Vec<u8>) -> u32 {
    RESULTS.with(|table| {
        let mut table = table.borrow_mut();
        let bytes = Some(bytes.into_boxed_slice());
        if let Some(i) = table.iter().position(Option::is_none) {
            table[i] = bytes;
            i as u32 + 1
        } else {
            table.push(bytes);
            table.len() as u32
        }
    })
}

fn with_live<T>(handle: u32, f: impl FnOnce(&[u8]) -> T) -> T {
    RESULTS.with(|table| {
        let table = table.borrow();
        match handle.checked_sub(1).and_then(|i| table.get(i as usize)) {
            Some(Some(bytes)) => f(bytes),
            _ => fail_hard(),
        }
    })
}

/// Address of the result bytes behind a live handle.
#[no_mangle]
pub extern "C" fn aprv_result_ptr(handle: u32) -> *const u8 {
    with_live(handle, <[u8]>::as_ptr)
}

/// Length of the result bytes behind a live handle.
#[no_mangle]
pub extern "C" fn aprv_result_len(handle: u32) -> usize {
    with_live(handle, <[u8]>::len)
}

/// Releases a live handle. A second release traps.
#[no_mangle]
pub extern "C" fn aprv_result_free(handle: u32) {
    RESULTS.with(|table| {
        let mut table = table.borrow_mut();
        match handle.checked_sub(1).and_then(|i| table.get_mut(i as usize)) {
            Some(slot @ Some(_)) => *slot = None,
            _ => fail_hard(),
        }
    });
}

// --- the call ---------------------------------------------------------------

#[no_mangle]
pub extern "C" fn aprv_abi_version() -> i32 {
    ABI_VERSION
}

/// The one call. See the module documentation for the order of checks.
#[no_mangle]
pub extern "C" fn aprv_call(abi_version: i32, operation: i32, input_ptr: usize, input_len: usize) -> u32 {
    if abi_version != ABI_VERSION {
        fail_hard();
    }
    let (base, test) = match operation {
        VERIFY_RECEIPT..=VERIFY_RECEIPT_ENDPOINT_SANDBOX => (operation, false),
        o if (TEST_OFFSET + VERIFY_RECEIPT..=TEST_OFFSET + VERIFY_RECEIPT_ENDPOINT_SANDBOX).contains(&o) => {
            (o - TEST_OFFSET, true)
        }
        _ => fail_hard(),
    };
    let bytes = input(input_ptr, input_len);
    install_host_clock();
    let out = if test {
        match Envelope::parse(bytes) {
            Some(env) => run(base, env.body, env.anchors, env.now_millis),
            None => b"{\"error\":\"INVALID_TEST_ENVELOPE\"}".to_vec(),
        }
    } else {
        run(base, bytes, None, None)
    };
    store(out)
}

fn run(op: i32, body: &[u8], anchors: Option<Vec<TrustAnchor>>, now_millis: Option<i64>) -> Vec<u8> {
    match op {
        VERIFY_RECEIPT => verify_receipt(body, anchors),
        VERIFY_SIGNED_DATA => verify_signed_data(body, anchors),
        VERIFY_RECEIPT_ENDPOINT_PRODUCTION => endpoint(Environment::Production, body, anchors, now_millis),
        _ => endpoint(Environment::Sandbox, body, anchors, now_millis),
    }
}

fn failure(reason: &str, message: &str) -> Vec<u8> {
    let mut o = Map::new();
    o.insert("verified".into(), Value::Bool(false));
    o.insert("reason".into(), Value::from(reason));
    o.insert("message".into(), Value::from(message));
    // serde_json's Map is ordered by key: message, reason, verified.
    Value::Object(o).to_string().into_bytes()
}

/// VERIFY_RECEIPT's input is the `receipt-data` string a client sends
/// (UTF-8 base64), decoded here by the repository's Apple-measured strict
/// rule, with the same size cap, order and messages as the core's
/// `decode_receipt_string` (crate-private, so restated; a production
/// module would call one public core function instead).
fn decode_receipt_data(text: &[u8]) -> Result<Vec<u8>, Vec<u8>> {
    if text.len() > aprv::MAX_RECEIPT_BYTES {
        return Err(failure(
            "INVALID_RECEIPT_FORMAT",
            &format!(
                "receipt exceeds the maximum accepted size of {} bytes of base64",
                aprv::MAX_RECEIPT_BYTES
            ),
        ));
    }
    // Bytes that are not UTF-8 are not base64 either.
    std::str::from_utf8(text)
        .ok()
        .and_then(aprv::base64::decode_receipt_base64)
        .ok_or_else(|| failure("INVALID_RECEIPT_FORMAT", "receipt-data is not valid base64"))
}

fn verify_receipt(receipt_data: &[u8], anchors: Option<Vec<TrustAnchor>>) -> Vec<u8> {
    let der = match decode_receipt_data(receipt_data) {
        Ok(der) => der,
        Err(refusal) => return refusal,
    };
    let roots = anchors.unwrap_or_else(|| apple_receipt_roots().to_vec());
    match verify_receipt_core(&der, &roots) {
        Ok(receipt) => format!("{{\"verified\":true,\"payload\":{}}}", app_receipt_json(&receipt)).into_bytes(),
        Err(CoreError::Verification(e)) => failure(e.reason().as_str(), e.detail()),
        Err(CoreError::Config(e)) => failure("CONFIGURATION", &e.to_string()),
        Err(_) => failure("INTERNAL_ERROR", "unclassified core error"),
    }
}

fn verify_signed_data(jws: &[u8], anchors: Option<Vec<TrustAnchor>>) -> Vec<u8> {
    let Ok(jws) = std::str::from_utf8(jws) else {
        return failure("INVALID_JWS_FORMAT", "jws is not valid UTF-8");
    };
    let roots = anchors.unwrap_or_else(|| apple_jws_roots().to_vec());
    // The builder insists on a bundle id and environments, but verify_raw
    // enforces NO claim: these values are never compared with anything.
    let verifier = JwsVerifier::builder()
        .trusted_roots(roots)
        .bundle_id("-")
        .accepted_environments([
            Environment::Production,
            Environment::Sandbox,
            Environment::Xcode,
            Environment::LocalTesting,
        ])
        .build();
    let verifier = match verifier {
        Ok(v) => v,
        Err(e) => return failure("CONFIGURATION", &e.to_string()),
    };
    match verifier.verify_raw(jws) {
        Ok(claims) => {
            // The exact signed payload JSON, as the signer wrote it: the
            // second segment, decoded again (it decoded strictly a moment
            // ago, inside verify_raw).
            let raw = jws
                .split('.')
                .nth(1)
                .and_then(aprv::base64::decode_base64url_strict)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default();
            format!(
                "{{\"verified\":true,\"payload\":{},\"payloadJson\":{}}}",
                Value::Object(claims),
                Value::from(raw)
            )
            .into_bytes()
        }
        Err(e) => failure(e.reason().as_str(), e.detail()),
    }
}

fn endpoint(env: Environment, body: &[u8], anchors: Option<Vec<TrustAnchor>>, now_millis: Option<i64>) -> Vec<u8> {
    let mut b = VerifyReceiptEndpoint::builder()
        .trusted_roots(anchors.unwrap_or_else(|| apple_receipt_roots().to_vec()))
        .environment(env);
    if let Some(ms) = now_millis {
        b = b.clock(Arc::new(FixedClock::from_unix_millis(ms)));
    }
    match b.build() {
        // Byte for byte today's endpoint answer. A body that is not UTF-8
        // is read lossily: a replacement character is neither valid JSON
        // nor valid base64, so it is refused like any malformed body.
        Ok(e) => e.verify_receipt_json(&String::from_utf8_lossy(body)).into_bytes(),
        Err(e) => format!("{{\"error\":\"CONFIGURATION\",\"message\":{}}}", Value::from(e.to_string())).into_bytes(),
    }
}

// --- the spike-only test envelope ---------------------------------------------
//
// "APRVT1" | u32le anchor count | (u32le len | DER)* | i64le now (i64::MIN = none) | body
// An anchor count of 0 means "the Apple roots", as the C ABI's NULL roots do.

struct Envelope<'a> {
    anchors: Option<Vec<TrustAnchor>>,
    now_millis: Option<i64>,
    body: &'a [u8],
}

impl<'a> Envelope<'a> {
    fn parse(b: &'a [u8]) -> Option<Self> {
        let rest = b.strip_prefix(b"APRVT1")?;
        let (count, mut rest) = take_u32(rest)?;
        let mut anchors = Vec::new();
        for _ in 0..count {
            let (len, r) = take_u32(rest)?;
            let der = r.get(..len as usize)?;
            anchors.push(TrustAnchor::from_der(der).ok()?);
            rest = r.get(len as usize..)?;
        }
        let now = i64::from_le_bytes(rest.get(..8)?.try_into().ok()?);
        Some(Envelope {
            anchors: if count == 0 { None } else { Some(anchors) },
            now_millis: if now == i64::MIN { None } else { Some(now) },
            body: rest.get(8..)?,
        })
    }
}

fn take_u32(b: &[u8]) -> Option<(u32, &[u8])> {
    Some((u32::from_le_bytes(b.get(..4)?.try_into().ok()?), b.get(4..)?))
}

// --- host clock ----------------------------------------------------------------

#[link(wasm_import_module = "aprv")]
extern "C" {
    /// Host wall clock, milliseconds since the Unix epoch.
    fn clock_now_ms() -> f64;
}

fn host_now() -> SystemTime {
    // SAFETY: an import with no arguments and a plain f64 result.
    let ms = unsafe { clock_now_ms() };
    if ms.is_finite() && ms >= 0.0 {
        UNIX_EPOCH + Duration::from_millis(ms as u64)
    } else {
        // Not a finite instant after 1970: judge every chain at 1970, where
        // no Apple chain is valid (fails closed).
        UNIX_EPOCH
    }
}

fn install_host_clock() {
    // Idempotent: the core keeps the first clock and refuses later ones.
    let _ = aprv::platform::install_clock(host_now);
}
