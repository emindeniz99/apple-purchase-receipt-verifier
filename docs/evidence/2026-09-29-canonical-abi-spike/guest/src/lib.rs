//! Spike only (2026-09-29, round 12): aprv.wasm with the canonical ABI
//! (Component Model) as its export ABI, on the same wasm32-wasip1 core
//! module as ABI v1 (docs/evidence/2026-09-26-wasm-abi-v1/shim/src/lib.rs).
//!
//! wit-bindgen generates the four exports, `cabi_realloc` and the
//! post-return functions from wit/aprv.wit. The bodies of the four
//! operations are ABI v1's (`verify_receipt`, `verify_signed_data`,
//! `endpoint`, `decode_receipt_data`, `failure`), copied unchanged except
//! that trust anchors come from `init` and the instant from `now-ms`.
//!
//! What changed against ABI v1:
//! - no `aprv_call`, operation numbers, handles or test envelope: four typed
//!   exports; the result string is freed by the post-return function;
//! - no `aprv.clock_now_ms` import: `now-ms` is an argument. The linked
//!   wasi-none.c still reads the clock through `aprv_clock_now_ms`, which is
//!   now DEFINED here (returns the current call's now-ms), so no import is
//!   left for it;
//! - `aprv.random_get` becomes the WIT import `host.random-get`:
//!   `aprv_random_get` (the symbol wasi-none.c calls for OpenSSL) is defined
//!   here on top of it.
//!
//! Traps (`unreachable`): a verify before a successful init, a second init
//! after a successful one, and a `random-get` answer of the wrong length.

wit_bindgen::generate!({ path: "wit", world: "aprv" });
// The WIT package `aprv:verifier` generates a module `aprv` (crate::aprv),
// which shadows the core crate, also named `aprv`: the core is `::aprv`.

use ::aprv::serde_json::{self, Map, Value};
use ::aprv::{
    apple_jws_roots, apple_receipt_roots, datetime, verify_receipt_core, AppReceipt, CoreError,
    Environment, FixedClock, InAppPurchase, JwsVerifier, TrustAnchor, VerifyReceiptEndpoint,
};
use exports::aprv::verifier::verify::{Environment as WitEnvironment, Guest};
use std::cell::{Cell, RefCell};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// The receipt JSON view, extracted verbatim at build time from rust/ffi,
// exactly as ABI v1 does (scripts/build.sh).
include!("wire_view.rs");

#[cold]
fn fail_hard() -> ! {
    core::arch::wasm32::unreachable()
}

// --- instance state ------------------------------------------------------------

/// None: not initialized. Some(None): the built-in Apple roots. Some(Some(v)): v.
type Anchors = Option<Vec<TrustAnchor>>;

thread_local! {
    static STATE: RefCell<Option<Anchors>> = const { RefCell::new(None) };
    static NOW_MS: Cell<u64> = const { Cell::new(0) };
}

fn anchors() -> Anchors {
    STATE.with(|s| match &*s.borrow() {
        Some(a) => a.clone(),
        None => fail_hard(),
    })
}

fn set_now(now_ms: u64) {
    NOW_MS.with(|n| n.set(now_ms));
    // Idempotent: the core keeps the first clock and refuses later ones.
    let _ = ::aprv::platform::install_clock(host_now);
}

fn host_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(NOW_MS.with(Cell::get))
}

// --- the two C symbols wasi-none.c calls ---------------------------------------------
// Defined here, they win over the import declarations in wasi-none.c, so the
// module imports neither `aprv.clock_now_ms` nor `aprv.random_get`.

/// The C side's clock (clock_time_get): the current call's now-ms.
#[no_mangle]
extern "C" fn aprv_clock_now_ms() -> f64 {
    NOW_MS.with(Cell::get) as f64
}

/// The C side's randomness (random_get): exactly `len` bytes from the host.
#[no_mangle]
extern "C" fn aprv_random_get(buf: i32, len: i32) -> i32 {
    let bytes = crate::aprv::verifier::host::random_get(len as u32);
    if bytes.len() != len as usize {
        fail_hard();
    }
    // SAFETY: wasi-libc passes a writable buffer of `len` bytes.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as usize as *mut u8, bytes.len()) };
    0
}

// --- the exports -----------------------------------------------------------------

struct Aprv;

impl Guest for Aprv {
    fn init(config_json: String) -> String {
        if STATE.with(|s| s.borrow().is_some()) {
            fail_hard();
        }
        match parse_config(&config_json) {
            Ok(a) => {
                STATE.with(|s| *s.borrow_mut() = Some(a));
                "{\"ok\":true}".into()
            }
            Err(message) => {
                let mut o = Map::new();
                o.insert("ok".into(), Value::Bool(false));
                o.insert("message".into(), Value::from(message));
                Value::Object(o).to_string()
            }
        }
    }

    fn verify_receipt(now_ms: u64, receipt_base64: String) -> String {
        let a = anchors();
        set_now(now_ms);
        into_string(verify_receipt(receipt_base64.as_bytes(), a))
    }

    fn verify_signed_data(now_ms: u64, jws: String) -> String {
        let a = anchors();
        set_now(now_ms);
        into_string(verify_signed_data(jws.as_bytes(), a))
    }

    fn verify_receipt_endpoint(env: WitEnvironment, now_ms: u64, request_json: String) -> String {
        let a = anchors();
        set_now(now_ms);
        let env = match env {
            WitEnvironment::Production => Environment::Production,
            WitEnvironment::Sandbox => Environment::Sandbox,
        };
        let now = i64::try_from(now_ms).unwrap_or(i64::MAX);
        into_string(endpoint(env, request_json.as_bytes(), a, Some(now)))
    }
}

export!(Aprv);

fn into_string(bytes: Vec<u8>) -> String {
    // Every body below produces JSON text (serde_json or format!).
    String::from_utf8(bytes).unwrap_or_else(|_| fail_hard())
}

/// "" or {} or {"roots":[]}: the built-in roots. {"roots":["<base64 DER>", ...]}: those.
fn parse_config(text: &str) -> Result<Anchors, String> {
    if text.trim().is_empty() {
        return Ok(None);
    }
    let v: Value = serde_json::from_str(text).map_err(|e| format!("config is not JSON: {e}"))?;
    let obj = v.as_object().ok_or("config is not a JSON object")?;
    let Some(roots) = obj.get("roots") else { return Ok(None) };
    let roots = roots.as_array().ok_or("roots is not an array")?;
    if roots.is_empty() {
        return Ok(None);
    }
    let mut out = Vec::with_capacity(roots.len());
    for (i, r) in roots.iter().enumerate() {
        let s = r.as_str().ok_or_else(|| format!("roots[{i}] is not a string"))?;
        let der = ::aprv::base64::decode_receipt_base64(s).ok_or_else(|| format!("roots[{i}] is not canonical base64"))?;
        out.push(TrustAnchor::from_der(&der).map_err(|e| format!("roots[{i}]: {e}"))?);
    }
    Ok(Some(out))
}

// --- ABI v1's operation bodies, unchanged ----------------------------------------

fn failure(reason: &str, message: &str) -> Vec<u8> {
    let mut o = Map::new();
    o.insert("verified".into(), Value::Bool(false));
    o.insert("reason".into(), Value::from(reason));
    o.insert("message".into(), Value::from(message));
    Value::Object(o).to_string().into_bytes()
}

fn decode_receipt_data(text: &[u8]) -> Result<Vec<u8>, Vec<u8>> {
    if text.len() > ::aprv::MAX_RECEIPT_BYTES {
        return Err(failure(
            "INVALID_RECEIPT_FORMAT",
            &format!(
                "receipt exceeds the maximum accepted size of {} bytes of base64",
                ::aprv::MAX_RECEIPT_BYTES
            ),
        ));
    }
    std::str::from_utf8(text)
        .ok()
        .and_then(::aprv::base64::decode_receipt_base64)
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
            let raw = jws
                .split('.')
                .nth(1)
                .and_then(::aprv::base64::decode_base64url_strict)
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
        Ok(e) => e.verify_receipt_json(&String::from_utf8_lossy(body)).into_bytes(),
        Err(e) => format!("{{\"error\":\"CONFIGURATION\",\"message\":{}}}", Value::from(e.to_string())).into_bytes(),
    }
}
