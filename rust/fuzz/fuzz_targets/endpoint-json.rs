#![no_main]

//! `VerifyReceiptEndpoint::verify_receipt_json`, the one entry point that
//! takes a request body rather than a receipt: JSON parse, `receipt-data`
//! extraction, the receipt-base64 rule, then the DER path. Its contract is
//! that every body — any bytes at all — gets a JSON object with a `status`
//! back, which is what is asserted after each call.

use apple_purchase_receipt_verifier::{
    apple_receipt_roots, serde_json, Environment, VerifyReceiptEndpoint,
};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn endpoint() -> &'static VerifyReceiptEndpoint {
    static ENDPOINT: OnceLock<VerifyReceiptEndpoint> = OnceLock::new();
    ENDPOINT.get_or_init(|| {
        VerifyReceiptEndpoint::builder()
            .trusted_roots(apple_receipt_roots().iter().cloned())
            .environment(Environment::Sandbox)
            .build()
            .expect("a non-empty anchor set")
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(body) = std::str::from_utf8(data) else {
        return;
    };
    let response = endpoint().verify_receipt_json(body);
    let parsed: serde_json::Value =
        serde_json::from_str(&response).expect("the endpoint answers with JSON");
    assert!(
        parsed
            .get("status")
            .and_then(serde_json::Value::as_i64)
            .is_some(),
        "the endpoint answers with a status: {response}"
    );
});
