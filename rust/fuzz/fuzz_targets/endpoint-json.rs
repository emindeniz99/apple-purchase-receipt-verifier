#![no_main]

//! `Verifier::verify_receipt_endpoint`, the one entry point that takes a
//! request body rather than a receipt: JSON read, `receipt-data`
//! extraction, the receipt-base64 rule, then the DER path. Its contract is
//! that every body (any bytes at all) gets Apple's response body back, a
//! JSON object whose first member is `status`, which is what is asserted
//! after each call.

use apple_purchase_receipt_verifier::{Config, Environment, Verifier};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn verifier() -> &'static Verifier {
    static VERIFIER: OnceLock<Verifier> = OnceLock::new();
    VERIFIER.get_or_init(|| Verifier::new(Config::default()))
}

fuzz_target!(|data: &[u8]| {
    let Ok(body) = std::str::from_utf8(data) else {
        return;
    };
    let response = verifier().verify_receipt_endpoint(Environment::Sandbox, body);
    assert!(
        response.starts_with("{\"status\":") && response.ends_with('}'),
        "the endpoint answers with a status: {response}"
    );
});
