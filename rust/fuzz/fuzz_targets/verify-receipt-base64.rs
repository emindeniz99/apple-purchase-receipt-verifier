#![no_main]

//! `Verifier::verify_receipt`: the string a client actually sends, through
//! the receipt-base64 rule and then the whole DER path. Seeded from the
//! `receipt-b64` fixtures and the public receipts, so the fuzzer starts from
//! strings that decode and verify rather than from noise it has to grow into
//! base64 by itself. Input that is not UTF-8 is skipped: the API takes
//! `&str`, so those bytes cannot reach it.

use apple_purchase_receipt_verifier::{Config, Verifier};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn verifier() -> &'static Verifier {
    static VERIFIER: OnceLock<Verifier> = OnceLock::new();
    VERIFIER.get_or_init(|| Verifier::new(Config::default()))
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = verifier().verify_receipt(text);
});
