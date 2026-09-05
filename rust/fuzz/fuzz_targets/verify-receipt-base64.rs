#![no_main]

//! `ReceiptVerifier::verify_base64` — the string a client actually sends,
//! through the receipt-base64 rule and then the whole DER path. Seeded from
//! the `receipt-b64` fixtures and the public receipts, so the fuzzer starts
//! from strings that decode and verify rather than from noise it has to
//! grow into base64 by itself. Input that is not UTF-8 is skipped: the API
//! takes `&str`, so those bytes cannot reach it.

use apple_purchase_receipt_verifier::{apple_receipt_roots, ReceiptVerifier};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn verifier() -> &'static ReceiptVerifier {
    static VERIFIER: OnceLock<ReceiptVerifier> = OnceLock::new();
    VERIFIER.get_or_init(|| {
        ReceiptVerifier::builder()
            .trusted_roots(apple_receipt_roots().iter().cloned())
            .bundle_id("dev.bonzer.weeka.app")
            .build()
            .expect("a non-empty anchor set and a bundle id")
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = verifier().verify_base64(text);
});
