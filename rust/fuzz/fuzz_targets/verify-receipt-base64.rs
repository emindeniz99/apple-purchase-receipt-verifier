#![no_main]

//! `Verifier::verify_receipt_bytes`: the string a client actually sends, as
//! the bytes `aprv.wasm` and every wrapper hand over, through the
//! receipt-base64 rule and then the whole DER path. Seeded from the
//! `receipt-b64` fixtures and the public receipts, so the fuzzer starts from
//! strings that decode and verify rather than from noise it has to grow into
//! base64 by itself.

use apple_purchase_receipt_verifier::{Config, Verifier};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn verifier() -> &'static Verifier {
    static VERIFIER: OnceLock<Verifier> = OnceLock::new();
    VERIFIER.get_or_init(|| Verifier::new(Config::default()))
}

fuzz_target!(|data: &[u8]| {
    let _ = verifier().verify_receipt_bytes(data);
});
