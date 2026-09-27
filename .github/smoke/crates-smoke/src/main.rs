//! Smoke-tests the crate as published to crates.io. Everything it touches — the
//! verifier, the failure type, the bundled root certificates — comes from the
//! resolved dependency, so a tarball missing `certs/` fails here rather than in
//! a user's build.
use apple_purchase_receipt_verifier::{Config, Reason, Verifier};

fn main() {
    let text = std::fs::read_to_string("receipt-sandbox-g5.b64")
        .expect("cannot read the fixture receipt-sandbox-g5.b64");
    let receipt_b64 = text.trim();

    // `build()` reports bundled roots that did not load as an error, where
    // `Config::defaults()` would leave every call answering INTERNAL_ERROR.
    let config = Config::builder()
        .build()
        .expect("the bundled Apple roots did not load");
    assert_eq!(
        config.roots().len(),
        3,
        "expected three bundled Apple roots"
    );
    let verifier = Verifier::new(config);

    // A real Apple-signed receipt against the real pinned root: exercises the
    // packaged certs, the DER reader, the chain build and the signature check.
    let receipt = verifier
        .verify_receipt(receipt_b64)
        .expect("verification failed");
    assert_eq!(
        receipt.receipt_type.as_deref(),
        Some("ProductionSandbox"),
        "unexpected receipt_type"
    );
    assert_eq!(
        receipt.bundle_id.as_deref(),
        Some("dev.bonzer.weeka.app"),
        "unexpected bundle_id"
    );

    // And the negative direction, so a verifier that accepted everything would
    // fail here too: the same receipt with one bit flipped in its signature,
    // the byte 128 from the end of the DER (BENCHMARKS.md).
    let mut der = decode_base64(receipt_b64);
    let index = der.len() - 128;
    der[index] ^= 0x01;
    match verifier.verify_receipt(&encode_base64(&der)) {
        Err(failure) if failure.reason() == Reason::InvalidSignature => {}
        Err(failure) => panic!(
            "rejected for {}, expected INVALID_SIGNATURE",
            failure.reason()
        ),
        Ok(_) => panic!("a tampered signature was not rejected"),
    }

    println!(
        "crates.io: published crate verified a genuine Apple receipt ({}, {} purchases) \
         and rejected a tampered signature",
        receipt.bundle_id.as_deref().unwrap_or("?"),
        receipt.in_app.len()
    );
}

// Standard padded base64, written out so the smoke crate depends on nothing but
// the crate under test.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn decode_base64(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.bytes().filter(|&c| c != b'=') {
        let value = ALPHABET
            .iter()
            .position(|&a| a == c)
            .expect("the fixture is not standard base64") as u32;
        acc = ((acc << 6) | value) & 0xffff;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

fn encode_base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().fold(0u32, |n, &b| (n << 8) | u32::from(b)) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}
