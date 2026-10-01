#![no_main]

//! The StoreKit 2 path: compact-JWS split, strict base64url, JSON header
//! and payload, `x5c` certificates, chain, ES256 signature. Same invariants
//! as the Go port's `FuzzVerifySignedData`: nothing panics, and a JWS
//! `verify_signed_data` accepts under the fixture root must be refused under
//! Apple's roots, or the anchors are not what decided it.

use apple_purchase_receipt_verifier::{Config, TrustAnchor, Verifier};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const JWS_ROOT: &[u8] = include_bytes!("../../../fixtures/generated/jws-root.der");

fn verifiers() -> &'static (Verifier, Verifier) {
    static VERIFIERS: OnceLock<(Verifier, Verifier)> = OnceLock::new();
    VERIFIERS.get_or_init(|| {
        let fixture = Config::builder()
            .roots([TrustAnchor::from_der(JWS_ROOT).expect("fixture root")])
            .build()
            .expect("a non-empty anchor set");
        (Verifier::new(fixture), Verifier::new(Config::default()))
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(jws) = std::str::from_utf8(data) else {
        return;
    };
    let (verifier, apple) = verifiers();
    if verifier.verify_signed_data(jws).is_ok() {
        assert!(
            apple.verify_signed_data(jws).is_err(),
            "this input verifies against Apple's roots too, \
             so the anchors are not being enforced"
        );
    }
});
