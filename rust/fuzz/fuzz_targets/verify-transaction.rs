#![no_main]

//! The StoreKit 2 path: compact-JWS split, strict base64url, JSON header
//! and payload, `x5c` certificates, chain, ES256 signature, then the three
//! public entry points' claim checks. Same invariants as the Go port's
//! `FuzzVerifyTransaction`: nothing panics, and a JWS `verify_raw` accepts
//! under the fixture root must be refused under Apple's roots, or the
//! anchors are not what decided it.

use apple_purchase_receipt_verifier::{apple_jws_roots, Environment, JwsVerifier, TrustAnchor};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const JWS_ROOT: &[u8] = include_bytes!("../../../fixtures/generated/jws-root.der");

fn verifiers() -> &'static (JwsVerifier, JwsVerifier) {
    static VERIFIERS: OnceLock<(JwsVerifier, JwsVerifier)> = OnceLock::new();
    VERIFIERS.get_or_init(|| {
        let fixture = JwsVerifier::builder()
            .trusted_roots([TrustAnchor::from_der(JWS_ROOT).expect("fixture root")])
            .bundle_id("com.example.app")
            .accepted_environments([Environment::Sandbox])
            .build()
            .expect("a non-empty anchor set and a bundle id");
        let unrelated = JwsVerifier::builder()
            .trusted_roots(apple_jws_roots().iter().cloned())
            .bundle_id("com.example.app")
            .accepted_environments([Environment::Sandbox])
            .build()
            .expect("a non-empty anchor set and a bundle id");
        (fixture, unrelated)
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(jws) = std::str::from_utf8(data) else {
        return;
    };
    let (verifier, unrelated) = verifiers();
    let _ = verifier.verify_transaction(jws);
    let _ = verifier.verify_app_transaction(jws);
    if verifier.verify_raw(jws).is_ok() {
        assert!(
            unrelated.verify_raw(jws).is_err(),
            "this input verifies against Apple's roots too, \
             so the anchors are not being enforced"
        );
    }
});
