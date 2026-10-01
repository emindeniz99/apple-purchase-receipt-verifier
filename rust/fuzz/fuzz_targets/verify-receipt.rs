#![no_main]

//! The whole legacy-receipt path on DER bytes: CMS walk, chain, signature,
//! payload parse. The bytes are base64-encoded first, so every input reaches
//! the DER path rather than stopping at the base64 rule.
//!
//! The invariants are the ones the Go port's `FuzzVerifyReceipt` states:
//! nothing panics; a failure is a `Failure` and never `INTERNAL_ERROR`,
//! which no input can make a correct library answer; and an accepted receipt
//! is accepted because of the anchors, proven by re-running it against an
//! unrelated anchor set and requiring failure. Without the last a fuzzer can
//! find crashes but never "accepts what it should not".
//!
//! The anchor set is the pinned Apple roots plus the generated fixture
//! root, so both the shared fixture receipts and the public Apple receipts
//! get past the chain check and the fuzzer can explore what lies beyond it.
//! The unrelated set is the fixture *JWS* root. The clock is fixed, so a
//! run is reproducible whatever day it replays.

use apple_purchase_receipt_verifier::__internal::base64_encode;
use apple_purchase_receipt_verifier::{Config, Reason, TrustAnchor, Verifier};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const RECEIPT_ROOT: &[u8] = include_bytes!("../../../fixtures/generated-0.7/receipt-root.der");
const JWS_ROOT: &[u8] = include_bytes!("../../../fixtures/generated/jws-root.der");
/// 2025-01-01T00:00:00Z, inside every fixture chain that verifies.
const NOW: i64 = 1_735_689_600_000;

fn verifiers() -> &'static (Verifier, Verifier) {
    static VERIFIERS: OnceLock<(Verifier, Verifier)> = OnceLock::new();
    VERIFIERS.get_or_init(|| {
        let mut trusted = Config::default().roots().to_vec();
        trusted.push(TrustAnchor::from_der(RECEIPT_ROOT).expect("fixture root"));
        let build = |roots: Vec<TrustAnchor>| {
            Verifier::new(
                Config::builder()
                    .roots(roots)
                    .clock(|| NOW)
                    .build()
                    .expect("a non-empty anchor set"),
            )
        };
        let unrelated = vec![TrustAnchor::from_der(JWS_ROOT).expect("fixture root")];
        (build(trusted), build(unrelated))
    })
}

fuzz_target!(|data: &[u8]| {
    let (trusted, unrelated) = verifiers();
    let receipt = base64_encode(data);
    match trusted.verify_receipt(&receipt) {
        Ok(_) => assert!(
            unrelated.verify_receipt(&receipt).is_err(),
            "this input verifies against an unrelated anchor set too, \
             so the anchors are not being enforced"
        ),
        Err(failure) => assert_ne!(
            failure.reason(),
            Reason::InternalError,
            "no input can make a correct library answer INTERNAL_ERROR: {failure}"
        ),
    }
});
