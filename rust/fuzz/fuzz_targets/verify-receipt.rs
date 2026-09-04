#![no_main]

//! The whole legacy-receipt path on DER bytes: CMS walk, payload parse,
//! chain build, signature check.
//!
//! The invariants are the three the Go port's `FuzzVerifyReceipt` states:
//! nothing panics; a failure is a `VerificationError` (`CoreError::Config`
//! is unreachable with a non-empty anchor set, so it is a bug here); and an
//! accepted receipt is accepted because of the anchors, proven by
//! re-running it against an unrelated anchor set and requiring failure.
//! Without the third a fuzzer can find crashes but never "accepts what it
//! should not".
//!
//! The anchor set is the pinned Apple roots plus the generated fixture
//! root, so both the shared fixture receipts and the two public Apple
//! receipts get past the chain check and the fuzzer can explore what lies
//! beyond it. The unrelated set is the fixture *JWS* root.

use apple_purchase_receipt_verifier::{
    apple_receipt_roots, verify_receipt_core, CoreError, TrustAnchor,
};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const RECEIPT_ROOT: &[u8] = include_bytes!("../../../fixtures/generated/receipt-root.der");
const JWS_ROOT: &[u8] = include_bytes!("../../../fixtures/generated/jws-root.der");

fn anchors() -> &'static (Vec<TrustAnchor>, Vec<TrustAnchor>) {
    static ANCHORS: OnceLock<(Vec<TrustAnchor>, Vec<TrustAnchor>)> = OnceLock::new();
    ANCHORS.get_or_init(|| {
        let mut trusted = apple_receipt_roots().to_vec();
        trusted.push(TrustAnchor::from_der(RECEIPT_ROOT).expect("fixture root"));
        let unrelated = vec![TrustAnchor::from_der(JWS_ROOT).expect("fixture root")];
        (trusted, unrelated)
    })
}

fuzz_target!(|data: &[u8]| {
    let (trusted, unrelated) = anchors();
    match verify_receipt_core(data, trusted) {
        Ok(_) => {
            assert!(
                verify_receipt_core(data, unrelated).is_err(),
                "this input verifies against an unrelated anchor set too, \
                 so the anchors are not being enforced"
            );
        }
        Err(CoreError::Verification(_)) => {}
        Err(CoreError::Config(err)) => {
            panic!("a configuration error escaped from a non-empty anchor set: {err}")
        }
        Err(other) => panic!("an error variant this target does not know: {other}"),
    }
});
