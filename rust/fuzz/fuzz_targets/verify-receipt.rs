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
//! The anchor check alone cannot see a broken content signature: a mutated
//! payload under a genuine chain verifies against the trusted anchors and
//! fails against the unrelated ones, as it should if the signature were
//! checked. A fuzzer cannot forge an RSA or ECDSA signature, so whatever it
//! gets accepted can only carry a payload some seed's signer signed. Every
//! seed file that verifies is read once, at start, and an accepted input's
//! payload must equal one of theirs. The seed directories are the ones
//! `run.sh` passes this target; a run seeded from elsewhere must add its
//! directories to `SEED_DIRS`.
//!
//! The anchor set is the pinned Apple roots plus the generated fixture
//! root, so both the shared fixture receipts and the public Apple receipts
//! get past the chain check and the fuzzer can explore what lies beyond it.
//! The unrelated set is the fixture *JWS* root. The clock is fixed, so a
//! run is reproducible whatever day it replays.

use apple_purchase_receipt_verifier::__internal::base64_encode;
use apple_purchase_receipt_verifier::{Config, Reason, TrustAnchor, Verifier};
use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

const RECEIPT_ROOT: &[u8] = include_bytes!("../../../fixtures/generated-0.7/receipt-root.der");
const JWS_ROOT: &[u8] = include_bytes!("../../../fixtures/generated/jws-root.der");
/// 2025-01-01T00:00:00Z, inside every fixture chain that verifies.
const NOW: i64 = 1_735_689_600_000;
/// Under `fixtures/`: what `run.sh` seeds this target with.
const SEED_DIRS: [&str; 3] = ["generated", "generated-0.7", "apple-official/certs"];

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

/// The payload JSON of every seed file the trusted verifier accepts.
fn signed_payloads() -> &'static HashSet<String> {
    static PAYLOADS: OnceLock<HashSet<String>> = OnceLock::new();
    PAYLOADS.get_or_init(|| {
        let (trusted, _) = verifiers();
        let fixtures = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures"));
        let mut files = Vec::new();
        for dir in SEED_DIRS {
            read_tree(&fixtures.join(dir), &mut files);
        }
        let payloads: HashSet<String> = files
            .iter()
            .filter_map(|file| trusted.verify_receipt(&base64_encode(file)).ok())
            .map(|payload| payload.to_json())
            .collect();
        // Loud rather than lenient: with no signed payload every acceptance
        // would be reported as a bypass.
        assert!(!payloads.is_empty(), "no seed under {fixtures:?} verifies");
        payloads
    })
}

/// Every file under `dir`, as libFuzzer reads a corpus directory.
fn read_tree(dir: &Path, files: &mut Vec<Vec<u8>>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for path in entries.flatten().map(|entry| entry.path()) {
        if path.is_dir() {
            read_tree(&path, files);
        } else if let Ok(bytes) = std::fs::read(&path) {
            files.push(bytes);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let (trusted, unrelated) = verifiers();
    let receipt = base64_encode(data);
    match trusted.verify_receipt(&receipt) {
        Ok(payload) => {
            assert!(
                signed_payloads().contains(&payload.to_json()),
                "this input verifies with a payload no seed's signer signed, \
                 so the signature does not cover what is returned"
            );
            assert!(
                unrelated.verify_receipt(&receipt).is_err(),
                "this input verifies against an unrelated anchor set too, \
                 so the anchors are not being enforced"
            );
        }
        Err(failure) => assert_ne!(
            failure.reason(),
            Reason::InternalError,
            "no input can make a correct library answer INTERNAL_ERROR: {failure}"
        ),
    }
});
