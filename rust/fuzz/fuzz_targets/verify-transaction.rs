#![no_main]

//! The StoreKit 2 path: compact-JWS split, strict base64url, JSON header
//! and payload, `x5c` certificates, chain, ES256 signature. Same invariants
//! as the Go port's `FuzzVerifySignedData`: nothing panics, and a JWS
//! `verify_signed_data_bytes` accepts under the fixture root must be
//! refused under Apple's roots, or the anchors are not what decided it.
//!
//! The anchor check alone cannot see a broken ES256 check: a mutated
//! payload under a genuine `x5c` chain passes it. A fuzzer cannot forge an
//! ECDSA signature, so an accepted JWS must carry the signing input
//! (`header.payload`) of a seed that verifies. The seeds are read once, at
//! start, from the directories `run.sh` passes this target; a run seeded
//! from elsewhere must add its directories to `SEED_DIRS`. The clock is
//! fixed, as `verify-receipt`'s is, so a run replays the same on any day.

use apple_purchase_receipt_verifier::{Config, TrustAnchor, Verifier};
use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

const JWS_ROOT: &[u8] = include_bytes!("../../../fixtures/generated/jws-root.der");
/// 2025-01-01T00:00:00Z, inside the fixture chains (2024 to 2050).
const NOW: i64 = 1_735_689_600_000;
/// Under `fixtures/`: what `run.sh` seeds this target with.
const SEED_DIRS: [&str; 3] = [
    "generated",
    "apple-official/mock_signed_data",
    "apple-official/xcode",
];

fn verifiers() -> &'static (Verifier, Verifier) {
    static VERIFIERS: OnceLock<(Verifier, Verifier)> = OnceLock::new();
    VERIFIERS.get_or_init(|| {
        let build = |roots: Vec<TrustAnchor>| {
            Verifier::new(
                Config::builder()
                    .roots(roots)
                    .clock(|| NOW)
                    .build()
                    .expect("a non-empty anchor set"),
            )
        };
        let fixture = vec![TrustAnchor::from_der(JWS_ROOT).expect("fixture root")];
        (build(fixture), build(Config::default().roots().to_vec()))
    })
}

/// `header.payload`: what the signature covers.
fn signing_input(jws: &[u8]) -> &[u8] {
    let end = jws.iter().rposition(|byte| *byte == b'.').unwrap_or(0);
    jws.get(..end).unwrap_or_default()
}

/// The signing input of every seed file the fixture verifier accepts, as
/// it is or without surrounding whitespace.
fn signed_inputs() -> &'static HashSet<Vec<u8>> {
    static INPUTS: OnceLock<HashSet<Vec<u8>>> = OnceLock::new();
    INPUTS.get_or_init(|| {
        let (verifier, _) = verifiers();
        let fixtures = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures"));
        let mut files = Vec::new();
        for dir in SEED_DIRS {
            read_tree(&fixtures.join(dir), &mut files);
        }
        let inputs: HashSet<Vec<u8>> = files
            .iter()
            .flat_map(|file| [file.as_slice(), file.trim_ascii()])
            .filter(|jws| verifier.verify_signed_data_bytes(jws).is_ok())
            .map(|jws| signing_input(jws).to_vec())
            .collect();
        // Loud rather than lenient: with no signed input every acceptance
        // would be reported as a bypass.
        assert!(!inputs.is_empty(), "no seed under {fixtures:?} verifies");
        inputs
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
    let (verifier, apple) = verifiers();
    if verifier.verify_signed_data_bytes(data).is_ok() {
        assert!(
            signed_inputs().contains(signing_input(data)),
            "this input verifies with a header and payload no seed's signer \
             signed, so the signature does not cover what is returned"
        );
        assert!(
            apple.verify_signed_data_bytes(data).is_err(),
            "this input verifies against Apple's roots too, \
             so the anchors are not being enforced"
        );
    }
});
