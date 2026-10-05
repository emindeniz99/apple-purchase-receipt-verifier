//! Evidence only (2026-10-05). How many signatures the core checks itself
//! (outside `X509_verify_cert`), and how long a verification takes, for the
//! shared receipt and the shared transaction. Copy to
//! `rust/tests/path_cost.rs` and run `cargo test -p
//! apple-purchase-receipt-verifier --test path_cost -- --nocapture`.

mod common;

use apple_purchase_receipt_verifier::__internal::keys_used_during;
use std::time::Instant;

const CALLS: u32 = 200;

#[test]
fn path_cost() {
    let receipt = common::receipt_der();
    let receipts = common::verifier([common::receipt_root()]);
    let jws = common::transaction_jws();
    let transactions = common::verifier([common::jws_root()]);
    let (verified, keys) = keys_used_during(|| common::verify_der(&receipts, &receipt));
    assert!(verified.is_ok());
    let started = Instant::now();
    for _ in 0..CALLS {
        let _ = common::verify_der(&receipts, &receipt);
    }
    eprintln!(
        "COST receipt: {} signature checks by the core, {:?} a verification",
        keys.len(),
        started.elapsed() / CALLS
    );
    let (verified, keys) = keys_used_during(|| transactions.verify_signed_data(&jws));
    assert!(verified.is_ok());
    let started = Instant::now();
    for _ in 0..CALLS {
        let _ = transactions.verify_signed_data(&jws);
    }
    eprintln!(
        "COST transaction: {} signature checks by the core, {:?} a verification",
        keys.len(),
        started.elapsed() / CALLS
    );
}
