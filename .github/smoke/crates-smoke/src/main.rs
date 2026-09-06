//! Smoke-tests the crate as published to crates.io. Everything it touches — the
//! verifier, the error type, the bundled root certificates — comes from the
//! resolved dependency, so a tarball missing `certs/` fails here rather than in
//! a user's build.
use apple_purchase_receipt_verifier::{apple_receipt_roots, Reason, ReceiptVerifier};

fn main() {
    let text = std::fs::read_to_string("receipt-sandbox-g5.b64")
        .expect("cannot read the fixture receipt-sandbox-g5.b64");
    let receipt_b64 = text.trim();

    let roots = apple_receipt_roots();
    assert_eq!(roots.len(), 3, "expected three bundled Apple roots");

    // A real Apple-signed receipt against the real pinned root: exercises the
    // packaged certs, the DER reader, the chain build and the signature check.
    let verifier = ReceiptVerifier::builder()
        .trusted_roots(roots.iter().cloned())
        .bundle_id("dev.bonzer.weeka.app")
        .build()
        .expect("cannot build the verifier");
    let receipt = verifier
        .verify_base64(receipt_b64)
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
    // fail here too.
    let other = ReceiptVerifier::builder()
        .trusted_roots(roots.iter().cloned())
        .bundle_id("com.other.app")
        .build()
        .expect("cannot build the second verifier");
    match other.verify_base64(receipt_b64) {
        Err(error) if error.reason() == Reason::WrongBundleId => {}
        Err(error) => panic!("rejected for {}, expected WRONG_BUNDLE_ID", error.reason()),
        Ok(_) => panic!("a receipt for another bundle id was not rejected"),
    }

    println!(
        "crates.io: published crate verified a genuine Apple receipt ({}, {} purchases) \
         and rejected a foreign bundle id",
        receipt.bundle_id.as_deref().unwrap_or("?"),
        receipt.in_app_purchases.len()
    );
}
