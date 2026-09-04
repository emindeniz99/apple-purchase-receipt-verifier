//! The real corpus: genuine Apple-signed receipts, verified against the
//! bundled Apple roots.
//!
//! These are the only fixtures nobody in this project can regenerate, and
//! they exercise the two chain shapes the generated corpus does not: a real
//! SHA-1/RSA legacy chain and a real SHA-256/RSA G5 chain.

mod common;

use apple_purchase_receipt_verifier::{
    apple_receipt_roots, base64, status, Environment, Reason, ReceiptVerifier,
    VerifyReceiptEndpoint, VerifyReceiptRequest,
};

fn verifier(bundle_id: &str) -> ReceiptVerifier {
    ReceiptVerifier::builder()
        .trusted_roots(apple_receipt_roots().iter().cloned())
        .bundle_id(bundle_id)
        .build()
        .unwrap()
}

#[test]
fn the_genuine_sandbox_g5_receipt_verifies_against_the_bundled_roots() {
    let der = common::read_base64_fixture("public-receipts/receipt-sandbox-g5.b64");
    let receipt = verifier("dev.bonzer.weeka.app").verify(&der).unwrap();
    assert_eq!(receipt.receipt_type.as_deref(), Some("ProductionSandbox"));
    assert_eq!(receipt.bundle_id.as_deref(), Some("dev.bonzer.weeka.app"));
    assert_eq!(receipt.in_app_purchases.len(), 2);
    assert!(receipt.creation_date.is_some());
    assert!(receipt.opaque_value.is_some());
    assert!(receipt.sha1_hash.is_some());
}

#[test]
fn the_genuine_legacy_sha1_chain_verifies() {
    // sha1WithRSAEncryption on the certificates, and no signedAttrs on the
    // SignerInfo — a shape the generated corpus does not have.
    let der = common::read_base64_fixture("public-receipts/receipt-sandbox-legacy.b64");
    let receipt = verifier("com.nutcall.alert").verify(&der).unwrap();
    assert_eq!(receipt.bundle_id.as_deref(), Some("com.nutcall.alert"));
    assert_eq!(receipt.in_app_purchases.len(), 187);
    // 187 purchases with a seven-byte web_order_line_item_id: the integer
    // bound has to admit real receipts, not just short ones.
    assert!(receipt.in_app_purchases.iter().any(|p| p
        .web_order_line_item_id
        .is_some_and(|id| id > 1_000_000_000)));
}

#[test]
fn the_two_genuine_receipts_are_rejected_under_the_wrong_bundle_id() {
    let der = common::read_base64_fixture("public-receipts/receipt-sandbox-g5.b64");
    assert_eq!(
        verifier("com.nutcall.alert")
            .verify(&der)
            .unwrap_err()
            .reason(),
        Reason::WrongBundleId
    );
}

#[test]
fn the_xcode_receipt_is_not_apple_signed_and_is_rejected() {
    // An Xcode/StoreKit-Test receipt is signed by a local test authority, so
    // it must fail the chain even though it parses perfectly.
    let der = common::read_base64_fixture("public-receipts/receipt-xcode-with-purchases.b64");
    assert_eq!(
        verifier("*").verify(&der).unwrap_err().reason(),
        Reason::InvalidChain
    );

    let empty = common::read_base64_fixture("apple-official/xcode/xcode-app-receipt-empty");
    assert_eq!(
        verifier("com.example.naturelab.backyardbirds.example")
            .verify(&empty)
            .unwrap_err()
            .reason(),
        Reason::InvalidChain
    );
}

#[test]
fn the_genuine_receipts_survive_a_round_trip_through_the_endpoint() {
    let der = common::read_base64_fixture("public-receipts/receipt-sandbox-g5.b64");
    let endpoint = VerifyReceiptEndpoint::builder()
        .trusted_roots(apple_receipt_roots().iter().cloned())
        .environment(Environment::Sandbox)
        .build()
        .unwrap();
    let response = endpoint.verify_receipt(&VerifyReceiptRequest::new(base64::encode(&der)));
    assert_eq!(response.status, status::OK);
    let receipt = response.receipt.unwrap();
    assert_eq!(receipt.get("bundle_id").unwrap(), "dev.bonzer.weeka.app");
    assert!(receipt.get("in_app").unwrap().as_array().unwrap().len() == 2);

    // The same receipt on a production endpoint is a sandbox receipt in the
    // wrong place.
    let production = VerifyReceiptEndpoint::builder()
        .trusted_roots(apple_receipt_roots().iter().cloned())
        .environment(Environment::Production)
        .build()
        .unwrap();
    assert_eq!(
        production
            .verify_receipt(&VerifyReceiptRequest::new(base64::encode(&der)))
            .status,
        status::SANDBOX_RECEIPT_ON_PRODUCTION
    );
}

#[test]
fn verifying_the_largest_genuine_receipt_is_fast_and_repeatable() {
    // 79 KB, 187 in-app purchases: the largest thing this library is ever
    // asked to verify, and the benchmark every DoS bound is measured
    // against.
    let der = common::read_base64_fixture("public-receipts/receipt-sandbox-legacy.b64");
    let verifier = verifier("com.nutcall.alert");
    let first = verifier.verify(&der).unwrap();
    let started = std::time::Instant::now();
    for _ in 0..10 {
        assert_eq!(verifier.verify(&der).unwrap(), first);
    }
    let elapsed = started.elapsed();
    assert!(elapsed.as_secs() < 20, "ten verifications took {elapsed:?}");
}

#[test]
fn apples_official_jws_fixtures_verify_against_apples_test_ca() {
    use apple_purchase_receipt_verifier::{JwsVerifier, TrustAnchor};
    let ca = TrustAnchor::from_der(&common::read_fixture("apple-official/certs/testCA.der"))
        .expect("Apple's test CA must parse");
    let verifier = JwsVerifier::builder()
        .trusted_roots([ca])
        .bundle_id("com.example")
        .accepted_environments([Environment::Sandbox])
        .build()
        .unwrap();
    // ecdsa-with-SHA384 over P-256 keys: the digest is wider than the field
    // and SEC1 truncation applies. A fixed "verify(message) with SHA-256"
    // implementation cannot verify this chain.
    let jws = common::read_text_fixture("apple-official/mock_signed_data/transactionInfo");
    let payload = verifier.verify_transaction(&jws).unwrap();
    assert_eq!(payload.bundle_id.as_deref(), Some("com.example"));
    assert_eq!(payload.signed_date, Some(1_672_956_154_000));
}
