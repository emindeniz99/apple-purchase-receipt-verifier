//! The real corpus: genuine Apple-signed receipts, verified against the
//! bundled Apple roots.
//!
//! These are the only fixtures nobody in this project can regenerate, and
//! they exercise the two chain shapes the generated corpus does not: a real
//! SHA-1/RSA legacy chain and a real SHA-256/RSA G5 chain.

mod common;

use apple_purchase_receipt_verifier::__internal::base64_encode;
use apple_purchase_receipt_verifier::{Config, Environment, Reason, TrustAnchor, Verifier};
use serde_json::Value;

fn verifier() -> Verifier {
    Verifier::new(Config::defaults())
}

fn genuine(name: &str) -> String {
    base64_encode(&common::read_base64_fixture(&format!(
        "public-receipts/{name}.b64"
    )))
}

#[test]
fn the_genuine_sandbox_g5_receipt_verifies_against_the_bundled_roots() {
    let receipt = verifier()
        .verify_receipt(&genuine("receipt-sandbox-g5"))
        .unwrap();
    assert_eq!(receipt.receipt_type.as_deref(), Some("ProductionSandbox"));
    assert_eq!(receipt.bundle_id.as_deref(), Some("dev.bonzer.weeka.app"));
    assert_eq!(receipt.in_app.len(), 2);
    assert!(receipt.receipt_creation_date_ms.is_some());
    assert!(receipt.opaque_value.is_some());
    assert!(receipt.sha1_hash.is_some());
}

#[test]
fn the_genuine_legacy_sha1_chain_verifies() {
    // sha1WithRSAEncryption on the certificates, and no signedAttrs on the
    // SignerInfo, a shape the generated corpus does not have.
    let receipt = verifier()
        .verify_receipt(&genuine("receipt-sandbox-legacy"))
        .unwrap();
    assert_eq!(receipt.bundle_id.as_deref(), Some("com.nutcall.alert"));
    assert_eq!(receipt.in_app.len(), 187);
    // 187 purchases with a seven-byte web_order_line_item_id: the integer
    // decoder has to admit real receipts, not just short ones.
    assert!(receipt.in_app.iter().any(|p| p
        .web_order_line_item_id
        .is_some_and(|id| id > 1_000_000_000)));
}

#[test]
fn a_genuine_receipt_is_returned_whatever_bundle_the_caller_expects() {
    // 0.7 takes no bundle id: the receipt comes back and the caller compares
    // bundle_id, which is where 0.6 answered WRONG_BUNDLE_ID.
    let receipt = verifier()
        .verify_receipt(&genuine("receipt-sandbox-g5"))
        .unwrap();
    let other = verifier()
        .verify_receipt(&genuine("receipt-sandbox-legacy"))
        .unwrap();
    assert_ne!(receipt.bundle_id, other.bundle_id);
}

#[test]
fn the_xcode_receipt_is_not_apple_signed_and_is_rejected() {
    // An Xcode/StoreKit-Test receipt is signed by a local test authority, so
    // it must fail the chain even though it parses perfectly.
    assert_eq!(
        verifier()
            .verify_receipt(&genuine("receipt-xcode-with-purchases"))
            .unwrap_err()
            .reason(),
        Reason::UntrustedChain
    );
    let empty = common::read_base64_fixture("apple-official/xcode/xcode-app-receipt-empty");
    assert_eq!(
        verifier()
            .verify_receipt(&base64_encode(&empty))
            .unwrap_err()
            .reason(),
        Reason::UntrustedChain
    );
}

#[test]
fn the_genuine_receipts_survive_a_round_trip_through_the_endpoint() {
    let body = serde_json::json!({ "receipt-data": genuine("receipt-sandbox-g5") }).to_string();
    let response: Value =
        serde_json::from_str(&verifier().verify_receipt_endpoint(Environment::Sandbox, &body))
            .unwrap();
    assert_eq!(response["status"], 0);
    assert_eq!(response["environment"], "Sandbox");
    let receipt = verifier()
        .verify_receipt(&genuine("receipt-sandbox-g5"))
        .unwrap();
    assert_eq!(
        response["receipt"]["bundle_id"].as_str(),
        receipt.bundle_id.as_deref()
    );
    assert_eq!(response["receipt"]["in_app"].as_array().unwrap().len(), 2);

    // The same receipt on a production endpoint is a sandbox receipt in the
    // wrong place.
    assert_eq!(
        verifier().verify_receipt_endpoint(Environment::Production, &body),
        "{\"status\":21007}"
    );
}

#[test]
fn verifying_the_largest_genuine_receipt_is_fast_and_repeatable() {
    // 79 KB, 187 in-app purchases: the largest thing this library is ever
    // asked to verify, and the benchmark every DoS bound is measured
    // against.
    let receipt = genuine("receipt-sandbox-legacy");
    let verifier = verifier();
    let first = verifier.verify_receipt(&receipt).unwrap();
    let started = std::time::Instant::now();
    for _ in 0..10 {
        assert_eq!(verifier.verify_receipt(&receipt).unwrap(), first);
    }
    let elapsed = started.elapsed();
    assert!(elapsed.as_secs() < 20, "ten verifications took {elapsed:?}");
}

#[test]
fn apples_official_jws_fixtures_verify_against_apples_test_ca() {
    let ca = TrustAnchor::from_der(&common::read_fixture("apple-official/certs/testCA.der"))
        .expect("Apple's test CA must parse");
    // ecdsa-with-SHA384 over P-256 keys: the digest is wider than the field
    // and SEC1 truncation applies. A fixed "verify(message) with SHA-256"
    // implementation cannot verify this chain.
    let jws = common::read_text_fixture("apple-official/mock_signed_data/transactionInfo");
    let payload = common::verifier([ca]).verify_signed_data(&jws).unwrap();
    let claims = common::claims(&payload);
    assert_eq!(claims["bundleId"], "com.example");
    assert_eq!(claims["signedDate"], 1_672_956_154_000_i64);
}

#[test]
fn a_genuine_receipt_with_one_content_byte_changed_is_an_invalid_signature() {
    // Genuine receipts carry no signedAttrs, unlike every receipt the
    // generated corpus has, so the RSA check here runs over the content
    // itself. One byte of the bundle id changed, with the chain and the
    // creation date left exactly as Apple signed them, must fail it.
    let genuine = common::read_base64_fixture("public-receipts/receipt-sandbox-g5.b64");
    let payload = verifier().verify_receipt(&base64_encode(&genuine)).unwrap();
    let bundle_id = payload.bundle_id_bytes.unwrap();
    let at = genuine
        .windows(bundle_id.len())
        .position(|window| window == bundle_id.as_slice())
        .expect("the bundle id is in the receipt");
    let mut tampered = genuine.clone();
    tampered[at + bundle_id.len() - 1] ^= 0x01;
    let failure = verifier()
        .verify_receipt(&base64_encode(&tampered))
        .unwrap_err();
    assert_eq!(failure.reason(), Reason::InvalidSignature, "{failure}");
}

#[test]
fn the_legacy_purchase_info_transaction_receipt_is_not_a_receipt() {
    // Intentional: the pre-2018 per-transaction receipt (base64 around an
    // old-style plist holding "purchase-info") is not supported. It is not
    // the PKCS#7 container a signature lives in, so Apple's own mock of it
    // fails as MALFORMED, and the endpoint answers 21002 as Apple's service
    // does for data it cannot read.
    let legacy = common::read_text_fixture("apple-official/mock_signed_data/legacyTransaction");
    let legacy = legacy.trim();
    assert_eq!(
        verifier().verify_receipt(legacy).unwrap_err().reason(),
        Reason::Malformed
    );
    let body = serde_json::json!({ "receipt-data": legacy }).to_string();
    assert_eq!(
        verifier().verify_receipt_endpoint(Environment::Sandbox, &body),
        "{\"status\":21002}"
    );
}

// --- Apple's production JWS chain ----------------------------------------

// A real App Store signing chain: the leaf, the WWDR G6 intermediate and
// Apple Root CA - G3, copied from the REAL_APPLE_* constants in
// ChainVerifierTest.java of Apple's app-store-server-library-java
// (https://github.com/apple/app-store-server-library-java, MIT licence,
// Copyright 2023 Apple Inc.). They are Apple's public certificates, not
// secrets.
const REAL_APPLE_SIGNING_CERTIFICATE: &str = concat!(
    "MIIEMTCCA7agAwIBAgIQR8KHzdn554Z/UoradNx9tzAKBggqhkjOPQQDAzB1MUQwQgYDVQQDDDtB",
    "cHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0",
    "eTELMAkGA1UECwwCRzYxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMB4XDTI1MDkx",
    "OTE5NDQ1MVoXDTI3MTAxMzE3NDcyM1owgZIxQDA+BgNVBAMMN1Byb2QgRUNDIE1hYyBBcHAgU3Rv",
    "cmUgYW5kIGlUdW5lcyBTdG9yZSBSZWNlaXB0IFNpZ25pbmcxLDAqBgNVBAsMI0FwcGxlIFdvcmxk",
    "d2lkZSBEZXZlbG9wZXIgUmVsYXRpb25zMRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJV",
    "UzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNnVvhcv7iT+7Ex5tBMBgrQspHzIsXRi0Yxfek7l",
    "v8wEmj/bHiWtNwJqc2BoHzsQiEjP7KFIIKg4Y8y0/nynuAmjggIIMIICBDAMBgNVHRMBAf8EAjAA",
    "MB8GA1UdIwQYMBaAFD8vlCNR01DJmig97bB85c+lkGKZMHAGCCsGAQUFBwEBBGQwYjAtBggrBgEF",
    "BQcwAoYhaHR0cDovL2NlcnRzLmFwcGxlLmNvbS93d2RyZzYuZGVyMDEGCCsGAQUFBzABhiVodHRw",
    "Oi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLXd3ZHJnNjAyMIIBHgYDVR0gBIIBFTCCAREwggENBgoq",
    "hkiG92NkBQYBMIH+MIHDBggrBgEFBQcCAjCBtgyBs1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNh",
    "dGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxl",
    "IHN0YW5kYXJkIHRlcm1zIGFuZCBjb25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5",
    "IGFuZCBjZXJ0aWZpY2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMDYGCCsGAQUFBwIBFipodHRw",
    "Oi8vd3d3LmFwcGxlLmNvbS9jZXJ0aWZpY2F0ZWF1dGhvcml0eS8wHQYDVR0OBBYEFIFioG4wMMVA",
    "1ku9zJmGNPAVn3eqMA4GA1UdDwEB/wQEAwIHgDAQBgoqhkiG92NkBgsBBAIFADAKBggqhkjOPQQD",
    "AwNpADBmAjEA+qXnREC7hXIWVLsLxznjRpIzPf7VHz9V/CTm8+LJlrQepnmcPvGLNcX6XPnlcgLA",
    "AjEA5IjNZKgg5pQ79knF4IbTXdKv8vutIDMXDmjPVT3dGvFtsGRwXOywR2kZCdSrfeot",
);

const REAL_APPLE_INTERMEDIATE: &str = concat!(
    "MIIDFjCCApygAwIBAgIUIsGhRwp0c2nvU4YSycafPTjzbNcwCgYIKoZIzj0EAwMwZzEbMBkGA1UE",
    "AwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhv",
    "cml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMjEwMzE3MjAzNzEwWhcN",
    "MzYwMzE5MDAwMDAwWjB1MUQwQgYDVQQDDDtBcHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0",
    "aW9ucyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTELMAkGA1UECwwCRzYxEzARBgNVBAoMCkFwcGxl",
    "IEluYy4xCzAJBgNVBAYTAlVTMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEbsQKC94PrlWmZXnXgtxz",
    "dVJL8T0SGYngDRGpngn3N6PT8JMEb7FDi4bBmPhCnZ3/sq6PF/cGcKXWsL5vOteRhyJ45x3ASP7c",
    "OB+aao90fcpxSv/EZFbniAbNgZGhIhpIo4H6MIH3MBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0j",
    "BBgwFoAUu7DeoVgziJqkipnevr3rr9rLJKswRgYIKwYBBQUHAQEEOjA4MDYGCCsGAQUFBzABhipo",
    "dHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFwcGxlcm9vdGNhZzMwNwYDVR0fBDAwLjAsoCqg",
    "KIYmaHR0cDovL2NybC5hcHBsZS5jb20vYXBwbGVyb290Y2FnMy5jcmwwHQYDVR0OBBYEFD8vlCNR",
    "01DJmig97bB85c+lkGKZMA4GA1UdDwEB/wQEAwIBBjAQBgoqhkiG92NkBgIBBAIFADAKBggqhkjO",
    "PQQDAwNoADBlAjBAXhSq5IyKogMCPtw490BaB677CaEGJXufQB/EqZGd6CSjiCtOnuMTbXVXmxxc",
    "xfkCMQDTSPxarZXvNrkxU3TkUMI33yzvFVVRT4wxWJC994OsdcZ4+RGNsYDyR5gmdr0nDGg=",
);

const REAL_APPLE_ROOT: &str = concat!(
    "MIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUgUm9v",
    "dCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UE",
    "CgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2",
    "WjBnMRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmlj",
    "YXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqG",
    "SM49AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtfTjjTuxxE",
    "tX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dvMVztK517IDvYuVTZXpmkOlEKMaNC",
    "MEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySrMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0P",
    "AQH/BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQCD6cHEFl4aXTQY2e3v9GwOAEZLuN+yRhHFD/3m",
    "eoyhpmvOwgPUnPWTxnS4at+qIxUCMG1mihDK1A3UT82NQz60imOlM27jbdoXt2QfyFMm+YhidDkL",
    "F1vLUagM6BgD56KyKA==",
);

/// Apple's own validation instant for the chain above, 2025-11-01T02:09:35Z.
const EFFECTIVE_DATE_MILLIS: i64 = 1_761_962_975_000;

/// A JWS over the real x5c whose signedDate is `signed_at`; its signature is
/// 64 zero bytes, since no payload Apple signed with this leaf is public.
fn real_chain_jws(signed_at: i64) -> String {
    let header = format!(
        r#"{{"alg":"ES256","x5c":["{REAL_APPLE_SIGNING_CERTIFICATE}","{REAL_APPLE_INTERMEDIATE}","{REAL_APPLE_ROOT}"]}}"#
    );
    common::join_jws(
        &common::base64url(header.as_bytes()),
        &common::base64url(format!(r#"{{"signedDate":{signed_at}}}"#).as_bytes()),
        &common::base64url(&[0; 64]),
    )
}

#[test]
fn apples_real_production_chain_passes_at_its_effective_date() {
    // The marker OIDs and the chain are checked before the signature, so
    // reaching INVALID_SIGNATURE, and not INVALID_CERTIFICATE_PURPOSE or
    // UNTRUSTED_CHAIN, is the proof that both passed on the real code path
    // against the bundled roots. If this fails, the bundled roots or the OID
    // checks no longer accept what Apple actually ships.
    let root = base64_decode(REAL_APPLE_ROOT);
    assert!(
        Config::defaults()
            .roots()
            .iter()
            .any(|anchor| anchor.der() == root.as_slice()),
        "Apple Root CA - G3 is not among the bundled roots"
    );
    let failure = verifier()
        .verify_signed_data(&real_chain_jws(EFFECTIVE_DATE_MILLIS))
        .unwrap_err();
    assert_eq!(failure.reason(), Reason::InvalidSignature, "{failure}");
}

#[test]
fn apples_real_production_chain_fails_outside_its_validity() {
    // The leaf is valid 2025-09-19 to 2027-10-13: a genuine chain is not a
    // pass at any date.
    for signed_at in [1_756_684_800_000_i64, 1_823_472_000_000] {
        let failure = verifier()
            .verify_signed_data(&real_chain_jws(signed_at))
            .unwrap_err();
        assert_eq!(
            failure.reason(),
            Reason::InvalidCertificate,
            "signedDate {signed_at}: {failure}"
        );
    }
}

fn base64_decode(text: &str) -> Vec<u8> {
    apple_purchase_receipt_verifier::__internal::base64_decode_lenient(text)
}
