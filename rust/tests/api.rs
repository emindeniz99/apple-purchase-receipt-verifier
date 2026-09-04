//! The public API's shape and its configuration contract.
//!
//! A security library's surface is part of its security: a caller must be
//! able to tell a misconfiguration from a verdict, to match on a reason
//! without parsing text, and to share one verifier across threads.

mod common;

#[cfg(feature = "endpoint")]
use apple_purchase_receipt_verifier::VerifyReceiptEndpoint;
use apple_purchase_receipt_verifier::{
    apple_jws_roots, apple_receipt_roots, verify_receipt_core, ConfigError, CoreError, Environment,
    JwsVerifier, Reason, ReceiptVerifier, TrustAnchor, VerificationError,
};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

#[test]
fn every_reason_spells_the_canonical_token() {
    // These eleven strings are the cross-port contract. A change here is a
    // change to fixtures/cases.schema.json and to all nine ports.
    let expected = [
        "INVALID_JWS_FORMAT",
        "INVALID_CERTIFICATE",
        "INVALID_CERTIFICATE_PURPOSE",
        "INVALID_CHAIN",
        "INVALID_SIGNATURE",
        "WRONG_BUNDLE_ID",
        "WRONG_ENVIRONMENT",
        "WRONG_APP_APPLE_ID",
        "INVALID_RECEIPT_FORMAT",
        "DEVICE_HASH_MISMATCH",
        "STALE_PAYLOAD",
    ];
    let actual: Vec<&str> = Reason::all().iter().map(|r| r.as_str()).collect();
    assert_eq!(actual, expected);
    assert_eq!(Reason::all().len(), 11);
}

#[test]
fn reason_round_trips_through_from_str_and_display() {
    for reason in Reason::all() {
        assert_eq!(Reason::from_str(reason.as_str()).unwrap(), *reason);
        assert_eq!(reason.to_string(), reason.as_str());
    }
}

#[test]
fn reason_from_str_rejects_a_twelfth_token() {
    let err = Reason::from_str("INVALID_EVERYTHING").unwrap_err();
    assert!(err.to_string().contains("INVALID_EVERYTHING"));
    assert!(
        Reason::from_str("invalid_chain").is_err(),
        "the token is case-sensitive"
    );
    assert!(Reason::from_str("").is_err());
}

#[test]
fn environment_spells_the_four_claim_strings() {
    let actual: Vec<&str> = Environment::all().iter().map(|e| e.as_str()).collect();
    assert_eq!(actual, ["Production", "Sandbox", "Xcode", "LocalTesting"]);
    for environment in Environment::all() {
        assert_eq!(
            Environment::from_str(environment.as_str()).unwrap(),
            *environment
        );
    }
    assert!(Environment::from_claim("production").is_none());
}

#[test]
fn verification_error_displays_as_reason_colon_detail() {
    let verifier = JwsVerifier::builder()
        .trusted_roots([common::jws_root()])
        .bundle_id("com.other.app")
        .accepted_environments([Environment::Sandbox])
        .build()
        .unwrap();
    let error = verifier
        .verify_transaction(&common::transaction_jws())
        .unwrap_err();
    assert_eq!(error.reason(), Reason::WrongBundleId);
    assert!(error.to_string().starts_with("WRONG_BUNDLE_ID: "));
    // The detail must never carry payload bytes or claims a caller would
    // then log. It names the mismatch, not the receipt.
    assert!(!error.detail().is_empty());
    let as_error: &dyn std::error::Error = &error;
    assert!(as_error.source().is_none());
}

#[test]
fn builders_reject_empty_trust_anchors() {
    let err = JwsVerifier::builder()
        .bundle_id("com.example.app")
        .accepted_environments([Environment::Sandbox])
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("trustedRoots"));

    assert!(ReceiptVerifier::builder()
        .bundle_id("com.example.app")
        .build()
        .is_err());
    #[cfg(feature = "endpoint")]
    assert!(VerifyReceiptEndpoint::builder()
        .environment(Environment::Sandbox)
        .build()
        .is_err());
}

#[test]
fn builders_reject_an_empty_bundle_id() {
    let err = JwsVerifier::builder()
        .trusted_roots([common::jws_root()])
        .bundle_id("")
        .accepted_environments([Environment::Sandbox])
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("bundleId"));
    assert!(ReceiptVerifier::builder()
        .trusted_roots([common::receipt_root()])
        .bundle_id("")
        .build()
        .is_err());
}

#[test]
fn jws_builder_rejects_an_empty_accepted_environment_set() {
    let err = JwsVerifier::builder()
        .trusted_roots([common::jws_root()])
        .bundle_id("com.example.app")
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("acceptedEnvironments"));
}

#[cfg(feature = "endpoint")]
#[test]
fn endpoint_rejects_an_environment_apple_does_not_have() {
    for environment in [Environment::Xcode, Environment::LocalTesting] {
        let err = VerifyReceiptEndpoint::builder()
            .trusted_roots([common::receipt_root()])
            .environment(environment)
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("Production or Sandbox"), "{err}");
    }
    let err = VerifyReceiptEndpoint::builder()
        .trusted_roots([common::receipt_root()])
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("environment"));
}

#[test]
fn misconfiguration_is_not_a_verification_verdict() {
    // ConfigError and VerificationError are different types, so a caller
    // cannot catch a programming mistake as a "receipt rejected". This test
    // exists to make that a regression if the types are ever merged.
    fn takes_config_error(_: ConfigError) {}
    fn takes_verification_error(_: VerificationError) {}
    let config = JwsVerifier::builder().bundle_id("x").build().unwrap_err();
    takes_config_error(config);
    let verifier = ReceiptVerifier::builder()
        .trusted_roots([common::receipt_root()])
        .bundle_id("com.example.app")
        .build()
        .unwrap();
    takes_verification_error(verifier.verify(&[]).unwrap_err());
}

#[test]
fn a_bad_trust_anchor_is_a_config_error() {
    assert!(TrustAnchor::from_der(&[0x30, 0x00]).is_err());
    assert!(TrustAnchor::from_der(&[]).is_err());
    assert!(TrustAnchor::from_pem("not a pem").is_err());
    assert!(TrustAnchor::from_pem("-----BEGIN CERTIFICATE-----\nAAAA\n").is_err());
}

#[test]
fn der_and_pem_anchors_are_interchangeable() {
    let der = common::read_fixture("generated/receipt-root.der");
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        apple_purchase_receipt_verifier::base64::encode(&der)
    );
    let from_der = ReceiptVerifier::builder()
        .trusted_roots([TrustAnchor::from_der(&der).unwrap()])
        .bundle_id("com.example.app")
        .build()
        .unwrap();
    let from_pem = ReceiptVerifier::builder()
        .trusted_roots([TrustAnchor::from_pem(&pem).unwrap()])
        .bundle_id("com.example.app")
        .build()
        .unwrap();
    let receipt = common::receipt_der();
    assert_eq!(
        from_der.verify(&receipt).unwrap(),
        from_pem.verify(&receipt).unwrap(),
        "the same anchor in two encodings must reach the same verdict"
    );
}

#[test]
fn a_pem_anchor_with_trailing_junk_still_parses_the_block() {
    let der = common::read_fixture("generated/receipt-root.der");
    let pem = format!(
        "junk before\n-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\njunk after\n",
        apple_purchase_receipt_verifier::base64::encode(&der)
    );
    assert!(TrustAnchor::from_pem(&pem).is_ok());
}

#[test]
fn verifiers_are_send_sync_and_static() {
    fn assert_shareable<T: Send + Sync + 'static>() {}
    assert_shareable::<JwsVerifier>();
    assert_shareable::<ReceiptVerifier>();
    #[cfg(feature = "endpoint")]
    assert_shareable::<VerifyReceiptEndpoint>();
    assert_shareable::<VerificationError>();
    assert_shareable::<ConfigError>();
    assert_shareable::<Reason>();
}

#[test]
fn one_verifier_answers_identically_from_sixteen_threads() {
    let verifier = Arc::new(
        ReceiptVerifier::builder()
            .trusted_roots([common::receipt_root()])
            .bundle_id("com.example.app")
            .build()
            .unwrap(),
    );
    let jws = Arc::new(
        JwsVerifier::builder()
            .trusted_roots([common::jws_root()])
            .bundle_id("com.example.app")
            .accepted_environments([Environment::Sandbox])
            .max_signed_age(Duration::from_secs(60))
            .clock(Arc::new(
                apple_purchase_receipt_verifier::FixedClock::from_unix_millis(1_722_945_610_000),
            ))
            .build()
            .unwrap(),
    );
    let receipt = Arc::new(common::receipt_der());
    let transaction = Arc::new(common::transaction_jws());
    let expected_receipt = verifier.verify(&receipt).unwrap();
    let expected_payload = jws.verify_transaction(&transaction).unwrap();

    let handles: Vec<_> = (0..16)
        .map(|_| {
            let verifier = Arc::clone(&verifier);
            let jws = Arc::clone(&jws);
            let receipt = Arc::clone(&receipt);
            let transaction = Arc::clone(&transaction);
            let expected_receipt = expected_receipt.clone();
            let expected_payload = expected_payload.clone();
            std::thread::spawn(move || {
                for _ in 0..25 {
                    assert_eq!(verifier.verify(&receipt).unwrap(), expected_receipt);
                    assert_eq!(
                        jws.verify_transaction(&transaction).unwrap(),
                        expected_payload
                    );
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn bundled_anchors_are_parsed_once_and_shared() {
    let first = apple_jws_roots();
    let second = apple_jws_roots();
    assert!(
        std::ptr::eq(first, second),
        "the OnceLock must hand back the same slice"
    );
    assert!(std::ptr::eq(apple_receipt_roots(), apple_jws_roots()));
}

#[test]
fn verify_receipt_core_is_public_and_skips_the_bundle_id_check() {
    // The endpoint needs this primitive; the alternative the other ports
    // once shipped is a wildcard bundle id inside a security library.
    let anchors = [common::receipt_root()];
    let receipt = verify_receipt_core(&common::receipt_der(), &anchors).unwrap();
    assert_eq!(receipt.bundle_id.as_deref(), Some("com.example.app"));

    // Same receipt, a verifier configured for a different bundle: the core
    // accepts it, the verifier does not. That difference is the whole
    // reason the doc comment says "you must check bundle_id yourself".
    let verifier = ReceiptVerifier::builder()
        .trusted_roots(anchors)
        .bundle_id("com.other.app")
        .build()
        .unwrap();
    assert_eq!(
        verifier
            .verify(&common::receipt_der())
            .unwrap_err()
            .reason(),
        Reason::WrongBundleId
    );
}

/// CONTRACT.md §1.4: "Misconfiguration is not a verification verdict. Empty
/// trust anchors ... the language's argument-error type, never a
/// `VerificationError`." This used to answer `INVALID_CHAIN`, which makes an
/// anchor-loading bug — a typo'd path, an empty environment variable, a
/// `Vec` filtered to nothing — look exactly like a forged receipt, and is
/// the shape §2.4 D-f names Swift as the outlier for.
#[test]
fn verify_receipt_core_with_no_anchors_is_a_configuration_error_not_a_verdict() {
    let error = verify_receipt_core(&common::receipt_der(), &[]).unwrap_err();
    assert_eq!(error.reason(), None, "an empty anchor set is not a verdict");
    assert_eq!(error.as_verification(), None);
    match &error {
        CoreError::Config(config) => {
            assert_eq!(config.detail(), "trustedRoots must not be empty");
        }
        other => panic!("expected a configuration error, got {other:?}"),
    }
    // The same bytes with a real anchor verify, so nothing about the receipt
    // was the problem.
    let anchors = [common::receipt_root()];
    assert_eq!(
        verify_receipt_core(&common::receipt_der(), &anchors)
            .unwrap()
            .bundle_id
            .as_deref(),
        Some("com.example.app")
    );
}

/// The two error types stay distinguishable through `std::error::Error`, so
/// a caller using `Box<dyn Error>` can still tell a bug from a verdict.
#[test]
fn a_core_error_carries_its_cause() {
    use std::error::Error as _;
    let config = verify_receipt_core(&common::receipt_der(), &[]).unwrap_err();
    assert!(config.source().unwrap().is::<ConfigError>());
    assert!(config.to_string().starts_with("configuration error: "));

    let anchors = [common::receipt_root()];
    let verdict = verify_receipt_core(b"not a receipt", &anchors).unwrap_err();
    assert_eq!(verdict.reason(), Some(Reason::InvalidReceiptFormat));
    assert!(verdict.source().unwrap().is::<VerificationError>());
    assert!(verdict.to_string().starts_with("INVALID_RECEIPT_FORMAT: "));
}

#[test]
fn the_device_guid_matrix_is_complete() {
    let verifier = ReceiptVerifier::builder()
        .trusted_roots([common::receipt_root()])
        .bundle_id("com.example.app")
        .build()
        .unwrap();
    let der = common::receipt_der();
    let base64 = apple_purchase_receipt_verifier::base64::encode(&der);
    let guid = common::device_guid();

    // Every input form is reachable with and without the device GUID.
    let a = verifier.verify(&der).unwrap();
    let b = verifier.verify_base64(&base64).unwrap();
    let c = verifier.verify_with_device_guid(&der, &guid).unwrap();
    let d = verifier
        .verify_base64_with_device_guid(&base64, &guid)
        .unwrap();
    assert_eq!(a, b);
    assert_eq!(a, c);
    assert_eq!(a, d);
}

#[test]
fn returned_byte_fields_are_copies_not_views_into_the_input() {
    let verifier = ReceiptVerifier::builder()
        .trusted_roots([common::receipt_root()])
        .bundle_id("com.example.app")
        .build()
        .unwrap();
    let mut der = common::receipt_der();
    let receipt = verifier.verify(&der).unwrap();
    let opaque = receipt.opaque_value.clone();
    // A caller reusing its buffer must not be able to mutate an
    // already-verified receipt.
    der.iter_mut().for_each(|byte| *byte = 0);
    assert_eq!(receipt.opaque_value, opaque);
}

#[test]
fn is_active_at_reads_only_the_signed_claims() {
    use apple_purchase_receipt_verifier::datetime::system_time_from_millis;
    let verifier = JwsVerifier::builder()
        .trusted_roots([common::jws_root()])
        .bundle_id("com.example.app")
        .accepted_environments([Environment::Sandbox])
        .build()
        .unwrap();
    let mut payload = verifier
        .verify_transaction(&common::transaction_jws())
        .unwrap();
    // No expiry and no revocation: always active.
    assert!(payload.is_active_at(system_time_from_millis(0)));
    assert!(payload.is_active_at(system_time_from_millis(4_070_908_800_000)));

    payload.expires_date = Some(2_000);
    assert!(payload.is_active_at(system_time_from_millis(1_999)));
    assert!(!payload.is_active_at(system_time_from_millis(2_000)));

    payload.revocation_date = Some(1_000);
    assert!(payload.is_active_at(system_time_from_millis(999)));
    assert!(
        !payload.is_active_at(system_time_from_millis(1_000)),
        "revocation wins"
    );
}

#[test]
fn a_typed_payload_agrees_with_its_own_claim_escape_hatch() {
    let verifier = JwsVerifier::builder()
        .trusted_roots([common::jws_root()])
        .bundle_id("com.example.app")
        .accepted_environments([Environment::Sandbox])
        .build()
        .unwrap();
    let payload = verifier
        .verify_transaction(&common::transaction_jws())
        .unwrap();
    assert_eq!(
        payload.bundle_id.as_deref(),
        payload.claims.get("bundleId").and_then(|v| v.as_str())
    );
    assert_eq!(
        payload.signed_date,
        payload.claims.get("signedDate").and_then(|v| v.as_i64())
    );
    // Contractual: Apple's date claims stay epoch-millisecond integers.
    assert_eq!(payload.signed_date, Some(1_722_945_600_000));

    let app = JwsVerifier::builder()
        .trusted_roots([common::jws_root()])
        .bundle_id("com.example.app")
        .accepted_environments([Environment::Sandbox])
        .app_apple_id(123_456_789)
        .build()
        .unwrap()
        .verify_app_transaction(&common::app_transaction_jws())
        .unwrap();
    assert_eq!(app.receipt_type.as_deref(), Some("Sandbox"));
    assert_eq!(app.app_apple_id, Some(123_456_789));
    assert_eq!(app.receipt_creation_date, Some(1_722_945_600_000));
}
