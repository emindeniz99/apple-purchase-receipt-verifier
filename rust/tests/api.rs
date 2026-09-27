//! The public API's shape and its configuration contract.
//!
//! A security library's surface is part of its security: a caller must be
//! able to tell a misconfiguration from a verdict, to match on a reason
//! without parsing text, to share one verifier across threads, and to build
//! payloads and failures by hand in its own tests.

mod common;

use apple_purchase_receipt_verifier::__internal::{base64_decode_lenient, base64_encode};
use apple_purchase_receipt_verifier::{
    AppleStatus, Config, ConfigError, Environment, Failure, InAppPurchase, JsonPayload, Reason,
    ReceiptPayload, TrustAnchor, Verifier, VERSION,
};
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

#[test]
fn every_reason_spells_the_canonical_token() {
    // These eight strings are the cross-port contract. A change here is a
    // change to fixtures/cases-0.7.schema.json and to all nine ports.
    let expected = [
        "MALFORMED",
        "TOO_LARGE",
        "INVALID_SIGNATURE",
        "UNTRUSTED_CHAIN",
        "INVALID_CERTIFICATE",
        "INVALID_CERTIFICATE_PURPOSE",
        "UNREADABLE_PAYLOAD",
        "INTERNAL_ERROR",
    ];
    let actual: Vec<&str> = Reason::all().iter().map(|r| r.as_str()).collect();
    assert_eq!(actual, expected);
}

#[test]
fn reason_round_trips_through_from_str_and_display() {
    for reason in Reason::all() {
        assert_eq!(Reason::from_str(reason.as_str()).unwrap(), *reason);
        assert_eq!(reason.to_string(), reason.as_str());
    }
    let err = Reason::from_str("INVALID_CHAIN").unwrap_err();
    assert!(
        err.to_string().contains("INVALID_CHAIN"),
        "a 0.6 token is gone"
    );
    assert!(
        Reason::from_str("malformed").is_err(),
        "the token is case-sensitive"
    );
    assert!(Reason::from_str("").is_err());
}

#[test]
fn environment_helpers_state_what_apples_strings_mean() {
    assert_eq!(Environment::Production.as_str(), "Production");
    assert_eq!(Environment::Sandbox.as_str(), "Sandbox");
    for (receipt_type, expected) in [
        (Some("Production"), Some(Environment::Production)),
        (Some("ProductionVPP"), Some(Environment::Production)),
        (Some("ProductionSandbox"), Some(Environment::Sandbox)),
        (Some("ProductionVPPSandbox"), Some(Environment::Sandbox)),
        (Some("Xcode"), None),
        (Some("production"), None),
        (Some(""), None),
        (None, None),
    ] {
        assert_eq!(
            Environment::from_receipt_type(receipt_type),
            expected,
            "{receipt_type:?}"
        );
    }
    for (claim, expected) in [
        (Some("Production"), Some(Environment::Production)),
        (Some("Sandbox"), Some(Environment::Sandbox)),
        (Some("Xcode"), None),
        (Some("LocalTesting"), None),
        (Some("ProductionSandbox"), None),
        (None, None),
    ] {
        assert_eq!(
            Environment::from_jws_environment(claim),
            expected,
            "{claim:?}"
        );
    }
}

#[test]
fn apple_status_names_every_documented_code() {
    let codes = [
        AppleStatus::OK,
        AppleStatus::REQUEST_NOT_POST,
        AppleStatus::NO_LONGER_SENT,
        AppleStatus::MALFORMED_RECEIPT_DATA,
        AppleStatus::RECEIPT_NOT_AUTHENTICATED,
        AppleStatus::SHARED_SECRET_MISMATCH,
        AppleStatus::SERVER_UNAVAILABLE,
        AppleStatus::SUBSCRIPTION_EXPIRED,
        AppleStatus::SANDBOX_RECEIPT_ON_PRODUCTION,
        AppleStatus::PRODUCTION_RECEIPT_ON_SANDBOX,
        AppleStatus::INTERNAL_DATA_ACCESS_ERROR,
        AppleStatus::ACCOUNT_NOT_FOUND,
        AppleStatus::INTERNAL_DATA_ACCESS_ERROR_RANGE_FIRST,
        AppleStatus::INTERNAL_DATA_ACCESS_ERROR_RANGE_LAST,
    ];
    assert_eq!(
        codes,
        [
            0, 21000, 21001, 21002, 21003, 21004, 21005, 21006, 21007, 21008, 21009, 21010, 21100,
            21199
        ]
    );
}

#[test]
fn version_is_the_manifest_version() {
    // release-please bumps Cargo.toml, so the constant follows it.
    assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
}

#[test]
fn a_failure_displays_as_reason_colon_message_and_carries_its_source() {
    use std::error::Error as _;
    let verifier = common::receipt_verifier();
    let failure = verifier.verify_receipt("not base64!").unwrap_err();
    assert_eq!(failure.reason(), Reason::Malformed);
    assert!(failure.to_string().starts_with("MALFORMED: "), "{failure}");
    assert!(!failure.message().is_empty());
    assert!(
        failure.source().is_none(),
        "only an unreadable payload carries a source"
    );

    // Apple-signed content that does not parse carries the parser's error,
    // so an operator can see why.
    let unreadable = common::verify_der(
        &common::verifier([common::anchor("generated-0.7/api-receipt-root.der")]),
        &common::read_fixture("generated-0.7/receipt-content-not-asn1.der"),
    )
    .unwrap_err();
    assert_eq!(unreadable.reason(), Reason::UnreadablePayload);
    assert!(unreadable.source().is_some(), "{unreadable:?}");

    // Callers build their own, for their own tests. Equality is reason and
    // message; the source is not compared.
    let built = Failure::new(Reason::UntrustedChain, "x");
    assert_eq!(
        built,
        Failure::new(Reason::UntrustedChain, "x").with_source(std::fmt::Error)
    );
    assert_ne!(built, Failure::new(Reason::UntrustedChain, "y"));
}

#[test]
fn an_empty_root_set_is_a_config_error_not_a_verdict() {
    let err: ConfigError = Config::builder().roots([]).build().unwrap_err();
    assert!(err.to_string().contains("roots"), "{err}");
    // Unset roots are Apple's bundled three, not an empty set.
    assert_eq!(Config::builder().build().unwrap().roots().len(), 3);
    assert_eq!(Config::defaults().roots().len(), 3);
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
    let der = common::read_fixture("generated-0.7/receipt-root.der");
    let pem = format!(
        "junk before\n-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\njunk after\n",
        base64_encode(&der)
    );
    let from_der = TrustAnchor::from_der(&der).unwrap();
    let from_pem = TrustAnchor::from_pem(&pem).unwrap();
    assert_eq!(from_der.der(), from_pem.der());
    let receipt = common::receipt_der();
    assert_eq!(
        common::verify_der(&common::verifier([from_der]), &receipt).unwrap(),
        common::verify_der(&common::verifier([from_pem]), &receipt).unwrap(),
        "the same anchor in two encodings must reach the same verdict"
    );
}

#[test]
fn the_api_types_are_send_sync_and_static() {
    fn assert_shareable<T: Send + Sync + 'static>() {}
    assert_shareable::<Verifier>();
    assert_shareable::<Config>();
    assert_shareable::<Failure>();
    assert_shareable::<ConfigError>();
    assert_shareable::<Reason>();
    assert_shareable::<ReceiptPayload>();
    assert_shareable::<JsonPayload>();
}

#[test]
fn one_verifier_answers_identically_from_sixteen_threads() {
    let verifier = Arc::new(common::verifier([
        common::receipt_root(),
        common::jws_root(),
    ]));
    let receipt = Arc::new(base64_encode(&common::receipt_der()));
    let transaction = Arc::new(common::transaction_jws());
    let expected_receipt = verifier.verify_receipt(&receipt).unwrap();
    let expected_payload = verifier.verify_signed_data(&transaction).unwrap();

    let handles: Vec<_> = (0..16)
        .map(|_| {
            let verifier = Arc::clone(&verifier);
            let receipt = Arc::clone(&receipt);
            let transaction = Arc::clone(&transaction);
            let expected_receipt = expected_receipt.clone();
            let expected_payload = expected_payload.clone();
            std::thread::spawn(move || {
                for _ in 0..25 {
                    assert_eq!(verifier.verify_receipt(&receipt).unwrap(), expected_receipt);
                    assert_eq!(
                        verifier.verify_signed_data(&transaction).unwrap(),
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
fn bundled_roots_are_parsed_once_and_shared() {
    let first = Config::defaults();
    let second = Config::defaults();
    for (a, b) in first.roots().iter().zip(second.roots()) {
        assert!(
            std::ptr::eq(a.der(), b.der()),
            "every Config::defaults() shares one parse of the bundled roots"
        );
    }
}

#[test]
fn the_clock_is_read_only_when_a_verdict_needs_it() {
    // Input that fails its own checks never reaches the clock, and a clock
    // that panics is the caller's defect: INTERNAL_ERROR with a fixed
    // message, never the panic's own text.
    let clock_panics = |root: TrustAnchor| {
        Verifier::new(
            Config::builder()
                .roots([root])
                .clock(|| panic!("the caller's clock broke"))
                .build()
                .unwrap(),
        )
    };
    let verifier = clock_panics(common::receipt_root());
    assert_eq!(
        verifier.verify_receipt("AAAA").unwrap_err().reason(),
        Reason::Malformed
    );
    assert_eq!(
        verifier.verify_signed_data("a.b.c").unwrap_err().reason(),
        Reason::Malformed
    );
    assert_eq!(
        verifier.verify_receipt_endpoint(Environment::Sandbox, "{}"),
        "{\"status\":21002}"
    );
    // A receipt that states its creation date needs no clock to verify.
    let dated = base64_encode(&common::receipt_der());
    assert!(verifier.verify_receipt(&dated).is_ok());
    // The endpoint's request_date does.
    let body = format!("{{\"receipt-data\":\"{dated}\"}}");
    assert_eq!(
        verifier.verify_receipt_endpoint(Environment::Sandbox, &body),
        "{\"status\":21009}"
    );

    let dateless = base64_encode(&common::read_fixture(
        "generated-0.7/receipt-no-creation-date.der",
    ));
    let failure = clock_panics(common::anchor("generated-0.7/divergence-receipt-root.der"))
        .verify_receipt(&dateless)
        .unwrap_err();
    assert_eq!(failure.reason(), Reason::InternalError);
    assert_eq!(failure.message(), "the configured clock panicked");
}

#[test]
fn the_device_hash_is_computable_from_the_returned_fields() {
    // 0.7 checks no device binding. The caller does, from these three
    // fields and the device identifier, with the formula the README shows.
    let receipt = common::verify_der(&common::receipt_verifier(), &common::receipt_der()).unwrap();
    let hash = |guid: &[u8]| {
        let mut sha1 = Sha1::new();
        sha1.update(guid);
        sha1.update(receipt.opaque_value.as_deref().unwrap());
        sha1.update(receipt.bundle_id_bytes.as_deref().unwrap());
        sha1.finalize().to_vec()
    };
    assert_eq!(
        receipt.sha1_hash.as_deref(),
        Some(hash(&common::device_guid()).as_slice())
    );
    assert_ne!(
        receipt.sha1_hash.as_deref(),
        Some(hash(&[0u8; 16]).as_slice()),
        "another device does not match"
    );
}

#[test]
fn returned_byte_fields_are_copies_not_views_into_the_input() {
    let verifier = common::receipt_verifier();
    let mut base64 = base64_encode(&common::receipt_der());
    let receipt = verifier.verify_receipt(&base64).unwrap();
    let opaque = receipt.opaque_value.clone();
    // A caller reusing its buffer must not be able to mutate an
    // already-verified receipt.
    base64.clear();
    assert_eq!(receipt.opaque_value, opaque);
}

#[test]
fn a_verified_jws_is_returned_exactly_as_signed() {
    let verifier = common::jws_verifier();
    let jws = common::transaction_jws();
    let payload = verifier.verify_signed_data(&jws).unwrap();
    let (_, segment, _) = common::split_jws(&jws);
    assert_eq!(
        payload.json().as_bytes(),
        base64_decode_lenient(&segment).as_slice()
    );
    assert_eq!(payload.to_string(), payload.json());
    // Apple's date claims stay epoch-millisecond integers.
    assert_eq!(
        common::claims(&payload)
            .get("signedDate")
            .and_then(serde_json::Value::as_i64),
        Some(1_722_945_600_000)
    );
    // An app transaction goes through the same method.
    let app = verifier
        .verify_signed_data(&common::app_transaction_jws())
        .unwrap();
    assert_eq!(
        common::claims(&app)
            .get("receiptType")
            .and_then(serde_json::Value::as_str),
        Some("Sandbox")
    );
}

#[test]
fn payloads_can_be_built_by_hand_and_write_canonical_json() {
    let mut unknown = BTreeMap::new();
    unknown.insert(13, vec![vec![1, 2, 3]]);
    unknown.insert(9, vec![b"a".to_vec(), b"b".to_vec()]);
    let receipt = ReceiptPayload {
        receipt_type: Some("ProductionSandbox".to_owned()),
        app_item_id: Some(i64::MAX),
        bundle_id: Some("com.example.app".to_owned()),
        bundle_id_bytes: Some(vec![0x0c, 0x01, 0x61]),
        receipt_creation_date_ms: Some(1_722_945_600_000),
        download_id: Some(-1),
        in_app: vec![InAppPurchase {
            quantity: Some(1),
            product_id: Some("line\nbreak \"quoted\" / \u{e9} \u{2028}".to_owned()),
            web_order_line_item_id: Some(42),
            is_trial_period: Some(false),
            ..InAppPurchase::default()
        }],
        unknown_attributes: unknown,
        ..ReceiptPayload::default()
    };
    // Keys in the design's order, ids as strings, unknown keys ascending
    // (9 before 13), JSON.stringify escapes, "/" and non-ASCII raw.
    assert_eq!(
        receipt.to_json(),
        "{\"receipt_type\":\"ProductionSandbox\",\"app_item_id\":\"9223372036854775807\",\
         \"bundle_id\":\"com.example.app\",\"bundle_id_bytes\":\"DAFh\",\
         \"application_version\":null,\"opaque_value\":null,\"sha1_hash\":null,\
         \"receipt_creation_date_ms\":1722945600000,\"download_id\":\"-1\",\
         \"version_external_identifier\":null,\"in_app\":[{\"quantity\":1,\
         \"product_id\":\"line\\nbreak \\\"quoted\\\" / \u{e9} \u{2028}\",\
         \"transaction_id\":null,\"purchase_date_ms\":null,\"original_transaction_id\":null,\
         \"original_purchase_date_ms\":null,\"expires_date_ms\":null,\
         \"web_order_line_item_id\":\"42\",\"cancellation_date_ms\":null,\
         \"is_trial_period\":false,\"is_in_intro_offer_period\":null,\
         \"unknown_attributes\":{}}],\"original_purchase_date_ms\":null,\
         \"original_application_version\":null,\"expiration_date_ms\":null,\
         \"unknown_attributes\":{\"9\":[\"YQ==\",\"Yg==\"],\"13\":[\"AQID\"]}}"
    );
    assert_eq!(JsonPayload::new("{}").json(), "{}");
}

#[test]
fn fresh_verifiers_answer_their_first_concurrent_calls_as_one_thread_would() {
    // The test above warms its verifier up single-threaded before any thread
    // starts, so a race that exists only on first use (the bundled roots'
    // one-time parse, say) never runs in it. Here each thread builds its own
    // verifier from the defaults and makes its very first call at the same
    // moment as the others, mixing every entry point; the answers are then
    // compared with those of a fresh verifier used by one thread.
    let genuine = base64_encode(&common::read_base64_fixture(
        "public-receipts/receipt-sandbox-g5.b64",
    ));
    let body = format!(r#"{{"receipt-data":"{genuine}"}}"#);
    let inputs = Arc::new((genuine, common::transaction_jws(), body));
    fn answers(
        verifier: &Verifier,
        (receipt, transaction, body): &(String, String, String),
    ) -> (
        Result<ReceiptPayload, Failure>,
        Result<JsonPayload, Failure>,
        String,
    ) {
        (
            verifier.verify_receipt(receipt),
            verifier.verify_signed_data(transaction),
            verifier.verify_receipt_endpoint(Environment::Sandbox, body),
        )
    }
    // The bundled roots, and a fixed clock so the endpoint's request_date
    // agrees across calls.
    fn fresh() -> Verifier {
        Verifier::new(
            Config::builder()
                .clock(|| 1_735_689_600_000)
                .build()
                .unwrap(),
        )
    }
    let threads = 16;
    let barrier = Arc::new(std::sync::Barrier::new(threads));
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let inputs = Arc::clone(&inputs);
            std::thread::spawn(move || {
                barrier.wait();
                answers(&fresh(), &inputs)
            })
        })
        .collect();
    let concurrent: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let expected = answers(&fresh(), &inputs);
    assert!(expected.0.is_ok());
    for answer in concurrent {
        assert_eq!(answer, expected);
    }
}
