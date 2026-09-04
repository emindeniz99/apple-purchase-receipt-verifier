//! The `verifyReceipt`-compatible endpoint.
//!
//! Its whole contract is "never fails": the Apple status code is a field of
//! the body it answers, for every input, including inputs that are not JSON.

mod common;

use apple_purchase_receipt_verifier::{
    base64, status, Environment, FixedClock, VerifyReceiptEndpoint, VerifyReceiptRequest,
};
use serde_json::Value;
use std::sync::Arc;

fn endpoint(environment: Environment) -> VerifyReceiptEndpoint {
    VerifyReceiptEndpoint::builder()
        .trusted_roots([common::receipt_root()])
        .environment(environment)
        .build()
        .unwrap()
}

fn endpoint_at(environment: Environment, now_millis: i64) -> VerifyReceiptEndpoint {
    VerifyReceiptEndpoint::builder()
        .trusted_roots([common::receipt_root()])
        .environment(environment)
        .clock(Arc::new(FixedClock::from_unix_millis(now_millis)))
        .build()
        .unwrap()
}

fn shared_receipt_base64() -> String {
    base64::encode(&common::receipt_der())
}

#[test]
fn a_sandbox_receipt_on_sandbox_answers_zero_with_the_full_body() {
    let response = endpoint(Environment::Sandbox)
        .verify_receipt(&VerifyReceiptRequest::new(shared_receipt_base64()));
    assert_eq!(response.status, status::OK);
    assert_eq!(response.environment, Some(Environment::Sandbox));
    let receipt = response.receipt.unwrap();
    assert_eq!(receipt.get("bundle_id").unwrap(), "com.example.app");
    assert_eq!(receipt.get("receipt_type").unwrap(), "ProductionSandbox");
    assert_eq!(receipt.get("application_version").unwrap(), "1.2.3");
    assert_eq!(receipt.get("in_app").unwrap().as_array().unwrap().len(), 2);
    // Apple renders every date three ways, and the numeric one is a string.
    assert_eq!(
        receipt.get("receipt_creation_date").unwrap(),
        "2024-08-06 12:00:00 Etc/GMT"
    );
    assert_eq!(
        receipt.get("receipt_creation_date_ms").unwrap(),
        "1722945600000"
    );
    assert_eq!(
        receipt.get("receipt_creation_date_pst").unwrap(),
        "2024-08-06 05:00:00 America/Los_Angeles"
    );
}

#[test]
fn in_app_scalars_are_rendered_as_apple_renders_them() {
    let response = endpoint(Environment::Sandbox)
        .verify_receipt(&VerifyReceiptRequest::new(shared_receipt_base64()));
    let receipt = response.receipt.unwrap();
    let entries = receipt.get("in_app").unwrap().as_array().unwrap();
    let vip = entries
        .iter()
        .find(|e| e.get("product_id").unwrap() == "com.example.app.vip")
        .unwrap();
    // Numbers cross the wire as strings, and the boolean as "true"/"false".
    assert_eq!(vip.get("quantity").unwrap(), "1");
    assert_eq!(vip.get("web_order_line_item_id").unwrap(), "42");
    assert!(matches!(
        vip.get("is_in_intro_offer_period"),
        Some(Value::String(_)) | None
    ));
    assert_eq!(
        vip.get("expires_date").unwrap(),
        "2030-02-01 09:30:00 Etc/GMT"
    );
}

#[test]
fn the_request_date_triple_comes_from_the_injected_clock() {
    let response = endpoint_at(Environment::Sandbox, 1_735_689_600_000)
        .verify_receipt(&VerifyReceiptRequest::new(shared_receipt_base64()));
    let receipt = response.receipt.unwrap();
    assert_eq!(
        receipt.get("request_date").unwrap(),
        "2025-01-01 00:00:00 Etc/GMT"
    );
    assert_eq!(receipt.get("request_date_ms").unwrap(), "1735689600000");
    assert_eq!(
        receipt.get("request_date_pst").unwrap(),
        "2024-12-31 16:00:00 America/Los_Angeles"
    );
    // The clock reaches the request date and nothing else: the receipt's own
    // creation date is unmoved.
    assert_eq!(
        receipt.get("receipt_creation_date_ms").unwrap(),
        "1722945600000"
    );
}

#[test]
fn the_request_date_crosses_both_dst_boundaries_correctly() {
    for (now, expected) in [
        (
            1_710_064_799_000i64,
            "2024-03-10 01:59:59 America/Los_Angeles",
        ),
        (1_710_064_800_000, "2024-03-10 03:00:00 America/Los_Angeles"),
        (1_730_624_399_000, "2024-11-03 01:59:59 America/Los_Angeles"),
        (1_730_624_400_000, "2024-11-03 01:00:00 America/Los_Angeles"),
    ] {
        let response = endpoint_at(Environment::Sandbox, now)
            .verify_receipt(&VerifyReceiptRequest::new(shared_receipt_base64()));
        assert_eq!(
            response.receipt.unwrap().get("request_date_pst").unwrap(),
            expected
        );
    }
}

#[test]
fn environment_routing_is_exhaustive_over_the_receipt_types() {
    // Production is exactly "Production" and "ProductionVPP"; everything
    // else, a missing attribute included, fails closed as non-production.
    let cases = [
        ("generated/receipt.der", false),
        ("generated/receipt-type-production.der", true),
        ("generated/receipt-type-vpp.der", true),
        ("generated/receipt-type-vpp-sandbox.der", false),
        ("generated/receipt-no-type.der", false),
    ];
    for (path, is_production) in cases {
        let der = common::read_fixture(path);
        let body = base64::encode(&der);
        let production = endpoint(Environment::Production)
            .verify_receipt(&VerifyReceiptRequest::new(body.clone()));
        let sandbox =
            endpoint(Environment::Sandbox).verify_receipt(&VerifyReceiptRequest::new(body));
        if is_production {
            assert_eq!(production.status, status::OK, "{path} on production");
            assert_eq!(
                sandbox.status,
                status::PRODUCTION_RECEIPT_ON_SANDBOX,
                "{path} on sandbox"
            );
        } else {
            assert_eq!(
                production.status,
                status::SANDBOX_RECEIPT_ON_PRODUCTION,
                "{path} on production"
            );
            assert_eq!(sandbox.status, status::OK, "{path} on sandbox");
        }
    }
}

#[test]
fn a_non_zero_status_carries_no_receipt_and_no_environment() {
    let bodies = [
        VerifyReceiptRequest::default(),
        VerifyReceiptRequest::new(""),
        VerifyReceiptRequest::new("not base64 at all"),
        VerifyReceiptRequest::new(base64::encode(&common::read_fixture(
            "generated/receipt-foreign.der",
        ))),
    ];
    for request in bodies {
        let response = endpoint(Environment::Sandbox).verify_receipt(&request);
        assert_ne!(response.status, status::OK);
        assert!(response.receipt.is_none());
        assert!(response.environment.is_none());
        // And the JSON body carries only the status.
        let json = response.to_json_value();
        assert_eq!(json.as_object().unwrap().len(), 1);
    }
}

#[test]
fn a_missing_or_empty_receipt_data_answers_21002() {
    let endpoint = endpoint(Environment::Sandbox);
    assert_eq!(
        endpoint
            .verify_receipt(&VerifyReceiptRequest::default())
            .status,
        status::MALFORMED
    );
    assert_eq!(
        endpoint
            .verify_receipt(&VerifyReceiptRequest::new(""))
            .status,
        status::MALFORMED
    );
}

#[test]
fn a_malformed_receipt_answers_21002_and_an_unauthenticated_one_21003() {
    let endpoint = endpoint(Environment::Sandbox);
    // Not a CMS blob at all.
    assert_eq!(
        endpoint
            .verify_receipt(&VerifyReceiptRequest::new("aaaaaaaaaaa"))
            .status,
        status::MALFORMED
    );
    // A genuine CMS blob that does not chain to the configured anchor.
    let foreign = base64::encode(&common::read_fixture("generated/receipt-foreign.der"));
    assert_eq!(
        endpoint
            .verify_receipt(&VerifyReceiptRequest::new(foreign))
            .status,
        status::NOT_AUTHENTICATED
    );
}

#[test]
fn password_and_exclude_old_transactions_are_accepted_and_never_read() {
    let endpoint = endpoint_at(Environment::Sandbox, 1_735_689_600_000);
    let plain = endpoint.verify_receipt(&VerifyReceiptRequest::new(shared_receipt_base64()));
    let decorated = endpoint.verify_receipt(&VerifyReceiptRequest {
        receipt_data: Some(shared_receipt_base64()),
        password: Some("a shared secret this library cannot check".to_owned()),
        exclude_old_transactions: Some(true),
    });
    assert_eq!(plain, decorated);
}

#[test]
fn the_json_entry_point_answers_a_body_for_anything() {
    let endpoint = endpoint(Environment::Sandbox);
    for body in [
        "",
        "not json",
        "null",
        "[]",
        "42",
        "\"text\"",
        "{}",
        "{\"receipt-data\":42}",
    ] {
        let answer = endpoint.verify_receipt_json(body);
        let parsed: Value = serde_json::from_str(&answer).unwrap();
        assert_eq!(parsed.get("status").unwrap(), 21002, "body {body:?}");
    }
}

#[test]
fn the_json_entry_point_matches_the_typed_one() {
    let endpoint = endpoint_at(Environment::Sandbox, 1_735_689_600_000);
    let body = serde_json::json!({ "receipt-data": shared_receipt_base64() }).to_string();
    let json: Value = serde_json::from_str(&endpoint.verify_receipt_json(&body)).unwrap();
    let typed = endpoint
        .verify_receipt(&VerifyReceiptRequest::new(shared_receipt_base64()))
        .to_json_value();
    assert_eq!(json, typed);
}

#[test]
fn the_json_response_is_byte_stable() {
    let endpoint = endpoint_at(Environment::Sandbox, 1_735_689_600_000);
    let body = serde_json::json!({ "receipt-data": shared_receipt_base64() }).to_string();
    let first = endpoint.verify_receipt_json(&body);
    for _ in 0..20 {
        assert_eq!(endpoint.verify_receipt_json(&body), first);
    }
}

#[test]
fn hostile_bodies_never_escape_the_never_fails_contract() {
    let endpoint = endpoint(Environment::Sandbox);
    let mut rng = common::Rng::new(0xABCD_EF01_2345_6789);
    for _ in 0..500 {
        let length = rng.below(200);
        let bytes: Vec<u8> = (0..length)
            .map(|_| u8::try_from(rng.below(256)).unwrap())
            .collect();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let response = endpoint.verify_receipt(&VerifyReceiptRequest::new(text.clone()));
        assert!(
            matches!(
                response.status,
                status::OK | status::MALFORMED | status::NOT_AUTHENTICATED
            ),
            "status {} for random input",
            response.status
        );
        let answer = endpoint.verify_receipt_json(&text);
        assert!(serde_json::from_str::<Value>(&answer).is_ok());
    }
}

#[test]
fn the_endpoint_never_produces_a_status_outside_its_documented_set() {
    // 21000, 21004, 21005, 21006, 21010 and 21100-21199 describe conditions
    // that only exist on Apple's server (COMPARISON.md), and this endpoint
    // must never invent one.
    let documented = [
        status::OK,
        status::MALFORMED,
        status::NOT_AUTHENTICATED,
        status::SANDBOX_RECEIPT_ON_PRODUCTION,
        status::PRODUCTION_RECEIPT_ON_SANDBOX,
        status::INTERNAL,
    ];
    assert_eq!(documented, [0, 21002, 21003, 21007, 21008, 21009]);
    for environment in [Environment::Production, Environment::Sandbox] {
        let endpoint = endpoint(environment);
        for name in [
            "generated/receipt.der",
            "generated/receipt-foreign.der",
            "generated/receipt-type-vpp.der",
            "generated/receipt-attribute-type-overflow.der",
            "generated/receipt-no-type.der",
        ] {
            let body = base64::encode(&common::read_fixture(name));
            let response = endpoint.verify_receipt(&VerifyReceiptRequest::new(body));
            assert!(
                documented.contains(&response.status),
                "{name}: {}",
                response.status
            );
        }
    }
}

#[test]
fn the_endpoint_does_not_check_the_bundle_id() {
    // Like Apple's endpoint. The caller compares receipt.bundle_id itself.
    let response = endpoint(Environment::Sandbox)
        .verify_receipt(&VerifyReceiptRequest::new(shared_receipt_base64()));
    assert_eq!(response.status, status::OK);
    assert_eq!(
        response.receipt.unwrap().get("bundle_id").unwrap(),
        "com.example.app"
    );
}

#[test]
fn an_injected_clock_cannot_authenticate_an_expired_chain() {
    // A receipt with no creation date falls back to the SYSTEM clock for
    // its chain-validity instant. Planting a clock inside the expired
    // certificate's window must not change that.
    let endpoint = VerifyReceiptEndpoint::builder()
        .trusted_roots([common::anchor(
            "generated/divergence-receipt-expired-root.der",
        )])
        .environment(Environment::Sandbox)
        .clock(Arc::new(FixedClock::from_unix_millis(1_590_969_600_000)))
        .build()
        .unwrap();
    let body = base64::encode(&common::read_fixture(
        "generated/receipt-expired-no-creation-date.der",
    ));
    assert_eq!(
        endpoint
            .verify_receipt(&VerifyReceiptRequest::new(body))
            .status,
        status::NOT_AUTHENTICATED
    );
}

#[test]
fn an_injected_clock_cannot_expire_a_valid_chain() {
    let endpoint = VerifyReceiptEndpoint::builder()
        .trusted_roots([common::anchor("generated/divergence-receipt-root.der")])
        .environment(Environment::Sandbox)
        .clock(Arc::new(FixedClock::from_unix_millis(4_070_908_800_000)))
        .build()
        .unwrap();
    let body = base64::encode(&common::read_fixture(
        "generated/receipt-no-creation-date.der",
    ));
    let response = endpoint.verify_receipt(&VerifyReceiptRequest::new(body));
    assert_eq!(response.status, status::OK);
    let receipt = response.receipt.unwrap();
    assert!(receipt.get("receipt_creation_date").is_none());
    assert_eq!(receipt.get("request_date_ms").unwrap(), "4070908800000");
}
