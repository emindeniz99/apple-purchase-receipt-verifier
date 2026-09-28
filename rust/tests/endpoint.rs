//! The `verifyReceipt`-compatible endpoint: Apple's response body, rendered
//! as Apple renders it.
//!
//! Its whole contract is "never fails": the Apple status code is a field of
//! the body it answers, for every input, including inputs that are not JSON.

mod common;

use apple_purchase_receipt_verifier::__internal::base64_encode;
use apple_purchase_receipt_verifier::{Environment, TrustAnchor};
use serde_json::{Map, Value};

const NOW: i64 = 1_735_689_600_000;

/// The response to `{"receipt-data": <base64 of fixture>}`, parsed.
fn respond_with(
    root: TrustAnchor,
    environment: Environment,
    now_millis: i64,
    fixture: &str,
) -> (String, Value) {
    let body = serde_json::json!({
        "receipt-data": base64_encode(&common::read_fixture(fixture))
    })
    .to_string();
    let text = common::verifier_at([root], now_millis).verify_receipt_endpoint(environment, &body);
    let parsed = serde_json::from_str(&text).unwrap();
    (text, parsed)
}

fn shared_receipt(environment: Environment, now_millis: i64) -> Map<String, Value> {
    let (_, response) = respond_with(
        common::receipt_root(),
        environment,
        now_millis,
        "generated-0.7/receipt.der",
    );
    assert_eq!(response["status"], 0, "{response}");
    response["receipt"].as_object().unwrap().clone()
}

#[test]
fn a_sandbox_receipt_on_sandbox_answers_zero_with_the_full_body() {
    let (_, response) = respond_with(
        common::receipt_root(),
        Environment::Sandbox,
        NOW,
        "generated-0.7/receipt.der",
    );
    assert_eq!(response["status"], 0);
    assert_eq!(response["environment"], "Sandbox");
    let receipt = &response["receipt"];
    assert_eq!(receipt["bundle_id"], "com.example.app");
    assert_eq!(receipt["receipt_type"], "ProductionSandbox");
    assert_eq!(receipt["application_version"], "1.2.3");
    assert_eq!(receipt["in_app"].as_array().unwrap().len(), 2);
    // Apple renders every date three ways, and the numeric one is a string.
    assert_eq!(
        receipt["receipt_creation_date"],
        "2024-08-06 12:00:00 Etc/GMT"
    );
    assert_eq!(receipt["receipt_creation_date_ms"], "1722945600000");
    assert_eq!(
        receipt["receipt_creation_date_pst"],
        "2024-08-06 05:00:00 America/Los_Angeles"
    );
}

#[test]
fn in_app_scalars_are_rendered_as_apple_renders_them() {
    let receipt = shared_receipt(Environment::Sandbox, NOW);
    let entries = receipt["in_app"].as_array().unwrap();
    let vip = entries
        .iter()
        .find(|e| e["product_id"] == "com.example.app.vip")
        .unwrap();
    // Numbers cross the wire as strings, and the boolean as "true"/"false".
    assert_eq!(vip["quantity"], "1");
    assert_eq!(vip["web_order_line_item_id"], "42");
    assert!(matches!(
        vip.get("is_in_intro_offer_period"),
        Some(Value::String(_)) | None
    ));
    assert_eq!(vip["expires_date"], "2030-02-01 09:30:00 Etc/GMT");
}

fn receipt_ids_response() -> (String, Value) {
    respond_with(
        common::anchor("generated-0.7/receipt-ids-root.der"),
        Environment::Production,
        NOW,
        "generated-0.7/receipt-ids.der",
    )
}

#[test]
fn the_legacy_ids_cross_the_wire_as_bare_numbers() {
    let (text, response) = receipt_ids_response();
    assert_eq!(response["status"], 0);
    let receipt = &response["receipt"];
    // Apple echoes attribute 1 twice, and defines adam_id as
    // "See app_item_id".
    assert_eq!(receipt["adam_id"], 1_234_567_890);
    assert_eq!(receipt["app_item_id"], 1_234_567_890);
    assert_eq!(receipt["version_external_identifier"], 456_789_012);
    assert_eq!(receipt["download_id"], 9_223_372_036_854_775_807_i64);
    // The wire text, not the parsed value: a serialiser routing the number
    // through a double writes 9223372036854775808 here.
    assert!(
        text.contains(r#""download_id":9223372036854775807"#),
        "download_id lost digits on the wire: {text}"
    );
    assert!(!text.contains("9223372036854775808"));
    // Numbers, not the strings Apple uses for the in-app integers.
    assert!(!text.contains(r#""adam_id":""#));
}

#[test]
fn is_trial_period_is_a_string_like_is_in_intro_offer_period() {
    let (_, response) = receipt_ids_response();
    let entries = response["receipt"]["in_app"].as_array().unwrap();
    let by_product = |product_id: &str| {
        entries
            .iter()
            .find(|entry| entry["product_id"] == product_id)
            .unwrap_or_else(|| panic!("no entry for {product_id}"))
            .get("is_trial_period")
            .cloned()
    };
    assert_eq!(
        by_product("com.example.app.coins100"),
        Some(Value::from("false"))
    );
    assert_eq!(by_product("com.example.app.vip"), Some(Value::from("true")));
}

#[test]
fn ids_a_receipt_does_not_carry_are_omitted_never_null() {
    let receipt = shared_receipt(Environment::Sandbox, NOW);
    for key in [
        "adam_id",
        "app_item_id",
        "download_id",
        "version_external_identifier",
    ] {
        assert!(
            !receipt.contains_key(key),
            "{key} must be absent, not null, when the receipt does not carry it"
        );
    }
    for entry in receipt["in_app"].as_array().unwrap() {
        assert!(entry.get("is_trial_period").is_none());
    }
    // Absence is the key being gone, which is only meaningful if `null`
    // never appears in the body at all.
    let text = serde_json::to_string(&Value::Object(receipt)).unwrap();
    assert!(!text.contains("null"), "{text}");
}

#[test]
fn a_web_order_line_item_id_of_zero_is_omitted_as_apple_omits_it() {
    let (_, response) = respond_with(
        common::anchor("generated-0.7/api-receipt-root.der"),
        Environment::Sandbox,
        NOW,
        "generated-0.7/receipt-web-order-zero.der",
    );
    assert_eq!(response["status"], 0);
    // The payload carries 0 on one purchase and 42 on the other: the 0 is
    // omitted, the 42 rendered.
    let payload = common::verify_der(
        &common::verifier([common::anchor("generated-0.7/api-receipt-root.der")]),
        &common::read_fixture("generated-0.7/receipt-web-order-zero.der"),
    )
    .unwrap();
    let entries = response["receipt"]["in_app"].as_array().unwrap();
    assert_eq!(entries.len(), payload.in_app.len());
    let mut zeros = 0;
    for (entry, purchase) in entries.iter().zip(&payload.in_app) {
        match purchase.web_order_line_item_id {
            Some(0) => {
                zeros += 1;
                assert!(
                    entry.get("web_order_line_item_id").is_none(),
                    "a consumable's 0 must not be rendered: {entry}"
                );
            }
            Some(id) => assert_eq!(entry["web_order_line_item_id"], id.to_string()),
            None => assert!(entry.get("web_order_line_item_id").is_none()),
        }
    }
    assert!(zeros > 0, "the fixture carries a 0");
}

#[test]
fn the_request_date_triple_comes_from_the_config_clock() {
    let receipt = shared_receipt(Environment::Sandbox, NOW);
    assert_eq!(receipt["request_date"], "2025-01-01 00:00:00 Etc/GMT");
    assert_eq!(receipt["request_date_ms"], "1735689600000");
    assert_eq!(
        receipt["request_date_pst"],
        "2024-12-31 16:00:00 America/Los_Angeles"
    );
    // The receipt's own creation date is read from the signed bytes, not the
    // clock.
    assert_eq!(receipt["receipt_creation_date_ms"], "1722945600000");
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
        assert_eq!(
            shared_receipt(Environment::Sandbox, now)["request_date_pst"],
            expected
        );
    }
}

#[test]
fn hostile_bodies_never_escape_the_never_fails_contract() {
    let verifier = common::receipt_verifier();
    let mut rng = common::Rng::new(0xABCD_EF01_2345_6789);
    for _ in 0..500 {
        let length = rng.below(200);
        let bytes: Vec<u8> = (0..length)
            .map(|_| u8::try_from(rng.below(256)).unwrap())
            .collect();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        for request in [
            text.clone(),
            serde_json::json!({ "receipt-data": text }).to_string(),
        ] {
            for environment in [Environment::Production, Environment::Sandbox] {
                let answer = verifier.verify_receipt_endpoint(environment, &request);
                let parsed: Value = serde_json::from_str(&answer).unwrap();
                assert!(
                    matches!(parsed["status"].as_i64(), Some(0 | 21002 | 21003)),
                    "status {} for random input",
                    parsed["status"]
                );
            }
        }
    }
}

#[test]
fn the_endpoint_never_produces_a_status_outside_its_documented_set() {
    // 21000, 21004, 21005, 21006, 21010 and 21100-21199 describe conditions
    // that only exist on Apple's server (COMPARISON.md), and this endpoint
    // must never invent one.
    let documented = [0, 21002, 21003, 21007, 21008, 21009];
    for environment in [Environment::Production, Environment::Sandbox] {
        for (root, name) in [
            ("receipt-root", "receipt"),
            ("receipt-root", "receipt-foreign"),
            ("receipt-root", "receipt-type-vpp"),
            ("divergence-receipt-root", "receipt-attribute-type-overflow"),
            ("receipt-root", "receipt-no-type"),
        ] {
            let (_, response) = respond_with(
                common::anchor(&format!("generated-0.7/{root}.der")),
                environment,
                NOW,
                &format!("generated-0.7/{name}.der"),
            );
            let status = response["status"].as_i64().unwrap();
            assert!(documented.contains(&status), "{name}: {status}");
        }
    }
}

#[test]
fn the_endpoint_does_not_check_the_bundle_id() {
    // Like Apple's endpoint. The caller compares receipt.bundle_id itself.
    assert_eq!(
        shared_receipt(Environment::Sandbox, NOW)["bundle_id"],
        "com.example.app"
    );
}

/// A receipt with no usable creation date is judged at the config clock
/// (owner, 2026-09-27): in 0.6 the fallback was the system clock and an
/// injected clock could not move it. Two expired-chain receipts pin both
/// directions.
#[test]
fn the_clock_stands_in_for_a_missing_creation_date() {
    // Inside the expired chain's window, the dateless receipt verifies.
    let (_, inside) = respond_with(
        common::anchor("generated-0.7/divergence-receipt-expired-root.der"),
        Environment::Sandbox,
        1_590_969_600_000,
        "generated-0.7/receipt-expired-no-creation-date.der",
    );
    assert_eq!(inside["status"], 0, "{inside}");
    assert!(inside["receipt"].get("receipt_creation_date").is_none());

    // Past the valid chain's window, the dateless receipt is outside it:
    // INVALID_CERTIFICATE, which the status table answers 21003.
    let (_, after) = respond_with(
        common::anchor("generated-0.7/divergence-receipt-root.der"),
        Environment::Sandbox,
        4_070_908_800_000,
        "generated-0.7/receipt-no-creation-date.der",
    );
    assert_eq!(after["status"], 21003, "{after}");

    // And inside it, the same receipt verifies with the clock as request date.
    let (_, now) = respond_with(
        common::anchor("generated-0.7/divergence-receipt-root.der"),
        Environment::Sandbox,
        NOW,
        "generated-0.7/receipt-no-creation-date.der",
    );
    assert_eq!(now["status"], 0);
    assert_eq!(now["receipt"]["request_date_ms"], "1735689600000");
}
