//! What the endpoint answers, by receipt and by environment.
//!
//! What matters here is what a caller builds a retry on. The status is
//! computed from the receipt's own `receipt_type`: a production endpoint
//! must never answer 0 for a sandbox receipt, or the 21007 routing that
//! keeps sandbox purchases out of production would be bypassed. 0.6 pinned
//! this on a result object that could be re-rendered for either environment;
//! 0.7 has no such object, so it is pinned on the two calls a caller makes:
//! `verify_receipt`, whose reason the status table turns into a status, and
//! `verify_receipt_endpoint`.

mod common;

use apple_purchase_receipt_verifier::__internal::base64_encode;
use apple_purchase_receipt_verifier::{Config, Environment, Reason, Verifier};
use serde_json::Value;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const NOW: i64 = 1_735_689_600_000;

fn verifier() -> Verifier {
    common::verifier_at([common::receipt_root()], NOW)
}

fn b64(fixture: &str) -> String {
    base64_encode(&common::read_fixture(fixture))
}

fn body(receipt_data: &str) -> String {
    serde_json::json!({ "receipt-data": receipt_data }).to_string()
}

fn status(response: &str) -> i64 {
    serde_json::from_str::<Value>(response).unwrap()["status"]
        .as_i64()
        .unwrap()
}

/// The whole routing table. A production receipt gives 0 on PRODUCTION and
/// 21008 on SANDBOX; a sandbox receipt, and one whose `receipt_type` is
/// missing or unknown (which fails closed as non-production), gives 21007 on
/// PRODUCTION and 0 on SANDBOX; a failed verification answers the same
/// status on both.
#[test]
fn routes_from_the_receipts_own_type() {
    let table = [
        // fixture, status on PRODUCTION, status on SANDBOX, environment()
        (
            "generated-0.7/receipt-type-production.der",
            0,
            21008,
            Some(Environment::Production),
        ),
        (
            "generated-0.7/receipt-type-vpp.der",
            0,
            21008,
            Some(Environment::Production),
        ),
        (
            "generated-0.7/receipt.der",
            21007,
            0,
            Some(Environment::Sandbox),
        ),
        (
            "generated-0.7/receipt-type-vpp-sandbox.der",
            21007,
            0,
            Some(Environment::Sandbox),
        ),
        ("generated-0.7/receipt-no-type.der", 21007, 0, None),
        ("generated-0.7/receipt-foreign.der", 21003, 21003, None),
    ];
    let verifier = verifier();
    for (fixture, production, sandbox, environment) in table {
        let receipt = body(&b64(fixture));
        assert_eq!(
            status(&verifier.verify_receipt_endpoint(Environment::Production, &receipt)),
            production,
            "{fixture} on PRODUCTION"
        );
        assert_eq!(
            status(&verifier.verify_receipt_endpoint(Environment::Sandbox, &receipt)),
            sandbox,
            "{fixture} on SANDBOX"
        );
        if let Ok(payload) = verifier.verify_receipt(&b64(fixture)) {
            // The payload states the environment the endpoint routes on.
            assert_eq!(payload.environment(), environment, "{fixture}");
        }
    }
}

/// A non-zero status carries nothing but the status; 0 carries environment
/// and receipt.
#[test]
fn only_status_zero_carries_the_receipt() {
    let verifier = verifier();
    for fixture in [
        "generated-0.7/receipt.der",
        "generated-0.7/receipt-type-production.der",
        "generated-0.7/receipt-foreign.der",
        "generated-0.7/receipt-tampered-payload.der",
    ] {
        for environment in [Environment::Production, Environment::Sandbox] {
            let response = verifier.verify_receipt_endpoint(environment, &body(&b64(fixture)));
            let label = format!("{fixture} on {environment}");
            if status(&response) == 0 {
                assert!(
                    response.starts_with(&format!(
                        "{{\"status\":0,\"environment\":\"{}\",\"receipt\":{{",
                        environment.as_str()
                    )),
                    "{label}: {response}"
                );
            } else {
                assert_eq!(
                    response,
                    format!("{{\"status\":{}}}", status(&response)),
                    "{label}"
                );
            }
        }
    }
}

/// Each failure, through the endpoint and through `verify_receipt`: the
/// reason `verify_receipt` names is the one the status table turns into the
/// status the endpoint answers.
#[test]
fn each_failure_answers_the_status_of_its_reason() {
    let table = |reason: Reason| match reason {
        Reason::Malformed | Reason::TooLarge => 21002,
        Reason::InvalidSignature
        | Reason::UntrustedChain
        | Reason::InvalidCertificate
        | Reason::InvalidCertificatePurpose => 21003,
        Reason::UnreadablePayload | Reason::InternalError => 21009,
    };
    let cases: [(Verifier, String, Reason); 7] = [
        (verifier(), "not base64!".to_owned(), Reason::Malformed),
        (verifier(), "AQIDBA==".to_owned(), Reason::Malformed),
        (verifier(), "A".repeat(3_145_729), Reason::TooLarge),
        (
            verifier(),
            b64("generated-0.7/receipt-foreign.der"),
            Reason::UntrustedChain,
        ),
        (
            common::verifier([common::anchor("generated-0.7/gaps-receipt-root.der")]),
            b64("generated-0.7/receipt-tampered-payload.der"),
            Reason::InvalidSignature,
        ),
        (
            common::verifier([common::anchor("generated-0.7/receipt-expired-root.der")]),
            b64("generated-0.7/receipt-expired-fresh.der"),
            Reason::InvalidCertificate,
        ),
        (
            common::verifier([common::anchor("generated-0.7/api-receipt-root.der")]),
            b64("generated-0.7/receipt-content-not-asn1.der"),
            Reason::UnreadablePayload,
        ),
    ];
    for (verifier, receipt, reason) in cases {
        assert_eq!(
            verifier.verify_receipt(&receipt).unwrap_err().reason(),
            reason
        );
        for environment in [Environment::Production, Environment::Sandbox] {
            let response = verifier.verify_receipt_endpoint(environment, &body(&receipt));
            // A receipt over the cap makes the body over the cap too: the
            // same 21002, from the body check.
            assert_eq!(
                response,
                format!("{{\"status\":{}}}", table(reason)),
                "{reason} on {environment}"
            );
        }
    }
}

#[test]
fn a_body_without_usable_receipt_data_answers_21002() {
    let verifier = verifier();
    for request in [
        "",
        "not json",
        "null",
        "[]",
        "[{\"receipt-data\":\"AQIDBA==\"}]",
        "42",
        "\"text\"",
        "{}",
        "{\"receipt-data\":\"\"}",
        "{\"receipt-data\":42}",
        "{\"receipt-data\":[\"AQIDBA==\"]}",
        "{\"receipt-data\":null}",
        "{\"receipt-data\":\"not base64!\"}",
        // The last receipt-data wins, as it would in a map.
        &format!(
            "{{\"receipt-data\":\"{}\",\"receipt-data\":7}}",
            b64("generated-0.7/receipt.der")
        ),
        // The whole object is read: a body that breaks after receipt-data
        // is refused.
        &format!(
            "{{\"receipt-data\":\"{}\",}}",
            b64("generated-0.7/receipt.der")
        ),
    ] {
        assert_eq!(
            verifier.verify_receipt_endpoint(Environment::Sandbox, request),
            "{\"status\":21002}",
            "{request:.60}"
        );
    }
}

#[test]
fn password_exclude_old_transactions_and_trailing_text_are_not_read() {
    let verifier = verifier();
    let receipt = b64("generated-0.7/receipt.der");
    let plain = verifier.verify_receipt_endpoint(Environment::Sandbox, &body(&receipt));
    assert_eq!(status(&plain), 0);
    for decorated in [
        serde_json::json!({
            "receipt-data": receipt,
            "password": "a shared secret this library cannot check",
            "exclude-old-transactions": true
        })
        .to_string(),
        // Anything after the object is not read.
        format!("{} trailing", body(&receipt)),
        // The first receipt-data is overridden by the last.
        format!("{{\"receipt-data\":\"junk\",\"receipt-data\":\"{receipt}\"}}"),
    ] {
        assert_eq!(
            verifier.verify_receipt_endpoint(Environment::Sandbox, &decorated),
            plain
        );
    }
}

#[test]
fn the_response_is_byte_stable_for_the_same_call() {
    let verifier = verifier();
    let request = body(&b64("generated-0.7/receipt.der"));
    let first = verifier.verify_receipt_endpoint(Environment::Sandbox, &request);
    for _ in 0..20 {
        assert_eq!(
            verifier.verify_receipt_endpoint(Environment::Sandbox, &request),
            first
        );
    }
}

/// At most once per call, and only when a verdict needs it: the endpoint's
/// request_date does, a receipt that states its creation date does not, and
/// input that fails its own checks never gets that far.
#[test]
fn the_clock_is_read_at_most_once_per_call_and_only_when_needed() {
    let reads = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&reads);
    let verifier = Verifier::new(
        Config::builder()
            .roots([common::receipt_root()])
            .clock(move || {
                counter.fetch_add(1, Ordering::SeqCst);
                NOW
            })
            .build()
            .unwrap(),
    );
    let receipt = b64("generated-0.7/receipt.der");
    let _ = verifier.verify_receipt_endpoint(Environment::Sandbox, &body(&receipt));
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    verifier.verify_receipt(&receipt).unwrap();
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    verifier.verify_signed_data("a.b.c").unwrap_err();
    verifier.verify_receipt("AAAA").unwrap_err();
    assert_eq!(reads.load(Ordering::SeqCst), 1);
}
