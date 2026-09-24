//! `VerifyReceiptResult`: one verification, rendered on demand.
//!
//! The point of the type is that a caller can act on the verdict (the
//! receipt, or the reason there is none) and still answer Apple's exact wire
//! body, for either environment, without verifying twice. These tests hold
//! the invariants that make that safe: exactly one of receipt and reason,
//! a status always recomputed from the receipt's own type, one clock read
//! per call, and renders that match the JSON endpoint byte for byte.

mod common;

use apple_purchase_receipt_verifier::{
    apple_receipt_roots, base64, status, Clock, Environment, FixedClock, Reason, TrustAnchor,
    VerifyReceiptEndpoint, VerifyReceiptOutcome, VerifyReceiptRequest, VerifyReceiptResult,
    MAX_REQUEST_BYTES,
};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const NOW: i64 = 1_735_689_600_000;

fn at(millis: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(millis)
}

fn endpoint_with(
    environment: Environment,
    anchors: impl IntoIterator<Item = TrustAnchor>,
    clock: Arc<dyn Clock>,
) -> VerifyReceiptEndpoint {
    VerifyReceiptEndpoint::builder()
        .trusted_roots(anchors)
        .environment(environment)
        .clock(clock)
        .build()
        .unwrap()
}

fn endpoint(environment: Environment) -> VerifyReceiptEndpoint {
    endpoint_with(
        environment,
        [common::receipt_root()],
        Arc::new(FixedClock::from_unix_millis(NOW)),
    )
}

fn b64(fixture: &str) -> String {
    base64::encode(&common::read_fixture(fixture))
}

fn body(receipt_data: &str) -> String {
    serde_json::json!({ "receipt-data": receipt_data }).to_string()
}

#[derive(Debug)]
struct CountingClock {
    at: SystemTime,
    reads: AtomicUsize,
}

impl CountingClock {
    fn new(millis: u64) -> Arc<Self> {
        Arc::new(CountingClock {
            at: at(millis),
            reads: AtomicUsize::new(0),
        })
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

impl Clock for CountingClock {
    fn now(&self) -> SystemTime {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.at
    }
}

/// Caller code the endpoint runs, and so the one public way to make the
/// pipeline panic.
#[derive(Debug)]
struct PanickingClock;

impl Clock for PanickingClock {
    fn now(&self) -> SystemTime {
        panic!("the injected clock exploded")
    }
}

fn assert_invariants(label: &str, result: &VerifyReceiptResult) {
    // A caller branches on one of these two; both present or both absent
    // would leave it guessing whether to unlock or to reject.
    assert_ne!(
        result.receipt().is_some(),
        result.failure_reason().is_some(),
        "{label}: exactly one of receipt and failure reason"
    );
    assert_eq!(result.verified(), result.receipt().is_some(), "{label}");
    match result.outcome() {
        VerifyReceiptOutcome::Verified(_) => assert!(result.verified(), "{label}"),
        VerifyReceiptOutcome::Failed { reason, cause } => {
            assert_eq!(Some(*reason), result.failure_reason(), "{label}");
            assert_eq!(
                cause.is_some(),
                *reason == Reason::InternalError,
                "{label}: a cause only for INTERNAL_ERROR"
            );
        }
    }
    let json: serde_json::Value = serde_json::from_str(&result.to_json()).unwrap();
    assert_eq!(json["status"], result.status(), "{label}: rendered status");
}

#[test]
fn every_status_carries_exactly_one_of_receipt_and_reason() {
    let sandbox_receipt = b64("generated/receipt.der");
    let production_receipt = b64("generated/receipt-type-production.der");
    let foreign = b64("generated/receipt-foreign.der");
    let panicking = endpoint_with(
        Environment::Sandbox,
        [common::receipt_root()],
        Arc::new(PanickingClock),
    );
    let cases: Vec<(&str, VerifyReceiptResult, i64, Option<Reason>)> = vec![
        (
            "sandbox receipt on sandbox",
            endpoint(Environment::Sandbox).verify_receipt_data(&sandbox_receipt),
            status::OK,
            None,
        ),
        (
            "production receipt on production",
            endpoint(Environment::Production).verify_receipt_data(&production_receipt),
            status::OK,
            None,
        ),
        (
            "sandbox receipt on production",
            endpoint(Environment::Production).verify_receipt_data(&sandbox_receipt),
            status::SANDBOX_RECEIPT_ON_PRODUCTION,
            None,
        ),
        (
            "production receipt on sandbox",
            endpoint(Environment::Sandbox).verify_receipt_data(&production_receipt),
            status::PRODUCTION_RECEIPT_ON_SANDBOX,
            None,
        ),
        (
            "empty receipt-data",
            endpoint(Environment::Sandbox).verify_receipt_data(""),
            status::MALFORMED,
            Some(Reason::MalformedRequest),
        ),
        (
            "receipt-data that is not base64",
            endpoint(Environment::Sandbox).verify_receipt_data("not base64 at all"),
            status::MALFORMED,
            Some(Reason::InvalidReceiptFormat),
        ),
        (
            "a receipt from another anchor",
            endpoint(Environment::Sandbox).verify_receipt_data(&foreign),
            status::NOT_AUTHENTICATED,
            Some(Reason::InvalidChain),
        ),
        (
            "a panic inside the endpoint",
            panicking.verify_receipt_data(&sandbox_receipt),
            status::INTERNAL,
            Some(Reason::InternalError),
        ),
    ];
    for (label, result, expected_status, expected_reason) in cases {
        assert_invariants(label, &result);
        assert_eq!(result.status(), expected_status, "{label}");
        assert_eq!(result.failure_reason(), expected_reason, "{label}");
        // 21007 and 21008 say "wrong environment", not "forged": the receipt
        // is valid and kept, so `verified` is not `status == 0`.
        assert_eq!(
            result.verified(),
            matches!(
                expected_status,
                status::OK
                    | status::SANDBOX_RECEIPT_ON_PRODUCTION
                    | status::PRODUCTION_RECEIPT_ON_SANDBOX
            ),
            "{label}"
        );
    }
}

#[test]
fn a_verified_receipt_re_renders_for_either_environment_without_verifying_again() {
    let types = [
        ("generated/receipt.der", false),
        ("generated/receipt-type-production.der", true),
        ("generated/receipt-type-vpp.der", true),
        ("generated/receipt-type-vpp-sandbox.der", false),
        ("generated/receipt-no-type.der", false),
    ];
    for (fixture, is_production) in types {
        let data = b64(fixture);
        for verified_on in [Environment::Production, Environment::Sandbox] {
            let result = endpoint(verified_on).verify_receipt_data(&data);
            assert!(result.verified(), "{fixture} on {verified_on}");
            for render in [Environment::Production, Environment::Sandbox] {
                // The re-render is exactly what an endpoint of that
                // environment would have answered for the same request.
                let expected = endpoint(render).verify_receipt_json(&body(&data));
                assert_eq!(
                    result.to_json_in(render).unwrap(),
                    expected,
                    "{fixture} verified on {verified_on}, rendered for {render}"
                );
                let status = result.to_response_in(render).unwrap().status;
                let expected_status = match (is_production, render) {
                    (true, Environment::Sandbox) => status::PRODUCTION_RECEIPT_ON_SANDBOX,
                    (false, Environment::Production) => status::SANDBOX_RECEIPT_ON_PRODUCTION,
                    _ => status::OK,
                };
                assert_eq!(status, expected_status, "{fixture} rendered for {render}");
            }
            // A sandbox receipt must never pass as a production purchase,
            // whichever endpoint verified it.
            if !is_production {
                let production = result.to_response_in(Environment::Production).unwrap();
                assert_ne!(production.status, status::OK, "{fixture}");
                assert!(production.receipt.is_none(), "{fixture}");
            }
        }
    }
}

#[test]
fn a_failed_result_answers_its_own_status_in_both_environments() {
    let foreign = b64("generated/receipt-foreign.der");
    for (data, expected) in [
        ("", status::MALFORMED),
        ("not base64 at all", status::MALFORMED),
        (foreign.as_str(), status::NOT_AUTHENTICATED),
    ] {
        let result = endpoint(Environment::Production).verify_receipt_data(data);
        for render in [Environment::Production, Environment::Sandbox] {
            assert_eq!(
                result.to_json_in(render).unwrap(),
                format!("{{\"status\":{expected}}}")
            );
        }
    }
}

#[test]
fn rendering_for_an_environment_apple_has_no_endpoint_for_is_refused_like_the_builder() {
    let result = endpoint(Environment::Sandbox).verify_receipt_data(&b64("generated/receipt.der"));
    for environment in [Environment::Xcode, Environment::LocalTesting] {
        let refused = VerifyReceiptEndpoint::builder()
            .trusted_roots([common::receipt_root()])
            .environment(environment)
            .build()
            .unwrap_err();
        assert_eq!(result.to_response_in(environment).unwrap_err(), refused);
        assert_eq!(result.to_json_in(environment).unwrap_err(), refused);
    }
}

#[test]
fn an_explicit_request_time_sets_request_date_and_never_reads_the_clock() {
    let clock = CountingClock::new(1_735_689_600_000);
    let endpoint = endpoint_with(
        Environment::Sandbox,
        [common::receipt_root()],
        clock.clone(),
    );
    let data = b64("generated/receipt.der");
    let explicit = at(4_070_908_800_000);
    for result in [
        endpoint.verify_receipt_data_at(&data, explicit),
        endpoint.verify_receipt_result_at(&VerifyReceiptRequest::new(data.clone()), explicit),
        endpoint.verify_receipt_result_from_json_at(&body(&data), explicit),
    ] {
        assert_eq!(result.request_date(), explicit);
        let receipt = result.to_response().receipt.unwrap();
        assert_eq!(receipt["request_date_ms"], "4070908800000");
        assert_eq!(receipt["request_date"], "2099-01-01 00:00:00 Etc/GMT");
    }
    assert_eq!(clock.reads(), 0, "an explicit time replaces the clock");
}

#[test]
fn an_explicit_request_time_cannot_move_certificate_validity() {
    // A receipt with no creation date is judged at the system clock. A
    // request time inside an expired certificate's window must not
    // authenticate it, and one far in the future must not expire a valid
    // chain: the time only reaches request_date.
    let expired = endpoint_with(
        Environment::Sandbox,
        [common::anchor(
            "generated/divergence-receipt-expired-root.der",
        )],
        Arc::new(FixedClock::from_unix_millis(NOW)),
    );
    let result = expired.verify_receipt_data_at(
        &b64("generated/receipt-expired-no-creation-date.der"),
        at(1_590_969_600_000),
    );
    assert_eq!(result.status(), status::NOT_AUTHENTICATED);

    let valid = endpoint_with(
        Environment::Sandbox,
        [common::anchor("generated/divergence-receipt-root.der")],
        Arc::new(FixedClock::from_unix_millis(NOW)),
    );
    let result = valid.verify_receipt_data_at(
        &b64("generated/receipt-no-creation-date.der"),
        at(4_070_908_800_000),
    );
    assert_eq!(result.status(), status::OK);
}

#[test]
fn without_an_explicit_time_the_clock_is_read_once_per_call() {
    let clock = CountingClock::new(1_735_689_600_000);
    let endpoint = endpoint_with(
        Environment::Production,
        [common::receipt_root()],
        clock.clone(),
    );
    let result = endpoint.verify_receipt_data(&b64("generated/receipt.der"));
    assert_eq!(clock.reads(), 1);
    assert_eq!(result.request_date(), at(1_735_689_600_000));
    // Rendering, in any environment and any number of times, reuses that
    // one instant: two renders of one result never disagree on the date.
    let first = result.to_json_in(Environment::Sandbox).unwrap();
    assert_eq!(result.to_json_in(Environment::Sandbox).unwrap(), first);
    let _ = result.to_json();
    let _ = result.to_response();
    assert_eq!(clock.reads(), 1, "rendering does not read the clock");

    let _ = endpoint.verify_receipt_data("");
    let _ = endpoint.verify_receipt_json("not json");
    assert_eq!(clock.reads(), 3, "failed calls read it once each too");
}

#[test]
fn the_bare_base64_path_answers_what_the_json_body_path_answers_for_every_receipt_fixture() {
    let fixtures = common::fixtures_dir();
    let mut anchors: Vec<TrustAnchor> = apple_receipt_roots().to_vec();
    let mut texts: Vec<(String, String)> = Vec::new();
    for entry in std::fs::read_dir(fixtures.join("generated")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.ends_with(".der") {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap();
        if name.ends_with("-root.der") {
            if let Ok(anchor) = TrustAnchor::from_der(&bytes) {
                anchors.push(anchor);
            }
        } else if name.starts_with("receipt") && !name.contains("der-cap") {
            // The two DER-cap receipts are left out: 3 MiB of DER is 4 MiB
            // of base64, which no request can carry.
            texts.push((name, base64::encode(&bytes)));
        }
    }
    // Client-shaped strings, verbatim: whitespace, base64url, bad padding.
    for directory in [
        "generated/receipt-b64",
        "public-receipts",
        "apple-official/xcode",
    ] {
        for entry in std::fs::read_dir(fixtures.join(directory)).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let is_receipt = name.ends_with(".txt")
                || name.ends_with(".b64")
                || name.starts_with("xcode-app-receipt");
            if is_receipt {
                texts.push((name, std::fs::read_to_string(&path).unwrap()));
            }
        }
    }
    let mut statuses = std::collections::BTreeMap::<i64, usize>::new();
    for environment in [Environment::Production, Environment::Sandbox] {
        let endpoint = endpoint_with(
            environment,
            anchors.iter().cloned(),
            Arc::new(FixedClock::from_unix_millis(NOW)),
        );
        for (name, text) in &texts {
            let request_body = body(text);
            let via_body = endpoint.verify_receipt_json(&request_body);
            let bare = endpoint.verify_receipt_data(text);
            let typed = endpoint.verify_receipt_result(&VerifyReceiptRequest::new(text.clone()));
            assert_eq!(typed.to_json(), bare.to_json(), "{name} on {environment}");
            // Every corpus body, receipt-byte-floor's ~1.38 MB of base64
            // included, is under the 3 MiB request cap, so the paths agree.
            assert!(request_body.len() <= MAX_REQUEST_BYTES, "{name}");
            assert_eq!(bare.to_json(), via_body, "{name} on {environment}");
            *statuses.entry(bare.status()).or_default() += 1;
        }
    }
    // The comparison is only worth something if it covered full receipt
    // bodies as well as bare statuses.
    // The corpus held 48 receipt strings when this was written.
    assert!(texts.len() >= 40, "{} fixtures", texts.len());
    for code in [
        status::OK,
        status::MALFORMED,
        status::NOT_AUTHENTICATED,
        status::SANDBOX_RECEIPT_ON_PRODUCTION,
        status::PRODUCTION_RECEIPT_ON_SANDBOX,
    ] {
        assert!(
            statuses.contains_key(&code),
            "no fixture answered {code}: {statuses:?}"
        );
    }
}

#[test]
fn a_panic_inside_the_endpoint_becomes_internal_error_never_a_panic() {
    let endpoint = endpoint_with(
        Environment::Sandbox,
        [common::receipt_root()],
        Arc::new(PanickingClock),
    );
    let data = b64("generated/receipt.der");
    for result in [
        endpoint.verify_receipt_data(&data),
        endpoint.verify_receipt_result(&VerifyReceiptRequest::new(data.clone())),
        endpoint.verify_receipt_result_from_json(&body(&data)),
    ] {
        assert_invariants("panicking clock", &result);
        assert_eq!(result.failure_reason(), Some(Reason::InternalError));
        assert_eq!(result.status(), status::INTERNAL);
        assert_eq!(
            result.failure_cause(),
            Some("the injected clock exploded"),
            "the cause names what failed"
        );
        assert_eq!(result.to_json(), r#"{"status":21009}"#);
    }
    assert_eq!(
        endpoint.verify_receipt_json(&body(&data)),
        r#"{"status":21009}"#
    );
}

/// The other road to INTERNAL_ERROR: a trusted signer signed content the
/// library cannot read. Same status as a contained panic, and the cause
/// says what could not be read, so an integrator can alert on it.
#[test]
fn unreadable_signed_content_is_internal_error_with_its_cause() {
    let endpoint = endpoint_with(
        Environment::Sandbox,
        [common::anchor("generated/verification-order-root.der")],
        Arc::new(FixedClock::from_unix_millis(NOW)),
    );
    let result =
        endpoint.verify_receipt_data(&b64("generated/receipt-unreadable-creation-date.der"));
    assert_invariants("unreadable signed content", &result);
    assert_eq!(result.failure_reason(), Some(Reason::InternalError));
    assert_eq!(result.status(), status::INTERNAL);
    let cause = result.failure_cause().unwrap();
    assert!(cause.contains("could not be read"), "{cause}");
    assert_eq!(result.to_json(), r#"{"status":21009}"#);
}

#[test]
fn an_unusable_envelope_is_a_malformed_request_and_bad_receipt_data_an_invalid_format() {
    // Both answer 21002 on the wire; the reason tells a caller whether the
    // client sent no receipt at all or sent a broken one.
    let endpoint = endpoint(Environment::Sandbox);
    for raw in [
        "",
        "not json",
        "null",
        "[]",
        "42",
        "{}",
        r#"{"receipt-data":42}"#,
        r#"{"receipt-data":null}"#,
        r#"{"receipt-data":""}"#,
    ] {
        let result = endpoint.verify_receipt_result_from_json(raw);
        assert_eq!(
            result.failure_reason(),
            Some(Reason::MalformedRequest),
            "{raw}"
        );
        assert_eq!(result.status(), status::MALFORMED, "{raw}");
    }
    assert_eq!(
        endpoint
            .verify_receipt_result(&VerifyReceiptRequest::default())
            .failure_reason(),
        Some(Reason::MalformedRequest)
    );
    assert_eq!(
        endpoint.verify_receipt_data("").failure_reason(),
        Some(Reason::MalformedRequest)
    );
    let broken = endpoint.verify_receipt_result_from_json(&body("not base64 at all"));
    assert_eq!(broken.failure_reason(), Some(Reason::InvalidReceiptFormat));
    assert_eq!(broken.status(), status::MALFORMED);
}

#[test]
fn the_endpoint_only_reasons_stay_outside_the_verifier_vocabulary() {
    // Reason::all() is the cross-port contract and the C ABI's numbering;
    // the two endpoint-only values must not grow it. INTERNAL_ERROR is a
    // verifier reason too (unreadable signed content), so it is in it.
    for (reason, token) in [
        (Reason::MalformedRequest, "MALFORMED_REQUEST"),
        (Reason::RequestTooLarge, "REQUEST_TOO_LARGE"),
    ] {
        assert!(!Reason::all().contains(&reason));
        assert_eq!(reason.as_str(), token);
        assert_eq!(Reason::from_str(token).unwrap(), reason);
    }
    assert!(Reason::all().contains(&Reason::InternalError));
    assert_eq!(Reason::all().len(), 11);
}
