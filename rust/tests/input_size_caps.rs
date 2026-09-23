//! Input size caps: the receipt string, the receipt DER, the endpoint's
//! request body and its nesting depth, the compact JWS and the depth of its
//! JSON.
//!
//! Every one of these inputs is decoded or parsed before any signature is
//! checked, so without a cap an attacker gets that work, and the memory it
//! allocates, for free. The receipt and request caps are Apple's own limit,
//! 3 MiB (measured 2026-09-23), fixed and the same in every port; the JWS
//! and depth caps are the shared cross-port numbers. Each cap is pinned three ways: one unit over is refused WITHOUT
//! the expensive step running, exactly at the cap is not refused by the cap,
//! and the exact answer a caller sees.
//!
//! "Without the expensive step running" is measured, not assumed: this
//! binary installs an allocator that counts per thread, and each refusal
//! must allocate a small fraction of what the skipped decode or parse would
//! have. Per thread, so the tests can run in parallel without perturbing
//! each other's counts.

mod common;

use apple_purchase_receipt_verifier::{
    base64, status, verify_receipt_core, CoreError, Environment, JwsVerifier, Reason,
    ReceiptVerifier, TrustAnchor, VerifyReceiptEndpoint, VerifyReceiptRequest,
    MAX_JSON_NESTING_DEPTH, MAX_JWS_BYTES, MAX_RECEIPT_BYTES, MAX_REQUEST_BYTES,
};
use serde_json::{json, Map, Value};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

// --- a per-thread allocation counter ------------------------------------

thread_local! {
    static ALLOCATED: Cell<usize> = const { Cell::new(0) };
}

fn count(bytes: usize) {
    // `try_with`: the counter may already be gone while a thread is torn
    // down, and an allocator must not panic.
    let _ = ALLOCATED.try_with(|total| total.set(total.get() + bytes));
}

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count(new_size.saturating_sub(layout.size()));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn measure<T>(body: impl FnOnce() -> T) -> (T, usize) {
    let before = ALLOCATED.with(Cell::get);
    let value = body();
    (value, ALLOCATED.with(Cell::get) - before)
}

/// What a refusal may allocate: its error message and nothing in proportion
/// to the input. Every skipped step below would allocate hundreds of
/// kilobytes at least.
const REFUSAL_BUDGET: usize = 16 * 1024;

// --- setup ----------------------------------------------------------------

fn receipt_verifier(anchor: TrustAnchor) -> ReceiptVerifier {
    ReceiptVerifier::builder()
        .trusted_roots([anchor])
        .bundle_id("com.example.app")
        .build()
        .unwrap()
}

fn endpoint(anchor: TrustAnchor) -> VerifyReceiptEndpoint {
    VerifyReceiptEndpoint::builder()
        .trusted_roots([anchor])
        .environment(Environment::Sandbox)
        .build()
        .unwrap()
}

fn jws_verifier() -> JwsVerifier {
    JwsVerifier::builder()
        .trusted_roots([common::jws_root()])
        .bundle_id("com.example.app")
        .accepted_environments([Environment::Sandbox])
        .build()
        .unwrap()
}

const FAILED_BODY: &str = r#"{"status":21002}"#;

/// `{"receipt-data":"<the shared genuine receipt>"<extra>}`.
fn body_with(extra: &str) -> String {
    let receipt = base64::encode(&common::receipt_der());
    format!(r#"{{"receipt-data":"{receipt}"{extra}}}"#)
}

/// A genuine body padded to exactly `len` bytes inside a string value, so
/// that parsing it would allocate the padding again.
fn body_of_len(len: usize) -> String {
    let empty = body_with(r#","pad":"""#);
    let body = body_with(&format!(r#","pad":"{}""#, "x".repeat(len - empty.len())));
    assert_eq!(body.len(), len);
    body
}

fn nested(depth: usize) -> String {
    format!("{}{}", "[".repeat(depth), "]".repeat(depth))
}

// --- receipt string: 3 MiB, before base64 decode -------------------------

#[test]
fn a_receipt_string_one_byte_over_the_cap_is_refused_before_decoding() {
    let verifier = receipt_verifier(common::receipt_root());
    let over = "A".repeat(MAX_RECEIPT_BYTES + 1);
    let guid = common::device_guid();

    let (error, allocated) = measure(|| verifier.verify_base64(&over).unwrap_err());
    assert_eq!(error.reason(), Reason::InvalidReceiptFormat);
    assert_eq!(
        error.detail(),
        "receipt exceeds the maximum accepted size of 3145728 bytes of base64"
    );
    // Decoding would have allocated 2.25 MiB.
    assert!(allocated < REFUSAL_BUDGET, "allocated {allocated} bytes");

    let (error, allocated) = measure(|| {
        verifier
            .verify_base64_with_device_guid(&over, &guid)
            .unwrap_err()
    });
    assert_eq!(error.reason(), Reason::InvalidReceiptFormat);
    assert!(error.detail().contains("maximum accepted size"));
    assert!(allocated < REFUSAL_BUDGET, "allocated {allocated} bytes");
}

#[test]
fn a_receipt_string_exactly_at_the_cap_is_decoded() {
    let verifier = receipt_verifier(common::receipt_root());
    let at = "A".repeat(MAX_RECEIPT_BYTES);
    let (error, allocated) = measure(|| verifier.verify_base64(&at).unwrap_err());
    // Refused, but by the CMS parser: 2.25 MiB of zeros is not a receipt.
    assert_eq!(error.reason(), Reason::InvalidReceiptFormat);
    assert!(!error.detail().contains("maximum accepted size"), "{error}");
    // And decoded to get there.
    assert!(
        allocated >= MAX_RECEIPT_BYTES / 4 * 3,
        "allocated {allocated}"
    );
}

#[test]
fn receipt_data_over_the_cap_answers_21002_at_the_endpoint_before_decoding() {
    let endpoint = endpoint(common::receipt_root());
    let over = "A".repeat(MAX_RECEIPT_BYTES + 1);
    let request = VerifyReceiptRequest::new(over.clone());

    let (result, allocated) = measure(|| endpoint.verify_receipt_data(&over));
    assert!(allocated < REFUSAL_BUDGET, "allocated {allocated} bytes");
    assert_eq!(result.status(), status::MALFORMED);
    assert_eq!(result.failure_reason(), Some(Reason::InvalidReceiptFormat));
    assert_eq!(result.to_json(), FAILED_BODY);

    let (result, allocated) = measure(|| endpoint.verify_receipt_result(&request));
    assert!(allocated < REFUSAL_BUDGET, "allocated {allocated} bytes");
    assert_eq!(result.failure_reason(), Some(Reason::InvalidReceiptFormat));
    assert_eq!(result.to_json(), FAILED_BODY);
}

#[test]
fn receipt_data_exactly_at_the_cap_is_decoded_at_the_endpoint() {
    let endpoint = endpoint(common::receipt_root());
    let at = "A".repeat(MAX_RECEIPT_BYTES);
    let (result, allocated) = measure(|| endpoint.verify_receipt_data(&at));
    assert!(
        allocated >= MAX_RECEIPT_BYTES / 4 * 3,
        "allocated {allocated}"
    );
    assert_eq!(result.failure_reason(), Some(Reason::InvalidReceiptFormat));
    assert_eq!(result.to_json(), FAILED_BODY);
}

// --- receipt DER: 3 MiB, before the CMS parse ----------------------------

#[test]
fn receipt_der_one_byte_over_the_cap_is_refused_before_parsing() {
    let verifier = receipt_verifier(common::receipt_root());
    let over = vec![0x30u8; MAX_RECEIPT_BYTES + 1];
    let expected = "receipt exceeds the maximum accepted size of 3145728 bytes";

    let (error, allocated) = measure(|| verifier.verify(&over).unwrap_err());
    assert_eq!(error.reason(), Reason::InvalidReceiptFormat);
    assert_eq!(error.detail(), expected);
    assert!(allocated < REFUSAL_BUDGET, "allocated {allocated} bytes");

    match verify_receipt_core(&over, &[common::receipt_root()]).unwrap_err() {
        CoreError::Verification(error) => assert_eq!(error.detail(), expected),
        other => panic!("expected a verification error, got {other:?}"),
    }
}

#[test]
fn receipt_der_exactly_at_the_cap_reaches_the_parser() {
    let verifier = receipt_verifier(common::receipt_root());
    let error = verifier
        .verify(&vec![0x30u8; MAX_RECEIPT_BYTES])
        .unwrap_err();
    assert_eq!(error.reason(), Reason::InvalidReceiptFormat);
    assert!(
        error.detail().starts_with("malformed CMS structure"),
        "{error}"
    );
}

#[test]
fn the_byte_floor_receipt_still_verifies_through_every_receipt_entry_point() {
    // cases.json: every port MUST accept 1 MiB of DER. Its base64 is about
    // 1.38 MB, under the 3 MiB string cap, and so is the body carrying it.
    let der = common::read_fixture("generated/receipt-byte-floor.der");
    let text = base64::encode(&der);
    assert!(text.len() < MAX_RECEIPT_BYTES);
    let anchor = common::anchor("generated/large-receipt-root.der");

    let verifier = receipt_verifier(anchor.clone());
    assert_eq!(verifier.verify(&der).unwrap().in_app_purchases.len(), 2300);
    assert_eq!(
        verifier
            .verify_base64(&text)
            .unwrap()
            .in_app_purchases
            .len(),
        2300
    );

    let endpoint = endpoint(anchor);
    assert_eq!(endpoint.verify_receipt_data(&text).status(), status::OK);
    assert_eq!(
        endpoint
            .verify_receipt_result(&VerifyReceiptRequest::new(text.clone()))
            .status(),
        status::OK
    );
    // Wrapped in a JSON body it is still under the 3 MiB request cap, as it
    // is under Apple's.
    let body = json!({ "receipt-data": text }).to_string();
    assert!(body.len() < MAX_REQUEST_BYTES);
    let result = endpoint.verify_receipt_result_from_json(&body);
    assert_eq!(result.status(), status::OK);
    assert_eq!(result.receipt().unwrap().in_app_purchases.len(), 2300);
}

// --- request body: 3 MiB of UTF-8, before serde_json ---------------------

#[test]
fn a_body_one_byte_over_the_cap_answers_21002_without_being_parsed() {
    // REQUEST_TOO_LARGE, the reason an HTTP layer maps to 413 as Apple does.
    let endpoint = endpoint(common::receipt_root());
    let over = body_of_len(MAX_REQUEST_BYTES + 1);
    let (result, allocated) = measure(|| endpoint.verify_receipt_result_from_json(&over));
    // Parsing would have allocated the 3 MiB pad string again.
    assert!(allocated < REFUSAL_BUDGET, "allocated {allocated} bytes");
    assert_eq!(result.status(), status::MALFORMED);
    assert_eq!(result.failure_reason(), Some(Reason::RequestTooLarge));
    assert_eq!(result.to_json(), FAILED_BODY);
    assert_eq!(endpoint.verify_receipt_json(&over), FAILED_BODY);
}

#[test]
fn a_body_exactly_at_the_cap_verifies() {
    let endpoint = endpoint(common::receipt_root());
    let result = endpoint.verify_receipt_result_from_json(&body_of_len(MAX_REQUEST_BYTES));
    assert_eq!(result.status(), status::OK);
}

#[test]
fn the_body_cap_counts_utf8_bytes_not_characters() {
    // Apple's limit counts UTF-8 bytes, and so does `str::len`. A body
    // padded with U+00E9 to one byte over the cap is barely half the cap in
    // characters, so a character count would let it through; the same shape
    // one byte shorter verifies.
    let endpoint = endpoint(common::receipt_root());
    let fixed = body_with(r#","pad":"""#).len();
    let padded = |bytes: usize| {
        let pad = format!("{}{}", "é".repeat(bytes / 2), "a".repeat(bytes % 2));
        body_with(&format!(r#","pad":"{pad}""#))
    };

    let over = padded(MAX_REQUEST_BYTES + 1 - fixed);
    assert_eq!(over.len(), MAX_REQUEST_BYTES + 1);
    assert!(over.chars().count() < MAX_REQUEST_BYTES / 2 + fixed);
    let result = endpoint.verify_receipt_result_from_json(&over);
    assert_eq!(result.failure_reason(), Some(Reason::RequestTooLarge));
    assert_eq!(result.to_json(), FAILED_BODY);

    let at = padded(MAX_REQUEST_BYTES - fixed);
    assert_eq!(at.len(), MAX_REQUEST_BYTES);
    assert_eq!(
        endpoint.verify_receipt_result_from_json(&at).status(),
        status::OK
    );
}

#[test]
fn the_caps_are_apples_three_mebibytes() {
    // Measured 2026-09-23: Apple's verifyReceipt answers a 3,145,728-byte
    // body and refuses a 3,145,729-byte one with HTTP 413. No receipt it
    // accepts can be larger than the body carrying it.
    assert_eq!(MAX_REQUEST_BYTES, 3_145_728);
    assert_eq!(MAX_RECEIPT_BYTES, 3_145_728);
}

#[test]
fn an_oversized_body_is_too_large_before_it_is_malformed() {
    // The size is decided before the depth scan and the parse, so a huge
    // body that is also not JSON is REQUEST_TOO_LARGE, as Apple's 413 is.
    let endpoint = endpoint(common::receipt_root());
    for body in [
        "[".repeat(MAX_REQUEST_BYTES + 1),
        "x".repeat(MAX_REQUEST_BYTES + 1),
    ] {
        let result = endpoint.verify_receipt_result_from_json(&body);
        assert_eq!(result.failure_reason(), Some(Reason::RequestTooLarge));
        assert_eq!(result.to_json(), FAILED_BODY);
    }
}

// --- request body nesting: 64, counted before serde_json -----------------

#[test]
fn a_body_nested_to_the_limit_verifies() {
    // The body object is level 1, so 63 more arrays make 64.
    let endpoint = endpoint(common::receipt_root());
    let body = body_with(&format!(
        r#","deep":{}"#,
        nested(MAX_JSON_NESTING_DEPTH - 1)
    ));
    assert_eq!(
        endpoint.verify_receipt_result_from_json(&body).status(),
        status::OK
    );
}

#[test]
fn a_body_nested_past_the_limit_answers_21002() {
    // 65 levels is well inside serde_json's own recursion limit of 128, so
    // parsing would succeed and the genuine receipt would verify: a 21002
    // here can only come from the count that runs first.
    let endpoint = endpoint(common::receipt_root());
    for depth in [MAX_JSON_NESTING_DEPTH, 100_000] {
        let body = body_with(&format!(r#","deep":{}"#, nested(depth)));
        let result = endpoint.verify_receipt_result_from_json(&body);
        assert_eq!(
            result.failure_reason(),
            Some(Reason::MalformedRequest),
            "{depth}"
        );
        assert_eq!(result.to_json(), FAILED_BODY);
    }
}

#[test]
fn brackets_inside_a_body_string_are_not_nesting() {
    let endpoint = endpoint(common::receipt_root());
    let body = body_with(&format!(r#","note":"{}""#, "[".repeat(1000)));
    assert_eq!(
        endpoint.verify_receipt_result_from_json(&body).status(),
        status::OK
    );
}

// --- compact JWS: 256 KiB, before any split or decode --------------------

fn decode_segment(segment: &str) -> Map<String, Value> {
    match serde_json::from_slice(&base64::decode_lenient(segment)).unwrap() {
        Value::Object(map) => map,
        other => panic!("not a JSON object: {other}"),
    }
}

fn encode_segment(map: &Map<String, Value>) -> String {
    common::base64url(serde_json::to_string(map).unwrap().as_bytes())
}

/// The shared transaction with `extra` added to its header and payload. The
/// signature no longer covers either, so a JWS that passes every format
/// check answers `INVALID_SIGNATURE`.
fn transaction_with(
    header_extra: Option<(&str, Value)>,
    payload_extra: Option<(&str, Value)>,
) -> String {
    let (header, payload, signature) = common::split_jws(&common::transaction_jws());
    let mut header = decode_segment(&header);
    let mut payload = decode_segment(&payload);
    if let Some((key, value)) = header_extra {
        header.insert(key.to_owned(), value);
    }
    if let Some((key, value)) = payload_extra {
        payload.insert(key.to_owned(), value);
    }
    common::join_jws(
        &encode_segment(&header),
        &encode_segment(&payload),
        &signature,
    )
}

/// The shared transaction padded to exactly `len` bytes. Base64url cannot
/// produce every length from one segment, so the header takes up the slack.
fn transaction_of_len(len: usize) -> String {
    for header_pad in 0..4 {
        let header = Some(("pad", Value::from("h".repeat(header_pad))));
        let base = transaction_with(header.clone(), Some(("pad", Value::from(""))));
        let payload = ((len - base.len()) * 3 / 4).saturating_sub(2);
        for extra in payload..payload + 4 {
            let jws = transaction_with(
                header.clone(),
                Some(("pad", Value::from("p".repeat(extra)))),
            );
            if jws.len() == len {
                return jws;
            }
        }
    }
    panic!("no padding reaches {len} bytes");
}

#[test]
fn a_jws_one_byte_over_the_cap_is_refused_before_decoding() {
    let verifier = jws_verifier();
    let over = transaction_of_len(MAX_JWS_BYTES + 1);
    let (error, allocated) = measure(|| verifier.verify_transaction(&over).unwrap_err());
    // Decoding the payload alone would have allocated about 190 KB.
    assert!(allocated < REFUSAL_BUDGET, "allocated {allocated} bytes");
    assert_eq!(error.reason(), Reason::InvalidJwsFormat);
    assert_eq!(
        error.detail(),
        "jws exceeds the maximum accepted size of 262144 bytes"
    );
    assert_eq!(
        verifier.verify_raw(&over).unwrap_err().detail(),
        error.detail()
    );
    assert_eq!(
        verifier.verify_app_transaction(&over).unwrap_err().detail(),
        error.detail()
    );
}

#[test]
fn a_jws_exactly_at_the_cap_reaches_the_signature_check() {
    let error = jws_verifier()
        .verify_transaction(&transaction_of_len(MAX_JWS_BYTES))
        .unwrap_err();
    // Past the cap, both JSON parses, both certificates and the chain.
    assert_eq!(error.reason(), Reason::InvalidSignature, "{error}");
}

// --- JWS header and payload nesting: 64, counted before serde_json -------

#[test]
fn jws_json_nested_to_the_limit_reaches_the_signature_check() {
    let deep = serde_json::from_str::<Value>(&nested(MAX_JSON_NESTING_DEPTH - 1)).unwrap();
    for jws in [
        transaction_with(Some(("deep", deep.clone())), None),
        transaction_with(None, Some(("deep", deep.clone()))),
    ] {
        let error = jws_verifier().verify_transaction(&jws).unwrap_err();
        assert_eq!(error.reason(), Reason::InvalidSignature, "{error}");
    }
}

#[test]
fn jws_json_nested_past_the_limit_is_a_format_failure() {
    // 65 levels parse under serde_json's own limit of 128; only the count
    // refuses them. Built as text because serde_json will not build them.
    let (header, payload, signature) = common::split_jws(&common::transaction_jws());
    let deepen = |segment: &str| {
        let text = String::from_utf8(base64::decode_lenient(segment)).unwrap();
        let text = format!(
            r#"{{"deep":{},{}"#,
            nested(MAX_JSON_NESTING_DEPTH),
            &text[1..]
        );
        common::base64url(text.as_bytes())
    };
    let cases = [
        (
            common::join_jws(&deepen(&header), &payload, &signature),
            "header",
        ),
        (
            common::join_jws(&header, &deepen(&payload), &signature),
            "payload",
        ),
    ];
    for (jws, what) in cases {
        let error = jws_verifier().verify_transaction(&jws).unwrap_err();
        assert_eq!(error.reason(), Reason::InvalidJwsFormat);
        assert_eq!(
            error.detail(),
            format!("{what} nests deeper than 64 levels")
        );
    }
}
