//! Input size caps: the receipt string, the endpoint's request body and its
//! nesting depth, the compact JWS and the depth of its JSON.
//!
//! Every one of these inputs is decoded or parsed before any signature is
//! checked, so without a cap an attacker gets that work, and the memory it
//! allocates, for free. The receipt and request caps are Apple's own limit,
//! 3 MiB (measured 2026-09-23), fixed and the same in every port; the JWS
//! and depth caps are the shared cross-port numbers (`docs/design/0.7-api.md`,
//! Bounds). Each cap is pinned three ways: one unit over is refused WITHOUT
//! the expensive step running, exactly at the cap is not refused by the cap,
//! and the exact answer a caller sees.
//!
//! "Without the expensive step running" is measured, not assumed: this
//! binary installs an allocator that counts per thread, and each refusal
//! must allocate a small fraction of what the skipped decode or parse would
//! have. Per thread, so the tests can run in parallel without perturbing
//! each other's counts.

mod common;

use apple_purchase_receipt_verifier::__internal::{base64_decode_lenient, base64_encode};
use apple_purchase_receipt_verifier::{Environment, Reason, TrustAnchor, Verifier};
use serde_json::{json, Map, Value};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

/// The receipt string and request body cap, in UTF-8 bytes.
const MAX_RECEIPT_BYTES: usize = 3_145_728;
const MAX_REQUEST_BYTES: usize = 3_145_728;
/// The compact JWS cap, in UTF-8 bytes.
const MAX_JWS_BYTES: usize = 262_144;
/// How deep any JSON document may nest.
const MAX_JSON_NESTING_DEPTH: usize = 64;

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

fn verifier(anchor: TrustAnchor) -> Verifier {
    common::verifier([anchor])
}

const FAILED_BODY: &str = r#"{"status":21002}"#;

fn status(response: &str) -> i64 {
    serde_json::from_str::<Value>(response).unwrap()["status"]
        .as_i64()
        .unwrap()
}

/// `{"receipt-data":"<the shared generated receipt>"<extra>}`.
fn body_with(extra: &str) -> String {
    let receipt = base64_encode(&common::receipt_der());
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

fn endpoint(verifier: &Verifier, body: &str) -> String {
    verifier.verify_receipt_endpoint(Environment::Sandbox, body)
}

// --- receipt string: 3 MiB, before base64 decode -------------------------

#[test]
fn a_receipt_string_one_byte_over_the_cap_is_refused_before_decoding() {
    let verifier = verifier(common::receipt_root());
    let over = "A".repeat(MAX_RECEIPT_BYTES + 1);
    let (error, allocated) = measure(|| verifier.verify_receipt(&over).unwrap_err());
    assert_eq!(error.reason(), Reason::TooLarge);
    assert_eq!(
        error.message(),
        "receipt exceeds the maximum accepted size of 3145728 bytes"
    );
    // Decoding would have allocated 2.25 MiB.
    assert!(allocated < REFUSAL_BUDGET, "allocated {allocated} bytes");
}

#[test]
fn a_receipt_string_exactly_at_the_cap_is_decoded() {
    let verifier = verifier(common::receipt_root());
    let at = "A".repeat(MAX_RECEIPT_BYTES);
    let (error, allocated) = measure(|| verifier.verify_receipt(&at).unwrap_err());
    // Refused, but by the CMS parser: 2.25 MiB of zeros is not a receipt.
    assert_eq!(error.reason(), Reason::Malformed);
    assert!(
        error.message().starts_with("malformed CMS structure"),
        "{error}"
    );
    // And decoded to get there.
    assert!(
        allocated >= MAX_RECEIPT_BYTES / 4 * 3,
        "allocated {allocated}"
    );
}

#[test]
fn the_receipt_cap_counts_utf8_bytes_not_characters() {
    // 1,572,865 two-byte characters are 3,145,730 bytes: over the cap in
    // bytes, half of it in characters. A character count would let it reach
    // the decoder, which would refuse it as MALFORMED instead.
    let verifier = verifier(common::receipt_root());
    let over = "\u{e9}".repeat(MAX_RECEIPT_BYTES / 2 + 1);
    assert!(over.chars().count() < MAX_RECEIPT_BYTES);
    assert_eq!(
        verifier.verify_receipt(&over).unwrap_err().reason(),
        Reason::TooLarge
    );
}

#[test]
fn receipt_data_over_the_cap_answers_21002_at_the_endpoint_before_decoding() {
    // A receipt string over the cap cannot fit in a body under the body cap,
    // so the body cap refuses it first, before the body is parsed or the
    // receipt decoded. Either way the answer is 21002.
    let verifier = verifier(common::receipt_root());
    let body = json!({ "receipt-data": "A".repeat(MAX_RECEIPT_BYTES + 1) }).to_string();
    assert!(body.len() > MAX_REQUEST_BYTES);
    let (response, allocated) = measure(|| endpoint(&verifier, &body));
    assert!(allocated < REFUSAL_BUDGET, "allocated {allocated} bytes");
    assert_eq!(response, FAILED_BODY);
}

#[test]
fn the_byte_floor_receipt_still_verifies_through_every_receipt_entry_point() {
    // Every port MUST accept 1 MiB of DER. Its base64 is about 1.38 MB,
    // under the 3 MiB string cap, and so is the body carrying it.
    let der = common::read_fixture("generated-0.7/receipt-byte-floor.der");
    let text = base64_encode(&der);
    assert!(text.len() < MAX_RECEIPT_BYTES);
    let verifier = verifier(common::anchor("generated-0.7/large-receipt-root.der"));
    assert_eq!(verifier.verify_receipt(&text).unwrap().in_app.len(), 2300);

    // Wrapped in a JSON body it is still under the 3 MiB request cap, as it
    // is under Apple's.
    let body = json!({ "receipt-data": text }).to_string();
    assert!(body.len() < MAX_REQUEST_BYTES);
    let response: Value = serde_json::from_str(&endpoint(&verifier, &body)).unwrap();
    assert_eq!(response["status"], 0);
    assert_eq!(
        response["receipt"]["in_app"].as_array().unwrap().len(),
        2300
    );
}

// --- request body: 3 MiB of UTF-8, before the parse -----------------------

#[test]
fn a_body_one_byte_over_the_cap_answers_21002_without_being_parsed() {
    // TOO_LARGE, which the status table answers 21002; an HTTP layer can map
    // it to 413 as Apple does.
    let verifier = verifier(common::receipt_root());
    let over = body_of_len(MAX_REQUEST_BYTES + 1);
    let (response, allocated) = measure(|| endpoint(&verifier, &over));
    // Parsing would have allocated the 3 MiB pad string again.
    assert!(allocated < REFUSAL_BUDGET, "allocated {allocated} bytes");
    assert_eq!(response, FAILED_BODY);
}

#[test]
fn a_body_exactly_at_the_cap_verifies() {
    let verifier = verifier(common::receipt_root());
    assert_eq!(
        status(&endpoint(&verifier, &body_of_len(MAX_REQUEST_BYTES))),
        0
    );
}

#[test]
fn the_body_cap_counts_utf8_bytes_not_characters() {
    // Apple's limit counts UTF-8 bytes, and so does `str::len`. A body
    // padded with U+00E9 to one byte over the cap is barely half the cap in
    // characters, so a character count would let it through; the same shape
    // one byte shorter verifies.
    let verifier = verifier(common::receipt_root());
    let fixed = body_with(r#","pad":"""#).len();
    let padded = |bytes: usize| {
        let pad = format!("{}{}", "\u{e9}".repeat(bytes / 2), "a".repeat(bytes % 2));
        body_with(&format!(r#","pad":"{pad}""#))
    };

    let over = padded(MAX_REQUEST_BYTES + 1 - fixed);
    assert_eq!(over.len(), MAX_REQUEST_BYTES + 1);
    assert!(over.chars().count() < MAX_REQUEST_BYTES / 2 + fixed);
    assert_eq!(endpoint(&verifier, &over), FAILED_BODY);

    let at = padded(MAX_REQUEST_BYTES - fixed);
    assert_eq!(at.len(), MAX_REQUEST_BYTES);
    assert_eq!(status(&endpoint(&verifier, &at)), 0);
}

#[test]
fn an_oversized_body_is_too_large_before_it_is_malformed() {
    // The size is decided before the parse, so a huge body that is also not
    // JSON is refused by the size check, cheaply.
    let verifier = verifier(common::receipt_root());
    for body in [
        "[".repeat(MAX_REQUEST_BYTES + 1),
        "x".repeat(MAX_REQUEST_BYTES + 1),
    ] {
        let (response, allocated) = measure(|| endpoint(&verifier, &body));
        assert!(allocated < REFUSAL_BUDGET, "allocated {allocated} bytes");
        assert_eq!(response, FAILED_BODY);
    }
}

// --- request body nesting: 64 ---------------------------------------------

#[test]
fn a_body_nested_to_the_limit_verifies() {
    // The body object is level 1, so 63 more arrays make 64.
    let verifier = verifier(common::receipt_root());
    let body = body_with(&format!(
        r#","deep":{}"#,
        nested(MAX_JSON_NESTING_DEPTH - 1)
    ));
    assert_eq!(status(&endpoint(&verifier, &body)), 0);
}

#[test]
fn a_body_nested_past_the_limit_answers_21002() {
    // The genuine receipt would verify: a 21002 here can only come from the
    // depth bound.
    let verifier = verifier(common::receipt_root());
    for depth in [MAX_JSON_NESTING_DEPTH, 100_000] {
        let body = body_with(&format!(r#","deep":{}"#, nested(depth)));
        assert_eq!(endpoint(&verifier, &body), FAILED_BODY, "{depth}");
    }
}

#[test]
fn brackets_inside_a_body_string_are_not_nesting() {
    let verifier = verifier(common::receipt_root());
    let body = body_with(&format!(r#","note":"{}""#, "[".repeat(1000)));
    assert_eq!(status(&endpoint(&verifier, &body)), 0);
}

// --- compact JWS: 256 KiB, before any split or decode --------------------

fn decode_segment(segment: &str) -> Map<String, Value> {
    match serde_json::from_slice(&base64_decode_lenient(segment)).unwrap() {
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
    let verifier = common::jws_verifier();
    let over = transaction_of_len(MAX_JWS_BYTES + 1);
    let (error, allocated) = measure(|| verifier.verify_signed_data(&over).unwrap_err());
    // Decoding the payload alone would have allocated about 190 KB.
    assert!(allocated < REFUSAL_BUDGET, "allocated {allocated} bytes");
    assert_eq!(error.reason(), Reason::TooLarge);
    assert_eq!(
        error.message(),
        "jws exceeds the maximum accepted size of 262144 bytes"
    );
}

#[test]
fn a_jws_exactly_at_the_cap_reaches_the_signature_check() {
    let error = common::jws_verifier()
        .verify_signed_data(&transaction_of_len(MAX_JWS_BYTES))
        .unwrap_err();
    // Past the cap, both JSON parses, both certificates and the chain.
    assert_eq!(error.reason(), Reason::InvalidSignature, "{error}");
}

// --- JWS header and payload nesting: 64 -----------------------------------

#[test]
fn jws_json_nested_to_the_limit_reaches_the_signature_check() {
    let deep = serde_json::from_str::<Value>(&nested(MAX_JSON_NESTING_DEPTH - 1)).unwrap();
    for jws in [
        transaction_with(Some(("deep", deep.clone())), None),
        transaction_with(None, Some(("deep", deep.clone()))),
    ] {
        let error = common::jws_verifier().verify_signed_data(&jws).unwrap_err();
        assert_eq!(error.reason(), Reason::InvalidSignature, "{error}");
    }
}

#[test]
fn jws_json_nested_past_the_limit_is_refused() {
    // A header nested past 64 is a broken outer structure: MALFORMED. A
    // payload nested past 64 does not parse, and a payload that does not
    // parse is carried to the signature check, which this unsigned one
    // fails: INVALID_SIGNATURE, never a verdict before the signature.
    let (header, payload, signature) = common::split_jws(&common::transaction_jws());
    let deepen = |segment: &str| {
        let text = String::from_utf8(base64_decode_lenient(segment)).unwrap();
        let text = format!(
            r#"{{"deep":{},{}"#,
            nested(MAX_JSON_NESTING_DEPTH),
            &text[1..]
        );
        common::base64url(text.as_bytes())
    };
    let header_error = common::jws_verifier()
        .verify_signed_data(&common::join_jws(&deepen(&header), &payload, &signature))
        .unwrap_err();
    assert_eq!(header_error.reason(), Reason::Malformed, "{header_error}");
    let payload_error = common::jws_verifier()
        .verify_signed_data(&common::join_jws(&header, &deepen(&payload), &signature))
        .unwrap_err();
    assert_eq!(
        payload_error.reason(),
        Reason::InvalidSignature,
        "{payload_error}"
    );
}
