//! JWS rejections: every shape the format check, the certificate checks and
//! the signature check must refuse, and the exact reason each gets.
//!
//! The order of the checks is observable. `cases-0.7.json` pins the order at
//! the level of whole vectors; these tests pin it at the level of one fault
//! at a time, including the faults no shared vector covers.

mod common;

use apple_purchase_receipt_verifier::__internal::x509::Certificate;
use apple_purchase_receipt_verifier::__internal::{base64_decode_lenient, base64_encode};
use apple_purchase_receipt_verifier::{Config, Failure, Reason, TrustAnchor, Verifier};
use serde_json::{json, Value};

fn verifier() -> Verifier {
    common::jws_verifier()
}

fn reason_of(jws: &str) -> Reason {
    verifier().verify_signed_data(jws).unwrap_err().reason()
}

fn expect_err(jws: &str) -> Failure {
    verifier().verify_signed_data(jws).unwrap_err()
}

/// 2025-01-01T00:00:00Z, inside the shared fixture chain's validity window.
const INSIDE_THE_CHAIN: i64 = 1_735_689_600_000;

/// 1971-01-01T00:00:00Z, before the shared fixture chain's notBefore.
const BEFORE_THE_CHAIN: i64 = 31_536_000_000;

#[test]
fn the_shared_transaction_verifies() {
    let payload = verifier()
        .verify_signed_data(&common::transaction_jws())
        .unwrap();
    assert_eq!(common::claims(&payload)["productId"], "com.example.app.pro");
}

#[test]
fn an_empty_string_is_not_a_jws() {
    assert_eq!(reason_of(""), Reason::Malformed);
}

#[test]
fn two_segments_are_rejected() {
    let (header, payload, _) = common::split_jws(&common::transaction_jws());
    assert_eq!(reason_of(&format!("{header}.{payload}")), Reason::Malformed);
}

#[test]
fn four_segments_are_rejected() {
    let jws = common::transaction_jws();
    assert_eq!(reason_of(&format!("{jws}.extra")), Reason::Malformed);
}

#[test]
fn a_header_that_is_not_json_is_rejected() {
    let (_, payload, signature) = common::split_jws(&common::transaction_jws());
    let header = common::base64url(b"not json at all");
    assert_eq!(
        reason_of(&common::join_jws(&header, &payload, &signature)),
        Reason::Malformed
    );
}

#[test]
fn a_header_that_is_a_json_array_is_rejected() {
    let (_, payload, signature) = common::split_jws(&common::transaction_jws());
    let header = common::base64url(b"[1,2,3]");
    assert_eq!(
        reason_of(&common::join_jws(&header, &payload, &signature)),
        Reason::Malformed
    );
}

#[test]
fn alg_must_be_es256() {
    for alg in ["RS256", "none", "ES384", "HS256", ""] {
        let jws = common::transaction_jws();
        let mut header = common::jws_header(&jws);
        header.insert("alg".to_owned(), json!(alg));
        assert_eq!(
            reason_of(&common::with_header(&jws, &header)),
            Reason::Malformed,
            "alg {alg} must be refused"
        );
    }
}

#[test]
fn alg_must_be_a_string() {
    let jws = common::transaction_jws();
    let mut header = common::jws_header(&jws);
    header.insert("alg".to_owned(), json!(256));
    assert_eq!(
        reason_of(&common::with_header(&jws, &header)),
        Reason::Malformed
    );
}

#[test]
fn x5c_must_be_present_and_hold_exactly_three_entries() {
    let jws = common::transaction_jws();
    let original = common::jws_header(&jws);
    let entries = original.get("x5c").unwrap().as_array().unwrap().clone();

    let mut absent = original.clone();
    absent.remove("x5c");
    assert_eq!(
        reason_of(&common::with_header(&jws, &absent)),
        Reason::Malformed
    );

    for count in [0usize, 1, 2, 4, 5] {
        let mut header = original.clone();
        let mut list: Vec<Value> = Vec::new();
        for index in 0..count {
            list.push(entries[index % entries.len()].clone());
        }
        header.insert("x5c".to_owned(), Value::Array(list));
        assert_eq!(
            reason_of(&common::with_header(&jws, &header)),
            Reason::Malformed,
            "an x5c of {count} entries must be refused"
        );
    }
}

#[test]
fn x5c_must_be_an_array_of_strings() {
    let jws = common::transaction_jws();
    let mut header = common::jws_header(&jws);
    header.insert("x5c".to_owned(), json!("a single string"));
    assert_eq!(
        reason_of(&common::with_header(&jws, &header)),
        Reason::Malformed
    );

    let mut header = common::jws_header(&jws);
    header.insert("x5c".to_owned(), json!([1, 2, 3]));
    assert_eq!(
        reason_of(&common::with_header(&jws, &header)),
        Reason::Malformed
    );
}

#[test]
fn an_x5c_entry_that_is_not_a_certificate_is_invalid_certificate() {
    let jws = common::transaction_jws();
    let original = common::jws_header(&jws);
    for index in 0..2 {
        let mut header = original.clone();
        let mut entries = original.get("x5c").unwrap().as_array().unwrap().clone();
        entries[index] = json!("bm90IGEgY2VydGlmaWNhdGU=");
        header.insert("x5c".to_owned(), Value::Array(entries));
        assert_eq!(
            reason_of(&common::with_header(&jws, &header)),
            Reason::InvalidCertificate,
            "x5c[{index}] holding non-certificate bytes"
        );
    }
}

#[test]
fn an_x5c_entry_that_is_not_base64_is_invalid_certificate() {
    let jws = common::transaction_jws();
    let mut header = common::jws_header(&jws);
    let mut entries = header.get("x5c").unwrap().as_array().unwrap().clone();
    entries[0] = json!("!!!! not base64 !!!!");
    header.insert("x5c".to_owned(), Value::Array(entries));
    assert_eq!(
        reason_of(&common::with_header(&jws, &header)),
        Reason::InvalidCertificate
    );
}

#[test]
fn an_x5c_certificate_carrying_one_extension_twice_is_invalid_certificate() {
    // RFC 5280 4.2 forbids a second instance of any extension. The parser
    // used to keep the first copy and drop the rest, which is a choice about
    // what the certificate means rather than a reading of it, so the same
    // bytes could answer "is this a CA" one way here and another way in a
    // port that kept the last copy. Both levels are pinned: the parser
    // refuses the certificate, and the verifier reports it as a defect of
    // the certificate rather than of the chain it sits on.
    let jws = common::read_text_fixture("generated/transaction-x5c-duplicate-extension.jws");
    let header = common::jws_header(&jws);
    let leaf = header.get("x5c").unwrap().as_array().unwrap()[0]
        .as_str()
        .unwrap();
    let der = base64_decode_lenient(leaf);
    assert!(Certificate::from_der(&der).is_err());

    let verifier = common::verifier([common::anchor("generated/hostile-jws-root.der")]);
    assert_eq!(
        verifier.verify_signed_data(&jws).unwrap_err().reason(),
        Reason::InvalidCertificate
    );
}

#[test]
fn the_third_x5c_entry_is_never_trusted_but_must_be_a_certificate() {
    // Swapping x5c[2] for another PKI's root must change nothing: the chain
    // terminates at a pinned anchor, not at a certificate the payload
    // supplied. Swapping it for bytes that are not a certificate is a
    // different thing, and is now INVALID_CERTIFICATE in every port
    // (transaction/reject-x5c-root-that-is-not-a-certificate).
    let jws = common::transaction_jws();
    let mut header = common::jws_header(&jws);
    let mut entries = header.get("x5c").unwrap().as_array().unwrap().clone();
    entries[2] = json!("bm90IGEgY2VydGlmaWNhdGUgYXQgYWxs");
    header.insert("x5c".to_owned(), Value::Array(entries));
    assert_eq!(
        reason_of(&common::with_header(&jws, &header)),
        Reason::InvalidCertificate
    );
}

/// A payload that does not parse as a JSON object in UTF-8 is not judged
/// before the signature: nothing unverified gets to decide between "broken"
/// and "Apple signed something odd". Unsigned, it is `INVALID_SIGNATURE`.
#[test]
fn a_payload_that_is_not_a_json_object_is_carried_to_the_signature_check() {
    let (header, _, signature) = common::split_jws(&common::transaction_jws());
    for body in [
        &b"\xff\xfe not json"[..],
        b"42",
        b"\"text\"",
        b"null",
        b"[]",
        b"",
        b"{\"a\":1,}",
    ] {
        let payload = common::base64url(body);
        assert_eq!(
            reason_of(&common::join_jws(&header, &payload, &signature)),
            Reason::InvalidSignature,
            "payload {:?}",
            String::from_utf8_lossy(body)
        );
    }
}

/// The signed twins: Apple-signed (here, test-root-signed) payloads that are
/// not JSON objects verify their chain and signature and then fail as
/// `UNREADABLE_PAYLOAD`, with the reader's error as the source.
#[test]
fn a_signed_payload_that_is_not_a_json_object_is_unreadable() {
    use std::error::Error as _;
    let verifier = common::verifier([common::anchor("generated-0.7/api-jws-root.der")]);
    for fixture in [
        "generated-0.7/jws-payload-empty-signed.jws",
        "generated-0.7/jws-payload-json-array-signed.jws",
    ] {
        let failure = verifier
            .verify_signed_data(&common::read_text_fixture(fixture))
            .unwrap_err();
        assert_eq!(failure.reason(), Reason::UnreadablePayload, "{fixture}");
        assert!(failure.source().is_some(), "{fixture}");
    }
}

#[test]
fn a_signature_of_the_wrong_length_is_rejected() {
    let (header, payload, signature) = common::split_jws(&common::transaction_jws());
    let raw = base64_decode_lenient(&signature);
    assert_eq!(raw.len(), 64);
    for length in [0usize, 1, 63, 65, 128] {
        let mut truncated = raw.clone();
        truncated.resize(length, 0x41);
        let encoded = common::base64url(&truncated);
        let error = expect_err(&common::join_jws(&header, &payload, &encoded));
        assert_eq!(
            error.reason(),
            Reason::InvalidSignature,
            "signature of {length} bytes"
        );
    }
}

#[test]
fn a_single_flipped_signature_byte_is_rejected() {
    let (header, payload, signature) = common::split_jws(&common::transaction_jws());
    let raw = base64_decode_lenient(&signature);
    for index in [0usize, 31, 32, 63] {
        let mut flipped = raw.clone();
        flipped[index] ^= 0x01;
        let encoded = common::base64url(&flipped);
        assert_eq!(
            reason_of(&common::join_jws(&header, &payload, &encoded)),
            Reason::InvalidSignature,
            "flipping signature byte {index}"
        );
    }
}

#[test]
fn a_flipped_payload_byte_is_rejected() {
    let jws = common::transaction_jws();
    let (header, payload, signature) = common::split_jws(&jws);
    let decoded = base64_decode_lenient(&payload);
    let text = String::from_utf8(decoded).unwrap();
    let tampered = text.replace("com.example.app.pro", "com.example.app.PRO");
    assert_ne!(text, tampered);
    let encoded = common::base64url(tampered.as_bytes());
    assert_eq!(
        reason_of(&common::join_jws(&header, &encoded, &signature)),
        Reason::InvalidSignature
    );
}

#[test]
fn a_foreign_root_is_an_untrusted_chain_not_a_purpose_error() {
    let error = Verifier::new(Config::defaults())
        .verify_signed_data(&common::transaction_jws())
        .unwrap_err();
    assert_eq!(error.reason(), Reason::UntrustedChain);
}

#[test]
fn marker_oids_are_checked_before_the_chain() {
    // Both fixtures chain correctly to their own root: if the marker check
    // ran after the chain walk, these would pass instead of reporting a
    // purpose error.
    for (root, jws) in [
        (
            "generated/jws-no-leaf-oid-root.der",
            "generated/transaction-no-leaf-oid.jws",
        ),
        (
            "generated/jws-no-intermediate-oid-root.der",
            "generated/transaction-no-intermediate-oid.jws",
        ),
    ] {
        assert_eq!(
            common::verifier([common::anchor(root)])
                .verify_signed_data(&common::read_text_fixture(jws))
                .unwrap_err()
                .reason(),
            Reason::InvalidCertificatePurpose,
            "{jws}"
        );
    }
}

#[test]
fn a_payload_is_never_rejected_for_its_age() {
    // Freshness is the caller's decision: a payload signed in 2024 still
    // verifies, and its signedDate is there for the caller.
    let payload = verifier()
        .verify_signed_data(&common::transaction_jws())
        .unwrap();
    assert_eq!(
        common::claims(&payload)["signedDate"],
        1_722_945_600_000_i64
    );
}

#[test]
fn the_chain_is_judged_at_the_signing_date() {
    // The historical payload's chain is expired today and was valid when it
    // was signed; the fresh one was signed after it expired, which is a
    // certificate outside its validity window (owner, 2026-09-27).
    let verifier = common::verifier([common::anchor("generated/jws-expired-root.der")]);
    let historical = common::read_text_fixture("generated/expired-cert-historical.jws");
    let fresh = common::read_text_fixture("generated/expired-cert-fresh.jws");
    assert!(verifier.verify_signed_data(&historical).is_ok());
    assert_eq!(
        verifier.verify_signed_data(&fresh).unwrap_err().reason(),
        Reason::InvalidCertificate
    );
}

/// 0.7 takes no bundle id, environment or app Apple id: the claims come back
/// as Apple signed them and the caller judges them, which is where 0.6
/// answered `WRONG_BUNDLE_ID`, `WRONG_ENVIRONMENT` and `WRONG_APP_APPLE_ID`.
#[test]
fn claims_are_returned_for_the_caller_to_judge() {
    let payload = verifier()
        .verify_signed_data(&common::transaction_jws())
        .unwrap();
    let claims = common::claims(&payload);
    assert_eq!(claims["bundleId"], "com.example.app");
    assert_eq!(claims["environment"], "Sandbox");

    let production = verifier()
        .verify_signed_data(&common::read_text_fixture(
            "generated/app-transaction-production.jws",
        ))
        .unwrap();
    let claims = common::claims(&production);
    assert_eq!(claims["receiptType"], "Production");
    assert_eq!(claims["appAppleId"], 123_456_789);
}

#[test]
fn a_broken_signature_is_refused_whatever_the_claims() {
    let (header, payload, signature) = common::split_jws(&common::transaction_jws());
    let mut broken = base64_decode_lenient(&signature);
    broken[0] ^= 0xff;
    let error = expect_err(&common::join_jws(
        &header,
        &payload,
        &common::base64url(&broken),
    ));
    assert_eq!(error.reason(), Reason::InvalidSignature);
}

// --- one signed payload, one accepted wire form -------------------------

/// The JWS signature segment is not covered by the signature, and it used to
/// be decoded leniently — every byte outside the alphabet skipped, the final
/// character's unused bits discarded. An attacker holding one Apple-signed
/// `jwsRepresentation` could therefore mint unboundedly many byte-distinct
/// strings that all verify to the same transaction, which defeats the
/// cheapest replay guard an integrator writes: a unique index on the JWS
/// string, or `WHERE sha256(signed_payload) = ?`. App Store Server
/// Notifications V2 are exactly this shape — the body *is* the JWS.
#[test]
fn junk_in_the_signature_segment_is_not_a_signature() {
    let jws = common::transaction_jws();
    assert!(verifier().verify_signed_data(&jws).is_ok(), "baseline");
    // A malformed segment is a format failure, decided before any
    // cryptography runs — the same class as a header that is not base64url
    // JSON — not a cryptographic verdict on a signature that was actually
    // checked.
    for suffix in ["=", "==", "!!!!", "\n", " ", "~~~", "\t", "AAAA!"] {
        let mutated = format!("{jws}{suffix}");
        assert_eq!(
            reason_of(&mutated),
            Reason::Malformed,
            "signature segment + {suffix:?} must not verify"
        );
    }
    // Interleaved, not only appended.
    let (header, payload, signature) = common::split_jws(&jws);
    let spaced: String = signature.chars().flat_map(|c| [c, '\n']).collect();
    assert_eq!(
        reason_of(&common::join_jws(&header, &payload, &spaced)),
        Reason::Malformed
    );
    // The standard alphabet is not the URL alphabet.
    let plus = signature.replacen('A', "+", 1);
    if plus != signature {
        assert_eq!(
            reason_of(&common::join_jws(&header, &payload, &plus)),
            Reason::Malformed
        );
    }
}

/// 86 base64 characters carry 516 bits; an ES256 signature is 512. The low
/// four bits of the final character are therefore unused, and a decoder that
/// discards them rather than requiring them to be zero accepts 16 spellings
/// of one signature. Exactly one must verify.
#[test]
fn only_the_canonical_spelling_of_the_signature_verifies() {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let jws = common::transaction_jws();
    let (header, payload, signature) = common::split_jws(&jws);
    let last = signature.as_bytes()[signature.len() - 1];
    let index = ALPHABET.iter().position(|c| *c == last).unwrap();
    let mut accepted = Vec::new();
    for low in 0..16 {
        let mut spelling = signature[..signature.len() - 1].to_owned();
        spelling.push(char::from(ALPHABET[(index & 0x30) | low]));
        let candidate = common::join_jws(&header, &payload, &spelling);
        if verifier().verify_signed_data(&candidate).is_ok() {
            accepted.push(spelling);
        }
    }
    assert_eq!(
        accepted.len(),
        1,
        "exactly one spelling of the final character may verify, got {accepted:?}"
    );
    assert_eq!(accepted[0], signature);
}

/// The header and payload segments are covered by the signing input, so
/// leniency there cannot change what is verified — but CONTRACT.md §2.1
/// rows 2 and 8 make "not base64url" an observable check, and a lenient
/// decoder never reaches it.
#[test]
fn a_segment_that_is_not_base64url_is_a_format_error() {
    let jws = common::transaction_jws();
    let (header, payload, signature) = common::split_jws(&jws);
    for mutated in [
        common::join_jws(&format!("{header}!"), &payload, &signature),
        common::join_jws(&format!("{header}="), &payload, &signature),
        common::join_jws(&header, &format!("{payload} "), &signature),
        common::join_jws(&header, &format!("{payload}\n"), &signature),
        common::join_jws(&header.replacen('e', "+", 1), &payload, &signature),
    ] {
        assert_eq!(reason_of(&mutated), Reason::Malformed, "{mutated}");
    }
}

// --- the signing date is read by value, not by spelling -----------------

/// `signedDate` fixes the instant the certificate chain is judged at. Read
/// with `as_i64` alone, a JSON number spelled `1.0` or `1e0` came back as
/// absent, and the chain was then judged at the clock instead: the spelling
/// of a number moving a certificate-validity verdict.
#[test]
fn a_signed_date_is_read_by_value_whatever_its_json_spelling() {
    // 1970-01-01, long before this fixture chain's notBefore, so the chain
    // is outside its window, identically for every spelling.
    for spelling in ["1", "1.0", "1e0", "1.0e0"] {
        assert_eq!(
            reason_of(&with_signed_date(spelling)),
            Reason::InvalidCertificate,
            "signedDate spelled {spelling} must judge the chain at 1970"
        );
    }
    // A number the chain *is* valid at reaches the signature check, so the
    // test above is really about the instant and not about parse failure.
    for spelling in ["1750000000000", "1.75e12"] {
        assert_eq!(
            reason_of(&with_signed_date(spelling)),
            Reason::InvalidSignature,
            "signedDate spelled {spelling} must judge the chain at 2025"
        );
    }
}

/// A `signedDate` that is not a representable instant (`1e300`, an integer
/// past `i64`), or not a number at all, counts as not stated: the clock
/// stands in for it (owner, 2026-09-27). Pinned by moving the clock: inside
/// the chain's window the input reaches the signature check, before it the
/// chain is outside its window.
#[test]
fn an_unrepresentable_signed_date_is_replaced_by_the_clock() {
    for spelling in [
        "1e300",
        "-1e300",
        "9223372036854775808",
        "\"1722945600000\"",
        "null",
    ] {
        let jws = with_signed_date(spelling);
        assert_eq!(
            common::verifier_at([common::jws_root()], INSIDE_THE_CHAIN)
                .verify_signed_data(&jws)
                .unwrap_err()
                .reason(),
            Reason::InvalidSignature,
            "signedDate {spelling} with the clock inside the chain"
        );
        assert_eq!(
            common::verifier_at([common::jws_root()], BEFORE_THE_CHAIN)
                .verify_signed_data(&jws)
                .unwrap_err()
                .reason(),
            Reason::InvalidCertificate,
            "signedDate {spelling} with the clock before the chain"
        );
    }
}

/// Splices a raw JSON value into `signedDate`, keeping every other claim.
/// The signature no longer covers the payload, which is fine: the chain
/// check runs first and is what these assertions read.
fn with_signed_date(raw_value: &str) -> String {
    let jws = common::transaction_jws();
    let (header, payload_b64, signature) = common::split_jws(&jws);
    let decoded = base64_decode_lenient(&payload_b64);
    let mut claims: serde_json::Map<String, Value> =
        serde_json::from_slice(&decoded).expect("payload is JSON");
    claims.remove("signedDate");
    let rest = serde_json::to_string(&claims).unwrap();
    let body = format!("{{\"signedDate\":{raw_value},{}", &rest[1..]);
    common::join_jws(&header, &common::base64url(body.as_bytes()), &signature)
}

/// `x5c[2]` has to BE a certificate, in every spelling of "is not one".
/// The differential this used to pin — java parsing the third entry and the
/// other eight ignoring it — is closed the other way: java's answer won,
/// because pinning acceptance would have made it drop a rejection it
/// already made. The entry is still never compared to an anchor and never
/// trusted, which is what the test above covers.
#[test]
fn the_third_x5c_entry_must_be_a_certificate() {
    let jws = common::transaction_jws();
    for entry in ["!!!!!!!!", "QUJDREVGRw", "", "not a certificate at all"] {
        let mut header = common::jws_header(&jws);
        header
            .get_mut("x5c")
            .and_then(Value::as_array_mut)
            .expect("x5c")[2] = Value::String(entry.to_owned());
        assert_eq!(
            reason_of(&common::with_header(&jws, &header)),
            Reason::InvalidCertificate,
            "x5c[2] = {entry:?} must be rejected as a certificate"
        );
    }
}

/// An `x5c` entry is standard base64 (RFC 7515 §4.1.6), which has no line
/// breaks: a PEM-style wrapped entry is not a certificate, even though
/// skipping the breaks would recover a genuine one. Java refused it first;
/// `transaction/reject-x5c-leaf-with-line-breaks` pins it for every port.
#[test]
fn x5c_entries_with_line_breaks_are_not_certificates() {
    let jws = common::transaction_jws();
    let mut header = common::jws_header(&jws);
    let x5c = header
        .get_mut("x5c")
        .and_then(Value::as_array_mut)
        .expect("x5c");
    for index in [0usize, 1] {
        let entry = x5c[index].as_str().unwrap().to_owned();
        let wrapped: String = entry
            .as_bytes()
            .chunks(64)
            .map(|line| String::from_utf8_lossy(line).into_owned())
            .collect::<Vec<_>>()
            .join("\n");
        x5c[index] = Value::String(wrapped);
    }
    // INVALID_CERTIFICATE, not the INVALID_SIGNATURE the rewritten header
    // would earn: the entries are refused before the signature is checked.
    assert_eq!(
        reason_of(&common::with_header(&jws, &header)),
        Reason::InvalidCertificate
    );
}

#[test]
fn non_ascii_claims_round_trip_as_utf8() {
    // Claims are UTF-8 on the wire (RFC 7519). The payload is handed back as
    // the exact text that was signed, so a product id or offer id carrying
    // non-ASCII text reaches the caller unchanged. The literals are escapes,
    // so this file's own encoding cannot mask the check.
    let product_id = "com.example.app.\u{e9}\u{20ac}\u{4e2d}";
    let offer = "\u{fc}ber-\u{20ac}-\u{4e2d}\u{6587}-\u{1f600}";
    let claims = json!({
        "productId": product_id,
        "offerIdentifier": offer,
        "signedDate": INSIDE_THE_CHAIN,
    })
    .to_string();
    let (root, jws) = common::mint::signed_jws(claims.as_bytes());
    let verifier = common::verifier_at(
        [apple_purchase_receipt_verifier::TrustAnchor::from_der(&root).unwrap()],
        INSIDE_THE_CHAIN,
    );
    let payload = verifier.verify_signed_data(&jws).unwrap();
    assert_eq!(payload.json(), claims);
    let parsed = common::claims(&payload);
    assert_eq!(parsed["productId"], product_id);
    assert_eq!(parsed["offerIdentifier"], offer);
}

#[test]
fn attacker_text_never_reaches_a_failure_message() {
    // A failure message is what a caller logs. No message quotes the input,
    // so a header crafted to forge a log line (a line break, a Unicode line
    // separator, NEL, an ANSI escape) cannot reach one, whatever check refuses
    // it.
    let hostile = "ES256\r\n2026-01-01 INFO forged\u{85}\u{2028}\u{1b}[2J";
    let mut header = common::jws_header(&common::transaction_jws());
    header.insert("alg".to_owned(), Value::from(hostile));
    let failure = expect_err(&common::with_header(&common::transaction_jws(), &header));
    let mut x5c_header = common::jws_header(&common::transaction_jws());
    x5c_header.insert("x5c".to_owned(), json!([hostile, hostile, hostile]));
    let x5c_failure = expect_err(&common::with_header(
        &common::transaction_jws(),
        &x5c_header,
    ));
    for failure in [failure, x5c_failure] {
        let text = failure.to_string();
        assert!(!text.contains("forged"), "{text}");
        assert!(
            !text.chars().any(|c| c.is_control() || c == '\u{2028}'),
            "{text:?}"
        );
    }
}

/// An EC SPKI on secp521r1, a curve this crate does not implement.
fn p521_spki() -> Vec<u8> {
    let mut bits = vec![0x00, 0x04];
    bits.extend_from_slice(&[0x11; 132]);
    common::der_seq(&[
        common::der_seq(&[
            common::der_oid("1.2.840.10045.2.1"),
            common::der_oid("1.3.132.0.35"),
        ]),
        common::der(0x03, &bits),
    ])
}

/// A curve is judged only on a key about to be used, after a pinned anchor
/// vouched for it: never on the unused third entry, and on an intermediate
/// no anchor signed it is the chain, not the certificate, that fails.
#[test]
fn an_unimplemented_curve_is_judged_only_on_a_vouched_key() {
    let stranger = common::mint::key(9);
    let p521 = |marker| {
        base64_encode(&common::mint::certificate_for_spki(
            "Stranger P-521",
            p521_spki(),
            "Stranger CA",
            &stranger,
            7,
            true,
            marker,
        ))
    };
    // A minted chain whose third entry is on P-521, signed as it stands.
    use common::mint::{certificate, key, RECEIPT_SIGNER_MARKER, WWDR_MARKER};
    use p256::ecdsa::signature::Signer;
    let (root_key, intermediate_key, leaf_key) = (key(11), key(12), key(13));
    let root = certificate("JWS Root", &root_key, "JWS Root", &root_key, 1, true, None);
    let intermediate = certificate(
        "JWS WWDR",
        &intermediate_key,
        "JWS Root",
        &root_key,
        2,
        true,
        Some(WWDR_MARKER),
    );
    let leaf = certificate(
        "JWS Leaf",
        &leaf_key,
        "JWS WWDR",
        &intermediate_key,
        3,
        false,
        Some(RECEIPT_SIGNER_MARKER),
    );
    let header = format!(
        r#"{{"alg":"ES256","x5c":["{}","{}","{}"]}}"#,
        base64_encode(&leaf),
        base64_encode(&intermediate),
        p521(None)
    );
    let signing_input = format!(
        "{}.{}",
        common::base64url(header.as_bytes()),
        common::base64url(br#"{"signedDate":1735689600000}"#)
    );
    let signature: p256::ecdsa::Signature = leaf_key.sign(signing_input.as_bytes());
    let minted = format!(
        "{signing_input}.{}",
        common::base64url(&signature.to_bytes())
    );
    let pinned = common::verifier([TrustAnchor::from_der(&root).unwrap()]);
    assert!(pinned.verify_signed_data(&minted).is_ok());

    // The shared transaction with an unvouched P-521 intermediate.
    let jws = common::transaction_jws();
    let mut header = common::jws_header(&jws);
    let mut entries = header.get("x5c").unwrap().as_array().unwrap().clone();
    entries[1] = json!(p521(Some(common::mint::WWDR_MARKER)));
    header.insert("x5c".to_owned(), Value::Array(entries));
    assert_eq!(
        reason_of(&common::with_header(&jws, &header)),
        Reason::UntrustedChain
    );
}
