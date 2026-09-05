//! JWS rejections: every shape the format check, the certificate checks and
//! the signature check must refuse, and the exact reason each gets.
//!
//! The order of the checks is observable. `cases.json` pins the order at the
//! level of whole vectors; these tests pin it at the level of one fault at a
//! time, including the faults no shared vector covers.

mod common;

use apple_purchase_receipt_verifier::{
    base64, x509::Certificate, Environment, FixedClock, JwsVerifier, Reason, VerificationError,
};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

fn verifier() -> JwsVerifier {
    JwsVerifier::builder()
        .trusted_roots([common::jws_root()])
        .bundle_id("com.example.app")
        .accepted_environments([Environment::Sandbox])
        .build()
        .unwrap()
}

fn reason_of(jws: &str) -> Reason {
    verifier().verify_transaction(jws).unwrap_err().reason()
}

fn expect_err(jws: &str) -> VerificationError {
    verifier().verify_transaction(jws).unwrap_err()
}

#[test]
fn the_shared_transaction_verifies() {
    let payload = verifier()
        .verify_transaction(&common::transaction_jws())
        .unwrap();
    assert_eq!(payload.product_id.as_deref(), Some("com.example.app.pro"));
}

#[test]
fn an_empty_string_is_not_a_jws() {
    assert_eq!(reason_of(""), Reason::InvalidJwsFormat);
}

#[test]
fn two_segments_are_rejected() {
    let (header, payload, _) = common::split_jws(&common::transaction_jws());
    assert_eq!(
        reason_of(&format!("{header}.{payload}")),
        Reason::InvalidJwsFormat
    );
}

#[test]
fn four_segments_are_rejected() {
    let jws = common::transaction_jws();
    assert_eq!(reason_of(&format!("{jws}.extra")), Reason::InvalidJwsFormat);
}

#[test]
fn a_header_that_is_not_json_is_rejected() {
    let (_, payload, signature) = common::split_jws(&common::transaction_jws());
    let header = common::base64url(b"not json at all");
    assert_eq!(
        reason_of(&common::join_jws(&header, &payload, &signature)),
        Reason::InvalidJwsFormat
    );
}

#[test]
fn a_header_that_is_a_json_array_is_rejected() {
    let (_, payload, signature) = common::split_jws(&common::transaction_jws());
    let header = common::base64url(b"[1,2,3]");
    assert_eq!(
        reason_of(&common::join_jws(&header, &payload, &signature)),
        Reason::InvalidJwsFormat
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
            Reason::InvalidJwsFormat,
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
        Reason::InvalidJwsFormat
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
        Reason::InvalidJwsFormat
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
            Reason::InvalidJwsFormat,
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
        Reason::InvalidJwsFormat
    );

    let mut header = common::jws_header(&jws);
    header.insert("x5c".to_owned(), json!([1, 2, 3]));
    assert_eq!(
        reason_of(&common::with_header(&jws, &header)),
        Reason::InvalidJwsFormat
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
    let der = base64::decode_lenient(leaf);
    assert!(Certificate::from_der(&der).is_err());

    let verifier = JwsVerifier::builder()
        .trusted_roots([common::anchor("generated/hostile-jws-root.der")])
        .bundle_id("com.example.app")
        .accepted_environments([Environment::Sandbox])
        .build()
        .unwrap();
    assert_eq!(
        verifier.verify_transaction(&jws).unwrap_err().reason(),
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

#[test]
fn a_payload_that_is_not_json_reports_a_format_error_not_a_signature_error() {
    let (header, _, signature) = common::split_jws(&common::transaction_jws());
    let payload = common::base64url(b"\xff\xfe not json");
    assert_eq!(
        reason_of(&common::join_jws(&header, &payload, &signature)),
        Reason::InvalidJwsFormat
    );
}

#[test]
fn a_payload_that_is_a_json_scalar_is_rejected() {
    let (header, _, signature) = common::split_jws(&common::transaction_jws());
    for body in ["42", "\"text\"", "null", "[]"] {
        let payload = common::base64url(body.as_bytes());
        assert_eq!(
            reason_of(&common::join_jws(&header, &payload, &signature)),
            Reason::InvalidJwsFormat,
            "payload {body}"
        );
    }
}

#[test]
fn a_signature_of_the_wrong_length_is_rejected() {
    let (header, payload, signature) = common::split_jws(&common::transaction_jws());
    let raw = apple_purchase_receipt_verifier::base64::decode_lenient(&signature);
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
    let raw = apple_purchase_receipt_verifier::base64::decode_lenient(&signature);
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
    let decoded = apple_purchase_receipt_verifier::base64::decode_lenient(&payload);
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
fn a_foreign_root_is_an_invalid_chain_not_a_purpose_error() {
    let verifier = JwsVerifier::builder()
        .trusted_roots(
            apple_purchase_receipt_verifier::apple_jws_roots()
                .iter()
                .cloned(),
        )
        .bundle_id("com.example.app")
        .accepted_environments([Environment::Sandbox])
        .build()
        .unwrap();
    let error = verifier
        .verify_transaction(&common::transaction_jws())
        .unwrap_err();
    assert_eq!(error.reason(), Reason::InvalidChain);
}

#[test]
fn marker_oids_are_checked_before_the_chain() {
    // Both fixtures chain correctly to their own root: if the marker check
    // ran after the chain walk, these would pass instead of reporting a
    // purpose error.
    let leaf = JwsVerifier::builder()
        .trusted_roots([common::anchor("generated/jws-no-leaf-oid-root.der")])
        .bundle_id("com.example.app")
        .accepted_environments([Environment::Sandbox])
        .build()
        .unwrap();
    assert_eq!(
        leaf.verify_transaction(&common::read_text_fixture(
            "generated/transaction-no-leaf-oid.jws"
        ))
        .unwrap_err()
        .reason(),
        Reason::InvalidCertificatePurpose
    );

    let intermediate = JwsVerifier::builder()
        .trusted_roots([common::anchor("generated/jws-no-intermediate-oid-root.der")])
        .bundle_id("com.example.app")
        .accepted_environments([Environment::Sandbox])
        .build()
        .unwrap();
    assert_eq!(
        intermediate
            .verify_transaction(&common::read_text_fixture(
                "generated/transaction-no-intermediate-oid.jws"
            ))
            .unwrap_err()
            .reason(),
        Reason::InvalidCertificatePurpose
    );
}

#[test]
fn the_staleness_boundary_is_inclusive() {
    let signed_at = 1_722_945_600_000i64;
    let build = |now: i64| {
        JwsVerifier::builder()
            .trusted_roots([common::jws_root()])
            .bundle_id("com.example.app")
            .accepted_environments([Environment::Sandbox])
            .max_signed_age(Duration::from_secs(60))
            .clock(Arc::new(FixedClock::from_unix_millis(now)))
            .build()
            .unwrap()
    };
    let jws = common::transaction_jws();
    // Exactly at the limit passes; one millisecond past does not.
    assert!(build(signed_at + 60_000).verify_transaction(&jws).is_ok());
    assert_eq!(
        build(signed_at + 60_001)
            .verify_transaction(&jws)
            .unwrap_err()
            .reason(),
        Reason::StalePayload
    );
    // A clock behind the signing date is never stale.
    assert!(build(signed_at - 86_400_000)
        .verify_transaction(&jws)
        .is_ok());
}

#[test]
fn without_max_signed_age_no_payload_is_ever_stale() {
    let verifier = JwsVerifier::builder()
        .trusted_roots([common::jws_root()])
        .bundle_id("com.example.app")
        .accepted_environments([Environment::Sandbox])
        .clock(Arc::new(FixedClock::from_unix_millis(4_070_908_800_000)))
        .build()
        .unwrap();
    assert!(verifier
        .verify_transaction(&common::transaction_jws())
        .is_ok());
}

#[test]
fn an_injected_clock_cannot_move_a_chain_verdict() {
    // The historical payload's chain is expired today and was valid when it
    // was signed. Neither a clock inside the window nor one far outside it
    // may change either verdict — the chain instant comes from the payload.
    let build = |now: i64| {
        JwsVerifier::builder()
            .trusted_roots([common::anchor("generated/jws-expired-root.der")])
            .bundle_id("com.example.app")
            .accepted_environments([Environment::Sandbox])
            .clock(Arc::new(FixedClock::from_unix_millis(now)))
            .build()
            .unwrap()
    };
    let historical = common::read_text_fixture("generated/expired-cert-historical.jws");
    let fresh = common::read_text_fixture("generated/expired-cert-fresh.jws");
    for now in [0i64, 1_590_969_600_000, 4_070_908_800_000] {
        assert!(
            build(now).verify_transaction(&historical).is_ok(),
            "historical at {now}"
        );
        assert_eq!(
            build(now).verify_transaction(&fresh).unwrap_err().reason(),
            Reason::InvalidChain,
            "fresh at {now}"
        );
    }
}

#[test]
fn claim_checks_run_bundle_id_before_environment() {
    // A payload that is wrong on both must report the bundle id.
    let verifier = JwsVerifier::builder()
        .trusted_roots([common::jws_root()])
        .bundle_id("com.other.app")
        .accepted_environments([Environment::Production])
        .build()
        .unwrap();
    assert_eq!(
        verifier
            .verify_transaction(&common::transaction_jws())
            .unwrap_err()
            .reason(),
        Reason::WrongBundleId
    );
}

#[test]
fn an_unknown_environment_claim_is_wrong_environment() {
    let verifier = JwsVerifier::builder()
        .trusted_roots([common::jws_root()])
        .bundle_id("com.example.app")
        .accepted_environments([
            Environment::Production,
            Environment::Xcode,
            Environment::LocalTesting,
        ])
        .build()
        .unwrap();
    assert_eq!(
        verifier
            .verify_transaction(&common::transaction_jws())
            .unwrap_err()
            .reason(),
        Reason::WrongEnvironment
    );
}

#[test]
fn a_production_app_transaction_needs_the_configured_apple_id() {
    let build = |app_apple_id: Option<u64>| {
        let mut builder = JwsVerifier::builder()
            .trusted_roots([common::jws_root()])
            .bundle_id("com.example.app")
            .accepted_environments([Environment::Production]);
        if let Some(id) = app_apple_id {
            builder = builder.app_apple_id(id);
        }
        builder.build().unwrap()
    };
    let jws = common::read_text_fixture("generated/app-transaction-production.jws");
    assert!(build(Some(123_456_789))
        .verify_app_transaction(&jws)
        .is_ok());
    assert_eq!(
        build(Some(999))
            .verify_app_transaction(&jws)
            .unwrap_err()
            .reason(),
        Reason::WrongAppAppleId
    );
    // Unset is a rejection, not a skip: an unconfigured verifier must not
    // accept a Production AppTransaction.
    assert_eq!(
        build(None)
            .verify_app_transaction(&jws)
            .unwrap_err()
            .reason(),
        Reason::WrongAppAppleId
    );
}

#[test]
fn verify_raw_enforces_no_claim_but_still_enforces_the_signature() {
    let verifier = JwsVerifier::builder()
        .trusted_roots([common::jws_root()])
        .bundle_id("conformance.unset.bundle.id")
        .accepted_environments([Environment::LocalTesting])
        .build()
        .unwrap();
    let claims = verifier.verify_raw(&common::transaction_jws()).unwrap();
    assert_eq!(claims.get("bundleId").unwrap(), "com.example.app");

    let (header, payload, signature) = common::split_jws(&common::transaction_jws());
    let mut broken = apple_purchase_receipt_verifier::base64::decode_lenient(&signature);
    broken[0] ^= 0xff;
    let error = verifier
        .verify_raw(&common::join_jws(
            &header,
            &payload,
            &common::base64url(&broken),
        ))
        .unwrap_err();
    assert_eq!(error.reason(), Reason::InvalidSignature);
}

#[test]
fn verify_raw_still_enforces_staleness() {
    let verifier = JwsVerifier::builder()
        .trusted_roots([common::jws_root()])
        .bundle_id("conformance.unset.bundle.id")
        .accepted_environments([Environment::LocalTesting])
        .max_signed_age(Duration::from_secs(60))
        .clock(Arc::new(FixedClock::from_unix_millis(1_735_689_600_000)))
        .build()
        .unwrap();
    assert_eq!(
        verifier
            .verify_raw(&common::transaction_jws())
            .unwrap_err()
            .reason(),
        Reason::StalePayload
    );
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
    assert!(verifier().verify_transaction(&jws).is_ok(), "baseline");
    // A malformed segment is a format failure, decided before any
    // cryptography runs — the same class as a header that is not base64url
    // JSON — not a cryptographic verdict on a signature that was actually
    // checked.
    for suffix in ["=", "==", "!!!!", "\n", " ", "~~~", "\t", "AAAA!"] {
        let mutated = format!("{jws}{suffix}");
        assert_eq!(
            reason_of(&mutated),
            Reason::InvalidJwsFormat,
            "signature segment + {suffix:?} must not verify"
        );
    }
    // Interleaved, not only appended.
    let (header, payload, signature) = common::split_jws(&jws);
    let spaced: String = signature.chars().flat_map(|c| [c, '\n']).collect();
    assert_eq!(
        reason_of(&common::join_jws(&header, &payload, &spaced)),
        Reason::InvalidJwsFormat
    );
    // The standard alphabet is not the URL alphabet.
    let plus = signature.replacen('A', "+", 1);
    if plus != signature {
        assert_eq!(
            reason_of(&common::join_jws(&header, &payload, &plus)),
            Reason::InvalidJwsFormat
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
        if verifier().verify_transaction(&candidate).is_ok() {
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
        assert_eq!(reason_of(&mutated), Reason::InvalidJwsFormat, "{mutated}");
    }
}

// --- date claims are read by value, not by spelling ---------------------

/// `signedDate` fixes the instant the certificate chain is judged at. Read
/// with `as_i64` alone, a JSON number spelled `1.0` or `1e0` came back as
/// *absent*, and the chain was then judged at the system clock instead —
/// the spelling of a number moving a certificate-validity verdict. All four
/// shipped ports read the value: Java `canConvertToLong()`, Node
/// `typeof === 'number'`, Python `isinstance(x, (int, float))`, Swift
/// `as? Double`.
#[test]
fn a_signed_date_is_read_by_value_whatever_its_json_spelling() {
    // 1970-01-01, long before this fixture chain's notBefore, so the chain
    // check fails — and it must fail identically for all three spellings.
    for spelling in ["1", "1.0", "1e0", "1.0e0"] {
        assert_eq!(
            reason_of(&with_signed_date(spelling)),
            Reason::InvalidChain,
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

/// Splices a raw JSON number into `signedDate`, keeping every other claim.
/// The signature no longer covers the payload, which is fine: the chain
/// check runs first and is what these assertions read.
fn with_signed_date(raw_number: &str) -> String {
    let jws = common::transaction_jws();
    let (header, payload_b64, signature) = common::split_jws(&jws);
    let decoded = apple_purchase_receipt_verifier::base64::decode_lenient(&payload_b64);
    let mut claims: serde_json::Map<String, Value> =
        serde_json::from_slice(&decoded).expect("payload is JSON");
    claims.remove("signedDate");
    let rest = serde_json::to_string(&claims).unwrap();
    let body = format!("{{\"signedDate\":{raw_number},{}", &rest[1..]);
    common::join_jws(&header, &common::base64url(body.as_bytes()), &signature)
}

/// `expiresDate` and `revocationDate` go through the same helper, and the
/// failure there is an entitlement decision: a `None` expiry means "never
/// expires" and a `None` revocation means "not revoked", so a float-spelled
/// claim used to report a refunded or lapsed transaction as still active.
#[test]
fn is_active_at_reads_float_spelled_dates() {
    use apple_purchase_receipt_verifier::TransactionPayload;
    use std::time::{Duration, UNIX_EPOCH};

    let now = UNIX_EPOCH + Duration::from_millis(1_700_000_000_000);
    for spelling in ["1690000000000", "1.69e12", "1690000000000.0"] {
        let payload: TransactionPayload = payload_from(&format!("{{\"expiresDate\":{spelling}}}"));
        assert!(
            !payload.is_active_at(now),
            "an expiry spelled {spelling} must expire"
        );
        let payload: TransactionPayload =
            payload_from(&format!("{{\"revocationDate\":{spelling}}}"));
        assert!(
            !payload.is_active_at(now),
            "a revocation spelled {spelling} must revoke"
        );
    }
    // The claim genuinely absent still means "never expires".
    assert!(payload_from("{}").is_active_at(now));
}

/// The modelled view of a claim set — the same construction the verifier
/// runs after the signature check, reached through the public
/// `from_claims`, so the date-reading helper under test is the same one.
fn payload_from(json: &str) -> apple_purchase_receipt_verifier::TransactionPayload {
    let claims: serde_json::Map<String, Value> = serde_json::from_str(json).unwrap();
    apple_purchase_receipt_verifier::TransactionPayload::from_claims(claims)
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

/// The asymmetry is deliberate: `x5c` entries are certificate containers,
/// decoded the way Java's MIME decoder and Swift's `.ignoreUnknownCharacters`
/// decode them, so line breaks and padding in one are not a rejection. Only
/// the three JWS segments are strict.
#[test]
fn x5c_entries_are_still_decoded_leniently() {
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
    // Still only INVALID_SIGNATURE — the rewritten header breaks the signing
    // input — which means both certificates parsed, carried their marker
    // OIDs and chained to the anchor.
    assert_eq!(
        reason_of(&common::with_header(&jws, &header)),
        Reason::InvalidSignature
    );
}
