//! Receipt rejections, one structural fault at a time.
//!
//! Most of these are built by taking the shared generated receipt apart with
//! the tests' own CMS reader and putting it back together with exactly one
//! thing changed — so the fault under test is the only difference, and a
//! test that stops failing because something else broke first is visible.

mod common;

use apple_purchase_receipt_verifier::__internal::base64_encode;
use apple_purchase_receipt_verifier::{Failure, Reason, ReceiptPayload, TrustAnchor, Verifier};
use asn1_rs::Oid;
use common::ber::parse_exact;
use common::cms::parse_cms;
use common::tag;

/// A verifier pinned to one root, taking DER for this file's rebuilt blobs.
struct DerVerifier(Verifier);

impl DerVerifier {
    fn verify(&self, der: &[u8]) -> Result<ReceiptPayload, Failure> {
        common::verify_der(&self.0, der)
    }
}

fn verifier_with(anchor: TrustAnchor) -> DerVerifier {
    DerVerifier(common::verifier([anchor]))
}

fn verifier() -> DerVerifier {
    verifier_with(common::receipt_root())
}

fn reason_of(bytes: &[u8]) -> Reason {
    verifier().verify(bytes).unwrap_err().reason()
}

#[test]
fn the_rebuilt_receipt_is_still_a_valid_receipt() {
    // The baseline the rest of this file depends on: taking the shared
    // receipt apart and putting it back together changes no verdict.
    let rebuilt = common::CmsBuilder::from_shared().build();
    let receipt = verifier().verify(&rebuilt).unwrap();
    assert_eq!(receipt.bundle_id.as_deref(), Some("com.example.app"));
    assert_eq!(receipt.in_app.len(), 2);
}

#[test]
fn an_empty_receipt_is_rejected() {
    assert_eq!(reason_of(&[]), Reason::Malformed);
}

#[test]
fn trailing_bytes_after_the_cms_blob_are_rejected() {
    // Accepting them would let an attacker append to a genuine receipt and
    // have it verify anyway.
    let mut der = common::receipt_der();
    der.push(0x00);
    assert_eq!(reason_of(&der), Reason::Malformed);

    let mut der = common::receipt_der();
    der.extend_from_slice(&[0x30, 0x03, 0x02, 0x01, 0x01]);
    assert_eq!(reason_of(&der), Reason::Malformed);
}

#[test]
fn a_truncated_receipt_is_rejected() {
    let der = common::receipt_der();
    for fraction in [2usize, 3, 4, 8, 16, 64] {
        let cut = der.len() / fraction;
        assert_eq!(
            reason_of(&der[..cut]),
            Reason::Malformed,
            "truncated to {cut} bytes"
        );
    }
}

#[test]
fn a_sequence_that_is_not_a_cms_is_rejected() {
    let not_cms = common::der_seq(&[common::der_int(1), common::der_int(2)]);
    assert_eq!(reason_of(&not_cms), Reason::Malformed);
}

#[test]
fn a_truncated_sequence_header_is_rejected() {
    assert_eq!(reason_of(&[0x30]), Reason::Malformed);
    assert_eq!(reason_of(&[0x30, 0x82]), Reason::Malformed);
    assert_eq!(reason_of(&[0x30, 0x82, 0xff]), Reason::Malformed);
}

#[test]
fn a_receipt_with_no_encapsulated_content_is_rejected() {
    let mut builder = common::CmsBuilder::from_shared();
    builder.content = None;
    assert_eq!(reason_of(&builder.build()), Reason::Malformed);
}

#[test]
fn content_that_is_not_an_octet_string_is_rejected() {
    let mut builder = common::CmsBuilder::from_shared();
    builder.content_as_sequence = true;
    assert_eq!(reason_of(&builder.build()), Reason::Malformed);
}

#[test]
fn a_receipt_with_no_signer_info_is_rejected() {
    let mut builder = common::CmsBuilder::from_shared();
    builder.include_signer_info = false;
    assert_eq!(reason_of(&builder.build()), Reason::Malformed);
}

#[test]
fn a_signer_named_by_an_unembedded_issuer_and_serial_is_rejected() {
    let mut builder = common::CmsBuilder::from_shared();
    builder.signer_serial = vec![0x7f, 0x7f, 0x7f, 0x7f];
    assert_eq!(reason_of(&builder.build()), Reason::Malformed);

    let mut builder = common::CmsBuilder::from_shared();
    builder.signer_issuer = common::der_seq(&[]);
    assert_eq!(reason_of(&builder.build()), Reason::Malformed);
}

#[test]
fn a_relabelled_digest_algorithm_fails_as_a_signature() {
    // No digest allowlist: whatever Apple signs with is accepted, as Java
    // accepts any signer algorithm (#160). Relabelling the digest of a
    // genuine signature cannot help an attacker: the messageDigest attribute
    // and the RSA DigestInfo both bind the real one.
    let builder = common::CmsBuilder::from_shared().with_sha512_digest();
    assert_eq!(reason_of(&builder.build()), Reason::InvalidSignature);
}

#[test]
fn more_than_ten_embedded_certificates_is_malformed() {
    let mut builder = common::CmsBuilder::from_shared();
    let original = builder.certificates.clone();
    while builder.certificates.len() <= 10 {
        builder.certificates.push(original[0].clone());
    }
    assert_eq!(builder.certificates.len(), 11);
    assert_eq!(reason_of(&builder.build()), Reason::Malformed);

    // Exactly ten is still accepted structurally — the bound is on parsing,
    // not on the walk, and it must not move the genuine case.
    let mut builder = common::CmsBuilder::from_shared();
    let original = builder.certificates.clone();
    while builder.certificates.len() < 10 {
        builder.certificates.push(original[0].clone());
    }
    assert!(verifier().verify(&builder.build()).is_ok());
}

#[test]
fn a_copy_of_the_signer_identity_ahead_of_the_signer_does_not_decide_the_verdict() {
    // The bag is unsigned, so anyone relaying a receipt can put a second
    // certificate with the signer's issuer and serial in front of the real
    // one. Taking the first match would fail a genuine receipt on it.
    let mut builder = common::CmsBuilder::from_shared();
    let signer = builder
        .certificates
        .iter()
        .position(|raw| {
            common::certificate_identity(raw)
                == Some((builder.signer_serial.clone(), builder.signer_issuer.clone()))
        })
        .expect("the shared receipt embeds its signer");
    // Same identity, a signature no issuer made: it decodes, and nothing
    // vouches for it.
    let mut copy = builder.certificates[signer].clone();
    *copy.last_mut().unwrap() ^= 0x01;
    assert!(TrustAnchor::from_der(&copy).is_ok());
    builder.certificates.insert(0, copy);
    assert!(verifier().verify(&builder.build()).is_ok());
}

#[test]
fn an_unparseable_embedded_certificate_is_rejected() {
    let mut builder = common::CmsBuilder::from_shared();
    builder
        .certificates
        .push(common::der_seq(&[common::der_int(1)]));
    assert_eq!(reason_of(&builder.build()), Reason::Malformed);
}

#[test]
fn a_message_digest_that_does_not_match_the_content_is_an_invalid_signature() {
    let mut builder = common::CmsBuilder::from_shared();
    assert!(
        builder.signed_attrs.is_some(),
        "the shared receipt carries signedAttrs"
    );
    let mut content = builder.content.clone().unwrap();
    // Flip a byte inside an in-app product id: the payload still parses,
    // so the failure has to come from the digest, not from the grammar.
    let needle = b"com.example.app.vip";
    let position = content
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("the shared receipt names the product");
    content[position] = b'C';
    builder.content = Some(content);
    assert_eq!(reason_of(&builder.build()), Reason::InvalidSignature);
}

#[test]
fn a_tampered_signature_is_an_invalid_signature() {
    let mut builder = common::CmsBuilder::from_shared();
    builder.signature[0] ^= 0xff;
    assert_eq!(reason_of(&builder.build()), Reason::InvalidSignature);
}

#[test]
fn a_signature_of_the_wrong_length_is_an_invalid_signature() {
    for length in [0usize, 1, 128, 255, 257] {
        let mut builder = common::CmsBuilder::from_shared();
        builder.signature = vec![0x41; length];
        assert_eq!(
            reason_of(&builder.build()),
            Reason::InvalidSignature,
            "signature of {length} bytes"
        );
    }
}

#[test]
fn a_foreign_root_is_an_untrusted_chain_and_not_a_purpose_error() {
    // The signer of receipt-foreign carries the marker OID, so a port that
    // checked the OID before the chain would report the wrong reason here.
    let der = common::read_fixture("generated-0.7/receipt-foreign.der");
    assert_eq!(reason_of(&der), Reason::UntrustedChain);
}

#[test]
fn a_signer_without_the_receipt_marker_oid_is_a_purpose_error() {
    let verifier = verifier_with(common::anchor(
        "generated-0.7/receipt-no-signer-oid-root.der",
    ));
    let der = common::read_fixture("generated-0.7/receipt-no-signer-oid.der");
    assert_eq!(
        verifier.verify(&der).unwrap_err().reason(),
        Reason::InvalidCertificatePurpose
    );
}

#[test]
fn chain_validity_is_judged_at_the_receipts_own_creation_date() {
    let verifier = verifier_with(common::anchor("generated-0.7/receipt-expired-root.der"));
    let historical = common::read_fixture("generated-0.7/receipt-expired-historical.der");
    let fresh = common::read_fixture("generated-0.7/receipt-expired-fresh.der");
    // Valid when it was signed, expired now: still accepted.
    assert!(verifier.verify(&historical).is_ok());
    // Claims to have been created after the chain expired: a certificate
    // outside its validity window (owner, 2026-09-27).
    assert_eq!(
        verifier.verify(&fresh).unwrap_err().reason(),
        Reason::InvalidCertificate
    );
}

/// Validity before the signature (owner, 2026-09-27, Q22): a receipt whose
/// chain is outside its window at the creation date is INVALID_CERTIFICATE
/// even when its signature is also broken.
#[test]
fn an_expired_chain_outranks_a_broken_signature() {
    let verifier = verifier_with(common::anchor("generated-0.7/receipt-expired-root.der"));
    let mut fresh = common::read_fixture("generated-0.7/receipt-expired-fresh.der");
    flip_a_signature_byte(&mut fresh);
    assert_eq!(
        verifier.verify(&fresh).unwrap_err().reason(),
        Reason::InvalidCertificate
    );
    // The control: the same flip inside the window is the signature.
    let mut historical = common::read_fixture("generated-0.7/receipt-expired-historical.der");
    flip_a_signature_byte(&mut historical);
    assert_eq!(
        verifier.verify(&historical).unwrap_err().reason(),
        Reason::InvalidSignature
    );
}

/// Flips a byte in the middle of the first SignerInfo's signature, found by
/// its bytes in the blob.
fn flip_a_signature_byte(der: &mut [u8]) {
    let signature = parse_cms(der).unwrap().signer_infos[0].signature.clone();
    let at = der
        .windows(signature.len())
        .position(|window| window == signature.as_slice())
        .unwrap();
    der[at + signature.len() / 2] ^= 0x01;
}

#[test]
fn a_receipt_stripped_of_its_device_hash_attribute_is_never_accepted() {
    // No generated fixture lacks attribute 5, and one cannot be forged: the
    // signature covers the payload, so removing an attribute breaks it. That
    // is the property worth pinning — a receipt that lost the attributes the
    // device check needs cannot be verified at all, let alone bound to a
    // device.
    let parts = common::receipt_parts();
    let mut builder = common::CmsBuilder::from_shared();
    builder.content = Some(strip_attribute(&parts.content, 5));
    builder.signed_attrs = None;
    let error = verifier().verify(&builder.build());
    assert_eq!(error.unwrap_err().reason(), Reason::InvalidSignature);
}

/// Removes every attribute of one type from a receipt payload, re-encoding
/// the SET around the remaining attributes.
fn strip_attribute(content: &[u8], attribute_type: u64) -> Vec<u8> {
    let node = parse_exact(content).unwrap();
    let kept: Vec<Vec<u8>> = node
        .children()
        .iter()
        .filter(|child| {
            let type_node = child.children().first().unwrap();
            let mut value = 0u64;
            for byte in type_node.contents {
                value = value * 256 + u64::from(*byte);
            }
            value != attribute_type
        })
        .map(|child| child.full.to_vec())
        .collect();
    common::der(tag::SET, &kept.concat())
}

#[test]
fn an_attribute_type_above_the_signed_32_bit_range_is_an_unreadable_payload() {
    use std::error::Error as _;
    let der = common::read_fixture("generated-0.7/receipt-attribute-type-overflow.der");
    let verifier = verifier_with(common::anchor("generated-0.7/divergence-receipt-root.der"));
    // Trusted chain and valid signature, so the full parse is where the type
    // is refused, and a trusted signer's unreadable content is
    // UNREADABLE_PAYLOAD, with the parser's error as its source.
    let error = verifier.verify(&der).unwrap_err();
    assert_eq!(
        error.reason(),
        Reason::UnreadablePayload,
        "fail closed: never clamp such a type onto a sentinel"
    );
    let source = error.source().expect("the parser's error").to_string();
    assert!(source.contains("type out of range"), "{source}");
}

#[test]
fn a_receipt_with_no_creation_date_still_verifies() {
    let verifier = verifier_with(common::anchor("generated-0.7/divergence-receipt-root.der"));
    let receipt = verifier.verify(&common::read_fixture(
        "generated-0.7/receipt-no-creation-date.der",
    ));
    let receipt = receipt.unwrap();
    assert!(receipt.receipt_creation_date_ms.is_none());
    assert_eq!(receipt.bundle_id.as_deref(), Some("com.example.app"));
}

#[test]
fn a_double_wrapped_payload_is_unwrapped_once() {
    let der = common::read_fixture("generated-0.7/receipt-double-wrapped.der");
    let receipt = verifier().verify(&der).unwrap();
    assert_eq!(receipt.in_app.len(), 2);
    assert_eq!(receipt.application_version.as_deref(), Some("1.2.3"));
}

#[test]
fn unmodelled_attributes_are_exposed_verbatim() {
    let receipt = verifier().verify(&common::receipt_der()).unwrap();
    let values = receipt
        .unknown_attributes
        .get(&9999)
        .expect("type 9999 is present");
    assert_eq!(values.len(), 1);
    assert_eq!(values[0], vec![0x01, 0x02, 0x03]);
    // Forward compatibility means the raw bytes, not a decoded guess: the
    // value is exactly the octet-string contents, undecoded.
    assert_eq!(
        receipt.unknown_attributes.len(),
        1,
        "only type 9999 is unmodelled here"
    );
    // Attribute 18 IS modelled, so it must not appear as unknown.
    assert!(!receipt.unknown_attributes.contains_key(&18));
    assert!(receipt.original_purchase_date_ms.is_some());
}

/// The receipt-ids fixture carries attributes 1, 15, 16 and 1713 under its
/// own root, because the shared generator mints fresh keys on every run and
/// nothing new can chain to `receipt-root.der`.
fn receipt_ids_receipt() -> ReceiptPayload {
    verifier_with(common::anchor("generated-0.7/receipt-ids-root.der"))
        .verify(&common::read_fixture("generated-0.7/receipt-ids.der"))
        .expect("the receipt-ids fixture must verify")
}

#[test]
fn the_legacy_ids_are_decoded_with_every_digit() {
    let receipt = receipt_ids_receipt();
    assert_eq!(receipt.app_item_id, Some(1_234_567_890));
    assert_eq!(receipt.version_external_identifier, Some(456_789_012));
    // 2^63 - 1: a nineteen-digit, eight-byte integer an IEEE-754 double
    // rounds to 2^63, which is why the fixture carries it. A port that
    // rounds answers …808 here, and real download ids run to eighteen
    // digits. 2^63 itself has no `i64` representation — it is one past
    // `i64::MAX` — so the string form is what a rounded port would get
    // wrong; the typed field cannot even hold the rounded value.
    assert_eq!(receipt.download_id, Some(9_223_372_036_854_775_807));
    assert_eq!(
        receipt.download_id.unwrap().to_string(),
        "9223372036854775807"
    );
    assert_ne!(
        receipt.download_id.unwrap().to_string(),
        "9223372036854775808"
    );
}

#[test]
fn is_trial_period_is_read_on_both_sides_of_the_boolean() {
    let receipt = receipt_ids_receipt();
    let by_product = |product_id: &str| common::purchase(&receipt, product_id).is_trial_period;
    assert_eq!(by_product("com.example.app.coins100"), Some(false));
    assert_eq!(by_product("com.example.app.vip"), Some(true));
}

#[test]
fn the_four_modelled_ids_leave_the_unknown_attribute_map() {
    let receipt = receipt_ids_receipt();
    for attribute_type in [1u32, 15, 16] {
        assert!(
            !receipt.unknown_attributes.contains_key(&attribute_type),
            "attribute {attribute_type} is modelled now"
        );
    }
    for purchase in &receipt.in_app {
        assert!(!purchase.unknown_attributes.contains_key(&1713));
    }
    // 9999 is still unmodelled, so forward compatibility is untouched.
    assert!(receipt.unknown_attributes.contains_key(&9999));
}

#[test]
fn ids_a_receipt_does_not_carry_are_absent_rather_than_zero() {
    // The shared sandbox receipt carries none of the four. Absent and
    // present-but-zero are different answers: Apple's sandbox does send 0.
    let receipt = verifier().verify(&common::receipt_der()).unwrap();
    assert_eq!(receipt.app_item_id, None);
    assert_eq!(receipt.download_id, None);
    assert_eq!(receipt.version_external_identifier, None);
    for purchase in &receipt.in_app {
        assert_eq!(purchase.is_trial_period, None);
    }
}

#[test]
fn the_receipt_size_bound_rejects_before_decoding() {
    let huge = "A".repeat(3_145_728 + 4);
    assert_eq!(
        verifier().0.verify_receipt(&huge).unwrap_err().reason(),
        Reason::TooLarge
    );
}

#[test]
fn line_wrapped_base64_is_refused() {
    let base64 = base64_encode(&common::receipt_der());
    assert!(verifier().0.verify_receipt(&base64).is_ok());
    // Line-wrapped base64 is refused, as Apple's verifyReceipt refuses it
    // (21002, measured 2026-09-23), rather than read as the same receipt.
    let wrapped: String = base64
        .as_bytes()
        .chunks(64)
        .map(|c| format!("{}\n", String::from_utf8_lossy(c)))
        .collect();
    assert_eq!(
        verifier().0.verify_receipt(&wrapped).unwrap_err().reason(),
        Reason::Malformed
    );
}

// The payload grammar (attribute SET shape, attribute INTEGER bounds, date
// spelling, empty dates) is tested against the parser itself, in
// `src/receipt_payload.rs`. A payload spliced into the shared receipt is
// not signed by the key the certificates name, so since the signature is
// checked before the full payload parse, such a receipt stops at
// INVALID_SIGNATURE and never reaches the parser this file used to probe.
// What the verifier does with a parser failure under a trusted signer is
// pinned above and by the `receipt/*` UNREADABLE_PAYLOAD vectors.

// --- CMS re-encoding: one signature, one accepted spelling ---------------

/// The eContent of a genuine, correctly signed receipt re-encoded as a
/// constructed `OCTET STRING` whose children are a `UTF8String` and an
/// `INTEGER`. The concatenated content octets are unchanged, so the RSA
/// signature still covers exactly the same bytes, and the certificates,
/// `SignerInfo` and signature are the genuine ones.
///
/// This verified before the reader started checking the children's tags:
/// X.690 §8.21 allows only `OCTET STRING`s inside a constructed
/// `OCTET STRING`, so joining anything else is reading a structure the
/// parser cannot represent instead of refusing it.
#[test]
fn a_constructed_octet_string_with_foreign_children_is_not_a_payload() {
    let parts = common::receipt_parts();
    let half = parts.content.len() / 2;
    let mut builder = common::CmsBuilder::from_shared();
    builder.content_tlv = Some(common::der(
        tag::OCTET_STRING_CONSTRUCTED,
        &[
            common::der(tag::UTF8_STRING, &parts.content[..half]),
            common::der(tag::INTEGER, &parts.content[half..]),
        ]
        .concat(),
    ));
    let blob = builder.build();
    assert_eq!(reason_of(&blob), Reason::Malformed);

    // The control: the same construction with legal OCTET STRING children is
    // ordinary BER and still verifies, so the rejection above is about the
    // tags and not about the chunking.
    let mut legal = common::CmsBuilder::from_shared();
    legal.content_tlv = Some(common::der(
        tag::OCTET_STRING_CONSTRUCTED,
        &[
            common::der(tag::OCTET_STRING, &parts.content[..half]),
            common::der(tag::OCTET_STRING, &parts.content[half..]),
        ]
        .concat(),
    ));
    let receipt = verifier().verify(&legal.build()).unwrap();
    assert_eq!(receipt.bundle_id.as_deref(), Some("com.example.app"));
}

/// A nested constructed `OCTET STRING` is legal BER, but a foreign tag at
/// any depth is not — the tag check has to recurse with the join.
#[test]
fn a_foreign_tag_nested_inside_a_constructed_octet_string_is_refused() {
    let parts = common::receipt_parts();
    let half = parts.content.len() / 2;
    let mut builder = common::CmsBuilder::from_shared();
    builder.content_tlv = Some(common::der(
        tag::OCTET_STRING_CONSTRUCTED,
        &[
            common::der(tag::OCTET_STRING, &parts.content[..half]),
            common::der(
                tag::OCTET_STRING_CONSTRUCTED,
                &common::der(tag::IA5_STRING, &parts.content[half..]),
            ),
        ]
        .concat(),
    ));
    assert_eq!(reason_of(&builder.build()), Reason::Malformed);
}

// --- the two SignerInfo branches stay separated -------------------------

/// Genuine Apple receipts carry no `signedAttrs`, so their signature is taken
/// directly over `cms.content`, which is a DER `SET`. The `signedAttrs`
/// branch signs `0x31 || signedAttrs[1..]`. Setting
/// `signedAttrs = 0xA0 || <the genuine payload SET>[1..]` therefore
/// reproduces byte for byte the bytes Apple signed, which would let a
/// genuine signature authenticate an entirely attacker-chosen `cms.content`.
///
/// This construction was *already* refused before the RFC 5652 §5.3 check
/// existed — Apple's receipt attributes are
/// `SEQUENCE { INTEGER, INTEGER, OCTET STRING }`, whose second field is
/// primitive, so the attribute walk died on the first one. That is an
/// accident of Apple's grammar, not a control, and it was untested. This
/// test is the regression guard; the `contentType`/`messageDigest`
/// requirement below is the stated control.
#[test]
fn signed_attrs_forged_from_the_payload_set_are_refused() {
    let parts = common::receipt_parts();
    let mut retagged = vec![tag::CONTEXT_0];
    retagged.extend_from_slice(&parts.content[1..]);

    let mut builder = common::CmsBuilder::from_shared();
    builder.signed_attrs = Some(retagged.clone());
    // The forged content: a payload the attacker wrote, in place of Apple's.
    builder.content = Some(common::der_set(&[common::der_seq(&[
        common::der_int(2),
        common::der_int(1),
        common::der(
            tag::OCTET_STRING,
            &common::der(tag::UTF8_STRING, b"com.attacker.forged"),
        ),
    ])]));
    assert_eq!(reason_of(&builder.build()), Reason::Malformed);

    // And with the genuine content, so the rejection is not the payload.
    let mut control = common::CmsBuilder::from_shared();
    control.signed_attrs = Some(retagged);
    assert_eq!(reason_of(&control.build()), Reason::Malformed);
}

/// RFC 5652 5.3 makes both attributes mandatory when `signedAttrs` are
/// present. Dropping either one leaves a signature that cannot be checked,
/// not a receipt with one fewer attribute: `INVALID_SIGNATURE`, as the Java
/// reference answers it.
#[test]
fn signed_attrs_without_content_type_or_message_digest_are_refused() {
    const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
    const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
    let parts = common::receipt_parts();
    let signed_attrs = parts
        .signed_attrs
        .expect("the shared receipt has signedAttrs");
    let mut as_set = vec![tag::SET];
    as_set.extend_from_slice(&signed_attrs[1..]);
    let parsed = parse_exact(&as_set).unwrap();

    for dropped in [CONTENT_TYPE, MESSAGE_DIGEST] {
        let wanted: Oid = dropped.parse().unwrap();
        let kept: Vec<Vec<u8>> = parsed
            .children()
            .iter()
            .filter(|attribute| {
                attribute.child(0).map(|oid| oid.contents) != Some(wanted.as_bytes())
            })
            .map(|attribute| attribute.full.to_vec())
            .collect();
        assert_eq!(
            kept.len(),
            parsed.children().len() - 1,
            "{dropped} was not there"
        );
        let mut rebuilt = vec![tag::CONTEXT_0];
        rebuilt.extend_from_slice(&common::der_set(&kept)[1..]);
        let mut builder = common::CmsBuilder::from_shared();
        builder.signed_attrs = Some(rebuilt);
        assert_eq!(
            reason_of(&builder.build()),
            Reason::InvalidSignature,
            "dropping {dropped} must leave a signature that cannot be checked"
        );
    }
}

/// A `signedAttrs` that is not an attribute set is a broken structure in
/// whichever `SignerInfo` carries it: `MALFORMED`, judged before any key is
/// used, so the verdict does not depend on whether a genuine `SignerInfo`
/// comes first and would otherwise have verified.
#[test]
fn a_broken_signed_attrs_set_is_malformed_in_either_signer_position() {
    let genuine = common::CmsBuilder::from_shared();
    let mut broken = common::CmsBuilder::from_shared();
    // An attribute whose values are not a SET.
    broken.signed_attrs = Some(common::der(
        tag::CONTEXT_0,
        &common::der_seq(&[common::der_oid("1.2.840.113549.1.9.3"), common::der_int(1)]),
    ));
    let broken = broken.signer_info();

    let mut broken_second = common::CmsBuilder::from_shared();
    broken_second.signer_infos_after = vec![broken.clone()];
    let mut broken_first = common::CmsBuilder::from_shared();
    broken_first.signer_infos_before = vec![broken];
    // The control: the genuine SignerInfo alone verifies.
    assert!(verifier().verify(&genuine.build()).is_ok());
    for blob in [broken_second.build(), broken_first.build()] {
        assert_eq!(reason_of(&blob), Reason::Malformed);
    }
}

/// A signer on a curve this crate does not implement is refused as a
/// certificate only once the chain vouched for it. Issued by nobody pinned,
/// its curve is nobody's business: `UNTRUSTED_CHAIN`.
#[test]
fn an_unvouched_signer_on_an_unimplemented_curve_is_an_untrusted_chain() {
    let mut bits = vec![0x00, 0x04];
    bits.extend_from_slice(&[0x11; 132]);
    let p521_spki = common::der_seq(&[
        common::der_seq(&[
            common::der_oid("1.2.840.10045.2.1"),
            common::der_oid("1.3.132.0.35"),
        ]),
        common::der(tag::BIT_STRING, &bits),
    ]);
    let signer = common::mint::certificate_for_spki(
        "Stranger P-521",
        p521_spki,
        "Stranger CA",
        &common::mint::key(9),
        7,
        false,
        Some(common::mint::RECEIPT_SIGNER_MARKER),
    );
    let mut builder = common::CmsBuilder::from_shared();
    builder.certificates = vec![signer];
    builder.signer_issuer = common::mint::name("Stranger CA");
    builder.signer_serial = vec![7];
    assert_eq!(reason_of(&builder.build()), Reason::UntrustedChain);
}

/// Policy-F8, the receipt twin: a receipt without a creation date is
/// judged at the clock, which has milliseconds. The minted chain is valid
/// until 2099-12-31T00:00:00Z, that instant included.
#[test]
fn a_dateless_receipt_is_judged_at_the_clock_to_the_millisecond() {
    use apple_purchase_receipt_verifier::Config;
    use common::mint::{certificate, key, name, RECEIPT_SIGNER_MARKER, WWDR_MARKER};
    const NOT_AFTER: i64 = 4_102_358_400_000;
    let (root_key, intermediate_key, signer_key) = (key(1), key(2), key(3));
    let root = certificate(
        "Test Root",
        &root_key,
        "Test Root",
        &root_key,
        1,
        true,
        None,
    );
    let intermediate = certificate(
        "Test WWDR",
        &intermediate_key,
        "Test Root",
        &root_key,
        2,
        true,
        Some(WWDR_MARKER),
    );
    let signer = certificate(
        "Test Signer",
        &signer_key,
        "Test WWDR",
        &intermediate_key,
        3,
        false,
        Some(RECEIPT_SIGNER_MARKER),
    );
    // One bundle id attribute and no attribute 12.
    let content = common::der_set(&[common::der_seq(&[
        common::der_int(2),
        common::der_int(1),
        common::der(0x04, &common::der(0x0c, b"com.example.app")),
    ])]);
    let mut builder = common::CmsBuilder::from_shared();
    builder.certificates = vec![signer, intermediate];
    builder.signer_issuer = name("Test WWDR");
    builder.signer_serial = vec![3];
    builder.signed_attrs = None;
    builder.signature_algorithm =
        common::der_seq(&[common::der_oid(common::mint::ECDSA_WITH_SHA256)]);
    builder.signature = signer_key.sign_der(&content);
    builder.content = Some(content);
    let receipt = builder.build();
    let at = |millis: i64| {
        let verifier = Verifier::new(
            Config::builder()
                .roots([TrustAnchor::from_der(&root).unwrap()])
                .clock(move || millis)
                .build()
                .unwrap(),
        );
        common::verify_der(&verifier, &receipt)
            .err()
            .map(|failure| failure.reason())
    };
    assert_eq!(at(NOT_AFTER), None);
    for outside in [NOT_AFTER + 1, NOT_AFTER + 999] {
        assert_eq!(at(outside), Some(Reason::InvalidCertificate), "{outside}");
    }
}
