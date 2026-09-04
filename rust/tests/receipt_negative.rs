//! Receipt rejections, one structural fault at a time.
//!
//! Most of these are built by taking the shared generated receipt apart with
//! the crate's own CMS reader and putting it back together with exactly one
//! thing changed — so the fault under test is the only difference, and a
//! test that stops failing because something else broke first is visible.

mod common;

use apple_purchase_receipt_verifier::asn1::tag;
use apple_purchase_receipt_verifier::{Reason, ReceiptVerifier, TrustAnchor};

fn verifier_with(anchor: TrustAnchor, bundle_id: &str) -> ReceiptVerifier {
    ReceiptVerifier::builder()
        .trusted_roots([anchor])
        .bundle_id(bundle_id)
        .build()
        .unwrap()
}

fn verifier() -> ReceiptVerifier {
    verifier_with(common::receipt_root(), "com.example.app")
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
    assert_eq!(receipt.in_app_purchases.len(), 2);
}

#[test]
fn an_empty_receipt_is_rejected() {
    assert_eq!(reason_of(&[]), Reason::InvalidReceiptFormat);
}

#[test]
fn trailing_bytes_after_the_cms_blob_are_rejected() {
    // Accepting them would let an attacker append to a genuine receipt and
    // have it verify anyway.
    let mut der = common::receipt_der();
    der.push(0x00);
    assert_eq!(reason_of(&der), Reason::InvalidReceiptFormat);

    let mut der = common::receipt_der();
    der.extend_from_slice(&[0x30, 0x03, 0x02, 0x01, 0x01]);
    assert_eq!(reason_of(&der), Reason::InvalidReceiptFormat);
}

#[test]
fn a_truncated_receipt_is_rejected() {
    let der = common::receipt_der();
    for fraction in [2usize, 3, 4, 8, 16, 64] {
        let cut = der.len() / fraction;
        assert_eq!(
            reason_of(&der[..cut]),
            Reason::InvalidReceiptFormat,
            "truncated to {cut} bytes"
        );
    }
}

#[test]
fn a_sequence_that_is_not_a_cms_is_rejected() {
    let not_cms = common::der_seq(&[common::der_int(1), common::der_int(2)]);
    assert_eq!(reason_of(&not_cms), Reason::InvalidReceiptFormat);
}

#[test]
fn a_truncated_sequence_header_is_rejected() {
    assert_eq!(reason_of(&[0x30]), Reason::InvalidReceiptFormat);
    assert_eq!(reason_of(&[0x30, 0x82]), Reason::InvalidReceiptFormat);
    assert_eq!(reason_of(&[0x30, 0x82, 0xff]), Reason::InvalidReceiptFormat);
}

#[test]
fn a_receipt_with_no_encapsulated_content_is_rejected() {
    let mut builder = common::CmsBuilder::from_shared();
    builder.content = None;
    assert_eq!(reason_of(&builder.build()), Reason::InvalidReceiptFormat);
}

#[test]
fn content_that_is_not_an_octet_string_is_rejected() {
    let mut builder = common::CmsBuilder::from_shared();
    builder.content_as_sequence = true;
    assert_eq!(reason_of(&builder.build()), Reason::InvalidReceiptFormat);
}

#[test]
fn a_receipt_with_no_signer_info_is_rejected() {
    let mut builder = common::CmsBuilder::from_shared();
    builder.include_signer_info = false;
    assert_eq!(reason_of(&builder.build()), Reason::InvalidReceiptFormat);
}

#[test]
fn a_signer_named_by_an_unembedded_issuer_and_serial_is_rejected() {
    let mut builder = common::CmsBuilder::from_shared();
    builder.signer_serial = vec![0x7f, 0x7f, 0x7f, 0x7f];
    assert_eq!(reason_of(&builder.build()), Reason::InvalidReceiptFormat);

    let mut builder = common::CmsBuilder::from_shared();
    builder.signer_issuer = common::der_seq(&[]);
    assert_eq!(reason_of(&builder.build()), Reason::InvalidReceiptFormat);
}

#[test]
fn a_digest_algorithm_outside_sha1_and_sha256_is_rejected() {
    // Apple signs receipts with SHA-1 or SHA-256. Anything else is a
    // receipt this library refuses to interpret rather than one it guesses.
    let builder = common::CmsBuilder::from_shared().with_sha512_digest();
    assert_eq!(reason_of(&builder.build()), Reason::InvalidReceiptFormat);
}

#[test]
fn more_than_ten_embedded_certificates_is_an_invalid_chain() {
    let mut builder = common::CmsBuilder::from_shared();
    let original = builder.certificates.clone();
    while builder.certificates.len() <= 10 {
        builder.certificates.push(original[0].clone());
    }
    assert_eq!(builder.certificates.len(), 11);
    assert_eq!(reason_of(&builder.build()), Reason::InvalidChain);

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
fn an_unparseable_embedded_certificate_is_rejected() {
    let mut builder = common::CmsBuilder::from_shared();
    builder
        .certificates
        .push(common::der_seq(&[common::der_int(1)]));
    assert_eq!(reason_of(&builder.build()), Reason::InvalidReceiptFormat);
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
fn a_foreign_root_is_an_invalid_chain_and_not_a_purpose_error() {
    // The signer of receipt-foreign carries the marker OID, so a port that
    // checked the OID before the chain would report the wrong reason here.
    let der = common::read_fixture("generated/receipt-foreign.der");
    assert_eq!(reason_of(&der), Reason::InvalidChain);
}

#[test]
fn a_signer_without_the_receipt_marker_oid_is_a_purpose_error() {
    let verifier = verifier_with(
        common::anchor("generated/receipt-no-signer-oid-root.der"),
        "com.example.app",
    );
    let der = common::read_fixture("generated/receipt-no-signer-oid.der");
    assert_eq!(
        verifier.verify(&der).unwrap_err().reason(),
        Reason::InvalidCertificatePurpose
    );
}

#[test]
fn chain_validity_is_judged_at_the_receipts_own_creation_date() {
    let verifier = verifier_with(
        common::anchor("generated/receipt-expired-root.der"),
        "com.example.app",
    );
    let historical = common::read_fixture("generated/receipt-expired-historical.der");
    let fresh = common::read_fixture("generated/receipt-expired-fresh.der");
    // Valid when it was signed, expired now: still accepted.
    assert!(verifier.verify(&historical).is_ok());
    // Claims to have been created after the chain expired: rejected.
    assert_eq!(
        verifier.verify(&fresh).unwrap_err().reason(),
        Reason::InvalidChain
    );
}

#[test]
fn a_wrong_device_guid_is_a_device_hash_mismatch() {
    let mut guid = common::device_guid();
    guid[0] ^= 0x10;
    assert_eq!(
        verifier()
            .verify_with_device_guid(&common::receipt_der(), &guid)
            .unwrap_err()
            .reason(),
        Reason::DeviceHashMismatch
    );
    // An empty GUID is a mismatch, not a skip.
    assert_eq!(
        verifier()
            .verify_with_device_guid(&common::receipt_der(), &[])
            .unwrap_err()
            .reason(),
        Reason::DeviceHashMismatch
    );
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
    let error = verifier().verify_with_device_guid(&builder.build(), &common::device_guid());
    assert_eq!(error.unwrap_err().reason(), Reason::InvalidSignature);
}

/// Removes every attribute of one type from a receipt payload, re-encoding
/// the SET around the remaining attributes.
fn strip_attribute(content: &[u8], attribute_type: u64) -> Vec<u8> {
    let node = apple_purchase_receipt_verifier::asn1::parse_exact(content).unwrap();
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
fn an_attribute_type_above_the_signed_32_bit_range_is_rejected() {
    let der = common::read_fixture("generated/receipt-attribute-type-overflow.der");
    let verifier = verifier_with(
        common::anchor("generated/divergence-receipt-root.der"),
        "com.example.app",
    );
    assert_eq!(
        verifier.verify(&der).unwrap_err().reason(),
        Reason::InvalidReceiptFormat,
        "fail closed: never clamp such a type onto a sentinel"
    );
}

#[test]
fn a_receipt_with_no_creation_date_still_verifies() {
    let verifier = verifier_with(
        common::anchor("generated/divergence-receipt-root.der"),
        "com.example.app",
    );
    let receipt = verifier.verify(&common::read_fixture(
        "generated/receipt-no-creation-date.der",
    ));
    let receipt = receipt.unwrap();
    assert!(receipt.creation_date.is_none());
    assert_eq!(receipt.bundle_id.as_deref(), Some("com.example.app"));
}

#[test]
fn a_double_wrapped_payload_is_unwrapped_once() {
    let der = common::read_fixture("generated/receipt-double-wrapped.der");
    let receipt = verifier().verify(&der).unwrap();
    assert_eq!(receipt.in_app_purchases.len(), 2);
    assert_eq!(receipt.app_version.as_deref(), Some("1.2.3"));
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
    assert!(receipt.original_purchase_date.is_some());
}

#[test]
fn the_receipt_size_bound_rejects_before_parsing() {
    let huge = vec![0x30u8; apple_purchase_receipt_verifier::MAX_RECEIPT_BYTES + 1];
    assert_eq!(reason_of(&huge), Reason::InvalidReceiptFormat);
}

#[test]
fn base64_and_der_entry_points_agree() {
    let der = common::receipt_der();
    let base64 = apple_purchase_receipt_verifier::base64::encode(&der);
    assert_eq!(
        verifier().verify(&der).unwrap(),
        verifier().verify_base64(&base64).unwrap()
    );
    // Line-wrapped base64, as a client might send it.
    let wrapped: String = base64
        .as_bytes()
        .chunks(64)
        .map(|c| format!("{}\n", String::from_utf8_lossy(c)))
        .collect();
    assert_eq!(
        verifier().verify(&der).unwrap(),
        verifier().verify_base64(&wrapped).unwrap()
    );
}

#[test]
fn an_attribute_set_that_is_not_a_set_is_rejected() {
    let mut builder = common::CmsBuilder::from_shared();
    builder.content = Some(common::der_seq(&[common::der_int(1)]));
    builder.signed_attrs = None;
    assert_eq!(reason_of(&builder.build()), Reason::InvalidReceiptFormat);
}

#[test]
fn an_attribute_with_fewer_than_three_fields_is_rejected() {
    let attribute = common::der_seq(&[common::der_int(2), common::der_int(1)]);
    let mut builder = common::CmsBuilder::from_shared();
    builder.content = Some(common::der_set(&[attribute]));
    builder.signed_attrs = None;
    assert_eq!(reason_of(&builder.build()), Reason::InvalidReceiptFormat);
}

#[test]
fn a_negative_or_oversized_attribute_integer_is_rejected() {
    let negative = common::der_seq(&[
        common::der(tag::INTEGER, &[0xff]),
        common::der_int(1),
        common::der(tag::OCTET_STRING, &common::der(tag::UTF8_STRING, b"x")),
    ]);
    let mut builder = common::CmsBuilder::from_shared();
    builder.content = Some(common::der_set(&[negative]));
    builder.signed_attrs = None;
    assert_eq!(reason_of(&builder.build()), Reason::InvalidReceiptFormat);

    let nine_bytes = common::der_seq(&[
        common::der(tag::INTEGER, &[0x00; 9]),
        common::der_int(1),
        common::der(tag::OCTET_STRING, &common::der(tag::UTF8_STRING, b"x")),
    ]);
    let mut builder = common::CmsBuilder::from_shared();
    builder.content = Some(common::der_set(&[nine_bytes]));
    builder.signed_attrs = None;
    assert_eq!(reason_of(&builder.build()), Reason::InvalidReceiptFormat);
}

#[test]
fn a_receipt_date_without_a_timezone_designator_is_rejected() {
    // A naive date would be read as the server's local time, and that date
    // is the instant the chain is judged at — the same receipt would verify
    // on one host and fail on another.
    for text in [
        "2024-08-06T12:00:00",
        "2024-08-06 12:00:00Z",
        "06/08/2024",
        "2024-02-31T00:00:00Z",
    ] {
        let attribute = common::der_seq(&[
            common::der_int(12),
            common::der_int(1),
            common::der(
                tag::OCTET_STRING,
                &common::der(tag::IA5_STRING, text.as_bytes()),
            ),
        ]);
        let mut builder = common::CmsBuilder::from_shared();
        builder.content = Some(common::der_set(&[attribute]));
        builder.signed_attrs = None;
        assert_eq!(
            reason_of(&builder.build()),
            Reason::InvalidReceiptFormat,
            "date {text} must be refused"
        );
    }
}

#[test]
fn an_empty_receipt_date_means_absent() {
    let attributes = [
        common::der_seq(&[
            common::der_int(2),
            common::der_int(1),
            common::der(
                tag::OCTET_STRING,
                &common::der(tag::UTF8_STRING, b"com.example.app"),
            ),
        ]),
        common::der_seq(&[
            common::der_int(21),
            common::der_int(1),
            common::der(tag::OCTET_STRING, &common::der(tag::IA5_STRING, b"")),
        ]),
    ];
    let mut builder = common::CmsBuilder::from_shared();
    builder.content = Some(common::der_set(&attributes));
    builder.signed_attrs = None;
    // The signature no longer verifies, but the payload parse is what is
    // under test: it must reach the signature check, not fail before it.
    assert_eq!(reason_of(&builder.build()), Reason::InvalidSignature);
}

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
    assert_eq!(reason_of(&blob), Reason::InvalidReceiptFormat);

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
    assert_eq!(reason_of(&builder.build()), Reason::InvalidReceiptFormat);
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
    assert_eq!(reason_of(&builder.build()), Reason::InvalidReceiptFormat);

    // And with the genuine content, so the rejection is not the payload.
    let mut control = common::CmsBuilder::from_shared();
    control.signed_attrs = Some(retagged);
    assert_eq!(reason_of(&control.build()), Reason::InvalidReceiptFormat);
}

/// RFC 5652 §5.3 makes both attributes mandatory when `signedAttrs` are
/// present. Dropping either one is a malformed `SignerInfo`, not a receipt
/// with one fewer attribute.
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
    let parsed = apple_purchase_receipt_verifier::asn1::parse_exact(&as_set).unwrap();

    for dropped in [CONTENT_TYPE, MESSAGE_DIGEST] {
        let wanted = apple_purchase_receipt_verifier::asn1::encode_oid(dropped).unwrap();
        let kept: Vec<Vec<u8>> = parsed
            .children()
            .iter()
            .filter(|attribute| {
                attribute.child(0).map(|oid| oid.contents) != Some(wanted.as_slice())
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
            Reason::InvalidReceiptFormat,
            "dropping {dropped} must be a malformed SignerInfo"
        );
    }
}
