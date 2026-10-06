// Evidence only (2026-10-06): appended to rust/tests/envelope_bounds.rs,
// which supplies `mod common`, `Envelope`, `unsigned_attribute` and
// `verify`. Prints the core's answer to receipts that are valid except for
// one grammar deviation the header walk's own rules caught, with how many
// full CMS decodes ran, and whether OpenSSL's `d2i_CMS_ContentInfo` alone
// takes the envelope.

/// The core's answer: `ok` with the fields a deviation could change, or
/// the reason; then the full decodes it took.
fn probe_answer(result: &Result<ReceiptPayload, Failure>, full_decodes: usize) -> String {
    let verdict = match result {
        Ok(payload) => format!(
            "ok bundle_id={:?} app_item_id={:?} unknown={:?}",
            payload.bundle_id, payload.app_item_id, payload.unknown_attributes
        ),
        Err(failure) => format!("{:?}", failure.reason()),
    };
    format!("{verdict} (full decodes: {full_decodes})")
}

fn openssl_alone(der: &[u8]) -> &'static str {
    match openssl::cms::CmsContentInfo::from_der(der) {
        Ok(_) => "decodes",
        Err(_) => "refuses",
    }
}

/// A minted P-256 PKI (root, WWDR-marked intermediate, marked signer whose
/// subject `Name` is `signer_subject` and whose extensions gain `extra`),
/// with its root pinned, as `receipt_signer_algorithms.rs` mints it.
struct Minted {
    verifier: apple_purchase_receipt_verifier::Verifier,
    signer_key: common::mint::SigningKey,
    certificates: Vec<Vec<u8>>,
}

fn minted(signer_subject: Option<Vec<u8>>, extra: Option<Vec<u8>>) -> Minted {
    use common::mint::{
        assemble, certificate, key, name, spki, ECDSA_WITH_SHA256, RECEIPT_SIGNER_MARKER,
        WWDR_MARKER,
    };
    let (root_key, intermediate_key, signer_key) = (key(1), key(2), key(3));
    let root = certificate("Test Root", &root_key, "Test Root", &root_key, 1, true, None);
    let intermediate = certificate(
        "Test WWDR",
        &intermediate_key,
        "Test Root",
        &root_key,
        2,
        true,
        Some(WWDR_MARKER),
    );
    let algorithm = der_seq(&[der_oid(ECDSA_WITH_SHA256)]);
    let mut extensions = vec![der_seq(&[
        der_oid(RECEIPT_SIGNER_MARKER),
        der(tag::OCTET_STRING, &[0x05, 0x00]),
    ])];
    extensions.extend(extra);
    let tbs = der_seq(&[
        der(tag::CONTEXT_0, &der_int(2)),
        der_int(3),
        algorithm.clone(),
        name("Test WWDR"),
        der_seq(&[der(0x17, b"200101000000Z"), der(0x18, b"20991231000000Z")]),
        signer_subject.unwrap_or_else(|| name("Test Signer")),
        spki(&signer_key),
        der(0xA3, &der_seq(&extensions)),
    ]);
    let signature = intermediate_key.sign_der(&tbs);
    let signer = assemble(tbs, algorithm, &signature);
    let config = apple_purchase_receipt_verifier::Config::builder()
        .roots([apple_purchase_receipt_verifier::TrustAnchor::from_der(&root).unwrap()])
        .clock(|| 1_735_689_600_000)
        .build()
        .unwrap();
    Minted {
        verifier: apple_purchase_receipt_verifier::Verifier::new(config),
        signer_key,
        certificates: vec![signer, intermediate],
    }
}

/// `content` signed by `pki`'s signer (ECDSA with SHA-256, no
/// signedAttrs), then `edit` applied to the envelope.
fn minted_receipt(pki: &Minted, content: &[u8], edit: impl FnOnce(&mut CmsBuilder)) -> Vec<u8> {
    let mut builder = CmsBuilder::from_shared();
    builder.content = Some(content.to_vec());
    builder.certificates = pki.certificates.clone();
    builder.signer_issuer = common::mint::name("Test WWDR");
    builder.signer_serial = vec![3];
    builder.signed_attrs = None;
    builder.signature_algorithm = der_seq(&[der_oid(common::mint::ECDSA_WITH_SHA256)]);
    builder.signature = pki.signer_key.sign_der(content);
    edit(&mut builder);
    builder.build()
}

/// A `ReceiptAttribute` with version 1 and `value` as its OCTET STRING
/// content, its type written as `type_tlv`; `rest` follows the value.
fn probe_attribute(type_tlv: Vec<u8>, value: Vec<u8>, rest: &[Vec<u8>]) -> Vec<u8> {
    let mut fields = vec![type_tlv, der_int(1), value];
    fields.extend_from_slice(rest);
    der_seq(&fields)
}

fn octets(value: &[u8]) -> Vec<u8> {
    der(tag::OCTET_STRING, value)
}

/// The bundle id value, a UTF8String.
fn bundle_id_value() -> Vec<u8> {
    der(tag::UTF8_STRING, b"com.example.app")
}

fn probe_payload(attributes: &[Vec<u8>]) -> Vec<u8> {
    der_set(attributes)
}

#[test]
fn walk_counter_probe_payload() {
    let pki = minted(None, None);
    let bundle = probe_attribute(der_int(2), octets(&bundle_id_value()), &[]);
    let item = probe_attribute(der_int(1), octets(&der_int(5)), &[]);
    let foreign_chunk = [
        &[0x24, 0x80][..],
        &der(tag::UTF8_STRING, &bundle_id_value()),
        &[0, 0],
    ]
    .concat();
    let eoc_in_string = [
        &[0x24, 2 + 2 + 17][..],
        &[0, 0],
        &[0x04, 17],
        &bundle_id_value(),
    ]
    .concat();
    let mut five_octet = vec![0x0c, 0x85, 0, 0, 0, 0, 15];
    five_octet.extend_from_slice(b"com.example.app");
    let control = probe_payload(&[bundle.clone(), item.clone()]);
    let wrap_foreign = [&[0x24, 0x80][..], &der(tag::INTEGER, &control), &[0, 0]].concat();
    let set_high_tag = [&[0x3f, 0x11, control.len() as u8 - 2][..], &control[2..]].concat();
    let set_five_octet = [
        &[0x31, 0x85, 0, 0, 0, 0, control.len() as u8 - 2][..],
        &control[2..],
    ]
    .concat();
    let fourth = |value: Vec<u8>| {
        probe_payload(&[
            bundle.clone(),
            probe_attribute(der_int(9000), octets(&[1]), &[value]),
        ])
    };
    let inputs: Vec<(&str, Vec<u8>)> = vec![
        ("control", control.clone()),
        (
            "attribute type INTEGER in high-tag form (1F 02)",
            probe_payload(&[
                probe_attribute(vec![0x1f, 0x02, 0x01, 0x02], octets(&bundle_id_value()), &[]),
                item.clone(),
            ]),
        ),
        (
            "app item id value INTEGER in high-tag form",
            probe_payload(&[
                bundle.clone(),
                probe_attribute(der_int(1), octets(&[0x1f, 0x02, 0x01, 0x05]), &[]),
            ]),
        ),
        (
            "bundle id UTF8String with a five-octet length",
            probe_payload(&[probe_attribute(der_int(2), octets(&five_octet), &[]), item.clone()]),
        ),
        ("payload SET in high-tag form (3F 11)", set_high_tag),
        ("payload SET with a five-octet length", set_five_octet),
        (
            "bundle id value a constructed OCTET STRING with a UTF8String chunk",
            probe_payload(&[probe_attribute(der_int(2), foreign_chunk, &[]), item.clone()]),
        ),
        (
            "bundle id value a constructed OCTET STRING with an EOC in its definite length",
            probe_payload(&[probe_attribute(der_int(2), eoc_in_string, &[]), item.clone()]),
        ),
        ("Xcode wrap with an INTEGER chunk", wrap_foreign),
        (
            "fourth field BOOLEAN of two octets",
            fourth(der(0x01, &[0x00, 0x00])),
        ),
        (
            "fourth field SEQUENCE holding a BOOLEAN of two octets",
            fourth(der_seq(&[der(0x01, &[0x00, 0x00])])),
        ),
        (
            "fourth field SEQUENCE holding an OID with a padded arc",
            fourth(der_seq(&[der(tag::OID, &[0x2a, 0x80, 0x01])])),
        ),
        (
            "fourth field SEQUENCE holding a constructed BOOLEAN",
            fourth(der_seq(&[der(0x21, &der(0x01, &[0xff]))])),
        ),
        (
            "fourth field SEQUENCE holding an end-of-contents",
            fourth(der_seq(&[vec![0, 0]])),
        ),
    ];
    for (label, content) in inputs {
        let der = minted_receipt(&pki, &content, |_| {});
        let (result, full) = cms_full_decodes_during(|| common::verify_der(&pki.verifier, &der));
        println!("PROBE payload | {label} | {}", probe_answer(&result, full));
    }
}

#[test]
fn walk_counter_probe_envelope() {
    // The shared receipt (RSA, signed content, no signedAttrs to edit), its
    // SignerInfo rebuilt field by field: nothing below is signed.
    let shared_signer_info = |edit: &dyn Fn(&mut Vec<Vec<u8>>)| {
        let mut builder = CmsBuilder::from_shared();
        let signer_info = builder.signer_info();
        let parsed = parse_exact(&signer_info).unwrap();
        let mut fields: Vec<Vec<u8>> = parsed.children().iter().map(|c| c.full.to_vec()).collect();
        edit(&mut fields);
        builder.include_signer_info = false;
        builder.signer_infos_after = vec![der_seq(&fields)];
        builder.build()
    };
    let unsigned = |value: Vec<u8>| {
        let mut envelope = Envelope::shared();
        envelope.unsigned_attributes = Some(unsigned_attribute(&value));
        envelope.build()
    };
    let content = CmsBuilder::from_shared().content.unwrap();
    let mut inputs: Vec<(String, Vec<u8>)> = vec![
        ("control: shared receipt".into(), CmsBuilder::from_shared().build()),
        (
            "SignerInfo version a constructed INTEGER".into(),
            shared_signer_info(&|f| f[0] = vec![0x22, 0x03, 0x02, 0x01, 0x01]),
        ),
        (
            "SignerInfo version in high-tag form (1F 02)".into(),
            shared_signer_info(&|f| f[0] = vec![0x1f, 0x02, 0x01, 0x01]),
        ),
        (
            "SignerInfo with an EOC before its sid".into(),
            shared_signer_info(&|f| f.insert(1, vec![0, 0])),
        ),
        (
            "SignerInfo with an EOC after its signature".into(),
            shared_signer_info(&|f| f.push(vec![0, 0])),
        ),
        (
            "SignerInfo signatureAlgorithm parameters SEQUENCE{padded INTEGER}".into(),
            shared_signer_info(&|f| {
                let at = f.len() - 2;
                f[at] = der_seq(&[
                    der_oid("1.2.840.113549.1.1.1"),
                    der_seq(&[vec![0x02, 0x02, 0x00, 0x01]]),
                ]);
            }),
        ),
        (
            "signerInfos SET with an EOC after the SignerInfo".into(),
            {
                let mut builder = CmsBuilder::from_shared();
                builder.signer_infos_after = vec![vec![0, 0]];
                builder.build()
            },
        ),
        (
            "eContent a constructed OCTET STRING with a UTF8String chunk".into(),
            {
                let mut builder = CmsBuilder::from_shared();
                builder.content_tlv =
                    Some([&[0x24, 0x80][..], &der(tag::UTF8_STRING, &content), &[0, 0]].concat());
                builder.build()
            },
        ),
    ];
    for (label, value) in [
        ("constructed BOOLEAN", der(0x21, &der(0x01, &[0xff]))),
        ("constructed INTEGER", der(0x22, &der(0x02, &[0x05]))),
        ("short UTCTime", der(0x17, b"0")),
        ("padded INTEGER", vec![0x02, 0x02, 0x00, 0x01]),
        ("BOOLEAN of two octets", der(0x01, &[0x00, 0x00])),
        ("end-of-contents", vec![0x00, 0x00]),
        ("primitive SEQUENCE", vec![0x10, 0x00]),
    ] {
        inputs.push((
            format!("unsigned attribute value: {label}"),
            unsigned(value.clone()),
        ));
        inputs.push((
            format!("unsigned attribute value: SEQUENCE holding a {label}"),
            unsigned(der_seq(&[value])),
        ));
    }
    for (label, result, full, alone) in inputs.into_iter().map(|(label, der)| {
        let (result, full) = verify(&der);
        (label, result, full, openssl_alone(&der))
    }) {
        println!(
            "PROBE envelope | {label} | {} | d2i_CMS_ContentInfo {alone}",
            probe_answer(&result, full)
        );
    }
    // Deviations inside a certificate the minted intermediate signs: the
    // signer's subject Name carries an attribute value OpenSSL keeps whole
    // (ASN1_PRINTABLE takes a SEQUENCE), or an extension's critical flag is
    // a constructed BOOLEAN.
    let name_with = |value: Vec<u8>| {
        der_seq(&[
            der_set(&[der_seq(&[der_oid("2.5.4.3"), der(0x0C, b"Test Signer")])]),
            der_set(&[der_seq(&[der_oid("2.5.4.10"), value])]),
        ])
    };
    let minted_inputs: Vec<(&str, Minted)> = vec![
        ("control: minted signer", minted(None, None)),
        (
            "minted signer Name value SEQUENCE{short UTCTime}",
            minted(Some(name_with(der_seq(&[der(0x17, b"0")]))), None),
        ),
        (
            "minted signer Name value SEQUENCE{padded INTEGER}",
            minted(Some(name_with(der_seq(&[vec![0x02, 0x02, 0x00, 0x01]]))), None),
        ),
        (
            "minted signer Name value SEQUENCE{end-of-contents}",
            minted(Some(name_with(der_seq(&[vec![0, 0]]))), None),
        ),
        (
            "minted signer Name value SEQUENCE{constructed INTEGER}",
            minted(Some(name_with(der_seq(&[der(0x22, &der(0x02, &[5]))]))), None),
        ),
        (
            "minted signer extension whose critical flag is a constructed BOOLEAN",
            minted(
                None,
                Some(der_seq(&[
                    der_oid("1.2.3.4"),
                    der(0x21, &der(0x01, &[0x00])),
                    der(tag::OCTET_STRING, &[0x05, 0x00]),
                ])),
            ),
        ),
    ];
    for (label, pki) in minted_inputs {
        let der = minted_receipt(&pki, &content, |_| {});
        let (result, full) = cms_full_decodes_during(|| common::verify_der(&pki.verifier, &der));
        println!(
            "PROBE envelope | {label} | {} | d2i_CMS_ContentInfo {}",
            probe_answer(&result, full),
            openssl_alone(&der)
        );
    }
}

/// The shared cases the narrowed walk moves, run on their fixtures.
#[test]
fn walk_counter_probe_cases() {
    for (id, fixture, root) in [
        ("receipt/unreadable-attribute-value-with-a-utf8string-chunk", "core-review-receipt-value-foreign-chunk", "core-review-receipt-root"),
        ("receipt/unreadable-double-wrap-with-a-foreign-chunk", "core-review-receipt-wrap-foreign-chunk", "core-review-receipt-root"),
        ("receipt/unreadable-attribute-type-in-high-tag-form", "core-review-receipt-high-tag-type", "core-review-receipt-root"),
        ("receipt/app-item-id-in-high-tag-form-is-kept-raw", "core-review-receipt-high-tag-value", "core-review-receipt-root"),
        ("receipt/bundle-id-with-a-five-octet-length-is-kept-raw", "core-review-receipt-five-octet-length", "core-review-receipt-root"),
        ("receipt/unreadable-fourth-field-boolean-of-two-octets", "core-review-receipt-fourth-boolean", "core-review-receipt-root"),
        ("receipt/unreadable-fourth-field-sequence-holding-a-padded-integer", "core-review-receipt-fourth-sequence", "core-review-receipt-root"),
        ("receipt/unreadable-fourth-field-sequence-holding-a-short-utctime", "core-review-r2-fourth-sequence-short-utctime", "core-review-receipt-root"),
        ("receipt/unreadable-fourth-field-sequence-holding-a-short-generalizedtime", "core-review-r2-fourth-sequence-short-generalizedtime", "core-review-receipt-root"),
        ("receipt/unreadable-fourth-field-sequence-holding-a-constructed-integer", "core-review-r2-fourth-sequence-constructed-integer", "core-review-receipt-root"),
        ("receipt/unreadable-fourth-field-sequence-holding-a-primitive-sequence", "core-review-r2-fourth-sequence-primitive-sequence", "core-review-receipt-root"),
        ("receipt/unreadable-fourth-field-sequence-holding-an-end-of-contents", "core-review-r2-fourth-sequence-end-of-contents", "core-review-receipt-root"),
        ("receipt/unreadable-fourth-field-sequence-holding-a-7-level-octet-string", "core-review-r2-fourth-sequence-7-level-octet-string", "core-review-receipt-root"),
        ("receipt/reject-an-unsigned-value-sequence-holding-a-short-utctime", "core-review-r2-unsigned-sequence-short-utctime", "receipt-root"),
    ] {
        let der = common::read_fixture(&format!("generated-0.7/{fixture}.der"));
        let verifier = common::verifier_at(
            [common::anchor(&format!("generated-0.7/{root}.der"))],
            1_735_689_600_000,
        );
        let (result, full) = cms_full_decodes_during(|| common::verify_der(&verifier, &der));
        println!(
            "PROBE case | {id} | {} | d2i_CMS_ContentInfo {}",
            probe_answer(&result, full),
            openssl_alone(&der)
        );
    }
}
