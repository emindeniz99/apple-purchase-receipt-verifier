
// Evidence only (2026-10-05): appended to rust/tests/jws_negative.rs, which
// supplies `mod common`, `base64_encode` and `TrustAnchor`. Prints the
// core's answer to JWS chains minted with the test PKI, each certificate
// signed as it stands, so only the core's own certificate reader stands
// between them and `ok`.

/// The chain of `common::mint::signed_jws`, with extensions added to the
/// intermediate and the leaf, the leaf's version INTEGER content given, and
/// `x5c[2]` replaced when `third` is given; and the root to pin.
fn probe_jws(
    intermediate_extra: &[Vec<u8>],
    leaf_extra: &[Vec<u8>],
    leaf_version: &[u8],
    third: Option<Vec<u8>>,
) -> (TrustAnchor, String) {
    use common::mint::{
        certificate, key, name, spki, ECDSA_WITH_SHA256, RECEIPT_SIGNER_MARKER, WWDR_MARKER,
    };
    use common::{der, der_int, der_oid, der_seq, tag};
    let algorithm = der_seq(&[der_oid(ECDSA_WITH_SHA256)]);
    let marker = |oid| der_seq(&[der_oid(oid), der(tag::OCTET_STRING, &[0x05, 0x00])]);
    let issue = |subject: &str,
                 subject_key: &common::mint::SigningKey,
                 issuer: &str,
                 issuer_key: &common::mint::SigningKey,
                 serial: u64,
                 version: &[u8],
                 extensions: Vec<Vec<u8>>| {
        let tbs = der_seq(&[
            der(tag::CONTEXT_0, &der(tag::INTEGER, version)),
            der_int(serial),
            algorithm.clone(),
            name(issuer),
            der_seq(&[der(0x17, b"200101000000Z"), der(0x18, b"20991231000000Z")]),
            name(subject),
            spki(subject_key),
            der(0xA3, &der_seq(&extensions)),
        ]);
        let signature = issuer_key.sign_der(&tbs);
        common::mint::assemble(tbs, algorithm.clone(), &signature)
    };
    let basic_ca = der_seq(&[
        der_oid("2.5.29.19"),
        der(0x01, &[0xFF]),
        der(tag::OCTET_STRING, &der_seq(&[der(0x01, &[0xFF])])),
    ]);
    let (root_key, intermediate_key, leaf_key) = (key(11), key(12), key(13));
    let root = certificate("JWS Root", &root_key, "JWS Root", &root_key, 1, true, None);
    let mut extensions = vec![basic_ca, marker(WWDR_MARKER)];
    extensions.extend_from_slice(intermediate_extra);
    let intermediate = issue(
        "JWS WWDR",
        &intermediate_key,
        "JWS Root",
        &root_key,
        2,
        &[2],
        extensions,
    );
    let mut extensions = vec![marker(RECEIPT_SIGNER_MARKER)];
    extensions.extend_from_slice(leaf_extra);
    let leaf = issue(
        "JWS Leaf",
        &leaf_key,
        "JWS WWDR",
        &intermediate_key,
        3,
        leaf_version,
        extensions,
    );
    let third = third.unwrap_or_else(|| root.clone());
    let header = format!(
        r#"{{"alg":"ES256","x5c":["{}","{}","{}"]}}"#,
        base64_encode(&leaf),
        base64_encode(&intermediate),
        base64_encode(&third)
    );
    let signing_input = format!(
        "{}.{}",
        common::base64url(header.as_bytes()),
        common::base64url(br#"{"signedDate":1735689600000}"#)
    );
    let signature = leaf_key.sign_raw(signing_input.as_bytes());
    let jws = format!("{signing_input}.{}", common::base64url(&signature));
    (TrustAnchor::from_der(&root).unwrap(), jws)
}

#[test]
fn x509_reader_probe() {
    use common::mint::{RECEIPT_SIGNER_MARKER, WWDR_MARKER};
    use common::{der, der_oid, der_seq, tag};
    let extension = |oid| der_seq(&[der_oid(oid), der(tag::OCTET_STRING, &[0x05, 0x00])]);
    // A basicConstraints whose value is a NULL, not a SEQUENCE.
    let undecodable_bc = der_seq(&[der_oid("2.5.29.19"), der(tag::OCTET_STRING, &[0x05, 0x00])]);
    let none: &[Vec<u8>] = &[];
    let inputs: Vec<(&str, (TrustAnchor, String))> = vec![
        ("baseline: version 2 (v3)", probe_jws(none, none, &[2], None)),
        ("leaf version 10 (v11)", probe_jws(none, none, &[10], None)),
        (
            "leaf version 2^32 + 2",
            probe_jws(none, none, &[0x01, 0x00, 0x00, 0x00, 0x02], None),
        ),
        (
            "leaf receipt-signing marker twice",
            probe_jws(none, &[extension(RECEIPT_SIGNER_MARKER)], &[2], None),
        ),
        (
            "leaf 1.2.3.4 twice",
            probe_jws(none, &[extension("1.2.3.4"), extension("1.2.3.4")], &[2], None),
        ),
        (
            "intermediate WWDR marker twice",
            probe_jws(&[extension(WWDR_MARKER)], none, &[2], None),
        ),
        (
            "leaf basicConstraints undecodable",
            probe_jws(none, &[undecodable_bc.clone()], &[2], None),
        ),
        (
            "x5c[2] basicConstraints undecodable",
            probe_jws(none, none, &[2], Some(third_with(&undecodable_bc))),
        ),
    ];
    for (label, (root, jws)) in inputs {
        let answer = match common::verifier([root]).verify_signed_data(&jws) {
            Ok(_) => "ok".to_owned(),
            Err(failure) => format!("{:?}", failure.reason()),
        };
        println!("PROBE {label}: {answer}");
    }
}

/// A self-issued certificate, outside the path, carrying `extra`.
fn third_with(extra: &[u8]) -> Vec<u8> {
    use common::mint::{key, name, spki, ECDSA_WITH_SHA256};
    use common::{der, der_int, der_oid, der_seq, tag};
    let k = key(21);
    let algorithm = der_seq(&[der_oid(ECDSA_WITH_SHA256)]);
    let tbs = der_seq(&[
        der(tag::CONTEXT_0, &der_int(2)),
        der_int(9),
        algorithm.clone(),
        name("Stranger"),
        der_seq(&[der(0x17, b"200101000000Z"), der(0x18, b"20991231000000Z")]),
        name("Stranger"),
        spki(&k),
        der(0xA3, &der_seq(&[extra.to_vec()])),
    ]);
    let signature = k.sign_der(&tbs);
    common::mint::assemble(tbs, algorithm, &signature)
}

/// The four shared cases whose intermediate carries a keyUsage or a cA
/// BOOLEAN that does not decode. Their `oneOf` lists every answer, so the
/// conformance run passes whatever the core says; this prints what it says.
#[test]
fn x509_reader_probe_cases() {
    let answer = |result: Result<(), apple_purchase_receipt_verifier::Failure>| match result {
        Ok(()) => "ok".to_owned(),
        Err(failure) => format!("{:?}", failure.reason()),
    };
    for (label, root, receipt) in [
        (
            "receipt/intermediate-with-a-malformed-key-usage-does-not-crash",
            "generated-0.7/keyusage-receipt-root.der",
            "generated-0.7/keyusage-receipt-intermediate-malformed.der",
        ),
        (
            "receipt/intermediate-with-an-empty-ca-boolean-does-not-crash",
            "generated-0.7/der-receipt-root.der",
            "generated-0.7/der-receipt-intermediate-ca-boolean-empty.der",
        ),
    ] {
        let base64 = base64_encode(&common::read_fixture(receipt));
        let result = common::verifier([common::anchor(root)])
            .verify_receipt(&base64)
            .map(|_| ());
        println!("PROBE {label}: {}", answer(result));
    }
    for (label, root, jws) in [
        (
            "signed-data/intermediate-with-a-malformed-key-usage-does-not-crash",
            "generated-0.7/keyusage-jws-root.der",
            "generated-0.7/keyusage-jws-intermediate-malformed.jws",
        ),
        (
            "signed-data/intermediate-with-an-empty-ca-boolean-does-not-crash",
            "generated-0.7/der-jws-root.der",
            "generated-0.7/der-jws-intermediate-ca-boolean-empty.jws",
        ),
    ] {
        let result = common::verifier([common::anchor(root)])
            .verify_signed_data(&common::read_text_fixture(jws))
            .map(|_| ());
        println!("PROBE {label}: {}", answer(result));
    }
}
